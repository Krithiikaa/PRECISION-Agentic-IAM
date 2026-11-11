"""Phase 12: the audit trail is tamper-EVIDENT.

Every tamper test does what an insider with database access would do -- an
UPDATE, DELETE or INSERT straight against the tables, bypassing the
application -- and then asserts the server-side verifier names it. Nothing
here checks a UI; nothing trusts a key read from the database.

    modification   EVENT_MODIFIED + EVENT_MAC_INVALID
    deletion       EVENT_DELETED, CHAIN_GAP
    reordering     ENTRY_HASH_MISMATCH / CHAIN_LINK_BROKEN
    insertion      EVENT_MAC_MISSING / EVENT_MAC_INVALID (before AND after sealing)
    chain rewrite  CHECKPOINT_MISMATCH (the attacker cannot re-sign)
    truncation     CHECKPOINT_MISMATCH
    forged signer  CHECKPOINT_UNTRUSTED_KEY
"""
from __future__ import annotations

import asyncio
import base64
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.audit import integrity as ig
from app.audit.chain import AUDIT_INTEGRITY_RULE, AuditChain
from app.audit.service import AuditService
from app.core.config import get_settings
from app.db.models.audit import AuditChainEntry, AuditCheckpoint, AuditEvent
from app.db.models.security import AlertSeverity, SecurityAlert
from app.monitoring.events import Event, EventType

pytestmark = pytest.mark.integration


@pytest.fixture
def chain(session, keystore):
    return AuditChain(session, keystore, get_settings())


async def _write(session, n=3, **kw):
    audit = AuditService(session)
    for i in range(n):
        await audit.record(Event(EventType.TOOL_EXECUTED, agent_did="did:poc:agent:risk-001",
                                 request_id=f"req-{i}", resource="credit_records",
                                 action="read", decision="ALLOW", reason=f"event {i}",
                                 metadata={"latency_ms": 12.5 + i, "n": i, "ok": True,
                                           "nested": {"b": [1, 2.0, "x"], "a": None}, **kw}))
    await session.flush()


def kinds(report):
    return {f.kind for f in report.findings}


# --------------------------------------------------------------------------
class TestCanonicalEncoding:
    def test_numbers_survive_a_jsonb_style_round_trip(self):
        assert ig.canonical_bytes({"x": 5.0}) == ig.canonical_bytes({"x": 5})
        assert ig.canonical_bytes({"x": 1e20}) == ig.canonical_bytes({"x": 10 ** 20})
        assert ig.canonical_bytes({"b": 1, "a": 2}) == ig.canonical_bytes({"a": 2, "b": 1})

    def test_different_values_hash_differently(self):
        assert ig.canonical_bytes({"x": 1}) != ig.canonical_bytes({"x": "1"})
        assert ig.canonical_bytes({"x": True}) != ig.canonical_bytes({"x": 1})

    def test_non_json_values_are_refused_not_stringified(self):
        with pytest.raises(TypeError):
            ig.canonical_bytes({"x": object()})


class TestSealingAndVerification:
    async def test_every_write_carries_a_mac(self, session):
        await _write(session, 1)
        row = (await session.execute(select(AuditEvent))).scalar_one()
        assert row.integrity_mac and len(row.integrity_mac) == 64

    async def test_a_clean_trail_verifies(self, session, chain):
        await _write(session, 5)
        result = await chain.seal(force_checkpoint=True)
        assert result.sealed == 5 and result.head_index == 5
        report = await chain.verify()
        assert report.ok, report.to_dict()
        assert report.entries_checked == 6           # genesis + 5
        assert report.checkpoints_verified == 1 and report.mac_checked

    async def test_each_entry_links_to_the_previous_one(self, session, chain):
        await _write(session, 3)
        await chain.seal()
        rows = (await session.execute(
            select(AuditChainEntry).order_by(AuditChainEntry.chain_index))).scalars().all()
        assert rows[0].kind == "GENESIS" and rows[0].prev_hash == ig.GENESIS_PREV
        for prev, cur in zip(rows, rows[1:]):
            assert cur.prev_hash == prev.entry_hash

    async def test_sealing_twice_seals_nothing_new(self, session, chain):
        await _write(session, 2)
        await chain.seal()
        again = await chain.seal()
        assert again.sealed == 0 and again.head_index == 2

    async def test_genesis_covers_everything_on_a_fresh_database(self, session, chain):
        await _write(session, 2)
        await chain.seal()
        report = await chain.verify()
        assert report.covers_from_seq == 1 and report.events_before_coverage == 0

    async def test_legacy_events_are_reported_as_outside_coverage_not_verified(
        self, session, chain
    ):
        await _write(session, 3)
        max_seq = (await session.execute(select(func.max(AuditEvent.seq)))).scalar_one()
        detail = {"covers_from_seq": max_seq + 1, "created": "test migration"}
        content = ig.genesis_content_hash(detail)
        session.add(AuditChainEntry(
            chain_index=0, kind="GENESIS", content_hash=content, prev_hash=ig.GENESIS_PREV,
            detail=detail, entry_hash=ig.entry_hash(
                chain_index=0, kind="GENESIS", event_seq=None, event_id=None,
                content_hash=content, prev_hash=ig.GENESIS_PREV)))
        await session.flush()
        await _write(session, 1)
        assert (await chain.seal()).sealed == 1
        report = await chain.verify()
        assert report.ok and report.events_before_coverage == 3


class TestTamperingIsDetected:
    async def test_modifying_a_sealed_event(self, session, chain):
        await _write(session, 3)
        await chain.seal()
        await session.execute(update(AuditEvent).where(AuditEvent.request_id == "req-1")
                              .values(decision="DENY"))
        report = await chain.verify()
        assert not report.ok
        assert {"EVENT_MODIFIED", "EVENT_MAC_INVALID"} <= kinds(report)

    async def test_modifying_only_the_timestamp(self, session, chain):
        await _write(session, 2)
        await chain.seal()
        await session.execute(update(AuditEvent).where(AuditEvent.request_id == "req-0")
                              .values(occurred_at=datetime(2020, 1, 1, tzinfo=timezone.utc)))
        assert "EVENT_MODIFIED" in kinds(await chain.verify())

    async def test_modifying_metadata(self, session, chain):
        await _write(session, 2)
        await chain.seal()
        await session.execute(update(AuditEvent).where(AuditEvent.request_id == "req-0")
                              .values(event_metadata={"latency_ms": 1}))
        assert "EVENT_MODIFIED" in kinds(await chain.verify())

    async def test_deleting_a_sealed_event(self, session, chain):
        await _write(session, 3)
        await chain.seal()
        await session.execute(delete(AuditEvent).where(AuditEvent.request_id == "req-1"))
        report = await chain.verify()
        assert "EVENT_DELETED" in kinds(report)

    async def test_deleting_a_chain_entry(self, session, chain):
        await _write(session, 3)
        await chain.seal()
        await session.execute(delete(AuditChainEntry).where(AuditChainEntry.chain_index == 2))
        report = await chain.verify()
        assert {"CHAIN_GAP", "CHAIN_LINK_BROKEN"} <= kinds(report)

    async def test_reordering_two_events(self, session, chain):
        await _write(session, 3)
        await chain.seal()
        a, b = (await session.execute(select(AuditChainEntry).where(
            AuditChainEntry.chain_index.in_([1, 2])).order_by(AuditChainEntry.chain_index)
        )).scalars().all()
        ida, seqa, idb, seqb = a.event_id, a.event_seq, b.event_id, b.event_seq
        # Swap which event each entry points at (via a placeholder: both are unique).
        await session.execute(update(AuditChainEntry).where(AuditChainEntry.chain_index == 1)
                              .values(event_id=uuid.uuid4(), event_seq=-1))
        await session.execute(update(AuditChainEntry).where(AuditChainEntry.chain_index == 2)
                              .values(event_id=ida, event_seq=seqa))
        await session.execute(update(AuditChainEntry).where(AuditChainEntry.chain_index == 1)
                              .values(event_id=idb, event_seq=seqb))
        report = await chain.verify()
        assert "ENTRY_HASH_MISMATCH" in kinds(report)

    async def test_inserting_a_forged_event_without_the_key(self, session, chain):
        await _write(session, 2)
        await chain.seal()
        session.add(AuditEvent(event_type=EventType.INCIDENT_REINSTATED,
                               agent_did="did:poc:agent:risk-001", decision="REINSTATED",
                               reason="forged by an insider", event_metadata={}))
        await session.flush()
        # Detected BEFORE the sealer reaches it...
        assert "EVENT_MAC_MISSING" in kinds(await chain.verify())
        # ...and still after the sealer has innocently chained it.
        assert (await chain.seal()).sealed == 1
        assert "EVENT_MAC_MISSING" in kinds(await chain.verify())

    async def test_inserting_a_forged_event_with_a_guessed_mac(self, session, chain):
        await _write(session, 1)
        session.add(AuditEvent(event_type=EventType.TOOL_EXECUTED, decision="ALLOW",
                               event_metadata={}, integrity_mac="ab" * 32))
        await session.flush()
        await chain.seal()
        assert "EVENT_MAC_INVALID" in kinds(await chain.verify())

    async def test_rewriting_the_chain_after_an_edit_is_caught_by_the_checkpoint(
        self, session, chain
    ):
        """The strongest DB-only attack: edit an event, recompute its MAC-less
        content hash and every later link. Only the signature stops it."""
        await _write(session, 4)
        await chain.seal(force_checkpoint=True)
        await session.execute(update(AuditEvent).where(AuditEvent.request_id == "req-1")
                              .values(reason="rewritten history"))
        entries = (await session.execute(select(AuditChainEntry).order_by(
            AuditChainEntry.chain_index))).scalars().all()
        prev = entries[0].entry_hash
        for e in entries[1:]:
            event = (await session.execute(select(AuditEvent).where(
                AuditEvent.id == e.event_id))).scalar_one()
            await session.refresh(event)
            content = ig.event_content_hash(ig.event_dict(event))
            h = ig.entry_hash(chain_index=e.chain_index, kind=e.kind, event_seq=e.event_seq,
                              event_id=str(e.event_id), content_hash=content, prev_hash=prev)
            await session.execute(update(AuditChainEntry).where(
                AuditChainEntry.chain_index == e.chain_index).values(
                content_hash=content, prev_hash=prev, entry_hash=h))
            prev = h
        report = await chain.verify()
        assert "CHECKPOINT_MISMATCH" in kinds(report)
        assert "ENTRY_HASH_MISMATCH" not in kinds(report)   # the rewrite was "perfect"

    async def test_truncating_the_tail_is_caught_by_the_checkpoint(self, session, chain):
        await _write(session, 3)
        await chain.seal(force_checkpoint=True)
        await session.execute(delete(AuditChainEntry).where(AuditChainEntry.chain_index == 3))
        await session.execute(delete(AuditEvent).where(AuditEvent.request_id == "req-2"))
        assert "CHECKPOINT_MISMATCH" in kinds(await chain.verify())

    async def test_a_checkpoint_signed_by_another_key_is_not_trusted(self, session, chain):
        await _write(session, 2)
        result = await chain.seal()
        rogue = Ed25519PrivateKey.generate()
        now = datetime.now(timezone.utc)
        kid = get_settings().audit_checkpoint_kid
        payload = ig.checkpoint_payload(chain_index=result.head_index,
                                        entry_hash_value=result.head_hash, signed_at=now, kid=kid)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        session.add(AuditCheckpoint(
            chain_index=result.head_index, entry_hash=result.head_hash, signed_at=now, kid=kid,
            public_key_b64=base64.b64encode(rogue.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw)).decode(),
            signature_b64=base64.b64encode(rogue.sign(payload)).decode()))
        await session.flush()
        assert "CHECKPOINT_UNTRUSTED_KEY" in kinds(await chain.verify())

    async def test_an_altered_checkpoint_signature_fails(self, session, chain):
        await _write(session, 2)
        await chain.seal(force_checkpoint=True)
        await session.execute(update(AuditCheckpoint).values(entry_hash="f" * 64))
        assert "CHECKPOINT_SIGNATURE_INVALID" in kinds(await chain.verify())

    async def test_an_event_left_unsealed_past_the_grace_period_is_reported(
        self, session, keystore
    ):
        await _write(session, 1)
        settings = get_settings().model_copy(update={"audit_unsealed_grace_seconds": 1})
        chain = AuditChain(session, keystore, settings)
        await chain.seal()
        await _write(session, 1)
        report = await chain.verify(now=datetime.now(timezone.utc) + timedelta(minutes=5))
        assert "UNSEALED_STALE" in kinds(report)

    async def test_an_unsealed_event_within_grace_is_not_a_violation(self, session, chain):
        await _write(session, 1)
        await chain.seal()
        await _write(session, 1)
        report = await chain.verify()
        assert report.ok and report.unsealed_within_grace == 1


class TestActionableSignal:
    async def test_a_violation_raises_a_critical_unattributed_alert_and_an_event(
        self, session, chain
    ):
        await _write(session, 2)
        await chain.seal()
        await session.execute(delete(AuditEvent).where(AuditEvent.request_id == "req-0"))
        report = await chain.verify()
        alert_id = await chain.report_violation(report)
        alert = (await session.execute(select(SecurityAlert).where(
            SecurityAlert.alert_id == alert_id))).scalar_one()
        assert alert.rule == AUDIT_INTEGRITY_RULE and alert.severity is AlertSeverity.CRITICAL
        assert alert.attributed is False and alert.agent_did is None
        events = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == EventType.AUDIT_INTEGRITY_VIOLATION))).scalars().all()
        assert len(events) == 1

    async def test_a_standing_violation_is_one_alert_not_one_per_pass(self, session, chain):
        await _write(session, 2)
        await chain.seal()
        await session.execute(delete(AuditEvent).where(AuditEvent.request_id == "req-0"))
        first = await chain.report_violation(await chain.verify())
        second = await chain.report_violation(await chain.verify())
        assert first == second
        assert (await session.execute(select(func.count(SecurityAlert.id)))).scalar_one() == 1

    async def test_a_clean_trail_raises_nothing(self, session, chain):
        await _write(session, 2)
        await chain.seal()
        assert await chain.report_violation(await chain.verify()) is None


class TestAppendOnlyGuard:
    async def test_the_trigger_refuses_update_and_delete(self, session):
        await _write(session, 1)
        await session.execute(text(ig.APPEND_ONLY_FUNCTION_DDL))
        await session.execute(text(ig.append_only_trigger_ddl("audit_events")))
        for stmt in (update(AuditEvent).values(reason="x"), delete(AuditEvent)):
            with pytest.raises(DBAPIError, match="AUDIT_APPEND_ONLY"):
                async with session.begin_nested():
                    await session.execute(stmt)
        # Inserts are still allowed: it is append-only, not read-only.
        await _write(session, 1)


class TestConcurrencyAndRestart:
    async def test_concurrent_writers_and_two_sealers_produce_one_valid_chain(
        self, engine, session, keystore
    ):
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)
        settings = get_settings()

        async def writer(i):
            async with maker() as s:
                for j in range(10):
                    await AuditService(s).record(Event(
                        EventType.TOOL_EXECUTED, request_id=f"w{i}-{j}", decision="ALLOW"))
                await s.commit()

        async def sealer():
            for _ in range(8):
                async with maker() as s:
                    await AuditChain(s, keystore, settings).seal()
                    await s.commit()
                await asyncio.sleep(0.01)

        await asyncio.gather(*(writer(i) for i in range(6)), sealer(), sealer())
        async with maker() as s:
            await AuditChain(s, keystore, settings).seal(full_sweep=True)
            await s.commit()
        async with maker() as s:
            report = await AuditChain(s, keystore, settings).verify()
            sealed = (await s.execute(select(func.count()).select_from(AuditChainEntry).where(
                AuditChainEntry.kind == "EVENT"))).scalar_one()
        assert report.ok, report.to_dict()
        assert sealed == 60

    async def test_a_transaction_that_commits_late_is_chained_late_not_skipped(
        self, engine, session, keystore
    ):
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)
        settings = get_settings()
        slow = maker()
        await AuditService(slow).record(Event(EventType.TOOL_EXECUTED, request_id="slow"))
        await slow.flush()                         # holds the LOWER seq, uncommitted
        async with maker() as fast:
            await AuditService(fast).record(Event(EventType.TOOL_EXECUTED, request_id="fast"))
            await fast.commit()
        async with maker() as s:
            assert (await AuditChain(s, keystore, settings).seal()).sealed == 1
            await s.commit()
        await slow.commit()
        await slow.close()
        async with maker() as s:
            assert (await AuditChain(s, keystore, settings).seal()).sealed == 1
            await s.commit()
        async with maker() as s:
            report = await AuditChain(s, keystore, settings).verify()
            order = (await s.execute(select(AuditChainEntry.event_seq).where(
                AuditChainEntry.kind == "EVENT").order_by(AuditChainEntry.chain_index)
            )).scalars().all()
        assert report.ok, report.to_dict()
        assert order[0] > order[1]                 # sealing order, not seq order

    async def test_a_restarted_sealer_continues_the_same_chain(self, engine, session, keystore):
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)
        settings = get_settings()
        for round_ in range(3):                    # three "process lifetimes"
            async with maker() as s:
                await _write(s, 2)
                await s.commit()
            async with maker() as s:
                await AuditChain(s, keystore, settings).seal(force_checkpoint=True)
                await s.commit()
        async with maker() as s:
            report = await AuditChain(s, keystore, settings).verify()
        assert report.ok and report.head_index == 6 and report.checkpoints_verified == 3


class TestIntegrityAPI:
    async def test_verification_requires_authentication(self, client):
        assert (await client.get("/api/v1/audit/integrity")).status_code == 401

    async def test_an_agent_may_not_read_integrity(self, client, keystore, control_plane,
                                                   risk_agent, sign_control_plane):
        from app.controlplane.client import canonical_body
        headers = sign_control_plane(risk_agent.did, method="GET",
                                     path="/api/v1/audit/integrity", body=canonical_body(None))
        response = await client.get("/api/v1/audit/integrity", headers=headers)
        assert response.status_code in (401, 403)

    async def test_the_identity_administrator_gets_a_server_side_verdict(
        self, session, cp_get, chain
    ):
        await _write(session, 2)
        await chain.seal(force_checkpoint=True)
        response = await cp_get("/api/v1/audit/integrity")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "VERIFIED" and body["checkpoints_verified"] == 1
        cps = (await cp_get("/api/v1/audit/integrity/checkpoints")).json()
        assert cps["checkpoints"][0]["chain_index"] == body["head_index"]
        assert cps["trusted_keys"]


class TestIndependentVerifier:
    """scripts/verify_audit_chain.py: no app process, a pinned key, read-only."""

    async def test_the_standalone_verifier_agrees_and_detects_tampering(
        self, engine, session, keystore
    ):
        import os
        import subprocess
        import sys
        from pathlib import Path

        maker = async_sessionmaker(bind=engine, expire_on_commit=False)
        settings = get_settings()
        async with maker() as s:
            await _write(s, 3)
            await s.commit()
        async with maker() as s:
            chain = AuditChain(s, keystore, settings)
            await chain.seal(force_checkpoint=True)
            await s.commit()
            key = chain.trusted_keys()[settings.audit_checkpoint_kid]
        script = Path(__file__).resolve().parents[2] / "scripts" / "verify_audit_chain.py"
        env = {**os.environ, "DATABASE_URL": str(engine.url.render_as_string(hide_password=False)),
               "KEYSTORE_MASTER_KEY": settings.keystore_master_key}

        def run(*extra):
            return subprocess.run([sys.executable, str(script), "--public-key", key,
                                   "--check-macs", *extra], env=env, capture_output=True,
                                  text=True, timeout=120)

        clean = run()
        assert clean.returncode == 0, clean.stdout + clean.stderr
        assert "VERIFIED" in clean.stdout and "MACs:                   checked" in clean.stdout

        async with maker() as s:
            await s.execute(update(AuditEvent).where(AuditEvent.request_id == "req-2")
                            .values(reason="edited offline"))
            await s.commit()
        tampered = run()
        assert tampered.returncode == 1, tampered.stdout
        assert "EVENT_MODIFIED" in tampered.stdout

        rogue = run("--expect-checkpoint", "3:" + "0" * 64)
        assert "EXTERNAL_CHECKPOINT_MISMATCH" in rogue.stdout


class TestTheSealerCannotBeSwitchedOffInProduction:
    def test_production_refuses_audit_sealer_disabled(self):
        from pydantic import ValidationError

        from tests.test_production_configuration import production
        with pytest.raises(ValidationError, match="AUDIT_SEALER_ENABLED"):
            production(audit_sealer_enabled=False)
        assert production().audit_sealer_enabled is True
