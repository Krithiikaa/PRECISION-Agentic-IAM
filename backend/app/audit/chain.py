"""Database side of the tamper-evident audit trail: sealer, verifier, alerting.

The cryptography and the verification rules are in app/audit/integrity.py and
are pure; this module only reads and writes rows. See that module's docstring
for what is and is not claimed.
"""
from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import integrity as ig
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.models.audit import AuditChainEntry, AuditCheckpoint, AuditEvent
from app.identity.keys import KeyStore

log = get_logger("audit.chain")

AUDIT_INTEGRITY_RULE = "AUDIT_INTEGRITY"


@dataclass
class SealResult:
    sealed: int
    head_index: int
    head_hash: str
    checkpoint_index: int | None = None


def _unsealed_query(floor_seq: int):
    sealed = select(AuditChainEntry.event_id).where(AuditChainEntry.event_id.is_not(None))
    return (select(AuditEvent)
            .where(AuditEvent.seq >= floor_seq, AuditEvent.id.not_in(sealed))
            .order_by(AuditEvent.seq))


class AuditChain:
    def __init__(self, session: AsyncSession, keystore: KeyStore | None = None,
                 settings: Settings | None = None) -> None:
        self.session = session
        self.keystore = keystore
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------ keys
    def _checkpoint_key(self) -> tuple[str, str] | None:
        """(kid, public key b64) of the checkpoint key, creating it on first use."""
        if self.keystore is None:
            return None
        kid = self.settings.audit_checkpoint_kid
        handle = (self.keystore.get_public_key(kid) if self.keystore.exists(kid)
                  else self.keystore.generate_key(kid))
        return kid, handle.public_key_b64

    def trusted_keys(self) -> dict[str, str]:
        keys: dict[str, str] = {}
        if self.keystore is not None and self.keystore.exists(self.settings.audit_checkpoint_kid):
            keys[self.settings.audit_checkpoint_kid] = self.keystore.get_public_key(
                self.settings.audit_checkpoint_kid).public_key_b64
        pinned = self.settings.audit_pinned_checkpoint_key.strip()
        if pinned:
            # A pin REPLACES trust in the keystore's key: an auditor's
            # out-of-band record is the stronger anchor.
            keys = {self.settings.audit_checkpoint_kid: pinned}
        return keys

    # ---------------------------------------------------------------- genesis
    async def _genesis(self) -> AuditChainEntry:
        existing = (await self.session.execute(
            select(AuditChainEntry).where(AuditChainEntry.chain_index == 0))).scalar_one_or_none()
        if existing is not None:
            return existing
        # Created lazily only on a database that never ran the Phase 12
        # migration (create_all: tests, fresh installs), where every row was
        # written by Phase 12 code. Coverage starts at seq 1, NOT at the
        # smallest committed seq: a transaction still in flight may hold a
        # lower seq, and starting above it would leave that row outside
        # coverage for ever (a regression test asserts this).
        detail = {"covers_from_seq": 1, "created": "lazily by the sealer",
                  "created_at": datetime.now(timezone.utc).isoformat()}
        content = ig.genesis_content_hash(detail)
        row = AuditChainEntry(
            chain_index=0, kind="GENESIS", event_id=None, event_seq=None,
            content_hash=content, prev_hash=ig.GENESIS_PREV, detail=detail,
            entry_hash=ig.entry_hash(chain_index=0, kind="GENESIS", event_seq=None,
                                     event_id=None, content_hash=content,
                                     prev_hash=ig.GENESIS_PREV))
        self.session.add(row)
        await self.session.flush()
        return row

    # ---------------------------------------------------------------- sealing
    async def seal(self, *, full_sweep: bool = False, force_checkpoint: bool = False,
                   now: datetime | None = None) -> SealResult:
        """Chain every committed, unsealed event. Caller commits.

        The advisory lock is TRANSACTION-scoped: it is released by the
        caller's commit or rollback, so a crashed sealer can never leave the
        chain locked. Two sealers (two API workers) serialise on it; the
        UNIQUE constraints on chain_index, event_id and event_seq are the
        backstop that turns any remaining race into an error, not a fork.
        """
        now = now or datetime.now(timezone.utc)
        await self.session.execute(text("SELECT pg_advisory_xact_lock(:k)"),
                                   {"k": ig.SEALER_LOCK_KEY})
        genesis = await self._genesis()
        covers_from = int((genesis.detail or {}).get("covers_from_seq") or 1)
        head = (await self.session.execute(
            select(AuditChainEntry).order_by(AuditChainEntry.chain_index.desc()).limit(1)
        )).scalar_one()
        floor = covers_from
        if not full_sweep:
            max_sealed = (await self.session.execute(
                select(func.max(AuditChainEntry.event_seq)))).scalar_one()
            if max_sealed is not None:
                floor = max(covers_from, int(max_sealed) - ig.LOOKBACK_SEQ)

        rows = (await self.session.execute(
            _unsealed_query(floor).limit(self.settings.audit_seal_batch_size)
        )).scalars().all()
        index, prev = head.chain_index, head.entry_hash
        for event in rows:
            index += 1
            content = ig.event_content_hash(ig.event_dict(event))
            h = ig.entry_hash(chain_index=index, kind="EVENT", event_seq=event.seq,
                              event_id=str(event.id), content_hash=content, prev_hash=prev)
            self.session.add(AuditChainEntry(
                chain_index=index, kind="EVENT", event_id=event.id, event_seq=event.seq,
                content_hash=content, prev_hash=prev, entry_hash=h, detail={}))
            prev = h
        if rows:
            await self.session.flush()

        checkpoint_index = None
        if rows or force_checkpoint:
            checkpoint_index = await self._maybe_checkpoint(index, prev, now=now,
                                                            force=force_checkpoint)
        return SealResult(sealed=len(rows), head_index=index, head_hash=prev,
                          checkpoint_index=checkpoint_index)

    async def _maybe_checkpoint(self, index: int, head_hash: str, *, now: datetime,
                                force: bool) -> int | None:
        key = self._checkpoint_key()
        if key is None:
            return None
        last = (await self.session.execute(
            select(AuditCheckpoint).order_by(AuditCheckpoint.chain_index.desc()).limit(1)
        )).scalar_one_or_none()
        if last is not None and last.chain_index >= index:
            return None
        due = (force or last is None
               or (now - last.signed_at).total_seconds() >= self.settings.audit_checkpoint_interval_seconds
               or index - last.chain_index >= 1000)
        if not due:
            return None
        kid, public = key
        payload = ig.checkpoint_payload(chain_index=index, entry_hash_value=head_hash,
                                        signed_at=now, kid=kid)
        signature = base64.b64encode(self.keystore.sign(kid, payload)).decode()
        self.session.add(AuditCheckpoint(chain_index=index, entry_hash=head_hash, signed_at=now,
                                         kid=kid, public_key_b64=public,
                                         signature_b64=signature))
        await self.session.flush()
        # Also to the process log: a copy outside the database is what lets
        # an operator detect truncation of the chain AND its checkpoints.
        log.info("audit_checkpoint_signed", chain_index=index, entry_hash=head_hash, kid=kid)
        return index

    # ----------------------------------------------------------- verification
    async def verify(self, *, now: datetime | None = None, batch: int = 5000) -> ig.IntegrityReport:
        now = now or datetime.now(timezone.utc)
        mac_key = ig.derive_mac_key(self.settings.keystore_master_key)
        verifier = ig.ChainVerifier(trusted_keys=self.trusted_keys(), mac_key=mac_key)
        last = -1
        while True:
            rows = (await self.session.execute(
                select(AuditChainEntry, AuditEvent)
                .outerjoin(AuditEvent, AuditEvent.id == AuditChainEntry.event_id)
                .where(AuditChainEntry.chain_index > last)
                .order_by(AuditChainEntry.chain_index).limit(batch))).all()
            if not rows:
                break
            for entry, event in rows:
                verifier.feed(ig.rows_to_entries([entry])[0],
                              ig.event_dict(event) if event is not None else None)
                last = entry.chain_index
        for cp in (await self.session.execute(
                select(AuditCheckpoint).order_by(AuditCheckpoint.chain_index))).scalars():
            verifier.check_checkpoint({"chain_index": cp.chain_index, "entry_hash": cp.entry_hash,
                                       "signed_at": cp.signed_at, "kid": cp.kid,
                                       "public_key_b64": cp.public_key_b64,
                                       "signature_b64": cp.signature_b64})
        before = 0
        within_grace = 0
        if verifier.covers_from_seq is not None:
            before = (await self.session.execute(select(func.count(AuditEvent.id)).where(
                AuditEvent.seq < verifier.covers_from_seq))).scalar_one()
            cutoff = ig.unsealed_grace_cutoff(now, self.settings.audit_unsealed_grace_seconds)
            for event in (await self.session.execute(
                    _unsealed_query(verifier.covers_from_seq))).scalars():
                ev = ig.event_dict(event)
                # Unsealed rows are checked by MAC, so a forged row is caught
                # before the sealer gets to it, not only after.
                verifier.check_mac(ev)
                if event.occurred_at < cutoff:
                    verifier.findings.append(ig.Finding(
                        "UNSEALED_STALE", "event older than the sealing grace period is not "
                        "in the chain (sealer down, or row inserted with a back-dated seq)",
                        event_seq=event.seq))
                else:
                    within_grace += 1
        return verifier.report(events_before_coverage=int(before),
                               unsealed_within_grace=within_grace)

    async def report_violation(self, report: ig.IntegrityReport) -> str | None:
        """Turn a failed verification into an audit event and a CRITICAL alert.

        The alert is unattributed (no agent DID moves trust) and de-duplicated
        per finding set, so a standing violation is one alert, not one per
        verification pass. Caller commits.
        """
        if report.ok:
            return None
        from app.audit.service import AuditService
        from app.db.models.security import AlertSeverity, AlertStatus, SecurityAlert
        from app.monitoring.events import Event, EventType

        first = report.findings[0]
        signature = ig.sha256_hex(ig.canonical_bytes(
            sorted(f"{f.kind}:{f.chain_index}:{f.event_seq}" for f in report.findings)))[:32]
        dedup = f"audit-integrity:{signature}"
        exists = (await self.session.execute(
            select(SecurityAlert.alert_id).where(SecurityAlert.dedup_key == dedup)
        )).scalar_one_or_none()
        summary = (f"Audit trail integrity violation: {len(report.findings)} finding(s); "
                   f"first {first.kind} at entry {first.chain_index} / seq {first.event_seq}")
        await AuditService(self.session).record(Event(
            EventType.AUDIT_INTEGRITY_VIOLATION, decision="VIOLATION", reason=summary[:500],
            metadata={"findings": [f.to_dict() for f in report.findings[:50]],
                      "finding_count": len(report.findings), "head_index": report.head_index,
                      "alert_dedup_key": dedup}))
        alert_id = exists
        if exists is None:
            alert_id = f"alert-{secrets.token_hex(6)}"
            self.session.add(SecurityAlert(
                alert_id=alert_id, agent_did=None, rule=AUDIT_INTEGRITY_RULE,
                severity=AlertSeverity.CRITICAL, status=AlertStatus.OPEN,
                summary=summary[:512], dedup_key=dedup, attributed=False,
                evidence={"findings": [f.to_dict() for f in report.findings[:50]],
                          "head_index": report.head_index,
                          "action": "Preserve the database and logs; compare against the "
                                    "last externally retained checkpoint; see "
                                    "docs/OPERATIONS_RUNBOOK.md (audit integrity)."}))
        await self.session.flush()
        log.error("audit_integrity_violation", findings=len(report.findings),
                  first=first.kind, chain_index=first.chain_index, alert_id=alert_id)
        return alert_id

    async def checkpoints(self, *, limit: int = 50) -> list[dict[str, Any]]:
        rows = (await self.session.execute(
            select(AuditCheckpoint).order_by(AuditCheckpoint.chain_index.desc()).limit(limit)
        )).scalars()
        return [{"chain_index": r.chain_index, "entry_hash": r.entry_hash,
                 "signed_at": r.signed_at.isoformat(), "kid": r.kid,
                 "public_key_b64": r.public_key_b64, "signature_b64": r.signature_b64}
                for r in rows]


def stale_cutoff(now: datetime, seconds: float) -> datetime:
    return now - timedelta(seconds=seconds)
