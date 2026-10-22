"""Heartbeats, staleness, revocation mirroring, resolution and deregistration."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.core.errors import IdentityError, NotFoundError
from app.db.models.agent import AgentStatus
from app.db.models.ans import ANSStatus

pytestmark = pytest.mark.integration


class TestHeartbeat:
    async def test_heartbeat_refreshes_liveness(self, ans_registry, registered_risk_agent):
        before = (await ans_registry.get(registered_risk_agent.did)).last_seen
        agent = await ans_registry.heartbeat(registered_risk_agent.did, active_tasks=3)
        assert agent.last_seen >= before
        assert agent.active_tasks == 3
        assert agent.status == ANSStatus.ACTIVE

    async def test_heartbeat_can_report_busy(self, ans_registry, registered_risk_agent):
        agent = await ans_registry.heartbeat(
            registered_risk_agent.did, status=ANSStatus.BUSY, active_tasks=5
        )
        assert agent.status == ANSStatus.BUSY

    async def test_heartbeat_cannot_move_the_endpoint(
        self, ans_registry, registered_risk_agent
    ):
        """Moving where traffic goes requires a fresh signed registration."""
        with pytest.raises(IdentityError, match="cannot change the endpoint"):
            await ans_registry.heartbeat(
                registered_risk_agent.did, endpoint="http://attacker.invalid:9999"
            )
        agent = await ans_registry.get(registered_risk_agent.did)
        assert agent.endpoint == "http://localhost:9003"

    async def test_unknown_agent_cannot_heartbeat(self, ans_registry):
        with pytest.raises(NotFoundError):
            await ans_registry.heartbeat("did:poc:agent:ghost-999")

    async def test_heartbeats_are_recorded(self, session, ans_registry,
                                           registered_risk_agent):
        from sqlalchemy import select
        from app.db.models.ans import ANSHeartbeat

        await ans_registry.heartbeat(registered_risk_agent.did, active_tasks=1)
        await ans_registry.heartbeat(registered_risk_agent.did, active_tasks=2)
        rows = (await session.execute(
            select(ANSHeartbeat).where(
                ANSHeartbeat.agent_did == registered_risk_agent.did)
        )).scalars().all()
        assert [r.active_tasks for r in rows] == [1, 2]


class TestStaleness:
    async def test_sweep_marks_overdue_agents_stale(
        self, session, ans_registry, registered_risk_agent
    ):
        from app.core.config import get_settings

        settings = get_settings()
        agent = await ans_registry.get(registered_risk_agent.did)
        agent.last_seen = datetime.now(timezone.utc) - timedelta(
            seconds=settings.ans_agent_timeout_seconds + 5
        )
        await session.flush()

        moved = await ans_registry.sweep()
        assert registered_risk_agent.did in moved["stale"]
        assert (await ans_registry.get(registered_risk_agent.did)).status == ANSStatus.STALE

    async def test_sweep_marks_long_overdue_agents_offline(
        self, session, ans_registry, registered_risk_agent
    ):
        from app.core.config import get_settings

        settings = get_settings()
        agent = await ans_registry.get(registered_risk_agent.did)
        agent.last_seen = datetime.now(timezone.utc) - timedelta(
            seconds=settings.ans_agent_offline_seconds + 5
        )
        await session.flush()

        moved = await ans_registry.sweep()
        assert registered_risk_agent.did in moved["offline"]
        assert (await ans_registry.get(registered_risk_agent.did)).status == ANSStatus.OFFLINE

    async def test_a_healthy_agent_is_left_alone(self, ans_registry,
                                                 registered_risk_agent):
        moved = await ans_registry.sweep()
        assert moved == {"stale": [], "offline": []}
        assert (await ans_registry.get(registered_risk_agent.did)).status == ANSStatus.ACTIVE

    async def test_a_stale_agent_recovers_on_the_next_heartbeat(
        self, session, ans_registry, registered_risk_agent
    ):
        from app.core.config import get_settings

        agent = await ans_registry.get(registered_risk_agent.did)
        agent.last_seen = datetime.now(timezone.utc) - timedelta(
            seconds=get_settings().ans_agent_timeout_seconds + 5
        )
        await session.flush()
        await ans_registry.sweep()

        recovered = await ans_registry.heartbeat(registered_risk_agent.did)
        assert recovered.status == ANSStatus.ACTIVE


class TestIdentityMirroring:
    async def test_terminated_identity_is_mirrored_into_the_registry(
        self, ans_registry, registry, registered_risk_agent
    ):
        await registry.terminate(registered_risk_agent.did, "COMPROMISED")
        revoked = await ans_registry.reconcile_identities()

        assert registered_risk_agent.did in revoked
        agent = await ans_registry.get(registered_risk_agent.did)
        assert agent.status == ANSStatus.TERMINATED

    async def test_suspended_identity_becomes_revoked_in_the_registry(
        self, ans_registry, registry, registered_risk_agent
    ):
        await registry.set_status(registered_risk_agent.did, AgentStatus.SUSPENDED, "anomaly")
        await ans_registry.reconcile_identities()
        assert (await ans_registry.get(registered_risk_agent.did)).status == ANSStatus.REVOKED

    async def test_a_revoked_agent_cannot_heartbeat_back_to_life(
        self, ans_registry, registry, registered_risk_agent
    ):
        await registry.terminate(registered_risk_agent.did, "COMPROMISED")
        await ans_registry.reconcile_identities()
        with pytest.raises(IdentityError, match="TERMINATED"):
            await ans_registry.heartbeat(registered_risk_agent.did)


class TestDeregistration:
    async def test_graceful_unregister_takes_the_agent_offline(
        self, ans_registry, registered_risk_agent
    ):
        agent = await ans_registry.unregister(registered_risk_agent.did, "SIGTERM")
        assert agent.status == ANSStatus.OFFLINE
        assert agent.active_tasks == 0

    async def test_unregistering_an_unknown_agent_fails(self, ans_registry):
        with pytest.raises(NotFoundError):
            await ans_registry.unregister("did:poc:agent:ghost-999")


class TestResolution:
    async def test_resolve_returns_everything_needed_to_make_contact(
        self, ans_registry, registered_risk_agent
    ):
        resolved = await ans_registry.resolve(registered_risk_agent.did)
        assert resolved["did"] == registered_risk_agent.did
        assert resolved["endpoint"] == "http://localhost:9003"
        assert resolved["status"] == "ACTIVE"
        assert "credit_analysis" in resolved["capabilities"]
        assert resolved["identity_status"] == "ACTIVE"

    async def test_resolution_reuses_the_phase_one_did_document(
        self, ans_registry, registered_risk_agent
    ):
        """ANS keeps no second copy of the DID Document and cannot disagree."""
        resolved = await ans_registry.resolve(registered_risk_agent.did)
        document = resolved["did_document"]
        assert document["id"] == registered_risk_agent.did
        assert (document["verificationMethod"][0]["publicKeyMultibase"]
                == registered_risk_agent.active_key.public_key_multibase)

    async def test_unknown_did_does_not_resolve(self, ans_registry):
        with pytest.raises(NotFoundError):
            await ans_registry.resolve("did:poc:agent:ghost-999")
