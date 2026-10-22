"""Capability-aware discovery, credential filtering and ranking."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.ans.discovery import DiscoveryQuery, DiscoveryReason
from app.credentials.issuer import IssueRequest
from app.credentials.status import CredentialStatusService
from app.db.models.agent import AgentStatus, AgentType
from app.db.models.ans import ANSStatus

pytestmark = pytest.mark.integration


@pytest.fixture
async def three_risk_agents(registry, agent_spec, ans_registry, sign_registration):
    """Three real agents offering credit_analysis, registered with real proofs."""
    agents = []
    for index, port in enumerate((9003, 9006, 9007), start=1):
        agent = await registry.create_agent(
            agent_spec(f"risk-00{index}", name=f"Credit Risk Agent {index}",
                       agent_type=AgentType.RISK,
                       capabilities=["credit_analysis", "risk_analysis"],
                       endpoint=f"http://localhost:{port}")
        )
        payload, signature = sign_registration(
            agent, endpoint=f"http://localhost:{port}",
            capabilities=["credit_analysis", "risk_analysis"],
        )
        result = await ans_registry.register(payload, signature)
        assert result.accepted
        agents.append(agent)
    return agents


def dids(candidates) -> list[str]:
    return [c.agent.did for c in candidates]


class TestCapabilityDiscovery:
    async def test_capability_match(self, discovery, registered_risk_agent):
        outcome = await discovery.discover(DiscoveryQuery(capability="credit_analysis"))
        assert dids(outcome.results) == [registered_risk_agent.did]
        assert outcome.reason == DiscoveryReason.MATCH
        assert outcome.selected.agent.did == registered_risk_agent.did

    async def test_capability_mismatch_returns_nothing(
        self, discovery, registered_risk_agent
    ):
        outcome = await discovery.discover(DiscoveryQuery(capability="payroll_access"))
        assert outcome.results == []
        assert outcome.reason == DiscoveryReason.NO_MATCHING_AGENT
        assert outcome.selected is None      # never a fallback

    async def test_multiple_required_capabilities(
        self, discovery, ans_registry, sign_registration, risk_agent
    ):
        payload, signature = sign_registration(
            risk_agent, capabilities=["credit_analysis", "risk_analysis"]
        )
        await ans_registry.register(payload, signature)

        both = await discovery.discover(
            DiscoveryQuery(capabilities=["credit_analysis", "risk_analysis"])
        )
        assert len(both.results) == 1

        missing = await discovery.discover(
            DiscoveryQuery(capabilities=["credit_analysis", "loan_decision"])
        )
        assert missing.results == []
        assert missing.rejected[0].reason_code == DiscoveryReason.CAPABILITY_MISMATCH

    async def test_result_explains_why_it_matched(self, discovery, registered_risk_agent):
        outcome = await discovery.discover(DiscoveryQuery(capability="credit_analysis"))
        names = [r["name"] for r in outcome.selected.reasons]
        assert names == ["capability", "status", "identity", "liveness"]
        assert all(r["passed"] for r in outcome.selected.reasons)
        assert all(r["detail"] for r in outcome.selected.reasons)

    async def test_rejection_explains_why_it_did_not(self, discovery, three_risk_agents,
                                                     ans_registry):
        agent = three_risk_agents[0]
        await ans_registry.unregister(agent.did, "TEST")

        outcome = await discovery.discover(DiscoveryQuery(capability="credit_analysis"))
        rejected = next(c for c in outcome.rejected if c.agent.did == agent.did)
        assert rejected.reason_code == DiscoveryReason.STATUS_NOT_DISCOVERABLE
        assert "OFFLINE" in next(
            r["detail"] for r in rejected.reasons if r["name"] == "status"
        )


class TestMultiAttributeDiscovery:
    async def test_organization_filter(self, discovery, registered_risk_agent):
        match = await discovery.discover(
            DiscoveryQuery(capability="credit_analysis",
                           organization="did:poc:organization:bank-demo")
        )
        assert len(match.results) == 1

        miss = await discovery.discover(
            DiscoveryQuery(capability="credit_analysis",
                           organization="did:poc:organization:someone-else")
        )
        assert miss.results == []

    async def test_status_filter(self, discovery, ans_registry, registered_risk_agent):
        await ans_registry.heartbeat(registered_risk_agent.did, status=ANSStatus.BUSY)

        default = await discovery.discover(DiscoveryQuery(capability="credit_analysis"))
        assert default.results == []
        assert default.rejected[0].reason_code == DiscoveryReason.STATUS_NOT_DISCOVERABLE

        explicit = await discovery.discover(
            DiscoveryQuery(capability="credit_analysis",
                           status=[ANSStatus.ACTIVE, ANSStatus.BUSY])
        )
        assert len(explicit.results) == 1

    async def test_trust_filter_does_not_invent_a_score(
        self, discovery, registered_risk_agent
    ):
        """Trust scores arrive in Phase 10; until then absence must exclude."""
        outcome = await discovery.discover(
            DiscoveryQuery(capability="credit_analysis", min_trust_score=50)
        )
        assert outcome.results == []
        assert outcome.rejected[0].reason_code == DiscoveryReason.TRUST_TOO_LOW
        assert "no trust score recorded" in next(
            r["detail"] for r in outcome.rejected[0].reasons if r["name"] == "trust"
        )

    async def test_healthy_endpoint_filter(self, discovery, session,
                                           ans_registry, registered_risk_agent):
        outcome = await discovery.discover(
            DiscoveryQuery(capability="credit_analysis", require_healthy_endpoint=True)
        )
        assert outcome.results == []       # never probed yet
        assert outcome.rejected[0].reason_code == DiscoveryReason.ENDPOINT_UNHEALTHY


class TestCredentialAwareDiscovery:
    async def test_agent_without_the_credential_is_filtered(
        self, discovery, registered_risk_agent
    ):
        outcome = await discovery.discover(
            DiscoveryQuery(capability="credit_analysis",
                           required_credentials=["ComplianceCredential"])
        )
        assert outcome.results == []
        assert outcome.rejected[0].reason_code == DiscoveryReason.CREDENTIAL_MISSING

    async def test_agent_with_a_valid_credential_is_returned(
        self, discovery, credential_issuer, compliance_issuer_did, registered_risk_agent
    ):
        await credential_issuer.issue(
            IssueRequest(compliance_issuer_did, registered_risk_agent.did,
                         "ComplianceCredential",
                         {"framework": "SOX", "status": "COMPLIANT",
                          "scope": "financial_data_processing"})
        )
        outcome = await discovery.discover(
            DiscoveryQuery(capability="credit_analysis",
                           required_credentials=["ComplianceCredential"])
        )
        assert dids(outcome.results) == [registered_risk_agent.did]
        detail = next(r["detail"] for r in outcome.selected.reasons
                      if r["name"] == "credential:ComplianceCredential")
        assert "valid" in detail

    async def test_revoked_credential_excludes_the_agent(
        self, session, discovery, credential_issuer, compliance_issuer_did,
        registered_risk_agent
    ):
        """The mandatory credential test (spec section 56)."""
        record = await credential_issuer.issue(
            IssueRequest(compliance_issuer_did, registered_risk_agent.did,
                         "ComplianceCredential",
                         {"framework": "SOX", "status": "COMPLIANT",
                          "scope": "financial_data_processing"})
        )
        query = DiscoveryQuery(capability="credit_analysis",
                               required_credentials=["ComplianceCredential"])
        assert len((await discovery.discover(query)).results) == 1

        await CredentialStatusService(session).revoke(record.credential_id, "COMPROMISED")

        outcome = await discovery.discover(query)
        assert outcome.results == []
        assert outcome.rejected[0].reason_code == DiscoveryReason.CREDENTIAL_INVALID
        assert "CREDENTIAL_REVOKED" in next(
            r["detail"] for r in outcome.rejected[0].reasons
            if r["name"].startswith("credential:")
        )

    async def test_expired_credential_excludes_the_agent(
        self, discovery, credential_issuer, compliance_issuer_did, registered_risk_agent
    ):
        import asyncio

        await credential_issuer.issue(
            IssueRequest(compliance_issuer_did, registered_risk_agent.did,
                         "ComplianceCredential",
                         {"framework": "SOX", "status": "COMPLIANT",
                          "scope": "financial_data_processing"},
                         ttl_seconds=1)
        )
        query = DiscoveryQuery(capability="credit_analysis",
                               required_credentials=["ComplianceCredential"])
        assert len((await discovery.discover(query)).results) == 1

        await asyncio.sleep(1.2)
        outcome = await discovery.discover(query)
        assert outcome.results == []
        assert "CREDENTIAL_EXPIRED" in next(
            r["detail"] for r in outcome.rejected[0].reasons
            if r["name"].startswith("credential:")
        )

    async def test_a_stale_index_row_cannot_smuggle_a_revoked_credential(
        self, session, discovery, credential_issuer, compliance_issuer_did,
        registered_risk_agent
    ):
        """The index says ACTIVE; live state says REVOKED. Live state wins."""
        from sqlalchemy import select
        from app.db.models.ans import ANSAgentCredential

        record = await credential_issuer.issue(
            IssueRequest(compliance_issuer_did, registered_risk_agent.did,
                         "ComplianceCredential",
                         {"framework": "SOX", "status": "COMPLIANT",
                          "scope": "financial_data_processing"})
        )
        session.add(ANSAgentCredential(
            agent_did=registered_risk_agent.did, credential_id=record.credential_id,
            credential_type="ComplianceCredential", status="ACTIVE",
            expires_at=record.expires_at, indexed_at=datetime.now(timezone.utc),
        ))
        await session.flush()
        await CredentialStatusService(session).revoke(record.credential_id, "COMPROMISED")

        # The index row still claims ACTIVE...
        indexed = (await session.execute(
            select(ANSAgentCredential).where(
                ANSAgentCredential.credential_id == record.credential_id)
        )).scalars().first()
        assert indexed.status == "ACTIVE"

        # ...and discovery still refuses, because it re-verifies.
        outcome = await discovery.discover(
            DiscoveryQuery(capability="credit_analysis",
                           required_credentials=["ComplianceCredential"])
        )
        assert outcome.results == []


class TestIdentityAndLiveness:
    async def test_terminated_identity_is_excluded(
        self, discovery, registry, registered_risk_agent
    ):
        await registry.terminate(registered_risk_agent.did, "COMPROMISED")
        outcome = await discovery.discover(DiscoveryQuery(capability="credit_analysis"))
        assert outcome.results == []
        assert outcome.rejected[0].reason_code == DiscoveryReason.IDENTITY_NOT_ELIGIBLE

    async def test_suspended_identity_is_excluded(
        self, discovery, registry, registered_risk_agent
    ):
        await registry.set_status(registered_risk_agent.did, AgentStatus.SUSPENDED, "anomaly")
        outcome = await discovery.discover(DiscoveryQuery(capability="credit_analysis"))
        assert outcome.results == []

    async def test_stale_heartbeat_excludes_the_agent(
        self, session, discovery, ans_registry, registered_risk_agent, settings=None
    ):
        from app.core.config import get_settings

        agent = await ans_registry.get(registered_risk_agent.did)
        agent.last_seen = datetime.now(timezone.utc) - timedelta(
            seconds=get_settings().ans_agent_timeout_seconds + 30
        )
        await session.flush()

        outcome = await discovery.discover(DiscoveryQuery(capability="credit_analysis"))
        assert outcome.results == []
        assert outcome.rejected[0].reason_code == DiscoveryReason.HEARTBEAT_STALE


class TestRankingAndSelection:
    async def test_multiple_candidates_are_all_returned(self, discovery, three_risk_agents):
        outcome = await discovery.discover(DiscoveryQuery(capability="credit_analysis"))
        assert len(outcome.results) == 3
        assert [c.rank for c in outcome.results] == [1, 2, 3]

    async def test_load_lowers_a_candidates_rank(
        self, session, discovery, ans_registry, three_risk_agents
    ):
        """Ranking uses observed load, not a hardcoded winner."""
        busy, idle = three_risk_agents[0], three_risk_agents[1]
        await ans_registry.heartbeat(busy.did, active_tasks=9)
        await ans_registry.heartbeat(idle.did, active_tasks=0)

        outcome = await discovery.discover(DiscoveryQuery(capability="credit_analysis"))
        order = dids(outcome.results)
        assert order.index(idle.did) < order.index(busy.did)

    async def test_ranking_is_deterministic(self, discovery, three_risk_agents):
        first = dids((await discovery.discover(
            DiscoveryQuery(capability="credit_analysis"))).results)
        second = dids((await discovery.discover(
            DiscoveryQuery(capability="credit_analysis"))).results)
        assert first == second

    async def test_credentials_raise_a_candidates_score(
        self, discovery, credential_issuer, compliance_issuer_did, three_risk_agents
    ):
        favoured = three_risk_agents[2]
        await credential_issuer.issue(
            IssueRequest(compliance_issuer_did, favoured.did, "ComplianceCredential",
                         {"framework": "SOX", "status": "COMPLIANT",
                          "scope": "financial_data_processing"})
        )
        outcome = await discovery.discover(
            DiscoveryQuery(capability="credit_analysis",
                           required_credentials=["ComplianceCredential"])
        )
        assert dids(outcome.results) == [favoured.did]

    async def test_limit_is_respected(self, discovery, three_risk_agents):
        outcome = await discovery.discover(
            DiscoveryQuery(capability="credit_analysis", limit=2)
        )
        assert len(outcome.results) == 2


class TestDiscoveryAudit:
    async def test_request_and_results_are_persisted(
        self, discovery, three_risk_agents
    ):
        outcome = await discovery.discover(
            DiscoveryQuery(capability="credit_analysis",
                           requester_did="did:poc:agent:coordinator-001")
        )
        stored = await discovery.get_request(outcome.request_id)
        assert stored["requester_did"] == "did:poc:agent:coordinator-001"
        assert stored["candidate_count"] == 3
        assert stored["matched_count"] == 3
        assert stored["selected_did"] == outcome.selected.agent.did
        assert stored["ans_latency_ms"] > 0
        assert len(stored["results"]) == 3

    async def test_no_match_is_recorded_with_its_reason(self, discovery,
                                                        registered_risk_agent):
        outcome = await discovery.discover(DiscoveryQuery(capability="payroll_access"))
        stored = await discovery.get_request(outcome.request_id)
        assert stored["reason"] == DiscoveryReason.NO_MATCHING_AGENT
        assert stored["selected_did"] is None
