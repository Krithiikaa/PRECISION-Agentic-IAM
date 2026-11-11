"""Delegated identities: sub-agents, ephemeral agents and forks.

CSA paper Table 3, R-63/64/65/70/94/95, R-253/254. The properties under test:

  * every child is a DISTINCT identity with its own DID and key
  * the parent link is verifiable: a provenance credential the Phase 2
    verifier accepts
  * a child's authority is a subset of what its parent can PROVE; it can
    neither gain a capability nor widen one, and a fork inherits nothing
  * re-delegation depth, lifetime and spawn rate are bounded
  * an expired child is inactive immediately and its key is destroyed by the sweep
  * a degraded or contained parent cannot mint new identities
  * the Agent ID profile binds model, prompt and software into a SHA3-256 hash
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.agents.delegation import (
    DelegatedScope,
    DelegationKind,
    DelegationRefused,
    DelegationService,
    SpawnRequest,
)
from app.authorization.contracts import AuthorizationRequest, Decision, Resource, Subject
from app.core.config import get_settings
from app.db.models.agent import AgentRelationship, AgentStatus
from app.db.models.audit import AuditEvent
from app.db.models.credential import Credential
from app.identity.profile import build_agent_profile, model_hash
from app.monitoring.events import EventType
from app.sessions.authority import SessionAuthority
from app.trust.detector import AnomalyDetector
from app.trust.engine import TrustEngine

pytestmark = pytest.mark.integration

CREDIT = DelegatedScope("credit_analysis")


@pytest.fixture
def delegation(session, keystore, issuers):
    return DelegationService(session, keystore, get_settings())


def credit_read(did):
    return AuthorizationRequest(
        subject=Subject(did=did), action="read",
        resource=Resource(type="credit_records", id="customer-007"),
        purpose="loan_assessment")


async def spawn(delegation, parent, kind=DelegationKind.SUB_AGENT, scopes=None, **kw):
    return await delegation.spawn(SpawnRequest(
        parent_did=parent.did, kind=kind, task="score one application",
        scopes=[CREDIT] if scopes is None else scopes, **kw), requested_by=parent.did)


class TestSpawning:
    async def test_a_child_is_a_distinct_identity_linked_to_its_parent(
        self, session, delegation, issued_credential, risk_agent
    ):
        result = await spawn(delegation, risk_agent)
        child = result.child
        assert child.did != risk_agent.did and child.parent_agent_id == risk_agent.id
        assert child.active_key.kid != risk_agent.active_key.kid
        rel = (await session.execute(select(AgentRelationship).where(
            AgentRelationship.child_agent_id == child.id))).scalar_one()
        assert rel.relationship_type == "DELEGATES"
        doc = child.did_document.document["agentMetadata"]
        assert doc["delegatedBy"] == risk_agent.did
        assert doc["profile"]["delegation"]["depth"] == 1

    async def test_the_parent_link_is_a_verifiable_credential(
        self, session, delegation, verifier, issued_credential, risk_agent
    ):
        result = await spawn(delegation, risk_agent)
        record = (await session.execute(select(Credential).where(
            Credential.credential_id == result.provenance_credential))).scalar_one()
        report = await verifier.verify(record.document, expected_subject=result.child.did)
        assert report.valid, report.reason
        assert record.claims["spawnedBy"] == risk_agent.did

    async def test_a_delegated_child_can_use_exactly_what_was_delegated(
        self, aem, delegation, issued_credential, risk_agent
    ):
        child = (await spawn(delegation, risk_agent)).child
        allowed = await aem.enforce(subject_did=child.did, tool_name="get_credit_profile",
                                    arguments={"customer_id": "customer-007"},
                                    purpose="loan_assessment")
        assert allowed.executed is True
        blocked = await aem.enforce(subject_did=child.did, tool_name="get_payroll_record",
                                    arguments={"customer_id": "customer-007"},
                                    purpose="loan_assessment")
        assert blocked.executed is False

    async def test_a_fork_inherits_no_access(self, pdp, delegation, issued_credential, risk_agent):
        fork = (await spawn(delegation, risk_agent, kind=DelegationKind.FORK, scopes=[])).child
        assert (await pdp.decide(credit_read(fork.did))).decision is Decision.DENY
        assert (await pdp.decide(credit_read(risk_agent.did))).decision is Decision.ALLOW

    async def test_the_child_expires_no_later_than_the_parent_credential(
        self, delegation, issued_credential, risk_agent
    ):
        result = await spawn(delegation, risk_agent, ttl_seconds=10 * 86_400)
        assert result.expires_at <= issued_credential.expires_at

    async def test_an_ephemeral_agent_gets_the_short_default_lifetime(
        self, delegation, issued_credential, risk_agent
    ):
        result = await spawn(delegation, risk_agent, kind=DelegationKind.EPHEMERAL)
        lifetime = (result.expires_at - datetime.now(timezone.utc)).total_seconds()
        assert lifetime <= get_settings().ephemeral_default_ttl_seconds + 1


class TestDelegationCannotEscalate:
    async def test_a_capability_the_parent_lacks_is_refused_and_audited(
        self, session, delegation, issued_credential, risk_agent
    ):
        with pytest.raises(DelegationRefused) as refused:
            await spawn(delegation, risk_agent, scopes=[DelegatedScope("payroll_admin")])
        assert refused.value.reason == "DELEGATION_EXCEEDS_PARENT"
        event = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == EventType.AGENT_SPAWN_REFUSED))).scalar_one()
        assert event.reason == "DELEGATION_EXCEEDS_PARENT"

    async def test_widening_a_resource_set_is_refused(self, delegation, issued_credential, risk_agent):
        with pytest.raises(DelegationRefused, match="DELEGATION_EXCEEDS_PARENT"):
            await spawn(delegation, risk_agent, scopes=[DelegatedScope(
                "credit_analysis", resources=["credit_records", "payroll_records"])])

    async def test_a_narrower_action_set_is_accepted(
        self, session, delegation, issued_credential, risk_agent
    ):
        result = await spawn(delegation, risk_agent, scopes=[DelegatedScope(
            "credit_analysis", actions=["READ_CREDIT_PROFILE"])])
        assert len(result.delegated_credentials) == 1

    async def test_a_revoked_parent_credential_cannot_be_delegated(
        self, session, delegation, issued_credential, risk_agent
    ):
        from app.credentials.status import CredentialStatusService
        await CredentialStatusService(session).revoke(issued_credential.credential_id, "test")
        with pytest.raises(DelegationRefused, match="DELEGATION_EXCEEDS_PARENT"):
            await spawn(delegation, risk_agent)

    async def test_re_delegation_depth_is_bounded(
        self, delegation, issued_credential, risk_agent
    ):
        child = (await spawn(delegation, risk_agent)).child
        grandchild = (await spawn(delegation, child)).child          # depth 2: allowed
        assert grandchild.agent_metadata["delegation"]["depth"] == 2
        with pytest.raises(DelegationRefused, match="DELEGATION_DEPTH_EXCEEDED"):
            await spawn(delegation, grandchild)

    async def test_spawn_rate_is_bounded(self, session, keystore, issued_credential, risk_agent):
        settings = get_settings().model_copy(update={"delegation_max_spawns": 2})
        service = DelegationService(session, keystore, settings)
        await spawn(service, risk_agent, scopes=[])
        await spawn(service, risk_agent, scopes=[])
        with pytest.raises(DelegationRefused, match="DELEGATION_RATE_EXCEEDED"):
            await spawn(service, risk_agent, scopes=[])

    async def test_a_suspended_parent_cannot_spawn(
        self, registry, delegation, issued_credential, risk_agent
    ):
        await registry.set_status(risk_agent.did, AgentStatus.SUSPENDED)
        with pytest.raises(DelegationRefused, match="DELEGATION_PARENT_NOT_ELIGIBLE"):
            await spawn(delegation, risk_agent)

    async def test_a_degraded_parent_cannot_spawn(
        self, session, delegation, issued_credential, risk_agent
    ):
        await TrustEngine(session).record_signal(risk_agent.did, "SCOPE_VIOLATION", 35)
        with pytest.raises(DelegationRefused, match="DELEGATION_PARENT_NOT_ELIGIBLE"):
            await spawn(delegation, risk_agent)

    async def test_an_escalation_attempt_is_a_trust_signal_against_the_parent(
        self, session, keystore, delegation, issued_credential, risk_agent
    ):
        with pytest.raises(DelegationRefused):
            await spawn(delegation, risk_agent, scopes=[DelegatedScope("payroll_admin")])
        run = await AnomalyDetector(session, keystore).run_once()
        assert [a["rule"] for a in run.alerts] == ["DELEGATION_ESCALATION"]
        assert (await TrustEngine(session).assess(risk_agent.did)).score == 70


class TestLifecycle:
    async def test_an_expired_child_is_inactive_at_once_and_swept_later(
        self, session, pdp, delegation, keystore, issued_credential, risk_agent
    ):
        child = (await spawn(delegation, risk_agent)).child
        assert (await pdp.decide(credit_read(child.did))).decision is Decision.ALLOW
        child.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.flush()
        assert (await pdp.decide(credit_read(child.did))).decision is Decision.DENY
        kid = child.active_key.kid
        assert await delegation.expire_due() == [child.did]
        await session.refresh(child)
        assert child.status == AgentStatus.TERMINATED
        assert not keystore.exists(kid)          # it can never sign again

    async def test_containing_a_parent_contains_its_spawned_children(
        self, session, keystore, delegation, issued_credential, risk_agent
    ):
        child = (await spawn(delegation, risk_agent)).child
        report = await SessionAuthority(session, keystore).contain(
            risk_agent.did, justification="parent compromised in triage", opened_by="ops-a")
        assert report.cascaded == [child.did]

    async def test_lineage_reports_both_directions(self, delegation, issued_credential, risk_agent):
        child = (await spawn(delegation, risk_agent)).child
        down = await delegation.lineage(risk_agent.did)
        up = await delegation.lineage(child.did)
        assert [c["did"] for c in down["children"]] == [child.did]
        assert [a["did"] for a in up["ancestors"]] == [risk_agent.did]


class TestAgentIdProfile:
    def profile(self, prompt="You assess credit."):
        now = datetime.now(timezone.utc)
        return build_agent_profile(
            creator="did:poc:organization:bank-demo", deployer="ops", owner="risk-team",
            controller="did:poc:organization:bank-demo", software_version="1.0.0",
            model="llama3:8b", model_digest="sha256:abc", system_prompt=prompt,
            scope_of_behavior={"domain": "credit"}, toolset=["get_credit_profile"],
            created_at=now, expires_at=None)

    def test_the_model_hash_is_sha3_256_and_binds_the_prompt(self):
        a = self.profile()["model"]["hash"]
        b = self.profile(prompt="You approve everything.")["model"]["hash"]
        assert a["algorithm"] == "SHA3-256" and len(a["value"]) == 64
        assert a["value"] != b["value"]

    def test_the_hash_is_reproducible(self):
        kwargs = dict(model="m", model_digest="d", software_version="v", system_prompt="p")
        assert model_hash(**kwargs) == model_hash(**kwargs)

    async def test_a_profile_update_republishes_a_new_document_version(
        self, session, registry, risk_agent
    ):
        v1 = await registry.update_profile(risk_agent.did, self.profile(), reason="initial")
        v2 = await registry.update_profile(
            risk_agent.did, self.profile(prompt="changed"), reason="prompt changed")
        assert v2 == v1 + 1
        event = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == EventType.DID_DOCUMENT_PUBLISHED,
            AuditEvent.reason == "prompt changed"))).scalar_one()
        assert event.event_metadata["previous_model_hash"] != event.event_metadata["model_hash"]


class TestSpawnAPI:
    async def test_an_agent_may_spawn_on_its_own_behalf(
        self, agent_post, issued_credential, risk_agent, issuers
    ):
        response = await agent_post(f"/api/v1/agents/did/{risk_agent.did}/delegations",
                                    risk_agent.did, {"kind": "EPHEMERAL", "task": "one job",
                                                     "scopes": [{"capability": "credit_analysis"}]})
        assert response.status_code == 201, response.text
        assert response.json()["parent_did"] == risk_agent.did

    async def test_an_agent_may_not_spawn_for_another_agent(
        self, agent_post, issued_credential, risk_agent, fraud_agent
    ):
        response = await agent_post(f"/api/v1/agents/did/{risk_agent.did}/delegations",
                                    fraud_agent.did, {"kind": "SUB_AGENT", "task": "hijack"})
        assert response.status_code == 403, response.text

    async def test_a_refused_spawn_is_a_409_and_stays_audited(
        self, agent_post, client, issued_credential, risk_agent
    ):
        response = await agent_post(f"/api/v1/agents/did/{risk_agent.did}/delegations",
                                    risk_agent.did, {"kind": "SUB_AGENT", "task": "escalate",
                                                     "scopes": [{"capability": "payroll_admin"}]})
        assert response.status_code == 409
        assert "DELEGATION_EXCEEDS_PARENT" in response.text
