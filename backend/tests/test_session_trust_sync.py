"""Phase 12 (E): stale authentication or trust state never authorizes.

Each test establishes access, changes ONE piece of trust state the way an
operator or the system would, and asserts the very next protected action is
refused -- through the real PDP, OPA and AEM, with no cache to clear and no
session to restart. "Session validity does not override current
authorization" is the property: nothing here logs anybody out first.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.authorization.contracts import Decision
from app.db.models.agent import AgentStatus
from app.db.models.hitl import ApprovalDecision, ApprovalRequest, ApprovalStatus

pytestmark = pytest.mark.integration


async def credit_read(aem, did, **kw):
    return await aem.enforce(subject_did=did, tool_name="get_credit_profile",
                             arguments={"customer_id": "customer-007"},
                             purpose="loan_assessment", **kw)


class TestIdentityChangesTakeEffectOnTheNextRequest:
    async def test_baseline_access_exists(self, aem, issued_credential, risk_agent):
        assert (await credit_read(aem, risk_agent.did)).executed

    async def test_a_revoked_credential_stops_the_next_request(
        self, session, aem, issued_credential, risk_agent
    ):
        from app.credentials.status import CredentialStatusService
        assert (await credit_read(aem, risk_agent.did)).executed
        await CredentialStatusService(session).revoke(issued_credential.credential_id, "test")
        denied = await credit_read(aem, risk_agent.did)
        assert denied.executed is False

    async def test_a_suspended_identity_is_denied_without_any_containment(
        self, registry, aem, issued_credential, risk_agent
    ):
        assert (await credit_read(aem, risk_agent.did)).executed
        await registry.set_status(risk_agent.did, AgentStatus.SUSPENDED, reason="operator")
        assert (await credit_read(aem, risk_agent.did)).executed is False

    async def test_a_terminated_identity_is_denied(
        self, registry, aem, issued_credential, risk_agent
    ):
        await registry.terminate(risk_agent.did)
        assert (await credit_read(aem, risk_agent.did)).executed is False

    async def test_an_expired_identity_is_denied_before_any_sweep_runs(
        self, session, aem, issued_credential, risk_agent
    ):
        risk_agent.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.flush()
        assert (await credit_read(aem, risk_agent.did)).executed is False


class TestOutstandingArtifactsAreCheckedAgainstCurrentState:
    async def test_a_live_jit_mandate_does_not_outlive_its_holders_suspension(
        self, registry, aem, issued_mandate, jit_policy_loaded, risk_agent
    ):
        await registry.set_status(risk_agent.did, AgentStatus.SUSPENDED, reason="operator")
        result = await credit_read(aem, risk_agent.did, jit_grant_id=issued_mandate.grant_id)
        assert result.executed is False

    async def test_a_human_approval_does_not_outlive_its_agents_suspension(
        self, session, registry, aem, approval_service, loan_credential, risk_agent,
        opa_data_loaded
    ):
        """Approved by a human, then the agent is suspended (not contained).
        The approval is an INPUT; the fresh decision still denies, and the
        approval is not spent by the refused attempt."""
        first = await aem.enforce(subject_did=risk_agent.did,
                                  tool_name="approve_loan_application",
                                  arguments={"application_id": "loan-7842"},
                                  purpose="loan_decision", request_id="p12-e-approval")
        approval = (first.decision.to_dict().get("evaluation") or {}).get("approval_request") \
            or {}
        record = (await session.execute(select(ApprovalRequest).where(
            ApprovalRequest.approval_id == approval.get("approval_id")))).scalar_one()
        from tests.test_phase12_containment import _Approver
        await approval_service.decide(record=record, approver=_Approver("loan.officer.2"),
                                      decision=ApprovalDecision.APPROVED)
        await registry.set_status(risk_agent.did, AgentStatus.SUSPENDED, reason="operator")
        retry = await aem.enforce(subject_did=risk_agent.did,
                                  tool_name="approve_loan_application",
                                  arguments={"application_id": "loan-7842"},
                                  purpose="loan_decision", request_id="p12-e-approval",
                                  approval_id=record.approval_id)
        assert retry.executed is False
        await session.refresh(record)
        assert record.status is ApprovalStatus.APPROVED          # not burned by a refusal

    async def test_an_approval_is_bound_to_the_exact_action(
        self, session, aem, approval_service, loan_credential, risk_agent, opa_data_loaded
    ):
        first = await aem.enforce(subject_did=risk_agent.did,
                                  tool_name="approve_loan_application",
                                  arguments={"application_id": "loan-7842"},
                                  purpose="loan_decision", request_id="p12-e-bind")
        approval_id = first.decision.to_dict()["evaluation"]["approval_request"]["approval_id"]
        record = (await session.execute(select(ApprovalRequest).where(
            ApprovalRequest.approval_id == approval_id))).scalar_one()
        from tests.test_phase12_containment import _Approver
        await approval_service.decide(record=record, approver=_Approver("loan.officer.2"),
                                      decision=ApprovalDecision.APPROVED)
        other = await aem.enforce(subject_did=risk_agent.did,
                                  tool_name="approve_loan_application",
                                  arguments={"application_id": "loan-1001"},
                                  purpose="loan_decision", request_id="p12-e-bind",
                                  approval_id=approval_id)
        assert other.executed is False


class TestDelegationFollowsTheParent:
    async def test_a_child_is_denied_once_its_parent_is_suspended(
        self, session, registry, agent_spec, credential_issuer, issuer_did, capability_claims,
        aem, pdp, risk_agent
    ):
        from app.credentials.issuer import IssueRequest
        child = await registry.create_agent(agent_spec("p12-e-child"))
        child.parent_agent_id = risk_agent.id
        await registry.set_status(child.did, AgentStatus.ACTIVE)
        await session.flush()
        await credential_issuer.issue(IssueRequest(
            issuer_did=issuer_did, subject_did=child.did,
            credential_type="AgentCapabilityCredential", claims=capability_claims,
            ttl_seconds=3600))
        assert (await credit_read(aem, child.did)).executed
        await registry.set_status(risk_agent.did, AgentStatus.SUSPENDED, reason="operator")
        assert (await credit_read(aem, child.did)).executed is False


class TestFailClosed:
    async def test_an_unreachable_policy_engine_denies(self, session, keystore, risk_agent,
                                                       issued_credential):
        from app.authorization.opa import OPAClient
        from app.authorization.pdp import PolicyDecisionPoint
        from app.authorization.contracts import AuthorizationRequest, Resource, Subject
        from app.core.config import get_settings
        dead = OPAClient(get_settings().model_copy(update={"opa_url": "http://127.0.0.1:1"}))
        pdp = PolicyDecisionPoint(session, keystore, opa=dead)
        decision = await pdp.decide(AuthorizationRequest(
            subject=Subject(did=risk_agent.did), action="read",
            resource=Resource(type="credit_records", id="customer-007"),
            purpose="loan_assessment"))
        assert decision.decision is not Decision.ALLOW


class TestDelegationChainFact:
    async def _child(self, session, registry, agent_spec, credential_issuer, issuer_did,
                     capability_claims, parent):
        from app.credentials.issuer import IssueRequest
        child = await registry.create_agent(agent_spec("p12-e-child2"))
        child.parent_agent_id = parent.id
        await registry.set_status(child.did, AgentStatus.ACTIVE)
        await session.flush()
        await credential_issuer.issue(IssueRequest(
            issuer_did=issuer_did, subject_did=child.did,
            credential_type="AgentCapabilityCredential", claims=capability_claims,
            ttl_seconds=3600))
        return child

    async def test_the_denial_names_the_chain_and_reversal_restores_the_child(
        self, session, registry, agent_spec, credential_issuer, issuer_did, capability_claims,
        aem, risk_agent
    ):
        child = await self._child(session, registry, agent_spec, credential_issuer, issuer_did,
                                  capability_claims, risk_agent)
        risk_agent.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.flush()
        denied = await credit_read(aem, child.did)
        assert denied.executed is False
        assert denied.decision.reason == "DELEGATION_CHAIN_INACTIVE"
        risk_agent.expires_at = None
        await session.flush()
        assert (await credit_read(aem, child.did)).executed

    async def test_the_pip_reports_the_chain(self, session, registry, agent_spec,
                                             credential_issuer, issuer_did, capability_claims,
                                             pdp, risk_agent):
        from app.authorization.contracts import AuthorizationRequest, Resource, Subject
        child = await self._child(session, registry, agent_spec, credential_issuer, issuer_did,
                                  capability_claims, risk_agent)
        from app.authorization.pip import PolicyInformationPoint
        ctx = await PolicyInformationPoint(session, None).collect(AuthorizationRequest(
            subject=Subject(did=child.did), action="read",
            resource=Resource(type="credit_records", id="customer-007"),
            purpose="loan_assessment"))
        chain = ctx.subject["delegation"]
        assert chain["depth"] == 1 and chain["chain_active"] is True
        assert chain["ancestors"][0]["did"] == risk_agent.did
