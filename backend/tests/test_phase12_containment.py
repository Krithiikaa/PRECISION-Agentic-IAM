"""Phase 12: containment closes every outstanding route to access.

Each test is a BYPASS ATTEMPT against the kill switch, not a happy path. The
happy path (lockout, identity suspension, JIT/MCP/ANS revocation, cascade) is
in test_trust_and_containment.py.

Defects closed here, each with a regression test:

  P12-A1  An approval granted BEFORE containment stayed APPROVED. After
          reinstatement it was still spendable, so a sign-off given to a
          compromised agent outlived the compromise.
  P12-A2  A PENDING approval survived containment; a human could approve it
          during the incident and the agent could spend it after.
  P12-A3  A cascade-contained child could be reinstated while the parent
          whose compromise caused the cascade was still contained.
  P12-A4  Reinstatement re-activated an identity without re-checking that it
          still had a usable key or had not expired.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, update

from app.core.config import get_settings
from app.core.errors import ConflictError
from app.db.models.agent import AgentKey, AgentStatus, KeyStatus
from app.db.models.audit import AuditEvent
from app.db.models.hitl import ApprovalDecision, ApprovalRequest, ApprovalStatus
from app.hitl.artifact import ApprovalBinding
from app.sessions.authority import SessionAuthority

pytestmark = pytest.mark.integration

ADMIN = "did:poc:administrator:identity-authority"
REVIEW = "Reviewed the audit trail and key custody; no misuse found after triage."


class _Approver:
    def __init__(self, username="loan.officer", roles=("LOAN_OFFICER",)):
        self.subject = f"sub-{username}"
        self.issuer = get_settings().keycloak_issuer
        self.username = username
        self.roles = roles
        self.provider = "keycloak-oidc"
        self.principal_urn = f"urn:iam:human:{self.subject}"


@pytest.fixture
def authority(session, keystore):
    return SessionAuthority(session, keystore, get_settings())


def _binding(did, request_id="authz-p12-1"):
    return ApprovalBinding(request_id=request_id, agent_did=did, action="approve_loan",
                           resource_type="loan_applications", resource_id="loan-7842",
                           purpose="loan_decision")


class TestApprovalsDoNotOutliveContainment:
    async def test_an_approved_but_unspent_approval_is_cancelled_and_cannot_be_spent(
        self, session, authority, approval_service, risk_agent
    ):
        record = await approval_service.request_approval(
            binding=_binding(risk_agent.did), presentation={"demo": True},
            reason="SENSITIVE_ACTION_REQUIRES_HUMAN")
        approved = await approval_service.decide(
            record=record, approver=_Approver(), decision=ApprovalDecision.APPROVED)
        assert approved.status is ApprovalStatus.APPROVED

        report = await authority.contain(risk_agent.did, justification="key theft suspected",
                                         opened_by=ADMIN)
        assert report.actions["approvals_cancelled"] == [approved.approval_id]

        await authority.reinstate(report.incident_id, reinstated_by="ops-b", review=REVIEW)
        # The bypass attempt: spend the pre-containment approval after reinstatement.
        assert await approval_service.consume(
            approved.approval_id, request_id="authz-p12-1") is False
        row = (await session.execute(select(ApprovalRequest).where(
            ApprovalRequest.approval_id == approved.approval_id))).scalar_one()
        await session.refresh(row)
        assert row.status is ApprovalStatus.CANCELLED

    async def test_a_pending_approval_cannot_be_approved_during_the_incident(
        self, session, authority, approval_service, risk_agent
    ):
        record = await approval_service.request_approval(
            binding=_binding(risk_agent.did, "authz-p12-2"), presentation={"demo": True},
            reason="SENSITIVE_ACTION_REQUIRES_HUMAN")
        report = await authority.contain(risk_agent.did, justification="anomalous approvals",
                                         opened_by=ADMIN)
        assert report.actions["approvals_cancelled"] == [record.approval_id]
        await session.refresh(record)
        assert record.status is ApprovalStatus.CANCELLED
        from app.hitl.service import ApprovalNotPending
        with pytest.raises(ApprovalNotPending):
            await approval_service.decide(record=record, approver=_Approver(),
                                          decision=ApprovalDecision.APPROVED)

    async def test_cancellation_is_audited_per_approval(
        self, session, authority, approval_service, risk_agent
    ):
        record = await approval_service.request_approval(
            binding=_binding(risk_agent.did, "authz-p12-3"), presentation={"demo": True},
            reason="SENSITIVE_ACTION_REQUIRES_HUMAN")
        await authority.contain(risk_agent.did, justification="audit trail check",
                                opened_by=ADMIN)
        events = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == "APPROVAL_CANCELLED"))).scalars().all()
        assert [e.event_metadata["approval_id"] for e in events] == [record.approval_id]
        assert events[0].event_metadata["cause"] == "containment"

    async def test_other_agents_approvals_are_untouched(
        self, session, authority, approval_service, risk_agent, fraud_agent
    ):
        other = await approval_service.request_approval(
            binding=_binding(fraud_agent.did, "authz-p12-4"), presentation={"demo": True},
            reason="SENSITIVE_ACTION_REQUIRES_HUMAN")
        await authority.contain(risk_agent.did, justification="targeted containment",
                                opened_by=ADMIN)
        await session.refresh(other)
        assert other.status is ApprovalStatus.PENDING

    async def test_a_consumed_approval_is_history_and_is_not_rewritten(
        self, session, authority, approval_service, risk_agent
    ):
        record = await approval_service.request_approval(
            binding=_binding(risk_agent.did, "authz-p12-5"), presentation={"demo": True},
            reason="SENSITIVE_ACTION_REQUIRES_HUMAN")
        await approval_service.decide(record=record, approver=_Approver(),
                                      decision=ApprovalDecision.APPROVED)
        assert await approval_service.consume(record.approval_id, request_id="authz-p12-5")
        report = await authority.contain(risk_agent.did, justification="after the fact",
                                         opened_by=ADMIN)
        assert report.actions["approvals_cancelled"] == []
        await session.refresh(record)
        assert record.status is ApprovalStatus.CONSUMED


class TestReinstatementRevalidatesTrust:
    async def _child(self, session, registry, agent_spec, parent):
        child = await registry.create_agent(agent_spec("p12-child"))
        child.parent_agent_id = parent.id
        await registry.set_status(child.did, AgentStatus.ACTIVE)
        await session.flush()
        return child

    async def test_a_child_cannot_be_reinstated_while_its_parent_is_contained(
        self, session, registry, agent_spec, authority, risk_agent
    ):
        child = await self._child(session, registry, agent_spec, risk_agent)
        await authority.contain(risk_agent.did, justification="parent compromised",
                                opened_by=ADMIN)
        child_incident = next(i for i in await authority.incidents()
                               if i["agent_did"] == child.did)
        with pytest.raises(ConflictError, match="ancestors_not_contained"):
            await authority.reinstate(child_incident["incident_id"], reinstated_by="ops-b",
                                      review=REVIEW)
        await session.refresh(child)
        assert child.status is AgentStatus.SUSPENDED
        refused = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == "INCIDENT_REINSTATEMENT_REFUSED"))).scalars().all()
        assert refused and any(not c["passed"] for c in refused[-1].event_metadata["revalidation"])

    async def test_the_child_can_return_once_the_parent_has(
        self, session, registry, agent_spec, authority, risk_agent
    ):
        child = await self._child(session, registry, agent_spec, risk_agent)
        report = await authority.contain(risk_agent.did, justification="parent compromised",
                                         opened_by=ADMIN)
        child_incident = next(i for i in await authority.incidents()
                              if i["agent_did"] == child.did)
        await authority.reinstate(report.incident_id, reinstated_by="ops-b", review=REVIEW)
        result, _ = await authority.reinstate(child_incident["incident_id"],
                                              reinstated_by="ops-b", review=REVIEW)
        assert all(c["passed"] for c in result["revalidation"])

    async def test_an_agent_with_no_active_key_is_not_reinstated(
        self, session, authority, risk_agent
    ):
        report = await authority.contain(risk_agent.did, justification="key compromise",
                                         opened_by=ADMIN)
        await session.execute(update(AgentKey).where(AgentKey.agent_id == risk_agent.id)
                              .values(status=KeyStatus.REVOKED))
        with pytest.raises(ConflictError, match="active_signing_key"):
            await authority.reinstate(report.incident_id, reinstated_by="ops-b", review=REVIEW)
        await session.refresh(risk_agent)
        assert risk_agent.status is AgentStatus.SUSPENDED

    async def test_an_expired_identity_is_not_reinstated(self, session, authority, risk_agent):
        report = await authority.contain(risk_agent.did, justification="dormant identity",
                                         opened_by=ADMIN)
        risk_agent.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        await session.flush()
        with pytest.raises(ConflictError, match="identity_not_expired"):
            await authority.reinstate(report.incident_id, reinstated_by="ops-b", review=REVIEW)

    async def test_a_successful_reinstatement_records_its_revalidation(
        self, session, authority, risk_agent
    ):
        report = await authority.contain(risk_agent.did, justification="false positive",
                                         opened_by=ADMIN)
        result, _ = await authority.reinstate(report.incident_id, reinstated_by="ops-b",
                                              review=REVIEW)
        names = {c["check"] for c in result["revalidation"]}
        assert names == {"identity_not_terminated", "identity_not_expired",
                         "active_signing_key", "ancestors_not_contained"}
        event = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == "INCIDENT_REINSTATED"))).scalar_one()
        assert event.event_metadata["revalidation"] == result["revalidation"]


class TestContainmentCannotBeInvokedOrUndoneByTheWrongParty:
    async def test_a_contained_agent_cannot_reinstate_itself(
        self, admin_post, agent_post, risk_agent
    ):
        created = await admin_post("/api/v1/security/incidents", {
            "agent_did": risk_agent.did, "justification": "contained for the bypass test"})
        assert created.status_code == 201, created.text
        incident = created.json()["incident_id"]
        response = await agent_post(f"/api/v1/security/incidents/{incident}/reinstate",
                                    risk_agent.did, {"review": REVIEW})
        # The contained identity is SUSPENDED: it cannot even authenticate.
        assert response.status_code in (401, 403), response.text

    async def test_another_agent_cannot_reinstate_a_contained_agent(
        self, admin_post, agent_post, risk_agent, fraud_agent
    ):
        created = await admin_post("/api/v1/security/incidents", {
            "agent_did": risk_agent.did, "justification": "contained for the bypass test"})
        incident = created.json()["incident_id"]
        response = await agent_post(f"/api/v1/security/incidents/{incident}/reinstate",
                                    fraud_agent.did, {"review": REVIEW})
        assert response.status_code == 403, response.text

    async def test_the_same_administrator_cannot_undo_their_own_containment(
        self, admin_post, risk_agent
    ):
        created = await admin_post("/api/v1/security/incidents", {
            "agent_did": risk_agent.did, "justification": "contained for the bypass test"})
        incident = created.json()["incident_id"]
        response = await admin_post(f"/api/v1/security/incidents/{incident}/reinstate",
                                    {"review": REVIEW})
        assert response.status_code == 409, response.text
        assert "separation of duties" in response.text

    async def test_containment_needs_an_authenticated_caller(self, client, risk_agent):
        response = await client.post("/api/v1/security/incidents", json={
            "agent_did": risk_agent.did, "justification": "anonymous kill switch attempt"})
        assert response.status_code == 401, response.text

    async def test_a_contained_agent_cannot_spawn_a_child_to_escape(
        self, admin_post, agent_post, risk_agent
    ):
        created = await admin_post("/api/v1/security/incidents", {
            "agent_did": risk_agent.did, "justification": "contained before an escape attempt"})
        assert created.status_code == 201
        response = await agent_post(f"/api/v1/agents/did/{risk_agent.did}/delegations",
                                    risk_agent.did, {"kind": "EPHEMERAL",
                                                     "purpose": "escape the lockout",
                                                     "ttl_seconds": 60})
        assert response.status_code in (401, 403), response.text


class TestRefusalCarriesTheRevalidation:
    """The console shows WHICH check failed, from the server's own result."""

    async def test_a_revalidation_refusal_returns_the_checks_over_http(
        self, session, admin_post, human_post, iam_admin_token, risk_agent
    ):
        created = await admin_post("/api/v1/security/incidents", {
            "agent_did": risk_agent.did, "justification": "contained for the 409 body test"})
        incident = created.json()["incident_id"]
        await session.execute(update(AgentKey).where(AgentKey.agent_id == risk_agent.id)
                              .values(status=KeyStatus.REVOKED))
        # A DIFFERENT principal (the human IAM administrator) reinstates.
        response = await human_post(f"/api/v1/security/incidents/{incident}/reinstate",
                                    iam_admin_token, {"review": REVIEW})
        assert response.status_code == 409, response.text
        body = response.json()
        assert body["error"] == "CONFLICT"
        failed = [c["check"] for c in body["revalidation"] if not c["passed"]]
        assert failed == ["active_signing_key"]

    async def test_a_separation_of_duties_refusal_has_no_revalidation(
        self, admin_post, risk_agent
    ):
        created = await admin_post("/api/v1/security/incidents", {
            "agent_did": risk_agent.did, "justification": "contained for the 409 body test"})
        incident = created.json()["incident_id"]
        response = await admin_post(f"/api/v1/security/incidents/{incident}/reinstate",
                                    {"review": REVIEW})
        assert response.status_code == 409
        assert response.json()["revalidation"] is None
        assert "separation of duties" in response.json()["detail"]
