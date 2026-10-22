"""The Phase 5 security matrix, as one auditable file.

Each test maps to a numbered requirement, so the matrix reads as a checklist
rather than being inferred from assertions scattered across the suite.

The organising claim:

    HUMAN AUTHENTICATION  !=  HUMAN APPROVAL
    HUMAN APPROVAL        !=  AUTHORIZATION
    AUTHORIZATION         !=  ENFORCEMENT

    Keycloak identifies the human.
    The approval records what they decided.
    The PDP decides whether it may proceed.
    The AEM lets the tool run.

Every request here goes over HTTP through the real guard, against the real OPA,
with real tokens from the real Keycloak. A rejection in this file is the
rejection a caller gets.
"""
from __future__ import annotations

import asyncio

import pytest

from app.db.models.hitl import ApprovalStatus
from app.enforcement.resources import loan_application_status

pytestmark = pytest.mark.integration

LOAN = "loan-7842"
OTHER_LOAN = "loan-1001"


def enforce_body(did, application_id=LOAN, **overrides):
    body = {
        "subject": {"did": did},
        "tool": "approve_loan_application",
        "arguments": {"application_id": application_id},
        "purpose": "loan_decision",
    }
    body.update(overrides)
    return body


@pytest.fixture
async def loan_agent(client, admin_post, control_plane, opa_ready):
    """A real agent identity holding a credential scoped to loan applications."""
    created = await admin_post("/api/v1/agents", {
        "slug": "risk-001", "name": "Credit Risk Analysis Agent",
        "agent_type": "RISK", "capabilities": ["credit_analysis"],
        "endpoint": "http://localhost:9003",
    })
    assert created.status_code == 201
    return created.json()


@pytest.fixture
async def loan_agent_credential(admin_post, loan_agent, issuers):
    response = await admin_post("/api/v1/credentials/issue", {
        "issuer": "did:poc:organization:bank-demo", "subject": loan_agent["did"],
        "credential_type": "AgentCapabilityCredential",
        "claims": {"capability": "credit_analysis",
                   "allowed_actions": ["APPROVE_LOAN"],
                   "allowed_resources": ["loan_applications"],
                   "purpose": "loan_decision"},
        "expires_in_seconds": 3600,
    })
    assert response.status_code == 201
    return response.json()


@pytest.fixture
async def escalate(cp_post, loan_agent, loan_agent_credential, approval_authority):
    """Attempt the loan decision and return the opened approval."""
    async def run(application_id=LOAN, did=None):
        response = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(did or loan_agent["did"], application_id),
        )
        body = response.json()
        request = body["decision"]["evaluation"].get("approval_request") or {}
        return body, request.get("approval_id"), request.get("retry_with_request_id")
    return run


class TestHITLSecurityMatrix:
    # 1 -- unauthenticated human -> rejected
    async def test_01_an_unauthenticated_caller_cannot_approve(self, client, escalate):
        _, approval_id, _ = await escalate()
        response = await client.post(
            f"/api/v1/hitl/approvals/{approval_id}/decide", json={"decision": "APPROVED"})
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "CONTROL_PLANE_PROOF_MISSING"

    # 2, 6 -- invalid token / invalid signature -> rejected
    async def test_02_an_invalid_token_is_rejected(self, client, escalate, keycloak_ready):
        _, approval_id, _ = await escalate()
        response = await client.post(
            f"/api/v1/hitl/approvals/{approval_id}/decide",
            json={"decision": "APPROVED"},
            headers={"Authorization": "Bearer not.a.token"})
        assert response.status_code == 401

    # 3, 4, 5 are covered precisely in test_oidc_human_identity.py, where the
    # signature can be held valid so the expiry, issuer and audience checks are
    # each reached and isolated. Repeating them here would only re-test the
    # signature.

    # 7 -- authenticated but unauthorized role -> rejected
    async def test_07_an_authenticated_human_with_no_role_is_refused(
        self, human_post, escalate, no_roles_token
    ):
        _, approval_id, _ = await escalate()
        response = await human_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide", no_roles_token,
            {"decision": "APPROVED"})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "HUMAN_MAY_NOT_APPROVE_THIS"

    async def test_07b_the_wrong_role_is_refused(
        self, human_post, escalate, iam_admin_token, auditor_token
    ):
        """§38, §28. An IAM administrator and an auditor are both genuine,
        authenticated humans -- and neither approves loans. Human roles and
        agent capabilities are different trust domains, and so are IAM
        administration and lending authority."""
        _, approval_id, _ = await escalate()
        for token in (iam_admin_token, auditor_token):
            response = await human_post(
                f"/api/v1/hitl/approvals/{approval_id}/decide", token,
                {"decision": "APPROVED"})
            assert response.status_code == 403
            assert response.json()["detail"]["reason"] == "HUMAN_MAY_NOT_APPROVE_THIS"

    # 8 -- authorized human -> approval allowed
    async def test_08_the_loan_officer_may_approve(
        self, human_post, escalate, loan_officer_token
    ):
        _, approval_id, _ = await escalate()
        response = await human_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide", loan_officer_token,
            {"decision": "APPROVED", "note": "within lending policy"})
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "APPROVED"
        assert body["approver"]["username"] == "loan.officer"
        assert body["artifact_signed_by"] == "did:poc:service:approval-authority"

    # 19 -- valid approval -> PDP re-evaluation -> ALLOW
    async def test_19_a_valid_approval_is_re_evaluated_and_allows(
        self, cp_post, human_post, escalate, loan_officer_token, loan_agent
    ):
        """THE HEADLINE. Note what happens between approval and execution:
        the PDP is asked AGAIN. The human decision is evidence, not a verdict.
        """
        _, approval_id, request_id = await escalate()
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})

        response = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(loan_agent["did"], request_id=request_id))
        body = response.json()
        assert body["decision"]["decision"] == "ALLOW"
        assert body["decision"]["reason"] == "HUMAN_APPROVED_AND_POLICY_MATCH"
        assert body["decision"]["policy"] == "loan-approval:v1"
        assert body["executed"] is True
        assert body["result"]["status"] == "APPROVED"

    # 18 -- rejected approval -> DENY, and the resource is untouched
    async def test_18_a_rejected_approval_blocks_the_action(
        self, cp_post, human_post, escalate, loan_officer_token, loan_agent
    ):
        _, approval_id, request_id = await escalate()
        rejected = await human_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide", loan_officer_token,
            {"decision": "REJECTED", "note": "amount could not be verified"})
        assert rejected.json()["status"] == "REJECTED"
        # A rejection is a real recorded decision with nothing to present.
        assert rejected.json()["artifact"] is None

        response = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(loan_agent["did"], request_id=request_id))
        body = response.json()
        assert body["decision"]["decision"] == "DENY"
        assert body["decision"]["reason"] == "APPROVAL_REJECTED"
        assert body["executed"] is False
        # OBSERVABLE, not inferred: the loan really was not decided.
        assert loan_application_status(LOAN) == "AWAITING_DECISION"

    # 9 -- approval for the wrong agent -> rejected
    async def test_09_an_approval_cannot_be_spent_by_another_agent(
        self, cp_post, human_post, escalate, loan_officer_token, admin_post, issuers
    ):
        _, approval_id, request_id = await escalate()
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})

        # A DIFFERENT agent, with its own valid credential for the same scope.
        other = (await admin_post("/api/v1/agents", {
            "slug": "risk-002", "name": "Second Risk Agent", "agent_type": "RISK",
            "capabilities": ["credit_analysis"], "endpoint": "http://localhost:9006",
        })).json()
        await admin_post("/api/v1/credentials/issue", {
            "issuer": "did:poc:organization:bank-demo", "subject": other["did"],
            "credential_type": "AgentCapabilityCredential",
            "claims": {"capability": "credit_analysis",
                       "allowed_actions": ["APPROVE_LOAN"],
                       "allowed_resources": ["loan_applications"],
                       "purpose": "loan_decision"},
            "expires_in_seconds": 3600})

        response = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(other["did"], request_id=request_id,
                         approval_id=approval_id))
        body = response.json()
        assert body["decision"]["decision"] == "DENY"
        assert body["decision"]["reason"] == "APPROVAL_BINDING_MISMATCH"
        assert body["executed"] is False

    # 10 -- approval for the wrong request -> rejected
    async def test_10_an_approval_is_bound_to_one_request(
        self, cp_post, human_post, escalate, loan_officer_token, loan_agent
    ):
        _, approval_id, _ = await escalate()
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})

        # Same everything, a NEW request id. A retry under a new id is a new
        # request and needs its own approval -- which is the intended semantics.
        response = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(loan_agent["did"], request_id="authz-a-different-request",
                         approval_id=approval_id))
        body = response.json()
        assert body["decision"]["decision"] == "DENY"
        assert body["decision"]["reason"] == "APPROVAL_BINDING_MISMATCH"

    # 11, 12 -- wrong action / wrong resource -> rejected (the TAMPER demo, §35)
    async def test_11_an_approval_cannot_be_moved_to_another_resource(
        self, cp_post, human_post, escalate, loan_officer_token, loan_agent
    ):
        """§35. Approve the small loan, try to spend it on the large one."""
        _, approval_id, request_id = await escalate(OTHER_LOAN)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})

        response = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(loan_agent["did"], LOAN, request_id=request_id,
                         approval_id=approval_id))
        body = response.json()
        assert body["decision"]["decision"] == "DENY"
        assert body["decision"]["reason"] == "APPROVAL_BINDING_MISMATCH"
        assert body["executed"] is False
        assert loan_application_status(LOAN) == "AWAITING_DECISION"
        # The denial NAMES the field that moved.
        approval = body["decision"]["evaluation"]["pip"]["approval"]
        failed = [c for c in approval["checks"] if not c["passed"]]
        assert "resource_id" in failed[0]["detail"]

    # 13 -- wrong purpose -> rejected
    async def test_13_a_different_purpose_is_not_covered(
        self, cp_post, human_post, escalate, loan_officer_token, loan_agent
    ):
        _, approval_id, request_id = await escalate()
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        response = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(loan_agent["did"], request_id=request_id,
                         approval_id=approval_id, purpose="marketing_analytics"))
        body = response.json()
        assert body["decision"]["decision"] == "DENY"
        assert body["executed"] is False

    # 15, 16 -- consumed / replayed approval -> rejected (§36)
    async def test_15_a_consumed_approval_cannot_be_replayed(
        self, cp_post, human_post, escalate, loan_officer_token, loan_agent
    ):
        """§36. Approve once, execute once, then try again."""
        _, approval_id, request_id = await escalate()
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})

        first = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(loan_agent["did"], request_id=request_id))
        assert first.json()["executed"] is True

        replay = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(loan_agent["did"], request_id=request_id))
        body = replay.json()
        assert body["decision"]["decision"] == "DENY"
        assert body["decision"]["reason"] == "APPROVAL_ALREADY_CONSUMED"
        assert body["executed"] is False

    # 14 -- expired approval -> rejected (§37)
    async def test_14_an_expired_approval_is_refused(
        self, session, keystore, cp_post, escalate, loan_agent
    ):
        """§37. Real elapsed time against the SERVER clock. No clock is faked."""
        from app.core.config import Settings, get_settings
        from app.db.models.hitl import ApprovalDecision
        from app.hitl.service import ApprovalService

        _, approval_id, request_id = await escalate()

        class _Officer:
            subject, issuer = "sub-officer", get_settings().keycloak_issuer
            username, roles = "loan.officer", ("LOAN_OFFICER",)
            provider, principal_urn = "keycloak-oidc", "urn:iam:human:sub-officer"

        settings = Settings.model_construct(
            **{**get_settings().model_dump(), "approval_ttl_seconds": 1})
        service = ApprovalService(session, keystore, settings)
        record = await service.require(approval_id)
        await service.decide(record=record, approver=_Officer(),
                             decision=ApprovalDecision.APPROVED)

        await asyncio.sleep(1.3)

        response = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(loan_agent["did"], request_id=request_id))
        body = response.json()
        assert body["decision"]["decision"] == "DENY"
        assert body["decision"]["reason"] == "APPROVAL_EXPIRED"
        assert body["executed"] is False

    # 17 -- tampered approval -> rejected
    async def test_17_a_tampered_artifact_is_refused(
        self, session, cp_post, human_post, escalate, loan_officer_token, loan_agent
    ):
        """Edit the SIGNED artifact directly in the database."""
        from app.hitl.service import ApprovalService

        _, approval_id, request_id = await escalate()
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})

        service = ApprovalService(session)
        record = await service.require(approval_id)
        artifact = dict(record.artifact)
        subject = dict(artifact["credentialSubject"])
        subject["resource_id"] = LOAN
        subject["approver"] = {**subject["approver"], "username": "mallory"}
        artifact["credentialSubject"] = subject
        record.artifact = artifact
        await session.flush()

        response = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(loan_agent["did"], request_id=request_id))
        body = response.json()
        assert body["decision"]["decision"] == "DENY"
        assert body["decision"]["reason"] == "APPROVAL_SIGNATURE_INVALID"
        assert body["executed"] is False

    # 20 -- direct resource bypass -> BLOCKED
    async def test_20_the_protected_tool_cannot_be_called_directly(self):
        from app.enforcement.tools import EnforcementBypassError, build_default_registry

        tool = build_default_registry().get("approve_loan_application")
        with pytest.raises(EnforcementBypassError):
            await tool(application_id=LOAN)
        assert loan_application_status(LOAN) == "AWAITING_DECISION"


class TestS7Closure:
    """§46. Every identity-plane mutation is authenticated, authorized, audited."""

    # 21 -- anonymous credential issuance -> rejected
    async def test_21_anonymous_credential_issuance_is_refused(
        self, client, loan_agent, issuers
    ):
        """The sharpest of the S-7 holes: mint yourself a capability credential
        and the PDP would faithfully ALLOW on it."""
        response = await client.post("/api/v1/credentials/issue", json={
            "issuer": "did:poc:organization:bank-demo", "subject": loan_agent["did"],
            "credential_type": "AgentCapabilityCredential",
            "claims": {"capability": "credit_analysis",
                       "allowed_resources": ["loan_applications", "payroll_records"],
                       "purpose": "loan_decision"},
            "expires_in_seconds": 3600})
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "CONTROL_PLANE_PROOF_MISSING"

    # 22 -- anonymous credential revocation -> rejected
    async def test_22_anonymous_credential_revocation_is_refused(
        self, client, loan_agent_credential
    ):
        credential_id = loan_agent_credential["credential_id"]
        response = await client.post(
            f"/api/v1/credentials/{credential_id}/revoke", json={"reason": "COMPROMISED"})
        assert response.status_code == 401
        status = (await client.get(
            f"/api/v1/credentials/{credential_id}/status")).json()
        assert status["status"] == "ACTIVE"

    # 23 -- unauthorized credential issuance -> rejected
    async def test_23_the_wrong_human_cannot_issue_credentials(
        self, human_post, loan_agent, issuers, loan_officer_token, auditor_token
    ):
        """§27, §45. A loan officer approves loans and has NO authority over
        IAM. An auditor reads and changes nothing."""
        for token in (loan_officer_token, auditor_token):
            response = await human_post("/api/v1/credentials/issue", token, {
                "issuer": "did:poc:organization:bank-demo",
                "subject": loan_agent["did"],
                "credential_type": "AgentCapabilityCredential",
                "claims": {"capability": "credit_analysis",
                           "allowed_actions": ["READ_CREDIT_PROFILE"],
                           "allowed_resources": ["credit_records"],
                           "purpose": "loan_assessment"},
                "expires_in_seconds": 3600})
            assert response.status_code == 403
            assert response.json()["detail"]["reason"] == "HUMAN_MAY_NOT_ADMINISTER_IAM"

    # 24 -- unauthorized credential revocation -> rejected
    async def test_24_the_wrong_human_cannot_revoke(
        self, human_post, client, loan_agent_credential, loan_officer_token
    ):
        credential_id = loan_agent_credential["credential_id"]
        response = await human_post(
            f"/api/v1/credentials/{credential_id}/revoke", loan_officer_token,
            {"reason": "COMPROMISED"})
        assert response.status_code == 403
        status = (await client.get(
            f"/api/v1/credentials/{credential_id}/status")).json()
        assert status["status"] == "ACTIVE"

    # 25 -- unauthorized agent termination -> rejected
    async def test_25_unauthorized_agent_termination_is_refused(
        self, client, human_post, loan_agent, loan_officer_token
    ):
        for kwargs in ({}, {"token": loan_officer_token}):
            if kwargs:
                response = await human_post(
                    f"/api/v1/agents/{loan_agent['id']}/status",
                    kwargs["token"], {"status": "TERMINATED", "reason": "x"})
                assert response.status_code == 403
            else:
                response = await client.post(
                    f"/api/v1/agents/{loan_agent['id']}/status",
                    json={"status": "TERMINATED", "reason": "x"})
                assert response.status_code == 401
        # Still alive.
        assert (await client.get(
            f"/api/v1/agents/{loan_agent['id']}")).json()["status"] == "ACTIVE"

    async def test_anonymous_agent_creation_is_refused(self, client, opa_ready,
                                                       control_plane):
        response = await client.post("/api/v1/agents", json={
            "slug": "rogue-001", "name": "Rogue", "agent_type": "RISK",
            "capabilities": ["credit_analysis"], "endpoint": "http://localhost:9099"})
        assert response.status_code == 401
        assert (await client.get("/api/v1/agents")).json() == []

    async def test_the_authorized_administrator_may_do_all_of_it(
        self, human_post, client, iam_admin_token, issuers, opa_ready, control_plane
    ):
        """§46. The positive half: authorized, and it works."""
        created = await human_post("/api/v1/agents", iam_admin_token, {
            "slug": "risk-003", "name": "Third Risk Agent", "agent_type": "RISK",
            "capabilities": ["credit_analysis"], "endpoint": "http://localhost:9007"})
        assert created.status_code == 201
        agent = created.json()

        issued = await human_post("/api/v1/credentials/issue", iam_admin_token, {
            "issuer": "did:poc:organization:bank-demo", "subject": agent["did"],
            "credential_type": "AgentCapabilityCredential",
            "claims": {"capability": "credit_analysis",
                       "allowed_actions": ["READ_CREDIT_PROFILE"],
                       "allowed_resources": ["credit_records"],
                       "purpose": "loan_assessment"},
            "expires_in_seconds": 3600})
        assert issued.status_code == 201, issued.text

        revoked = await human_post(
            f"/api/v1/credentials/{issued.json()['credential_id']}/revoke",
            iam_admin_token, {"reason": "SUPERSEDED"})
        assert revoked.status_code == 200

        terminated = await human_post(
            f"/api/v1/agents/{agent['id']}/status", iam_admin_token,
            {"status": "TERMINATED", "reason": "DECOMMISSIONED"})
        assert terminated.status_code == 200
        assert terminated.json()["status"] == "TERMINATED"


class TestNoAgentSelfApproval:
    """§55. The attack the whole phase exists to prevent."""

    async def test_an_agent_cannot_decide_its_own_approval(
        self, agent_post, escalate, loan_agent
    ):
        _, approval_id, _ = await escalate()
        response = await agent_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide", loan_agent["did"],
            {"decision": "APPROVED"})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "AGENT_MAY_NOT_APPROVE"

    async def test_a_machine_administrator_cannot_approve_for_a_human(
        self, cp_post, escalate
    ):
        """A machine key is not a person. No number of control-plane roles
        makes it one."""
        _, approval_id, _ = await escalate()
        response = await cp_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide",
            "did:poc:administrator:identity-authority", {"decision": "APPROVED"})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "MACHINE_MAY_NOT_APPROVE"

    async def test_an_agent_asserting_its_own_approval_is_ignored(
        self, cp_post, escalate, loan_agent
    ):
        """The agent supplies `{"approval": {"valid": true}}` in its context."""
        _, _, request_id = await escalate()
        response = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(loan_agent["did"], request_id=request_id,
                         context={"approval": {"valid": True},
                                  "human_approved": True, "approved": True}))
        body = response.json()
        assert body["decision"]["decision"] == "HUMAN_APPROVAL_REQUIRED"
        assert body["executed"] is False
        assert set(body["decision"]["evaluation"]["rejected_context_keys"]) == {
            "approval", "approved", "human_approved"}


class TestPrivilegeEscalation:
    """§45, in both directions."""

    async def test_a_loan_officer_cannot_modify_policy(
        self, human_post, loan_officer_token, policies_loaded
    ):
        response = await human_post(
            "/api/v1/policies/loan-credit-read/deactivate", loan_officer_token, None)
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == \
            "HUMAN_MAY_NOT_PERFORM_MACHINE_OPERATION"

    async def test_no_human_administers_policy(
        self, human_post, iam_admin_token, policies_loaded
    ):
        """Deliberate: changing what the system ENFORCES requires a machine
        principal with a key, not a browser session."""
        response = await human_post(
            "/api/v1/policies/loan-credit-read/deactivate", iam_admin_token, None)
        assert response.status_code == 403

    async def test_a_human_cannot_heartbeat_as_an_agent(
        self, client, loan_officer_token, opa_ready, control_plane
    ):
        response = await client.post(
            "/api/v1/authorize",
            json={"subject": {"did": "did:poc:agent:risk-001"}, "action": "read",
                  "resource": {"type": "credit_records", "id": "customer-007"},
                  "purpose": "loan_assessment"},
            headers={"Authorization": f"Bearer {loan_officer_token}"})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == \
            "HUMAN_MAY_NOT_PERFORM_MACHINE_OPERATION"

    async def test_an_auditor_may_read_an_approval_but_not_decide_it(
        self, human_post, client, escalate, auditor_token
    ):
        _, approval_id, _ = await escalate()
        read = await client.get(f"/api/v1/hitl/approvals/{approval_id}",
                                headers={"Authorization": f"Bearer {auditor_token}"})
        assert read.status_code == 200
        decided = await human_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide", auditor_token,
            {"decision": "APPROVED"})
        assert decided.status_code == 403


class TestNoBlindApproval:
    """§15, §16. The human must see exactly what they are approving."""

    async def test_the_approval_screen_carries_everything_needed_to_judge(
        self, client, escalate, loan_officer_token
    ):
        _, approval_id, _ = await escalate()
        body = (await client.get(
            f"/api/v1/hitl/approvals/{approval_id}",
            headers={"Authorization": f"Bearer {loan_officer_token}"})).json()
        p = body["presentation"]
        assert p["agent"]["did"].startswith("did:poc:agent:")
        assert p["action"]["label"] == "APPROVE_LOAN"
        assert p["resource"]["id"] == LOAN
        assert p["resource"]["detail"]["amount"] == "₹25,00,000"
        assert p["resource"]["detail"]["applicant"]
        assert p["purpose"] == "loan_decision"
        assert p["policy"]["explanation"]
        assert body["requested_at"] and body["request_expires_at"]

    async def test_the_screen_shows_attested_capabilities_not_claims(
        self, client, escalate, loan_officer_token
    ):
        """An approver must not be shown a self-declared capability as though
        it were verified."""
        _, approval_id, _ = await escalate()
        body = (await client.get(
            f"/api/v1/hitl/approvals/{approval_id}",
            headers={"Authorization": f"Bearer {loan_officer_token}"})).json()
        assert body["presentation"]["agent"]["verified_capabilities"] == \
            ["credit_analysis"]

    async def test_the_screen_is_not_a_data_exfiltration_route(
        self, client, escalate, loan_officer_token
    ):
        """The approver sees the loan, not a credit file."""
        _, approval_id, _ = await escalate()
        body = (await client.get(
            f"/api/v1/hitl/approvals/{approval_id}",
            headers={"Authorization": f"Bearer {loan_officer_token}"})).json()
        assert "credit_score" not in str(body)

    async def test_viewing_is_recorded(self, client, escalate, loan_officer_token):
        """Auditable evidence that the decision was INFORMED."""
        _, approval_id, _ = await escalate()
        await client.get(f"/api/v1/hitl/approvals/{approval_id}",
                         headers={"Authorization": f"Bearer {loan_officer_token}"})
        events = (await client.get("/api/v1/audit?limit=200")).json()
        viewed = [e for e in events if e["event_type"] == "APPROVAL_VIEWED"]
        assert viewed
        assert viewed[0]["metadata"]["approval_id"] == approval_id
        assert viewed[0]["metadata"]["viewer_username"] == "loan.officer"


class TestAuditTrail:
    """§30, §31. The whole lifecycle, correlated."""

    async def test_the_full_lifecycle_is_recorded(
        self, client, cp_post, human_post, escalate, loan_officer_token, loan_agent
    ):
        _, approval_id, request_id = await escalate()
        await client.get(f"/api/v1/hitl/approvals/{approval_id}",
                         headers={"Authorization": f"Bearer {loan_officer_token}"})
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        await cp_post("/api/v1/enforce",
                      "did:poc:administrator:enforcement-gateway",
                      enforce_body(loan_agent["did"], request_id=request_id))

        events = (await client.get("/api/v1/audit?limit=400")).json()
        types = {e["event_type"] for e in events}
        for expected in ("HUMAN_AUTHENTICATED", "APPROVAL_REQUESTED",
                         "APPROVAL_VIEWED", "APPROVAL_APPROVED",
                         "AUTHORIZATION_REEVALUATED", "APPROVAL_CONSUMED",
                         "POLICY_ALLOW", "AEM_ALLOWED", "TOOL_EXECUTED"):
            assert expected in types, expected

    async def test_the_flow_is_correlated_by_request_id(
        self, client, cp_post, human_post, escalate, loan_officer_token, loan_agent
    ):
        """§31. One loan action, traceable end to end."""
        _, approval_id, request_id = await escalate()
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        await cp_post("/api/v1/enforce",
                      "did:poc:administrator:enforcement-gateway",
                      enforce_body(loan_agent["did"], request_id=request_id))

        events = (await client.get("/api/v1/audit?limit=400")).json()
        correlated = [e for e in events if e.get("request_id") == request_id]
        types = {e["event_type"] for e in correlated}
        assert {"AEM_INTERCEPT", "AUTHORIZATION_REQUESTED", "APPROVAL_REQUESTED",
                "APPROVAL_APPROVED", "AUTHORIZATION_REEVALUATED",
                "APPROVAL_CONSUMED", "AEM_ALLOWED"} <= types

    async def test_the_approver_is_named_in_the_trail(
        self, client, human_post, escalate, loan_officer_token
    ):
        _, approval_id, _ = await escalate()
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        events = (await client.get("/api/v1/audit?limit=200")).json()
        approved = [e for e in events if e["event_type"] == "APPROVAL_APPROVED"][0]
        assert approved["metadata"]["approver_username"] == "loan.officer"
        assert approved["metadata"]["approver_roles"] == ["LOAN_OFFICER"]
        assert approved["metadata"]["signed_by"] == "did:poc:service:approval-authority"

    async def test_no_token_or_secret_is_ever_logged(
        self, client, human_post, escalate, loan_officer_token
    ):
        """§30. Not the access token, not a refresh token, not a password."""
        _, approval_id, _ = await escalate()
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        trail = str((await client.get("/api/v1/audit?limit=400")).json())
        assert loan_officer_token not in trail
        for forbidden in ("password", "refresh_token", "client_secret"):
            assert forbidden not in trail.lower()


class TestFailClosed:
    """§43, §44."""

    async def test_an_unavailable_identity_provider_blocks_the_action(
        self, client, escalate, loan_officer_token, monkeypatch
    ):
        """§44. HUMAN_APPROVAL_REQUIRED must NEVER become ALLOW because the
        approval path is unavailable. The action stays blocked."""
        from app.humans.oidc import OIDCReason, OIDCValidator, TokenInvalid

        _, approval_id, _ = await escalate()

        def unavailable(self, token):
            raise TokenInvalid(OIDCReason.PROVIDER_UNAVAILABLE,
                               "the identity provider is unreachable")

        monkeypatch.setattr(OIDCValidator, "validate", unavailable)
        response = await client.post(
            f"/api/v1/hitl/approvals/{approval_id}/decide",
            json={"decision": "APPROVED"},
            headers={"Authorization": f"Bearer {loan_officer_token}"})
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == OIDCReason.PROVIDER_UNAVAILABLE
        assert loan_application_status(LOAN) == "AWAITING_DECISION"

    async def test_an_unavailable_policy_engine_blocks_approval(
        self, client, escalate, loan_officer_token, monkeypatch
    ):
        from app.authorization.opa import OPAClient, OPAUnavailableError

        _, approval_id, _ = await escalate()

        async def unavailable(self, input_document, *, decision_url=None):
            raise OPAUnavailableError("the policy engine is not reachable")

        monkeypatch.setattr(OPAClient, "evaluate", unavailable)
        response = await client.post(
            f"/api/v1/hitl/approvals/{approval_id}/decide",
            json={"decision": "APPROVED"},
            headers={"Authorization": f"Bearer {loan_officer_token}"})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == \
            "CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE"

    def test_hitl_cannot_be_configured_off(self):
        from pydantic import ValidationError

        from app.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(hitl_enabled=False)


class TestApprovalIsNotStandingPermission:
    """§56. Specific, bounded, expiring, single-use, context-bound."""

    async def test_approving_once_does_not_permit_the_next_action(
        self, cp_post, human_post, escalate, loan_officer_token, loan_agent
    ):
        """The most important negative property: a human approving one thing
        does not give the agent standing authority."""
        _, approval_id, request_id = await escalate()
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        await cp_post("/api/v1/enforce",
                      "did:poc:administrator:enforcement-gateway",
                      enforce_body(loan_agent["did"], request_id=request_id))

        # A brand-new attempt on the OTHER loan: straight back to a human.
        response = await cp_post(
            "/api/v1/enforce", "did:poc:administrator:enforcement-gateway",
            enforce_body(loan_agent["did"], OTHER_LOAN))
        body = response.json()
        assert body["decision"]["decision"] == "HUMAN_APPROVAL_REQUIRED"
        assert body["executed"] is False
        assert loan_application_status(OTHER_LOAN) == "AWAITING_DECISION"

    async def test_an_approval_never_becomes_a_credential(
        self, client, human_post, escalate, loan_officer_token, loan_agent
    ):
        """Approving an action must not grant the agent a capability."""
        _, approval_id, _ = await escalate()
        before = (await client.get(
            f"/api/v1/credentials?subject={loan_agent['did']}")).json()
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        after = (await client.get(
            f"/api/v1/credentials?subject={loan_agent['did']}")).json()
        assert len(after) == len(before)
