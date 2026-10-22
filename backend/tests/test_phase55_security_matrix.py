"""The Phase 5.5 security matrix, as one auditable file.

Every request here goes over HTTP through the real guard, against the real OPA,
with real RS256 tokens from the real Keycloak. A rejection in this file is the
rejection a caller gets.

What Phase 5.5 adds to the Phase 5 matrix, and why each one mattered:

    THE AMOUNT DECIDES        a loan officer could approve any sum. Now the
                              amount is an authorization input, read
                              server-side, and policy decides what it means.
    TAMPERING FAILS           the approval binds the amount, so a figure that
                              moves after a person agreed to it invalidates the
                              approval instead of riding along with it.
    TWO PEOPLE MEANS TWO      one human signing twice is not two humans.
    MAKER != CHECKER          the officer who submitted it cannot sign it off.
    KEYS ROTATE               without invalidating history, and without letting
                              a retired key issue anything new.

The Phase 5 organising claim is unchanged and is re-asserted throughout:

    HUMAN AUTHENTICATION  !=  HUMAN APPROVAL
    HUMAN APPROVAL        !=  AUTHORIZATION
    AUTHORIZATION         !=  ENFORCEMENT
"""
from __future__ import annotations

import pytest

from app.enforcement.resources import (
    loan_application_status,
    material_attributes,
    set_loan_amount,
)

pytestmark = pytest.mark.integration

AUTONOMOUS = "loan-2201"      # Rs 5,00,000    -- scenario A
SINGLE = "loan-7842"          # Rs 25,00,000   -- scenario B
DUAL = "loan-9001"            # Rs 2,00,00,000 -- scenario C
SELF_SUBMITTED = "loan-5150"  # submitted_by: loan.officer
GATEWAY = "did:poc:administrator:enforcement-gateway"


def enforce_body(did, application_id=SINGLE, **overrides):
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
async def attempt(cp_post, loan_agent, loan_agent_credential, approval_authority):
    """Attempt the loan decision through the AEM. Returns the full response."""
    async def run(application_id=SINGLE, did=None, **overrides):
        response = await cp_post(
            "/api/v1/enforce", GATEWAY,
            enforce_body(did or loan_agent["did"], application_id, **overrides),
        )
        body = response.json()
        request = body["decision"]["evaluation"].get("approval_request") or {}
        return body, request.get("approval_id"), request.get("retry_with_request_id")
    return run


# ===========================================================================
# §24 -- the three end-to-end scenarios, at the CONFIGURED thresholds
# ===========================================================================
class TestScenarios:
    async def test_scenario_a_a_small_loan_decides_on_agent_authority(
        self, attempt
    ):
        """Rs 5,00,000. Risk agent -> PDP -> ALLOW, and the resource changes.

        No human is involved because policy says none is needed at this amount.
        The credential is still required, still verified, and still scoped.
        """
        body, approval_id, _ = await attempt(AUTONOMOUS)
        assert body["decision"]["decision"] == "ALLOW"
        assert body["decision"]["reason"] == "WITHIN_AGENT_APPROVAL_AUTHORITY"
        assert body["executed"] is True
        assert approval_id is None, "no human should have been asked"
        assert loan_application_status(AUTONOMOUS) == "APPROVED"

    async def test_scenario_b_a_mid_value_loan_needs_one_officer(
        self, attempt, cp_post, human_post, loan_officer_token, loan_agent
    ):
        """Rs 25,00,000. Escalate -> Keycloak -> loan officer -> PDP -> ALLOW."""
        body, approval_id, request_id = await attempt(SINGLE)
        assert body["decision"]["decision"] == "HUMAN_APPROVAL_REQUIRED"
        assert body["decision"]["reason"] == "SENSITIVE_ACTION_REQUIRES_HUMAN"
        assert body["executed"] is False
        assert loan_application_status(SINGLE) == "AWAITING_DECISION"

        decided = await human_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide",
            loan_officer_token, {"decision": "APPROVED"})
        assert decided.status_code == 200
        assert decided.json()["required_approvals"] == 1
        assert decided.json()["status"] == "APPROVED"

        retried = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], SINGLE, request_id=request_id))
        assert retried.json()["decision"]["decision"] == "ALLOW"
        assert retried.json()["executed"] is True
        assert loan_application_status(SINGLE) == "APPROVED"

    async def test_scenario_c_a_high_value_loan_needs_two_distinct_officers(
        self, attempt, cp_post, human_post, loan_officer_token,
        second_loan_officer_token, loan_agent
    ):
        """Rs 2,00,00,000. Officer A, then Officer B, then PDP -> ALLOW."""
        body, approval_id, request_id = await attempt(DUAL)
        assert body["decision"]["decision"] == "HUMAN_APPROVAL_REQUIRED"
        assert body["decision"]["reason"] == "DUAL_APPROVAL_REQUIRED"
        assert body["decision"]["evaluation"]["approval_request"][
            "required_approvals"] == 2

        first = await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                                 loan_officer_token, {"decision": "APPROVED"})
        assert first.status_code == 200
        # STILL PENDING. One officer is not two.
        assert first.json()["status"] == "PENDING"
        assert first.json()["approvals_recorded"] == 1
        assert first.json()["awaiting_approvals"] == 1
        assert first.json()["artifact"] is None

        # And the action is still blocked in the meantime.
        blocked = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], DUAL, request_id=request_id))
        assert blocked.json()["executed"] is False
        assert loan_application_status(DUAL) == "AWAITING_DECISION"

        second = await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                                  second_loan_officer_token, {"decision": "APPROVED"})
        assert second.status_code == 200
        assert second.json()["status"] == "APPROVED"
        assert second.json()["approvals_recorded"] == 2
        usernames = [s["username"] for s in second.json()["signoffs"]]
        assert usernames == ["loan.officer", "loan.officer.2"]

        released = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], DUAL, request_id=request_id))
        assert released.json()["decision"]["decision"] == "ALLOW"
        assert released.json()["executed"] is True
        assert loan_application_status(DUAL) == "APPROVED"


# ===========================================================================
# §25 -- the negative demonstrations
# ===========================================================================
class TestNegatives:
    async def test_wrong_role_is_denied(
        self, attempt, human_post, iam_admin_token, auditor_token, no_roles_token
    ):
        _, approval_id, _ = await attempt(DUAL)
        for token in (iam_admin_token, auditor_token, no_roles_token):
            response = await human_post(
                f"/api/v1/hitl/approvals/{approval_id}/decide", token,
                {"decision": "APPROVED"})
            assert response.status_code == 403
            assert response.json()["detail"]["reason"] == "HUMAN_MAY_NOT_APPROVE_THIS"

    async def test_self_approval_is_denied(
        self, attempt, human_post, loan_officer_token
    ):
        """The officer of record on loan-5150 is loan.officer."""
        assert material_attributes(
            "loan_applications", SELF_SUBMITTED)["submitted_by"] == "loan.officer"
        _, approval_id, _ = await attempt(SELF_SUBMITTED)
        response = await human_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide",
            loan_officer_token, {"decision": "APPROVED"})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "SELF_APPROVAL_PROHIBITED"
        assert response.json()["detail"]["policy"] == "cp-humans:v1"

    async def test_a_different_officer_may_approve_what_the_first_submitted(
        self, attempt, human_post, second_loan_officer_token
    ):
        """The rule refuses ONE person, not the application. Without this the
        previous test would also pass if approvals were simply broken."""
        _, approval_id, _ = await attempt(SELF_SUBMITTED)
        response = await human_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide",
            second_loan_officer_token, {"decision": "APPROVED"})
        assert response.status_code == 200
        assert response.json()["status"] == "APPROVED"

    async def test_the_same_human_cannot_satisfy_both_approvals(
        self, attempt, human_post, loan_officer_token
    ):
        """§6. Human A approves. Human A attempts the second approval. DENY."""
        _, approval_id, _ = await attempt(DUAL)
        first = await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                                 loan_officer_token, {"decision": "APPROVED"})
        assert first.status_code == 200

        again = await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                                 loan_officer_token, {"decision": "APPROVED"})
        assert again.status_code == 403
        assert again.json()["detail"]["reason"] == "APPROVER_ALREADY_SIGNED"

    async def test_a_tampered_amount_denies_and_the_resource_is_untouched(
        self, attempt, cp_post, human_post, loan_officer_token, loan_agent
    ):
        """§3. THE HEADLINE NEGATIVE.

        A human is shown Rs 25,00,000 and approves Rs 25,00,000. The amount is
        then changed to Rs 2,50,00,000 before the action executes. The approval
        does not cover the new figure -- it was never about it.
        """
        _, approval_id, request_id = await attempt(SINGLE)
        approved = await human_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide",
            loan_officer_token, {"decision": "APPROVED"})
        assert approved.json()["binding"]["amount_inr"] == 2_500_000

        set_loan_amount(SINGLE, 25_000_000)

        retried = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], SINGLE, request_id=request_id))
        body = retried.json()
        assert body["decision"]["decision"] == "DENY"
        assert body["decision"]["reason"] == "APPROVAL_BINDING_MISMATCH"
        assert body["executed"] is False
        assert loan_application_status(SINGLE) == "AWAITING_DECISION"

    async def test_a_tampered_amount_names_the_field_that_moved(
        self, attempt, cp_post, human_post, loan_officer_token, loan_agent
    ):
        """A denial must be diagnostic. 'The amount changed' and 'this is a
        different loan' are very different incidents."""
        _, approval_id, request_id = await attempt(SINGLE)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        set_loan_amount(SINGLE, 25_000_000)

        retried = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], SINGLE, request_id=request_id))
        checks = retried.json()["decision"]["evaluation"]["pip"]["approval"]["checks"]
        binding = next(c for c in checks if c["name"] == "binding")
        assert binding["passed"] is False
        assert "amount_inr" in binding["detail"]

    async def test_a_tampered_resource_denies(
        self, attempt, cp_post, human_post, loan_officer_token, loan_agent
    ):
        """An approval for one application, spent on another."""
        _, approval_id, request_id = await attempt(SINGLE)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})

        moved = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], "loan-1001", request_id=request_id,
            approval_id=approval_id))
        assert moved.json()["decision"]["decision"] != "ALLOW"
        assert moved.json()["executed"] is False
        assert loan_application_status("loan-1001") == "AWAITING_DECISION"

    async def test_a_wrong_agent_cannot_use_another_agents_approval(
        self, attempt, cp_post, human_post, loan_officer_token, admin_post, issuers
    ):
        """§16. The approval names an agent DID."""
        _, approval_id, request_id = await attempt(SINGLE)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})

        other = (await admin_post("/api/v1/agents", {
            "slug": "fraud-001", "name": "Fraud Detection Agent",
            "agent_type": "FRAUD", "capabilities": ["credit_analysis"],
            "endpoint": "http://localhost:9004",
        })).json()
        await admin_post("/api/v1/credentials/issue", {
            "issuer": "did:poc:organization:bank-demo", "subject": other["did"],
            "credential_type": "AgentCapabilityCredential",
            "claims": {"capability": "credit_analysis",
                       "allowed_actions": ["APPROVE_LOAN"],
                       "allowed_resources": ["loan_applications"],
                       "purpose": "loan_decision"},
            "expires_in_seconds": 3600,
        })

        stolen = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            other["did"], SINGLE, request_id=request_id, approval_id=approval_id))
        assert stolen.json()["decision"]["decision"] != "ALLOW"
        assert stolen.json()["executed"] is False

    async def test_a_replayed_approval_is_denied(
        self, attempt, cp_post, human_post, loan_officer_token, loan_agent
    ):
        """§16. Approve once, execute once, then try the same approval again."""
        _, approval_id, request_id = await attempt(SINGLE)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})

        first = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], SINGLE, request_id=request_id))
        assert first.json()["executed"] is True

        replay = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], SINGLE, request_id=request_id,
            approval_id=approval_id))
        assert replay.json()["decision"]["decision"] == "DENY"
        assert replay.json()["decision"]["reason"] == "APPROVAL_ALREADY_CONSUMED"

    async def test_a_partially_approved_dual_request_is_denied(
        self, attempt, cp_post, human_post, loan_officer_token, loan_agent
    ):
        """One of two. The action stays blocked, and says why."""
        _, approval_id, request_id = await attempt(DUAL)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})

        blocked = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], DUAL, request_id=request_id))
        assert blocked.json()["executed"] is False
        assert blocked.json()["decision"]["decision"] == "HUMAN_APPROVAL_REQUIRED"
        assert blocked.json()["decision"]["reason"] == "DUAL_APPROVAL_REQUIRED"
        assert loan_application_status(DUAL) == "AWAITING_DECISION"

    async def test_a_rejection_blocks_and_the_resource_is_untouched(
        self, attempt, cp_post, human_post, loan_officer_token, loan_agent
    ):
        _, approval_id, request_id = await attempt(SINGLE)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "REJECTED"})

        retried = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], SINGLE, request_id=request_id))
        assert retried.json()["decision"]["decision"] == "DENY"
        assert retried.json()["decision"]["reason"] == "APPROVAL_REJECTED"
        assert loan_application_status(SINGLE) == "AWAITING_DECISION"


# ===========================================================================
# §18 -- the human role matrix, plus the machine principal class
# ===========================================================================
class TestRoleMatrix:
    """Each row is a principal and what it may and may not do.

    MACHINE_ADMIN is implemented as the MACHINE administrator principal class
    (`did:poc:administrator:*`), not as a Keycloak realm role. `cp-humans`
    denies humans every machine operation by name, and adding a human role that
    could perform them would undo that. The interpretation is recorded in
    docs/PHASE_5_5_ARCHITECTURE.md and asserted below in both directions.
    """

    async def test_loan_officer_approves_loans_and_nothing_else(
        self, attempt, human_post, loan_officer_token, client
    ):
        _, approval_id, _ = await attempt(SINGLE)
        approved = await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                                    loan_officer_token, {"decision": "APPROVED"})
        assert approved.status_code == 200

        # ...and may not administer identity.
        refused = await client.post(
            "/api/v1/agents",
            json={"slug": "sneaky", "name": "x", "agent_type": "RISK",
                  "capabilities": [], "endpoint": "http://localhost:9099"},
            headers={"Authorization": f"Bearer {loan_officer_token}"})
        assert refused.status_code == 403
        assert refused.json()["detail"]["reason"] == "HUMAN_MAY_NOT_ADMINISTER_IAM"

    async def test_auditor_reads_and_approves_nothing(
        self, attempt, human_post, auditor_token, client
    ):
        _, approval_id, _ = await attempt(SINGLE)
        readable = await client.get(
            f"/api/v1/hitl/approvals/{approval_id}",
            headers={"Authorization": f"Bearer {auditor_token}"})
        assert readable.status_code == 200

        refused = await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                                   auditor_token, {"decision": "APPROVED"})
        assert refused.status_code == 403

    async def test_iam_admin_administers_identity_and_approves_nothing(
        self, attempt, human_post, iam_admin_token, client
    ):
        created = await client.post(
            "/api/v1/agents",
            json={"slug": "kyc-042", "name": "KYC Agent", "agent_type": "KYC",
                  "capabilities": ["kyc"], "endpoint": "http://localhost:9098"},
            headers={"Authorization": f"Bearer {iam_admin_token}"})
        assert created.status_code == 201

        _, approval_id, _ = await attempt(SINGLE)
        refused = await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                                   iam_admin_token, {"decision": "APPROVED"})
        assert refused.status_code == 403

    async def test_a_no_role_human_is_authenticated_and_permitted_nothing(
        self, attempt, human_post, no_roles_token, client
    ):
        """Authenticated but unauthorized is a distinct, tested state."""
        me = await client.get("/api/v1/hitl/me",
                              headers={"Authorization": f"Bearer {no_roles_token}"})
        assert me.status_code == 200
        assert me.json()["roles"] == []

        _, approval_id, _ = await attempt(SINGLE)
        for path in (f"/api/v1/hitl/approvals/{approval_id}/decide",
                     f"/api/v1/hitl/approvals/{approval_id}/cancel"):
            response = await human_post(path, no_roles_token, {"decision": "APPROVED"}
                                        if "decide" in path else {"reason": "no"})
            assert response.status_code == 403

    async def test_machine_admin_performs_control_plane_operations(
        self, cp_post, control_plane, approval_authority, client
    ):
        """The MACHINE administrator class. It rotates the approval key and
        administers identity -- and cannot approve anything."""
        rotated = await cp_post(
            "/api/v1/hitl/authority/keys/rotate",
            "did:poc:administrator:identity-authority",
            {"reason": "matrix test"})
        assert rotated.status_code == 200
        assert rotated.json()["active"]["generation"] == 2

    async def test_a_machine_admin_may_not_approve(
        self, attempt, cp_post, control_plane
    ):
        _, approval_id, _ = await attempt(SINGLE)
        response = await cp_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide",
            "did:poc:administrator:identity-authority", {"decision": "APPROVED"})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "MACHINE_MAY_NOT_APPROVE"

    async def test_no_human_role_may_rotate_the_signing_key(
        self, client, iam_admin_token, loan_officer_token, keycloak_ready
    ):
        """Changing which key attests that a person agreed to something must
        require more than a browser session."""
        for token in (iam_admin_token, loan_officer_token):
            response = await client.post(
                "/api/v1/hitl/authority/keys/rotate", json={"reason": "nope"},
                headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 403
            assert response.json()["detail"]["reason"] == (
                "HUMAN_MAY_NOT_PERFORM_MACHINE_OPERATION")

    async def test_an_agent_may_not_approve(
        self, attempt, agent_post, loan_agent
    ):
        _, approval_id, _ = await attempt(SINGLE)
        response = await agent_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide",
            loan_agent["did"], {"decision": "APPROVED"})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "AGENT_MAY_NOT_APPROVE"

    async def test_an_unauthenticated_caller_may_not_rotate_the_key(self, client):
        response = await client.post("/api/v1/hitl/authority/keys/rotate",
                                     json={"reason": "anonymous"})
        assert response.status_code == 401

    async def test_the_key_register_is_readable_and_carries_no_secret(
        self, client, approval_authority
    ):
        """PUBLIC MATERIAL ONLY, for the same reason a DID Document is public:
        everything here is what a verifier needs to check a signature."""
        response = await client.get("/api/v1/hitl/authority/keys")
        assert response.status_code == 200
        body = response.json()
        assert body["active"]["generation"] == 1
        assert body["keys"][0]["private_key"] == "NEVER EXPOSED - held by the KeyStore"
        assert body["keys"][0]["public_key_multibase"]
        assert "privateKey" not in response.text
        assert "PRIVATE KEY" not in response.text.upper()


# ===========================================================================
# The amendment surface Phase 5.5 added. A new mutation is a new attack
# surface, so it is enumerated here the way every other one is.
# ===========================================================================
class TestLoanAmendment:
    """Amending an amount is as consequential as approving.

    The amount decides which band a request falls in, and therefore how many
    humans it needs. So the ability to change it is guarded like an approval:
    proved identity, a policy decision, an audit record -- and a role held by
    exactly one machine principal and by no human at all.
    """

    async def test_the_core_banking_principal_may_amend(
        self, cp_post, control_plane, opa_ready
    ):
        response = await cp_post(
            f"/api/v1/loans/{SINGLE}/amount",
            "did:poc:administrator:core-banking",
            {"amount_inr": 25_000_000, "reason": "applicant revised the request"})
        assert response.status_code == 200
        assert response.json()["amount_inr"] == 25_000_000
        assert response.json()["previous_amount_inr"] == 2_500_000

    async def test_no_human_may_amend_an_amount(
        self, client, loan_officer_token, iam_admin_token, keycloak_ready
    ):
        """An officer who could restate an amount and then approve it would
        have defeated the amount policy and maker-checker in one move."""
        for token in (loan_officer_token, iam_admin_token):
            response = await client.post(
                f"/api/v1/loans/{SINGLE}/amount", json={"amount_inr": 1},
                headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 403
            assert response.json()["detail"]["reason"] == (
                "HUMAN_MAY_NOT_PERFORM_MACHINE_OPERATION")

    async def test_another_machine_administrator_may_not_amend(
        self, cp_post, control_plane, opa_ready
    ):
        """Least privilege, demonstrated: the identity administrator holds a
        real key, authenticates perfectly, and is refused."""
        response = await cp_post(
            f"/api/v1/loans/{SINGLE}/amount",
            "did:poc:administrator:identity-authority", {"amount_inr": 1})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "MISSING_CONTROL_PLANE_ROLE"

    async def test_an_agent_may_not_amend(
        self, agent_post, loan_agent, opa_ready
    ):
        response = await agent_post(
            f"/api/v1/loans/{SINGLE}/amount", loan_agent["did"],
            {"amount_inr": 1})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "AGENT_MAY_NOT_ADMINISTER"

    async def test_an_anonymous_caller_may_not_amend(
        self, client, control_plane, opa_ready
    ):
        response = await client.post(f"/api/v1/loans/{SINGLE}/amount",
                                     json={"amount_inr": 1})
        assert response.status_code == 401

    async def test_amending_over_http_invalidates_an_existing_approval(
        self, attempt, cp_post, human_post, loan_officer_token, loan_agent,
        control_plane
    ):
        """§3 END TO END, through the real amendment path.

        Nothing is reached into: a human approves, an authorized upstream
        principal restates the amount over HTTP, and the approval stops
        applying -- by name, with the field that moved.
        """
        _, approval_id, request_id = await attempt(SINGLE)
        approved = await human_post(
            f"/api/v1/hitl/approvals/{approval_id}/decide",
            loan_officer_token, {"decision": "APPROVED"})
        assert approved.json()["binding"]["amount_inr"] == 2_500_000

        amended = await cp_post(
            f"/api/v1/loans/{SINGLE}/amount",
            "did:poc:administrator:core-banking",
            {"amount_inr": 25_000_000, "reason": "restated upstream"})
        assert amended.status_code == 200

        retried = await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], SINGLE, request_id=request_id))
        body = retried.json()
        assert body["decision"]["decision"] == "DENY"
        assert body["decision"]["reason"] == "APPROVAL_BINDING_MISMATCH"
        assert body["executed"] is False
        assert loan_application_status(SINGLE) == "AWAITING_DECISION"

    async def test_amending_does_not_touch_the_approval_record(
        self, session, attempt, cp_post, human_post, loan_officer_token,
        control_plane
    ):
        """The approval is not revoked. It stays a true, signed record of what
        that person agreed to -- it simply is not about this request any more.
        Invalidating it here would be the wrong shape."""
        from app.hitl.service import ApprovalService

        _, approval_id, _ = await attempt(SINGLE)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        await cp_post(f"/api/v1/loans/{SINGLE}/amount",
                      "did:poc:administrator:core-banking",
                      {"amount_inr": 25_000_000})

        record = await ApprovalService(session).require(approval_id)
        assert record.status.value == "APPROVED"
        assert record.artifact is not None
        assert record.binding["amount_inr"] == 2_500_000

    async def test_the_amendment_is_audited_with_both_figures(
        self, client, cp_post, control_plane, opa_ready
    ):
        await cp_post(f"/api/v1/loans/{SINGLE}/amount",
                      "did:poc:administrator:core-banking",
                      {"amount_inr": 25_000_000, "reason": "restated upstream"})
        events = (await client.get("/api/v1/audit?limit=200")).json()
        amended = [e for e in events if e["event_type"] == "LOAN_AMOUNT_AMENDED"]
        assert len(amended) == 1
        assert amended[0]["metadata"]["amount_before"] == 2_500_000
        assert amended[0]["metadata"]["amount_after"] == 25_000_000
        assert amended[0]["metadata"]["amended_by"] == (
            "did:poc:administrator:core-banking")


# ===========================================================================
# §13 -- SAML stays DOCUMENTED, and is not faked
# ===========================================================================
class TestSAMLStatus:
    """OIDC is implemented. SAML federation is a documented integration path.

    The distinction is worth a test rather than a paragraph, because the
    tempting failure is a stub: an endpoint that accepts something SAML-shaped
    and proves nothing. There is no second real enterprise IdP available to
    federate against here, and standing one up purely to have something to
    point at would be inventing the component the honesty rests on NOT having.

    The integration path -- Enterprise IdP --SAML--> Keycloak --OIDC--> this
    application -- needs no code here at all: Keycloak is the SAML Service
    Provider and this application only ever sees an OIDC token.
    """

    async def test_no_saml_endpoint_is_exposed(self, client):
        from app.main import app

        paths = [getattr(route, "path", "") for route in app.routes]
        assert not [p for p in paths if "saml" in p.lower()]

    def test_no_saml_parsing_exists_in_the_application(self):
        """No SAML in CODE.

        Comments and docstrings that say SAML is not implemented are exactly
        what should be there, so they are tokenized away rather than matched --
        otherwise the honest documentation would fail its own test.
        """
        import io
        import pathlib as _pathlib
        import tokenize

        app_dir = _pathlib.Path(__file__).resolve().parents[1] / "app"
        offenders = []
        for path in app_dir.rglob("*.py"):
            source = path.read_text()
            for token in tokenize.generate_tokens(io.StringIO(source).readline):
                if token.type in (tokenize.COMMENT, tokenize.STRING):
                    continue
                if "saml" in token.string.lower():
                    offenders.append(f"{path.relative_to(app_dir)}:{token.start[0]}")
        assert offenders == [], (
            "SAML must stay documented rather than stubbed: " + ", ".join(offenders)
        )

    def test_no_saml_library_is_a_dependency(self):
        """A stub needs no library; a real implementation does. Neither is here."""
        import pathlib as _pathlib

        backend = _pathlib.Path(__file__).resolve().parents[1]
        requirements = (backend / "requirements.txt").read_text().lower()
        for library in ("python3-saml", "pysaml2", "python-saml", "onelogin"):
            assert library not in requirements

    async def test_the_configured_provider_is_oidc_and_says_so(self, client):
        config = (await client.get("/api/v1/hitl/config")).json()
        assert config["provider"] == "keycloak"
        assert config["flow"] == "authorization_code+pkce"


# ===========================================================================
# §19 -- S-7 stays closed
# ===========================================================================
class TestS7Regression:
    @pytest.mark.parametrize("method,path,body", [
        ("POST", "/api/v1/agents",
         {"slug": "anon", "name": "x", "agent_type": "RISK",
          "capabilities": [], "endpoint": "http://localhost:9097"}),
        ("POST", "/api/v1/credentials/issue",
         {"issuer": "did:poc:organization:bank-demo",
          "subject": "did:poc:agent:risk-001",
          "credential_type": "AgentCapabilityCredential",
          "claims": {"capability": "credit_analysis",
                     "allowed_actions": ["APPROVE_LOAN"],
                     "allowed_resources": ["loan_applications"],
                     "purpose": "loan_decision"},
          "expires_in_seconds": 60}),
        ("POST", "/api/v1/hitl/authority/keys/rotate", {"reason": "anonymous"}),
    ])
    async def test_anonymous_mutations_are_refused(
        self, client, method, path, body, control_plane, opa_ready
    ):
        response = await client.request(method, path, json=body)
        assert response.status_code == 401
        assert response.json()["detail"]["error"] == (
            "CONTROL_PLANE_AUTHENTICATION_FAILED")

    async def test_anonymous_revocation_and_termination_are_refused(
        self, client, admin_post, control_plane, issuers, opa_ready
    ):
        agent = (await admin_post("/api/v1/agents", {
            "slug": "risk-009", "name": "Risk", "agent_type": "RISK",
            "capabilities": ["credit_analysis"], "endpoint": "http://localhost:9096",
        })).json()
        issued = await admin_post("/api/v1/credentials/issue", {
            "issuer": "did:poc:organization:bank-demo", "subject": agent["did"],
            "credential_type": "AgentCapabilityCredential",
            "claims": {"capability": "credit_analysis",
                       "allowed_actions": ["APPROVE_LOAN"],
                       "allowed_resources": ["loan_applications"],
                       "purpose": "loan_decision"},
            "expires_in_seconds": 600,
        })
        assert issued.status_code == 201, issued.text
        credential = issued.json()

        revoke = await client.post(
            f"/api/v1/credentials/{credential['credential_id']}/revoke",
            json={"reason": "COMPROMISED"})
        assert revoke.status_code == 401

        terminate = await client.post(
            f"/api/v1/agents/{agent['did']}/status",
            json={"status": "TERMINATED", "reason": "anonymous"})
        assert terminate.status_code == 401

    async def test_an_authorized_machine_identity_is_allowed(
        self, admin_post, control_plane, opa_ready
    ):
        response = await admin_post("/api/v1/agents", {
            "slug": "risk-010", "name": "Risk", "agent_type": "RISK",
            "capabilities": ["credit_analysis"], "endpoint": "http://localhost:9095",
        })
        assert response.status_code == 201


# ===========================================================================
# §14 -- the state machine, over HTTP
# ===========================================================================
class TestStateMachine:
    async def test_a_consumed_approval_cannot_become_approved_again(
        self, attempt, cp_post, human_post, loan_officer_token,
        second_loan_officer_token, loan_agent
    ):
        _, approval_id, request_id = await attempt(SINGLE)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], SINGLE, request_id=request_id))

        # A DIFFERENT officer, so the two-person rule is not what refuses
        # this -- the state machine is.
        again = await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                                 second_loan_officer_token, {"decision": "APPROVED"})
        assert again.status_code == 409
        assert "CONSUMED" in again.json()["detail"]

    async def test_a_rejected_approval_cannot_become_approved(
        self, attempt, human_post, loan_officer_token, second_loan_officer_token
    ):
        _, approval_id, _ = await attempt(DUAL)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "REJECTED"})
        again = await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                                 second_loan_officer_token, {"decision": "APPROVED"})
        assert again.status_code == 409
        assert "REJECTED" in again.json()["detail"]

    async def test_a_cancelled_approval_cannot_become_approved(
        self, attempt, human_post, loan_officer_token, second_loan_officer_token
    ):
        _, approval_id, _ = await attempt(SINGLE)
        cancelled = await human_post(
            f"/api/v1/hitl/approvals/{approval_id}/cancel",
            loan_officer_token, {"reason": "withdrawn"})
        assert cancelled.status_code == 200
        again = await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                                 second_loan_officer_token, {"decision": "APPROVED"})
        assert again.status_code == 409
        assert "CANCELLED" in again.json()["detail"]


# ===========================================================================
# §26 -- the audit trail
# ===========================================================================
class TestAudit:
    async def test_a_dual_control_cycle_is_fully_recorded_and_correlated(
        self, client, attempt, cp_post, human_post, loan_officer_token,
        second_loan_officer_token, loan_agent
    ):
        _, approval_id, request_id = await attempt(DUAL)
        await client.get(f"/api/v1/hitl/approvals/{approval_id}",
                         headers={"Authorization": f"Bearer {loan_officer_token}"})
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})   # refused
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         second_loan_officer_token, {"decision": "APPROVED"})
        await cp_post("/api/v1/enforce", GATEWAY, enforce_body(
            loan_agent["did"], DUAL, request_id=request_id))

        events = (await client.get("/api/v1/audit?limit=500")).json()
        types = {e["event_type"] for e in events}
        for required in (
            "APPROVAL_REQUESTED", "POLICY_ESCALATED", "APPROVAL_VIEWED",
            "APPROVAL_SIGNOFF_RECORDED", "APPROVAL_APPROVED",
            "APPROVAL_DUAL_CONTROL_SATISFIED", "APPROVAL_CONSUMED",
            "AUTHORIZATION_REEVALUATED", "POLICY_HUMAN_APPROVAL_REQUIRED",
            "AEM_ALLOWED", "TOOL_EXECUTED",
        ):
            assert required in types, f"{required} missing from {sorted(types)}"

        escalation = next(e for e in events if e["event_type"] == "POLICY_ESCALATED")
        assert escalation["metadata"]["required_approvals"] == 2
        assert escalation["metadata"]["tier"] == "DUAL_CONTROL"
        assert escalation["metadata"]["amount_inr"] == 20_000_000

        signoffs = [e for e in events
                    if e["event_type"] == "APPROVAL_SIGNOFF_RECORDED"]
        assert len(signoffs) == 2
        assert {e["metadata"]["approver_username"] for e in signoffs} == {
            "loan.officer", "loan.officer.2"}

        # Correlated end to end by ONE request id.
        correlated = [e for e in events if e["request_id"] == request_id]
        assert len(correlated) >= 8

    async def test_the_duplicate_approver_attempt_is_recorded_as_its_own_event(
        self, client, attempt, human_post, loan_officer_token
    ):
        _, approval_id, _ = await attempt(DUAL)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})

        events = (await client.get("/api/v1/audit?limit=500")).json()
        denied = [e for e in events
                  if e["event_type"] == "CONTROL_PLANE_DENIED"
                  and e["reason"] == "APPROVER_ALREADY_SIGNED"]
        assert denied, "the two-person violation must be visible in the trail"

    async def test_no_secret_appears_in_the_audit_trail(
        self, client, attempt, human_post, loan_officer_token
    ):
        _, approval_id, _ = await attempt(SINGLE)
        await human_post(f"/api/v1/hitl/approvals/{approval_id}/decide",
                         loan_officer_token, {"decision": "APPROVED"})
        raw = (await client.get("/api/v1/audit?limit=500")).text
        assert loan_officer_token not in raw
        assert "PRIVATE KEY" not in raw.upper()
