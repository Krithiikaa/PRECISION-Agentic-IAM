"""HTTP surface of the authorization plane: /authorize, /enforce, /policies.

PHASE 4.5: every call in this file is now a SIGNED control-plane request. The
agent signs for itself when asking about itself; the policy administrator signs
for policy administration. That is not test scaffolding -- an unsigned request
to any of these routes is refused before the PDP is reached, which is exactly
what test_control_plane_security_matrix.py asserts.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration

BANK = "did:poc:organization:bank-demo"
CLAIMS = {
    "capability": "credit_analysis",
    "allowed_actions": ["READ_CREDIT_PROFILE"],
    "allowed_resources": ["credit_records"],
    "purpose": "loan_assessment",
}


@pytest.fixture
async def agent(client, control_plane, admin_post):
    response = await admin_post("/api/v1/agents", {
        "slug": "risk-001", "name": "Credit Risk Analysis Agent", "agent_type": "RISK",
        "capabilities": ["credit_analysis"], "endpoint": "http://localhost:9003",
    })
    assert response.status_code == 201
    return response.json()


@pytest.fixture
async def credential(client, agent, issuers, admin_post):
    response = await admin_post("/api/v1/credentials/issue", {
        "issuer": BANK, "subject": agent["did"],
        "credential_type": "AgentCapabilityCredential",
        "claims": CLAIMS, "expires_in_seconds": 3600,
    })
    assert response.status_code == 201
    return response.json()


def authorize_body(did, **overrides):
    body = {
        "subject": {"did": did},
        "action": "read",
        "resource": {"type": "credit_records", "id": "customer-007"},
        "purpose": "loan_assessment",
    }
    body.update(overrides)
    return body


class TestAuthorizeEndpoint:
    async def test_allow_over_http(self, cp_post, credential, agent, opa_ready):
        report = (await cp_post("/api/v1/authorize", agent["did"],
                                authorize_body(agent["did"]))).json()
        assert report["decision"] == "ALLOW"
        assert report["reason"] == "VALID_CREDENTIAL_AND_POLICY_MATCH"
        assert report["policy"] == "loan-credit-read:v1"

    async def test_deny_is_a_verdict_not_an_error(self, cp_post, credential, agent,
                                                  opa_ready):
        response = await cp_post("/api/v1/authorize", agent["did"], authorize_body(
            agent["did"], resource={"type": "payroll_records", "id": "customer-007"},
        ))
        assert response.status_code == 200      # an answer, not a server error
        assert response.json()["decision"] == "DENY"
        assert response.json()["reason"] == "RESOURCE_NOT_ALLOWED"

    async def test_human_approval_required_over_http(self, cp_post, credential, agent,
                                                     opa_ready):
        report = (await cp_post("/api/v1/authorize", agent["did"], authorize_body(
            agent["did"], action="approve_loan",
        ))).json()
        assert report["decision"] == "HUMAN_APPROVAL_REQUIRED"
        assert report["reason"] == "SENSITIVE_ACTION_REQUIRES_HUMAN"

    async def test_the_response_explains_itself(self, cp_post, credential, agent,
                                                opa_ready):
        report = (await cp_post("/api/v1/authorize", agent["did"],
                                authorize_body(agent["did"]))).json()
        for field in ("decision", "reason", "policy_id", "policy_version",
                      "stages", "latency_ms", "request_id", "decided_at"):
            assert field in report
        assert [s["name"] for s in report["stages"]] == ["validate", "pip", "opa"]
        assert report["latency_ms"] > 0

    async def test_malformed_request_is_rejected(self, cp_post, agent, opa_ready):
        response = await cp_post("/api/v1/authorize", agent["did"],
                                 authorize_body(agent["did"], purpose=""))
        assert response.status_code >= 400
        assert response.status_code != 200

    async def test_unknown_field_is_refused(self, cp_post, agent, opa_ready):
        response = await cp_post("/api/v1/authorize", agent["did"], {
            **authorize_body(agent["did"]), "allow": True,
        })
        assert response.status_code == 422      # extra="forbid"

    async def test_self_asserted_context_does_not_authorize(self, cp_post, agent,
                                                            opa_ready):
        """No credential + "I'm allowed" is still DENY.

        Note what the agent HAS proved here: control of its own DID. It is
        genuinely authenticated, and still denied -- authentication is not
        authorization, and neither is asserting the answer.
        """
        report = (await cp_post("/api/v1/authorize", agent["did"], authorize_body(
            agent["did"], context={"allow": True, "decision": "ALLOW"},
        ))).json()
        assert report["decision"] == "DENY"
        assert report["evaluation"]["rejected_context_keys"] == ["allow", "decision"]


class TestEnforceEndpoint:
    async def test_allowed_call_returns_the_resource(self, cp_post, credential, agent,
                                                     opa_ready):
        body = (await cp_post("/api/v1/enforce", agent["did"], {
            "subject": {"did": agent["did"]}, "tool": "get_credit_profile",
            "arguments": {"customer_id": "customer-007"}, "purpose": "loan_assessment",
        })).json()
        assert body["executed"] is True
        assert body["result"]["credit_score"] == 742
        assert body["decision"]["decision"] == "ALLOW"

    async def test_blocked_call_returns_no_resource_data(self, cp_post, credential,
                                                         agent, opa_ready):
        body = (await cp_post("/api/v1/enforce", agent["did"], {
            "subject": {"did": agent["did"]}, "tool": "get_payroll_record",
            "arguments": {"customer_id": "customer-007"}, "purpose": "loan_assessment",
        })).json()
        assert body["executed"] is False
        assert body["result"] is None
        assert body["decision"]["reason"] == "RESOURCE_NOT_ALLOWED"
        assert "annual_salary_gbp" not in str(body)

    async def test_unknown_tool_is_404(self, cp_post, agent, opa_ready):
        response = await cp_post("/api/v1/enforce", agent["did"], {
            "subject": {"did": agent["did"]}, "tool": "get_everything",
            "arguments": {}, "purpose": "loan_assessment",
        })
        assert response.status_code == 404

    async def test_protected_tools_are_listed_with_their_resource_and_action(
        self, client
    ):
        tools = (await client.get("/api/v1/enforce/tools")).json()
        names = {t["name"] for t in tools}
        # An INVENTORY, asserted exactly so a tool cannot appear behind the
        # boundary without somebody noticing. Phase 5 added the loan
        # decision, which is the one gated on a human; Phase 7 added the
        # payment execution, which is the one an A2A instruction reaches --
        # and which no caller can ever NAME, because the AEM derives it from
        # the signed (action, resource_type) pair.
        assert names == {"get_credit_profile", "get_payroll_record",
                         "approve_loan_application",
                         "execute_payment_instruction"}
        for tool in tools:
            assert tool["protected"] is True
            assert tool["resource"] and tool["action"]

        # Every (action, resource_type) pair maps to exactly ONE tool. An
        # ambiguous enforcement path is one an attacker gets to choose
        # between, and Phase 7 made that mapping load-bearing.
        pairs = [(t["action"], t["resource"]) for t in tools]
        assert len(pairs) == len(set(pairs))


class TestPolicyAdministration:
    async def test_policies_are_listed_with_lifecycle_metadata(
        self, client, session, opa_ready
    ):
        from app.authorization.pap import PolicyAdministrationPoint
        from app.core.config import get_settings

        await PolicyAdministrationPoint(session, get_settings()).load_all()
        report = (await client.get("/api/v1/policies")).json()
        assert report["engine"]["reachable"] is True
        ids = {p["policy_id"] for p in report["policies"]}
        assert {"loan-credit-read", "resource-scope", "credential-state",
                "sensitive-action"} <= ids
        for policy in report["policies"]:
            for field in ("version", "status", "owner", "scope", "in_engine"):
                assert field in policy

    async def test_reload_reports_what_was_loaded(self, cp_post, control_plane,
                                                  policy_admin_did, opa_ready):
        body = (await cp_post("/api/v1/policies/reload", policy_admin_did)).json()
        assert "loan-credit-read" in body["loaded"]

    async def test_deactivating_a_policy_removes_it_from_the_engine(
        self, cp_post, credential, agent, session, control_plane, policy_admin_did,
        opa_ready
    ):
        """Deactivation is real, and makes the system MORE restrictive."""
        from app.authorization.pap import PolicyAdministrationPoint
        from app.core.config import get_settings

        pap = PolicyAdministrationPoint(session, get_settings())
        await pap.load_all()

        allowed = (await cp_post("/api/v1/authorize", agent["did"],
                                 authorize_body(agent["did"]))).json()
        assert allowed["decision"] == "ALLOW"

        try:
            response = await cp_post("/api/v1/policies/loan-credit-read/deactivate",
                                     policy_admin_did)
            assert response.json()["status"] == "INACTIVE"

            after = (await cp_post("/api/v1/authorize", agent["did"],
                                   authorize_body(agent["did"]))).json()
            # No allow rule remains -> default deny. Never the reverse.
            assert after["decision"] == "DENY"
            assert after["reason"] == "NO_MATCHING_POLICY"
        finally:
            # Restore, so the shared OPA server is left as found.
            await cp_post("/api/v1/policies/loan-credit-read/activate", policy_admin_did)


class TestAuthorizationHealth:
    async def test_health_reports_the_engine_and_fail_closed_posture(
        self, client, opa_ready
    ):
        body = (await client.get("/api/v1/authorize/health")).json()
        assert body["phase"] == 4
        assert body["opa"]["available"] is True
        assert body["fail_closed"] is True
        assert "DENY" in body["note"]


class TestDecisionLog:
    async def test_decisions_are_queryable(self, client, cp_post, credential, agent,
                                           opa_ready):
        await cp_post("/api/v1/authorize", agent["did"], authorize_body(agent["did"]))
        await cp_post("/api/v1/authorize", agent["did"], authorize_body(
            agent["did"], resource={"type": "payroll_records", "id": "customer-007"},
        ))
        rows = (await client.get("/api/v1/authorize/decisions",
                                 params={"subject": agent["did"]})).json()
        assert len(rows) == 2
        assert {r["decision"] for r in rows} == {"ALLOW", "DENY"}
        for row in rows:
            assert row["request_id"] and row["purpose"] and row["reason"]

    async def test_decisions_can_be_filtered(self, client, cp_post, credential, agent,
                                             opa_ready):
        await cp_post("/api/v1/authorize", agent["did"], authorize_body(agent["did"]))
        await cp_post("/api/v1/authorize", agent["did"], authorize_body(
            agent["did"], resource={"type": "payroll_records"},
        ))
        denies = (await client.get("/api/v1/authorize/decisions",
                                   params={"decision": "DENY"})).json()
        assert denies and all(r["decision"] == "DENY" for r in denies)


class TestPolicyReconciliation:
    """OPA holds policy in memory. An OPA restart leaves it empty, and the
    default-deny combining algorithm then denies everything -- safe, but it does
    not recover on its own. The reconciler restores the declared set."""

    async def test_reconcile_is_a_noop_when_the_set_is_intact(self, session, opa_ready):
        from app.authorization.pap import PolicyAdministrationPoint
        from app.core.config import get_settings

        pap = PolicyAdministrationPoint(session, get_settings())
        await pap.load_all()
        outcome = await pap.reconcile()
        assert outcome["reconciled"] is False
        assert outcome["reason"] == "policy set intact"

    async def test_reconcile_restores_a_missing_module(self, session, opa_ready):
        from app.authorization.pap import PolicyAdministrationPoint
        from app.core.config import get_settings

        pap = PolicyAdministrationPoint(session, get_settings())
        await pap.load_all()

        # Simulate what an OPA restart does to one module.
        await pap.opa.delete_policy("agentic_iam/loan/credit")
        assert "agentic_iam/loan/credit" not in await pap.opa.list_policies()

        outcome = await pap.reconcile()
        assert outcome["reconciled"] is True
        assert "agentic_iam/loan/credit" in outcome["restored"]
        assert "agentic_iam/loan/credit" in await pap.opa.list_policies()

    async def test_reconcile_never_loads_an_inactive_policy(self, session, opa_ready):
        """Recovery restores the DECLARED set; it cannot relax anything."""
        from app.authorization.pap import PolicyAdministrationPoint
        from app.core.config import get_settings

        pap = PolicyAdministrationPoint(session, get_settings())
        declared = {d.module_id for d in pap.read_definitions() if d.status == "ACTIVE"}
        await pap.load_all()
        outcome = await pap.reconcile()
        assert set(outcome.get("restored", [])) <= declared
