"""Read authorization: the matrix, and escalation against it (Phase 10).

WHAT PHASE 9 FOUND. Ten read endpoints served an anonymous caller the audit
trail, the credential inventory, the approval queue, human identities and
loan records. Phase 10 put the existing `ControlPlaneGuard` in front of
them — the same mechanism that already protected every mutation, deciding
in Rego, accepting either a human OIDC token or a signed machine proof.

WHAT THIS FILE TESTS. Not "is there a guard" — `test_route_security_inventory.py`
does that structurally. This tests that the guard decides *correctly*:

    VERTICAL escalation    a role reaching for a domain above it
    HORIZONTAL escalation  a role reaching sideways into a peer's domain
    anonymous access       no identity at all

Least privilege is only real if someone checks that the separations bite.
The sharpest one here: **IAM_ADMIN cannot read a loan.** It administers
agent identity, and the fact that it can suspend the agent processing a
customer's file does not give it the file.
"""
from __future__ import annotations

import json
import urllib.request

import pytest

pytestmark = pytest.mark.integration

OPA = "http://localhost:8181/v1/data/agentic_iam/control_plane/decision"

READ_OPERATIONS = [
    "identity_read", "credential_read", "audit_read",
    "approval_read", "grant_read", "policy_read", "loan_read",
]

# The matrix, written out so a reviewer sees it whole. A role gaining a
# domain here is a one-line change that this file makes visible.
EXPECTED_HUMAN = {
    # Oversight that cannot see the whole system is not oversight. AUDITOR
    # reads everything and can change nothing -- every mutation denies it.
    "AUDITOR": set(READ_OPERATIONS),
    # Administers identity. NOT loans.
    "IAM_ADMIN": {"identity_read", "credential_read", "audit_read",
                  "approval_read", "grant_read", "policy_read"},
    # Decides one loan. Needs the file and the queue, and nothing else.
    "LOAN_OFFICER": {"approval_read", "loan_read"},
    # Decides one payment. A2A instructions surface through grants.
    "PAYMENT_OFFICER": {"approval_read", "grant_read"},
}

EXPECTED_ADMIN = {
    "identity_admin": {"identity_read", "credential_read", "audit_read",
                       "approval_read", "grant_read"},
    "policy_admin": {"policy_read"},
    "loan_admin": {"loan_read"},
}


def decide(principal: dict, operation: str) -> str:
    body = {"input": {
        "principal": principal, "operation": operation,
        "target": {"type": "x", "id": "y"},
        "classification": "AUTHORIZED_READ",
    }}
    request = urllib.request.Request(
        OPA, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response).get("result", {}).get("decision")


def human(*roles: str) -> dict:
    return {"type": "human", "id": "u", "username": "u", "roles": list(roles)}


def administrator(*roles: str) -> dict:
    return {"type": "administrator", "did": "did:poc:administrator:x",
            "roles": list(roles)}


@pytest.fixture(autouse=True)
def _policies(policies_loaded):
    """Every test here asks the REAL OPA. A stubbed decision would assert
    nothing about the Rego that actually runs."""
    return policies_loaded


class TestTheHumanReadMatrix:
    @pytest.mark.parametrize("role", sorted(EXPECTED_HUMAN))
    def test_a_role_reads_exactly_its_declared_domains(self, role):
        granted = {op for op in READ_OPERATIONS
                   if decide(human(role), op) == "ALLOW"}
        assert granted == EXPECTED_HUMAN[role], (
            f"{role} reads {sorted(granted)}, the matrix says "
            f"{sorted(EXPECTED_HUMAN[role])}"
        )

    def test_a_human_with_no_role_reads_nothing(self):
        for operation in READ_OPERATIONS:
            assert decide(human(), operation) == "DENY", operation

    def test_an_unknown_role_grants_nothing(self):
        """A role somebody invented in Keycloak must not become authority
        here. The matrix is an allow-list keyed on role NAME."""
        for operation in READ_OPERATIONS:
            assert decide(human("SUPERUSER"), operation) == "DENY", operation


class TestVerticalEscalation:
    """Reaching for a domain above your role."""

    def test_a_loan_officer_cannot_read_the_audit_trail(self):
        """The trail shows every decision the system made. Deciding one loan
        requires none of it."""
        assert decide(human("LOAN_OFFICER"), "audit_read") == "DENY"

    def test_a_loan_officer_cannot_read_the_credential_inventory(self):
        assert decide(human("LOAN_OFFICER"), "credential_read") == "DENY"

    def test_a_loan_officer_cannot_read_the_agent_registry(self):
        assert decide(human("LOAN_OFFICER"), "identity_read") == "DENY"

    def test_no_officer_role_can_read_the_policy_set(self):
        """Knowing which rules are live is the first half of evading them --
        in particular which amount band to stay under."""
        assert decide(human("LOAN_OFFICER"), "policy_read") == "DENY"
        assert decide(human("PAYMENT_OFFICER"), "policy_read") == "DENY"

    def test_reading_never_implies_writing(self):
        """A read role must not have acquired a mutation on the way in."""
        for operation in ("approval_decide", "credential_revoke",
                          "agent_status_change", "policy_deactivate",
                          "loan_amend", "jit_revoke"):
            assert decide(human("AUDITOR"), operation) == "DENY", operation


class TestHorizontalEscalation:
    """Reaching sideways into a peer's domain."""

    def test_the_identity_administrator_cannot_read_a_loan(self):
        """THE SHARPEST SEPARATION IN THE MATRIX.

        IAM_ADMIN administers agents. It can suspend the agent that
        processes a customer's file -- and that does not give it the file.
        """
        assert decide(human("IAM_ADMIN"), "loan_read") == "DENY"
        assert decide(administrator("identity_admin"), "loan_read") == "DENY"

    def test_the_loan_officer_cannot_read_payment_grants(self):
        assert decide(human("LOAN_OFFICER"), "grant_read") == "DENY"

    def test_the_payment_officer_cannot_read_loans(self):
        """Payment bands and loan bands are separate authorities on
        purpose."""
        assert decide(human("PAYMENT_OFFICER"), "loan_read") == "DENY"

    def test_the_policy_administrator_cannot_read_identity_or_audit(self):
        assert decide(administrator("policy_admin"), "identity_read") == "DENY"
        assert decide(administrator("policy_admin"), "audit_read") == "DENY"

    def test_the_identity_administrator_cannot_read_policy(self):
        assert decide(administrator("identity_admin"), "policy_read") == "DENY"

    @pytest.mark.parametrize("role", sorted(EXPECTED_ADMIN))
    def test_an_administrator_reads_exactly_its_declared_domains(self, role):
        granted = {op for op in READ_OPERATIONS
                   if decide(administrator(role), op) == "ALLOW"}
        assert granted == EXPECTED_ADMIN[role]

    def test_the_enforcement_gateway_reads_nothing(self):
        """The gateway drives /authorize and /enforce for any subject. If it
        could also read, one compromised automation credential would be both
        an enforcement path and a disclosure path."""
        for operation in READ_OPERATIONS:
            assert decide(administrator("enforcement"), operation) == "DENY", operation


class TestAnonymousAndMalformedPrincipals:
    def test_an_unrecognised_principal_type_reads_nothing(self):
        for operation in READ_OPERATIONS:
            assert decide({"type": "unknown", "id": "?"}, operation) == "DENY"

    def test_an_agent_cannot_read_the_administrative_surface(self):
        """An agent may ask about ITSELF (agent_self.rego). The read matrix
        is a different thing: the audit trail and the approval queue are not
        an agent's business however well it authenticates."""
        agent = {"type": "agent", "did": "did:poc:agent:risk-001", "roles": []}
        for operation in ("audit_read", "approval_read", "policy_read",
                          "loan_read", "credential_read"):
            assert decide(agent, operation) == "DENY", operation

    def test_claiming_a_role_as_an_agent_grants_nothing(self):
        """Human roles and agent capabilities are separate trust domains.
        An agent asserting `roles: [AUDITOR]` is asserting something it has
        no standing to assert.

        `identity_read` is excluded because an agent holds it ALREADY, by
        being an agent -- see the test below. The point here is that
        claiming a human role adds nothing: the impostor reaches exactly
        what an agent with no claimed roles reaches, and no more.
        """
        impostor = {"type": "agent", "did": "did:poc:agent:risk-001",
                    "roles": ["AUDITOR", "IAM_ADMIN"]}
        plain = {"type": "agent", "did": "did:poc:agent:risk-001", "roles": []}
        for operation in READ_OPERATIONS:
            assert decide(impostor, operation) == decide(plain, operation), (
                f"claiming a human role changed the answer for {operation}"
            )
        for operation in set(READ_OPERATIONS) - {"identity_read"}:
            assert decide(impostor, operation) == "DENY", operation

    def test_an_agent_may_resolve_a_peer_identity_and_nothing_more(self):
        """PHASE 10, DELIBERATE AND NARROW.

        Phase 3's discovery flow has a coordinator cross-check what ANS told
        it against the identity authority -- the check that makes an endpoint
        substitution in the directory detectable. Guarding the registry
        without this would have turned that check into a 401 and silently
        removed the control, which is worse than the disclosure it prevents.

        So an authenticated agent holds `identity_read` -- and ONLY that. It
        discloses nothing the public ANS directory and DID Documents do not
        already publish, and it replaces an ANONYMOUS read with an
        attributable one.
        """
        agent = {"type": "agent", "did": "did:poc:agent:risk-001", "roles": []}
        assert decide(agent, "identity_read") == "ALLOW"
        for operation in set(READ_OPERATIONS) - {"identity_read"}:
            assert decide(agent, operation) == "DENY", operation


class TestOverHTTP:
    """The matrix decided in Rego is the matrix enforced on the wire."""

    @pytest.mark.parametrize(
        "path",
        ["/api/v1/audit", "/api/v1/agents", "/api/v1/credentials",
         "/api/v1/hitl/approvals", "/api/v1/hitl/humans", "/api/v1/loans",
         "/api/v1/policies", "/api/v1/authorize/decisions", "/api/v1/jit",
         "/api/v1/a2a/transactions"],
    )
    async def test_anonymous_is_refused(self, client, path):
        response = await client.get(path)
        assert response.status_code in (401, 403), (
            f"{path} served an anonymous caller: the Phase 9 HIGH finding "
            f"has re-opened"
        )

    async def test_an_authorised_administrator_is_served(self, cp_get):
        assert (await cp_get("/api/v1/audit?limit=1")).status_code == 200

    async def test_the_wrong_administrator_is_refused_over_http(self, cp_get):
        """identity-authority holds identity_admin, which the matrix does NOT
        map to policy_read. The refusal must survive the trip through HTTP,
        not merely exist in Rego."""
        response = await cp_get("/api/v1/policies")
        assert response.status_code in (401, 403)

    async def test_the_right_administrator_is_served(self, policy_admin_get):
        assert (await policy_admin_get("/api/v1/policies")).status_code == 200

    async def test_a_loan_is_refused_to_the_identity_administrator(self, cp_get):
        assert (await cp_get("/api/v1/loans")).status_code in (401, 403)

    async def test_a_loan_is_served_to_the_loan_administrator(self, loan_admin_get):
        assert (await loan_admin_get("/api/v1/loans")).status_code == 200

    async def test_a_refusal_does_not_disclose_what_was_behind_it(self, client):
        """A 401 says you were refused, not what exists."""
        body = (await client.get("/api/v1/loans")).text.lower()
        for leaked in ("applicant", "amount_inr", "customer-"):
            assert leaked not in body
