"""JIT policy: issuance bounds, eligibility, and failing closed.

These tests drive the REAL OPA with the REAL Rego. Where fail-closed behaviour
is asserted, the configuration document is genuinely removed from the running
engine and put back afterwards -- a mock would prove the mock.

The single most important test in this file is
`test_an_escalated_action_cannot_be_mandated`: it is the structural reason a
mandate cannot be used to get around a human approval.
"""
from __future__ import annotations

import pytest

from app.authorization.opa import OPAClient
from app.core.config import get_settings

pytestmark = pytest.mark.integration

JIT_DATA_PATH = "agentic_iam/config/jit"


async def decide(opa_client, **overrides):
    """Evaluate the JIT issuance package with sensible defaults."""
    document = {
        "request_id": "authz-test",
        "decision": {"decision": "ALLOW", "reason": "VALID_CREDENTIAL_AND_POLICY_MATCH"},
        "requested": {
            "action": "read",
            "resource_type": "credit_records",
            "resource_ids": ["customer-007"],
            "ttl_seconds": 300,
            "max_uses": 3,
        },
        "pip": {"approval": {"valid": False}},
    }
    for key, value in overrides.items():
        if key in ("decision", "requested", "pip"):
            document[key] = {**document[key], **value} if isinstance(value, dict) else value
        else:
            document[key] = value
    result = await opa_client.evaluate(
        document, decision_url=get_settings().jit_decision_url
    )
    return result.document


@pytest.fixture
def jit_opa(opa_client, jit_policy_loaded):
    """An OPA client with the JIT configuration guaranteed present."""
    return opa_client


# ===========================================================================
#  The happy path
# ===========================================================================
class TestIssuancePermitted:
    async def test_an_eligible_action_within_bounds_is_permitted(self, jit_opa):
        document = await decide(jit_opa)
        assert document["decision"] == "ALLOW"
        assert document["reason"] == "JIT_ISSUANCE_PERMITTED"

    async def test_the_granted_bounds_are_echoed_by_policy(self, jit_opa):
        """The AEM signs what POLICY approved, not what the caller asked for."""
        document = await decide(jit_opa, requested={"ttl_seconds": 120, "max_uses": 2})
        assert document["granted_ttl_seconds"] == 120
        assert document["granted_max_uses"] == 2

    async def test_the_amount_ceiling_comes_from_configuration(self, jit_opa):
        document = await decide(jit_opa)
        assert document["max_amount_inr"] == 1_000_000

    async def test_the_ttl_ceiling_itself_is_permitted(self, jit_opa):
        """`>` not `>=`: asking for exactly the maximum is allowed."""
        document = await decide(jit_opa, requested={"ttl_seconds": 900})
        assert document["decision"] == "ALLOW"

    async def test_the_use_ceiling_itself_is_permitted(self, jit_opa):
        document = await decide(jit_opa, requested={"max_uses": 5})
        assert document["decision"] == "ALLOW"

    async def test_a_type_scoped_mandate_is_permitted_by_this_configuration(
        self, jit_opa
    ):
        """`require_explicit_resource_ids` is false for the shipped action."""
        document = await decide(jit_opa, requested={"resource_ids": []})
        assert document["decision"] == "ALLOW"


# ===========================================================================
#  THE HITL BOUNDARY -- the most important tests in this file
# ===========================================================================
class TestHITLBoundary:
    async def test_an_escalated_action_cannot_be_mandated(self, jit_opa):
        """A mandate is not a human, and policy asking for one is not satisfied
        by asking for a grant instead.

        This is the structural reason JIT cannot bypass HITL: issuance runs the
        full data-plane evaluation first, and anything short of a clean ALLOW
        refuses the mandate.
        """
        document = await decide(jit_opa, decision={
            "decision": "HUMAN_APPROVAL_REQUIRED",
            "reason": "SENSITIVE_ACTION_REQUIRES_HUMAN",
        })
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_SCOPE_EXCEEDS_DECISION"
        assert "cannot substitute" in document["detail"]

    async def test_a_dual_control_escalation_cannot_be_mandated(self, jit_opa):
        """One officer's approval must never cover a burst of loans."""
        document = await decide(jit_opa, decision={
            "decision": "HUMAN_APPROVAL_REQUIRED",
            "reason": "DUAL_APPROVAL_REQUIRED",
        })
        assert document["decision"] == "DENY"
        assert document["escalation_reason"] == "DUAL_APPROVAL_REQUIRED"

    async def test_approve_loan_is_excluded_from_jit_entirely(self, jit_opa):
        """Belt and braces: excluded by NAME as well as by omission.

        Two independent reasons to refuse, because this is the interaction that
        would quietly undo maker-checker.
        """
        document = await decide(jit_opa, decision={"decision": "ALLOW"}, requested={
            "action": "approve_loan", "resource_type": "loan_applications",
            "resource_ids": ["loan-7842"],
        }, pip={"approval": {"valid": True}})
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_ACTION_NOT_ELIGIBLE"

    async def test_disburse_funds_is_excluded(self, jit_opa):
        document = await decide(jit_opa, requested={
            "action": "disburse_funds", "resource_type": "loan_applications",
        })
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_ACTION_NOT_ELIGIBLE"

    async def test_override_decision_is_excluded(self, jit_opa):
        document = await decide(jit_opa, requested={
            "action": "override_decision", "resource_type": "loan_applications",
        })
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_ACTION_NOT_ELIGIBLE"


class TestLoanReadEligibility:
    """Reading a loan is mandatable; deciding one is not.

    This pair is the whole of T-2 expressed in configuration: the amount-bearing
    action that carries the mandate ceiling is a READ, and every action that
    represents a human decision stays excluded.
    """

    async def test_reading_a_loan_application_is_eligible(self, jit_opa):
        document = await decide(jit_opa, requested={
            "action": "read", "resource_type": "loan_applications",
            "resource_ids": ["loan-2201"],
        })
        assert document["decision"] == "ALLOW"

    async def test_reading_a_loan_carries_the_amount_ceiling(self, jit_opa):
        """The ceiling comes from configuration, never from the request."""
        document = await decide(jit_opa, requested={
            "action": "read", "resource_type": "loan_applications",
            "resource_ids": ["loan-2201"],
        })
        assert document["max_amount_inr"] == 1_000_000

    async def test_being_able_to_READ_loans_does_not_make_APPROVING_eligible(
        self, jit_opa
    ):
        """The T-2 boundary, asserted where it would most plausibly erode.

        Adding `loan_applications` to the read allow-list must not leak into the
        approval action. An agent holding a mandate to read loans up to a
        ceiling still cannot obtain one to approve any loan, at any amount.
        """
        document = await decide(jit_opa, decision={"decision": "ALLOW"}, requested={
            "action": "approve_loan", "resource_type": "loan_applications",
            "resource_ids": ["loan-2201"],
        }, pip={"approval": {"valid": True}})
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_ACTION_NOT_ELIGIBLE"


class TestDualControlCannotBeMandated:
    """The policy-level proof required by decision T-2.

    Three independent refusals, so removing any one of them still leaves dual
    control intact. That redundancy is deliberate: this is the interaction that
    would quietly undo maker-checker, and a single guard would be a single point
    of erosion.
    """

    async def test_guard_one_a_dual_control_verdict_refuses_issuance(self, jit_opa):
        """Even if the action were eligible, the escalation refuses."""
        document = await decide(jit_opa, decision={
            "decision": "HUMAN_APPROVAL_REQUIRED",
            "reason": "DUAL_APPROVAL_REQUIRED",
        })
        assert document["decision"] == "DENY"
        assert document["escalation_reason"] == "DUAL_APPROVAL_REQUIRED"

    async def test_guard_two_the_action_is_not_on_the_allow_list(self, jit_opa):
        """Even with a clean ALLOW, approve_loan is not eligible."""
        document = await decide(jit_opa, decision={"decision": "ALLOW"}, requested={
            "action": "approve_loan", "resource_type": "loan_applications",
            "resource_ids": ["loan-9001"],
        })
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_ACTION_NOT_ELIGIBLE"

    async def test_guard_three_the_action_is_excluded_by_name(self):
        """And it is named in `excluded_actions`, not merely omitted.

        Omission is a decision nobody wrote down. Naming it is one a reviewer
        can find, and it carries the reasoning with it.
        """
        import json
        import pathlib

        config = json.loads(pathlib.Path(
            get_settings().resolved_policy_dir / "data" / "jit_policy.json"
        ).read_text())
        excluded = config["excluded_actions"]["actions"]
        assert "approve_loan" in excluded
        assert "disburse_funds" in excluded
        assert "override_decision" in excluded
        # The reasoning is recorded where the next operator will look.
        assert any("maker-checker" in line
                   for line in config["excluded_actions"]["_comment"])

    async def test_a_dual_control_amount_is_not_mandatable_at_any_ttl(self, jit_opa):
        """Shrinking the window does not make it acceptable."""
        for ttl in (1, 60, 900):
            document = await decide(jit_opa, decision={
                "decision": "HUMAN_APPROVAL_REQUIRED",
                "reason": "DUAL_APPROVAL_REQUIRED",
            }, requested={"ttl_seconds": ttl, "max_uses": 1})
            assert document["decision"] == "DENY", ttl


# ===========================================================================
#  Bounds
# ===========================================================================
class TestBounds:
    async def test_an_excessive_ttl_is_refused(self, jit_opa):
        """Matrix item R."""
        document = await decide(jit_opa, requested={"ttl_seconds": 99_999})
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_TTL_EXCEEDS_POLICY_MAXIMUM"
        assert document["max_ttl_seconds"] == 900

    async def test_an_excessive_budget_is_refused(self, jit_opa):
        document = await decide(jit_opa, requested={"max_uses": 999})
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_USES_EXCEED_POLICY_MAXIMUM"
        assert document["max_uses"] == 5

    async def test_a_zero_ttl_is_malformed(self, jit_opa):
        document = await decide(jit_opa, requested={"ttl_seconds": 0})
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_MALFORMED_REQUEST"

    async def test_a_zero_budget_is_malformed(self, jit_opa):
        document = await decide(jit_opa, requested={"max_uses": 0})
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_MALFORMED_REQUEST"


# ===========================================================================
#  Eligibility
# ===========================================================================
class TestEligibility:
    async def test_an_ineligible_resource_type_is_refused(self, jit_opa):
        """payroll_records is a real resource, and not JIT-eligible."""
        document = await decide(jit_opa, requested={"resource_type": "payroll_records"})
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_ACTION_NOT_ELIGIBLE"

    async def test_an_unknown_action_is_refused(self, jit_opa):
        """An ALLOW-LIST: an action nobody analysed for reuse is not eligible."""
        document = await decide(jit_opa, requested={"action": "exfiltrate"})
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_ACTION_NOT_ELIGIBLE"

    async def test_a_denied_action_cannot_be_mandated(self, jit_opa):
        """Matrix item P/S: the mandate is refused for the SAME reason.

        A caller is not told "JIT denied" when what actually happened is that
        it may not perform the action at all.
        """
        document = await decide(jit_opa, decision={
            "decision": "DENY", "reason": "CREDENTIAL_REVOKED",
        })
        assert document["decision"] == "DENY"
        assert document["reason"] == "JIT_SCOPE_EXCEEDS_DECISION"
        assert document["detail"] == "CREDENTIAL_REVOKED"

    async def test_a_resource_scope_denial_cannot_be_mandated(self, jit_opa):
        document = await decide(jit_opa, decision={
            "decision": "DENY", "reason": "RESOURCE_NOT_ALLOWED",
        })
        assert document["decision"] == "DENY"
        assert document["detail"] == "RESOURCE_NOT_ALLOWED"


# ===========================================================================
#  Fail closed -- the configuration genuinely removed
# ===========================================================================
class TestFailsClosed:
    async def test_removing_the_configuration_denies_every_issuance(self, jit_opa):
        """An unconfigured maximum TTL is NEVER 'unlimited'.

        The single most dangerous way for a configuration document to go
        missing. This removes it from the RUNNING engine and restores it, so
        what is asserted is the engine's behaviour rather than a mock's.
        """
        client = OPAClient(get_settings())
        try:
            saved = await client.get_data(JIT_DATA_PATH)
            await client.delete_data(JIT_DATA_PATH)
            try:
                document = await decide(client)
                assert document["decision"] == "DENY"
                assert document["reason"] == "JIT_POLICY_UNCONFIGURED"
            finally:
                await client.put_data(JIT_DATA_PATH, saved)
            # And it works again once restored -- so the test cannot pass by
            # having broken the engine for everything that follows.
            restored = await decide(client)
            assert restored["decision"] == "ALLOW"
        finally:
            await client.aclose()

    async def test_the_default_decision_is_deny(self, jit_opa):
        """Default-deny, like every other combining algorithm here."""
        import pathlib

        source = pathlib.Path(
            get_settings().resolved_policy_dir / "jit" / "issuance.rego"
        ).read_text()
        assert 'default decision := {' in source
        head = source[source.index("default decision := {"):]
        assert '"decision": "DENY"' in head[:200]


# ===========================================================================
#  No policy logic in Python
# ===========================================================================
class TestPolicyLivesInRego:
    def test_no_ttl_threshold_literal_appears_in_the_jit_package(self):
        """The ceilings are configuration, and the rules are Rego.

        A number in Python would be a second opinion that could disagree with
        the reviewed one -- and Python would win, silently.
        """
        import pathlib

        import app.jit as jit_package

        root = pathlib.Path(jit_package.__file__).parent
        for path in root.glob("*.py"):
            source = path.read_text()
            for literal in ("900", "300 ", "max_ttl_seconds =", "jit_eligible_actions"):
                assert literal not in source, f"{path.name} contains {literal!r}"

    def test_no_eligibility_list_appears_in_python(self):
        import pathlib

        import app.jit as jit_package

        root = pathlib.Path(jit_package.__file__).parent
        for path in root.glob("*.py"):
            source = path.read_text()
            assert "approve_loan" not in source or "presentation" in path.name, (
                f"{path.name} names a specific action; eligibility belongs in Rego"
            )

    def test_the_rego_contains_no_numeric_threshold(self):
        """`policies/jit/issuance.rego` reads every bound from data."""
        import pathlib
        import re

        source = pathlib.Path(
            get_settings().resolved_policy_dir / "jit" / "issuance.rego"
        ).read_text()
        rules = "\n".join(
            line for line in source.splitlines() if not line.strip().startswith("#")
        )
        # The only digits permitted are the policy version and rego.v1.
        stripped = rules.replace("v1", "").replace("rego.v1", "")
        assert not re.search(r"\b\d{2,}\b", stripped), (
            "a numeric threshold appears in the rules; it belongs in "
            "policies/data/jit_policy.json"
        )
