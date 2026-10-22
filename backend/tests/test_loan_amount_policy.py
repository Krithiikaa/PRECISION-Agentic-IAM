"""Phase 5.5 -- the amount IS an authorization input.

THE GAP THIS FILE CLOSES. Phase 5 escalated `approve_loan` on the name of the
action alone, so a five-lakh loan and a two-crore loan were the same
authorization question, and a LOAN_OFFICER could approve any amount at all.

Three properties are asserted here, and each fails differently if it is wrong:

    THE AMOUNT REACHES POLICY    from server-side state, via the PIP. Not from
                                 the caller, and not from the browser that
                                 displayed it.
    POLICY DECIDES WHAT IT MEANS the bands are Rego reading configuration.
                                 There is no threshold comparison in Python,
                                 and a test below greps for one.
    IT FAILS CLOSED              thresholds absent -> DENY. An unconfigured
                                 limit must never read as "no limit".
"""
from __future__ import annotations

import pathlib
import re

import pytest

from app.authorization.contracts import Decision, Reason
from app.enforcement.resources import (
    material_attributes,
    set_loan_amount,
)

pytestmark = pytest.mark.integration

# The three §24 scenarios, by application. The AMOUNTS live in the resource
# records and the THRESHOLDS live in policy configuration, so this table names
# neither -- it names the applications and the outcome policy reaches.
AUTONOMOUS = "loan-2201"      # Rs 5,00,000
SINGLE = "loan-7842"          # Rs 25,00,000
DUAL = "loan-9001"            # Rs 2,00,00,000


@pytest.fixture
def loan_pdp(session, keystore, opa_ready):
    from app.authorization.pdp import PolicyDecisionPoint

    from app.core.config import get_settings

    return PolicyDecisionPoint(session, keystore, get_settings())


@pytest.fixture
def amount_request(risk_agent):
    from app.authorization.contracts import AuthorizationRequest, Resource, Subject

    def make(application_id, **overrides):
        params = dict(
            subject=Subject(did=overrides.pop("did", risk_agent.did)),
            action=overrides.pop("action", "approve_loan"),
            resource=Resource(type="loan_applications", id=application_id),
            purpose="loan_decision",
        )
        params.update(overrides)
        return AuthorizationRequest(**params)

    return make


class TestTheAmountReachesPolicy:
    """The PIP establishes it from the record. Nobody supplies it."""

    async def test_the_pip_reports_the_amount_from_the_resource_record(
        self, session, keystore, amount_request
    ):
        from app.authorization.pip import PolicyInformationPoint
        from app.core.config import get_settings

        context = await PolicyInformationPoint(
            session, keystore, get_settings()
        ).collect(amount_request(SINGLE))
        attributes = context.resource["attributes"]
        assert attributes["available"] is True
        assert attributes["amount_inr"] == 2_500_000
        assert attributes["currency"] == "INR"

    async def test_an_unreadable_resource_reports_unavailable_not_zero(
        self, session, keystore, amount_request
    ):
        """A defaulted amount would be a threshold decision made by a missing
        record. It is reported as absent, with a reason."""
        from app.authorization.pip import PolicyInformationPoint
        from app.core.config import get_settings

        context = await PolicyInformationPoint(
            session, keystore, get_settings()
        ).collect(amount_request("loan-does-not-exist"))
        attributes = context.resource["attributes"]
        assert attributes["available"] is False
        assert "amount_inr" not in attributes
        assert "loan-does-not-exist" in attributes["detail"]

    async def test_a_caller_supplied_amount_does_not_reach_the_decision(
        self, loan_pdp, loan_credential, amount_request
    ):
        """The whole reason the amount is read server-side.

        The agent claims a trivial amount on an application that genuinely
        needs two people. Policy reads the record, not the claim.
        """
        decision = await loan_pdp.decide(amount_request(
            DUAL, context={"amount_inr": 1, "amount": 1, "loan_amount": 1},
        ))
        assert decision.decision is Decision.HUMAN_APPROVAL_REQUIRED
        assert decision.reason == Reason.DUAL_APPROVAL_REQUIRED


class TestTheBands:
    """Three amounts, three outcomes, one action and one credential."""

    async def test_below_the_autonomous_limit_the_agent_decides(
        self, loan_pdp, loan_credential, amount_request
    ):
        """§24 scenario A. The amount removes the HUMAN, not the
        authorization: the credential is still required and still checked."""
        decision = await loan_pdp.decide(amount_request(AUTONOMOUS))
        assert decision.decision is Decision.ALLOW
        assert decision.reason == Reason.WITHIN_AGENT_APPROVAL_AUTHORITY
        assert decision.policy_id == "loan-amount"

    async def test_the_middle_band_needs_one_human(
        self, loan_pdp, loan_credential, amount_request
    ):
        """§24 scenario B."""
        decision = await loan_pdp.decide(amount_request(SINGLE))
        assert decision.decision is Decision.HUMAN_APPROVAL_REQUIRED
        assert decision.reason == Reason.SENSITIVE_ACTION_REQUIRES_HUMAN
        assert decision.evaluation["opa_document"]["required_approvals"] == 1

    async def test_above_the_single_approver_limit_needs_two_humans(
        self, loan_pdp, loan_credential, amount_request
    ):
        """§24 scenario C."""
        decision = await loan_pdp.decide(amount_request(DUAL))
        assert decision.decision is Decision.HUMAN_APPROVAL_REQUIRED
        assert decision.reason == Reason.DUAL_APPROVAL_REQUIRED
        assert decision.policy_id == "loan-amount"
        assert decision.evaluation["opa_document"]["required_approvals"] == 2

    async def test_the_autonomous_band_still_requires_the_credential(
        self, loan_pdp, risk_agent, amount_request
    ):
        """No credential, small amount. Still denied.

        The amount band decides whether a PERSON is needed. It never decides
        whether the agent was entitled to act at all.
        """
        decision = await loan_pdp.decide(amount_request(AUTONOMOUS))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.MISSING_CAPABILITY

    async def test_the_autonomous_band_still_requires_the_right_purpose(
        self, loan_pdp, loan_credential, amount_request
    ):
        decision = await loan_pdp.decide(
            amount_request(AUTONOMOUS, purpose="marketing_analysis"))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.PURPOSE_NOT_ALLOWED


class TestFailingClosed:
    async def test_an_unreadable_amount_denies(
        self, loan_pdp, loan_credential, amount_request
    ):
        """Nobody should be asked to approve a figure nobody can state, and no
        agent should proceed on one."""
        decision = await loan_pdp.decide(amount_request("loan-does-not-exist"))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.RESOURCE_ATTRIBUTES_UNAVAILABLE

    async def test_missing_thresholds_deny_rather_than_permitting(
        self, loan_pdp, loan_credential, amount_request, opa_client
    ):
        """THE MOST DANGEROUS WAY FOR A CONFIG DOCUMENT TO GO MISSING.

        An absent threshold must never read as "no limit". The document is
        genuinely removed from the running engine here, and restored afterwards
        -- asserting it from a stubbed client would prove only that Python
        agrees with Python.
        """
        from app.authorization.pap import PolicyAdministrationPoint
        from app.core.config import get_settings

        pap = PolicyAdministrationPoint(loan_pdp.session, get_settings(), opa_client)
        definition = next(
            d for d in pap.read_data_definitions() if d.data_id == "loan-amount-policy"
        )
        await opa_client.delete_data(definition.path)
        try:
            decision = await loan_pdp.decide(amount_request(AUTONOMOUS))
            assert decision.decision is Decision.DENY
            assert decision.reason == Reason.LOAN_POLICY_UNCONFIGURED
        finally:
            await opa_client.put_data(definition.path, definition.document)

        # And the engine is back to deciding normally.
        restored = await loan_pdp.decide(amount_request(AUTONOMOUS))
        assert restored.decision is Decision.ALLOW


class TestTheThresholdIsNotInPython:
    """§22. The material risk decision belongs in Rego, and stays there."""

    def test_no_amount_threshold_comparison_exists_in_the_application(self):
        """Greps the application for `amount > <number>` and friends.

        A structural assertion rather than a stylistic one: the moment a
        threshold appears in Python there are two answers to "is this a large
        loan?", they can disagree, and the Python one wins silently.
        """
        app_dir = pathlib.Path(__file__).resolve().parents[1] / "app"
        pattern = re.compile(
            r"amount\w*\s*(?:>=|<=|>|<)\s*[\d_]|"
            r"[\d_]{5,}\s*(?:>=|<=|>|<)\s*amount"
        )
        offenders = [
            f"{path.relative_to(app_dir)}:{n}: {line.strip()}"
            for path in app_dir.rglob("*.py")
            for n, line in enumerate(path.read_text().splitlines(), 1)
            if pattern.search(line)
        ]
        assert offenders == [], (
            "An amount threshold comparison appeared in Python. The amount "
            "policy belongs in policies/loan/amount.rego, reading thresholds "
            "from policies/data/loan_amount_policy.json:\n" + "\n".join(offenders)
        )

    def test_the_thresholds_live_in_policy_configuration(self):
        import json

        repo = pathlib.Path(__file__).resolve().parents[2]
        document = json.loads(
            (repo / "policies" / "data" / "loan_amount_policy.json").read_text()
        )
        thresholds = document["thresholds"]
        assert isinstance(thresholds["agent_autonomous_limit_inr"], int)
        assert isinstance(thresholds["single_approver_limit_inr"], int)
        # The bands must be ordered, or the middle band is empty and every loan
        # is either autonomous or dual.
        assert (thresholds["agent_autonomous_limit_inr"]
                < thresholds["single_approver_limit_inr"])

    def test_the_manifest_declares_the_configuration_and_its_failure_mode(self):
        import json

        repo = pathlib.Path(__file__).resolve().parents[2]
        manifest = json.loads((repo / "policies" / "manifest.json").read_text())
        entry = next(d for d in manifest["data"] if d["data_id"] == "loan-amount-policy")
        assert entry["path"] == "agentic_iam/config/loan"
        assert entry["status"] == "ACTIVE"
        # What happens when it is missing is recorded, not left to be
        # discovered during an incident.
        assert "LOAN_POLICY_UNCONFIGURED" in entry["fails_closed"]


class TestTheAmountIsBound:
    """§3, §4. The approval means the amount the person was shown."""

    async def test_the_binding_covers_the_amount(self, amount_request):
        from app.hitl.artifact import ApprovalBinding

        request = amount_request(SINGLE)
        binding = ApprovalBinding.from_request(request)
        assert binding.amount_inr == 2_500_000
        assert binding.currency == "INR"

        before = binding.digest()
        set_loan_amount(SINGLE, 25_000_000)
        after = ApprovalBinding.from_request(request).digest()
        assert after != before

    async def test_the_binding_names_the_field_that_moved(self, amount_request):
        from app.hitl.artifact import ApprovalBinding

        request = amount_request(SINGLE)
        before = ApprovalBinding.from_request(request)
        set_loan_amount(SINGLE, 25_000_000)
        after = ApprovalBinding.from_request(request)
        assert before.differences(after) == ["amount_inr"]

    def test_the_verifier_compares_every_bound_field(self):
        """The verifier's field list is derived from the binding itself.

        A hand-written list here would silently stop comparing any material
        attribute added later -- which is the exact failure the binding exists
        to prevent, reintroduced one field at a time.
        """
        import dataclasses

        from app.hitl.artifact import _BINDING_FIELDS, ApprovalBinding

        assert tuple(
            f.name for f in dataclasses.fields(ApprovalBinding)
        ) == _BINDING_FIELDS

    def test_material_attributes_are_server_side_only(self):
        """`material_attributes` takes a type and an id. There is no parameter
        through which a caller could supply a value."""
        import inspect

        parameters = list(inspect.signature(material_attributes).parameters)
        assert parameters == ["resource_type", "resource_id"]
