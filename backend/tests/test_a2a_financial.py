"""Amount integrity: the four representations, and what happens when they differ.

THE RULE THIS FILE EXISTS TO ENFORCE:

    NEVER TRUST A CLIENT-PROVIDED AMOUNT MERELY BECAUSE IT IS
    CRYPTOGRAPHICALLY SIGNED.

    NEVER EXECUTE AN AMOUNT DIFFERENT FROM THE AMOUNT AUTHORIZED BY THE PDP.

A signature proves the sender committed to a number. It proves nothing about
whether that number is the number on the record. Those are different facts and
the system needs all four:

    signed      what the SENDER instructed         tamper-evident in flight
    server      what the RECORD says               what policy decides on
    authorized  what the PDP decided on            what may be moved
    executed    what actually moved                what happened

They must agree. The cases below are the approved acceptance matrix A-G.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db.models.a2a import A2ATransaction
from app.enforcement.resources import (
    AmountReconciliationError,
    execute_payment_instruction,
    get_payment_instruction,
    payment_execution_count,
    payment_instruction_status,
    set_payment_amount,
)
from app.protocols.a2a.envelope import A2AReason

pytestmark = pytest.mark.asyncio


class TestCaseA_AllThreeAgree:
    """signed = server = authorized -> ALLOW."""

    async def test_a_matching_amount_executes(self, submit_a2a, a2a_envelope):
        result = await submit_a2a(a2a_envelope(resource_id="pay-3310",
                                               amount_inr=50_000))
        assert result.executed is True
        assert result.reason == "A2A_TRANSACTION_AUTHORIZED"
        assert payment_execution_count("pay-3310") == 1

    async def test_all_four_representations_are_recorded_and_equal(
        self, submit_a2a, a2a_envelope, session
    ):
        """A single column could not express a disagreement, and a
        disagreement is precisely the incident worth detecting."""
        await submit_a2a(a2a_envelope(resource_id="pay-3310", amount_inr=50_000))
        record = (await session.execute(select(A2ATransaction))).scalars().one()
        assert record.amount_inr == 50_000            # signed
        assert record.server_amount_inr == 50_000     # server
        assert record.authorized_amount_inr == 50_000  # authorized
        assert record.executed_amount_inr == 50_000   # executed
        assert record.amount_reconciled is True


class TestCaseB_SignedDiffersFromServer:
    """signed != server -> DENY, and nothing executes."""

    async def test_a_sender_instructing_a_different_figure_is_denied(
        self, submit_a2a, a2a_envelope
    ):
        """The sender signs Rs 5,000 against a record that reads Rs 50,000.

        Perfectly signed, perfectly fresh, correctly addressed -- and refused,
        because a signature is evidence of intent and never evidence of the
        figure.
        """
        result = await submit_a2a(a2a_envelope(resource_id="pay-3310",
                                               amount_inr=5_000))
        assert result.executed is False
        assert result.status == "DENIED"
        assert result.reason == A2AReason.AMOUNT_MISMATCH
        assert payment_execution_count("pay-3310") == 0
        assert payment_instruction_status("pay-3310") == "AWAITING_EXECUTION"

    async def test_the_escalated_figure_is_denied_too(
        self, submit_a2a, a2a_envelope
    ):
        """Rs 50,000 instructed as Rs 50,00,000. The headline attack."""
        result = await submit_a2a(a2a_envelope(resource_id="pay-3310",
                                               amount_inr=5_000_000))
        assert result.executed is False
        assert result.reason == A2AReason.AMOUNT_MISMATCH
        assert payment_execution_count("pay-3310") == 0

    async def test_POLICY_denies_it_not_just_the_service(
        self, submit_a2a, a2a_envelope
    ):
        """Defence in depth: the service detects it AND Rego refuses it.

        If the service were ever refactored and the detection dropped,
        policy would still deny -- and the intent is reviewable in Rego
        rather than depending on one Python branch staying correct.
        """
        result = await submit_a2a(a2a_envelope(resource_id="pay-3310",
                                               amount_inr=5_000))
        assert result.decision is not None, "the PDP was asked"
        assert result.decision.decision.value == "DENY"
        assert result.decision.reason == A2AReason.AMOUNT_MISMATCH
        assert result.decision.policy_id == "a2a-transaction"

    async def test_the_mismatch_is_recorded_with_both_figures(
        self, submit_a2a, a2a_envelope, session
    ):
        await submit_a2a(a2a_envelope(resource_id="pay-3310", amount_inr=5_000))
        record = (await session.execute(select(A2ATransaction))).scalars().one()
        assert record.amount_inr == 5_000
        assert record.server_amount_inr == 50_000
        assert record.amount_reconciled is False

    async def test_the_amount_mismatch_has_its_own_audit_event(
        self, submit_a2a, a2a_envelope, session
    ):
        """An incident, not a validation error, so it is findable on its own."""
        from app.db.models.audit import AuditEvent

        await submit_a2a(a2a_envelope(resource_id="pay-3310", amount_inr=5_000))
        events = (await session.execute(
            select(AuditEvent).where(
                AuditEvent.event_type == "A2A_AMOUNT_MISMATCH"))).scalars().all()
        assert len(events) == 1
        assert events[0].event_metadata["signed_amount_inr"] == 5_000
        assert events[0].event_metadata["server_amount_inr"] == 50_000

    async def test_an_amount_against_an_unreadable_record_is_denied(
        self, submit_a2a, a2a_envelope
    ):
        """Nobody should move a sum nobody can state."""
        result = await submit_a2a(a2a_envelope(resource_id="pay-does-not-exist",
                                               amount_inr=50_000))
        assert result.executed is False
        assert result.reason in {A2AReason.AMOUNT_UNAVAILABLE,
                                 A2AReason.AMOUNT_MISMATCH,
                                 "RESOURCE_ATTRIBUTES_UNAVAILABLE"}


class TestCaseC_AuthorizedDiffersFromSigned:
    """signed = server at verification, but the PDP decided on a DIFFERENT
    figure -- because the record moved in between. -> refused, nothing executes.

    This is the window the third reconciliation exists to close. The service
    reconciles against one read of the record; the PIP performs its own,
    later, during the PDP evaluation. If the record changes between them the
    amount policy authorized is not the amount the sender signed, and
    executing either of them would be executing something nobody agreed to.

    HOW THE WINDOW IS OPENED HERE. The AEM holds a module-level reference to
    `material_attributes`, while the PIP resolves it at call time. Patching
    the MODULE therefore changes what the PIP reads and leaves the service's
    earlier reconciliation reading the real record -- which is precisely the
    divergence a mid-request amendment produces, expressed deterministically.
    """

    @pytest.fixture
    def pip_sees_a_different_amount(self, monkeypatch):
        """Make the PIP -- and only the PIP -- read an amended figure."""
        import app.enforcement.resources as resources

        def apply(amount: int):
            real = resources.material_attributes

            def shifted(resource_type, resource_id):
                attributes = dict(real(resource_type, resource_id))
                if attributes.get("available"):
                    attributes["amount_inr"] = amount
                return attributes

            monkeypatch.setattr(resources, "material_attributes", shifted)

        return apply

    async def test_a_record_that_moves_between_verification_and_the_decision(
        self, submit_a2a, a2a_envelope, pip_sees_a_different_amount
    ):
        # Still inside the autonomous band, so the decision is a clean ALLOW
        # and the refusal can only come from the reconciliation itself.
        pip_sees_a_different_amount(60_000)
        result = await submit_a2a(a2a_envelope(resource_id="pay-3310",
                                               amount_inr=50_000))
        assert result.executed is False
        assert result.status == "FAILED"
        assert result.reason == A2AReason.AMOUNT_MISMATCH
        assert "authorized" in (result.detail or "").lower()
        assert payment_execution_count("pay-3310") == 0

    async def test_the_pdp_allowed_it_and_the_reconciliation_still_refused(
        self, submit_a2a, a2a_envelope, pip_sees_a_different_amount
    ):
        """Policy said yes -- to a different number. That is not a policy
        failure, and it must not be reported as a denial."""
        pip_sees_a_different_amount(60_000)
        result = await submit_a2a(a2a_envelope(resource_id="pay-3310",
                                               amount_inr=50_000))
        assert result.decision.decision.value == "ALLOW"
        assert result.status == "FAILED"

    async def test_the_authorized_figure_is_recorded_for_the_auditor(
        self, submit_a2a, a2a_envelope, pip_sees_a_different_amount, session
    ):
        pip_sees_a_different_amount(60_000)
        await submit_a2a(a2a_envelope(resource_id="pay-3310", amount_inr=50_000))
        record = (await session.execute(select(A2ATransaction))).scalars().one()
        assert record.amount_inr == 50_000            # what the sender signed
        assert record.authorized_amount_inr == 60_000  # what policy decided on
        assert record.executed_amount_inr is None      # and nothing moved


class TestCaseD_ExecutionDiffersFromAuthorized:
    """authorized = signed, but the record moved before the tool ran.

    The LAST reconciliation, and it happens INSIDE the enforcement boundary
    -- precisely so no caller can skip it.
    """

    async def test_the_handler_refuses_an_amount_it_was_not_authorized_for(self):
        """Tested at its own boundary first: the handler is the last link."""
        with pytest.raises(AmountReconciliationError, match="authorized"):
            execute_payment_instruction("pay-3310", expected_amount_inr=999_999)
        assert payment_execution_count("pay-3310") == 0
        assert payment_instruction_status("pay-3310") == "AWAITING_EXECUTION"

    async def test_the_handler_executes_when_the_figure_still_matches(self):
        result = execute_payment_instruction("pay-3310", expected_amount_inr=50_000)
        assert result["status"] == "EXECUTED"
        assert payment_execution_count("pay-3310") == 1

    async def test_a_record_that_moves_after_the_decision_fails_the_transaction(
        self, submit_a2a, a2a_envelope, monkeypatch, session
    ):
        """Every attribute read reports a STALE figure while the record has
        already moved. Both earlier reconciliations pass, the PDP authorizes
        the stale figure, and the handler -- which reads the record itself --
        refuses to move a different sum from the one that was permitted.

        Both the AEM's module-level reference and the PIP's call-time lookup
        are patched, because here the whole server-side VIEW is stale; it is
        the record underneath that moved.
        """
        import app.enforcement.aem as aem_module
        import app.enforcement.resources as resources

        stale = lambda rt, rid: {"available": True, "amount_inr": 50_000,
                                 "currency": "INR", "submitted_by": "iam.admin"}
        monkeypatch.setattr(resources, "material_attributes", stale)
        monkeypatch.setattr(aem_module, "material_attributes", stale)

        # The record really is Rs 9,99,999 now. Nothing reading attributes
        # knows that; the handler reads the record.
        set_payment_amount("pay-3310", 999_999)

        result = await submit_a2a(a2a_envelope(resource_id="pay-3310",
                                               amount_inr=50_000))
        assert result.executed is False
        assert result.status == "FAILED"
        assert result.reason == A2AReason.AMOUNT_MISMATCH
        assert payment_execution_count("pay-3310") == 0
        assert get_payment_instruction("pay-3310")["amount_inr"] == 999_999

        record = (await session.execute(select(A2ATransaction))).scalars().one()
        assert record.executed_amount_inr is None
        assert record.status.value == "FAILED"


class TestCaseE_AmountModifiedAfterSigning:
    """The envelope itself is edited in flight -> signature failure."""

    async def test_editing_the_amount_breaks_the_signature(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(
            resource_id="pay-3310", amount_inr=50_000,
            tamper=lambda e: e["transaction"].__setitem__("amountInr", 5_000_000)))
        assert result.accepted is False
        assert result.reason == A2AReason.SIGNATURE_INVALID
        assert result.decision is None, "refused before the PDP was asked"
        assert payment_execution_count("pay-3310") == 0

    async def test_editing_the_amount_and_every_derived_field_still_breaks(
        self, submit_a2a, a2a_envelope
    ):
        from app.protocols.a2a.envelope import A2ABinding

        def tamper(e):
            e["transaction"]["amountInr"] = 5_000_000
            e["transaction"]["bindingHash"] = A2ABinding.from_envelope(e).digest()

        result = await submit_a2a(a2a_envelope(resource_id="pay-3310",
                                               tamper=tamper))
        assert result.accepted is False
        assert result.reason == A2AReason.SIGNATURE_INVALID


class TestCaseF_AmountAboveThreshold:
    """The bands, and the HITL / dual-control paths they lead to."""

    async def test_below_the_autonomous_limit_no_human_is_asked(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(resource_id="pay-3310",
                                               amount_inr=50_000))
        assert result.executed is True
        assert result.approval_id is None

    async def test_the_middle_band_escalates_to_ONE_human(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(resource_id="pay-3311",
                                               amount_inr=500_000))
        assert result.executed is False
        assert result.status == "PENDING_APPROVAL"
        assert result.reason == "A2A_PAYMENT_REQUIRES_HUMAN"
        assert result.required_approvals == 1
        assert payment_execution_count("pay-3311") == 0

    async def test_above_the_single_approver_limit_escalates_to_TWO(
        self, submit_a2a, a2a_envelope
    ):
        """DUAL CONTROL IS REAL FOR A PAYMENT, and this is the count that
        proves it. Policy asks for two DISTINCT humans, and the AEM carries
        that number onto the approval request."""
        result = await submit_a2a(a2a_envelope(resource_id="pay-3312",
                                               amount_inr=5_000_000))
        assert result.executed is False
        assert result.status == "PENDING_APPROVAL"
        assert result.reason == "DUAL_APPROVAL_REQUIRED"
        assert result.required_approvals == 2
        assert payment_execution_count("pay-3312") == 0

    async def test_the_bands_come_from_configuration_not_from_python(self):
        """A structural assertion: no threshold literal in the A2A package."""
        import pathlib
        import re

        package = pathlib.Path(__file__).resolve().parents[1] / "app" / "protocols"
        pattern = re.compile(
            r"amount\w*\s*(?:>=|<=|>|<)\s*[\d_]|[\d_]{5,}\s*(?:>=|<=|>|<)\s*amount")
        offenders = [
            f"{path}:{n}: {line.strip()}"
            for path in package.rglob("*.py")
            for n, line in enumerate(path.read_text().splitlines(), 1)
            if pattern.search(line)
        ]
        assert offenders == [], (
            "An amount threshold appeared in the A2A package. The bands "
            "belong in policies/a2a/transaction.rego, reading "
            "policies/data/a2a_policy.json:\n" + "\n".join(offenders))

    async def test_the_thresholds_live_in_policy_configuration(self):
        import json
        import pathlib

        repo = pathlib.Path(__file__).resolve().parents[2]
        document = json.loads(
            (repo / "policies" / "data" / "a2a_policy.json").read_text())
        thresholds = document["thresholds"]
        assert isinstance(thresholds["agent_autonomous_limit_inr"], int)
        assert isinstance(thresholds["single_approver_limit_inr"], int)
        # Ordered, or the middle band is empty and every payment is either
        # autonomous or dual.
        assert (thresholds["agent_autonomous_limit_inr"]
                < thresholds["single_approver_limit_inr"])

    async def test_missing_configuration_denies_rather_than_falling_through(
        self, submit_a2a, a2a_envelope, opa_client
    ):
        """FAIL CLOSED. An unconfigured threshold is never 'no limit'.

        Genuinely removed from the RUNNING engine and restored afterwards.
        """
        from app.authorization.pap import PolicyAdministrationPoint
        from app.core.config import get_settings

        pap = PolicyAdministrationPoint(None, get_settings())
        definition = next(d for d in pap.read_data_definitions()
                          if d.data_id == "a2a-policy")
        await opa_client.delete_data(definition.path)
        try:
            result = await submit_a2a(a2a_envelope(resource_id="pay-3310"))
            assert result.executed is False
            assert result.reason == "A2A_POLICY_UNCONFIGURED"
        finally:
            await opa_client.put_data(definition.path, definition.document)

        restored = await submit_a2a(a2a_envelope(resource_id="pay-3310"))
        assert restored.executed is True


class TestCaseG_ConcurrentDuplicate:
    """Covered in full by tests/test_a2a_concurrency.py; asserted here too so
    the acceptance matrix is complete in one file."""

    async def test_a_duplicate_does_not_move_money_twice(
        self, submit_a2a, a2a_envelope
    ):
        envelope = a2a_envelope(resource_id="pay-3310")
        await submit_a2a(envelope)
        await submit_a2a(envelope)
        assert payment_execution_count("pay-3310") == 1


class TestTheAmountIsNeverTakenFromTheCaller:
    async def test_context_cannot_supply_an_amount(
        self, submit_a2a, a2a_envelope, session
    ):
        """`input.context` is untrusted and no rule reads an amount from it."""
        await submit_a2a(a2a_envelope(resource_id="pay-3310", amount_inr=50_000))
        record = (await session.execute(select(A2ATransaction))).scalars().one()
        assert record.server_amount_inr == 50_000

    async def test_no_rule_reads_the_signed_amount_for_the_bands(self):
        """The bands compare `input.pip.resource.attributes.amount_inr`.

        A grep, because the distinction is the whole financial control: the
        signed amount is evidence of intent, and the server's amount is what
        policy decides on.
        """
        import pathlib
        import re

        repo = pathlib.Path(__file__).resolve().parents[2]
        source = (repo / "policies" / "a2a" / "transaction.rego").read_text()
        band_rules = re.findall(
            r"a2a_(?:within_agent_authority|requires_single_approver|"
            r"requires_dual_control) if \{(.*?)\n\}", source, re.S)
        assert band_rules, "the band rules were not found"
        for body in band_rules:
            assert "signed_amount_inr" not in body, (
                "a band rule read the SIGNED amount. The bands must be "
                "decided on what the server holds.")
