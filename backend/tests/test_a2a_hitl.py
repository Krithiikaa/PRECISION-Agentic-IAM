"""A2A escalation through the EXISTING Phase 5/5.5 approval machinery.

PHASE 7 BUILDS NO SECOND APPROVAL MECHANISM. The same `ApprovalBinding`, the
same `ApprovalService`, the same signing authority, the same
`UNIQUE (approval_id, issuer, subject)` two-person rule, the same
maker-checker refusal. Only two things are new: a dedicated PAYMENT_OFFICER
role, and a presentation a person can actually judge a payment from.

THE NEGATIVE THAT MATTERS MOST, and the one the approval explicitly required:

    An A2A payment above the single-approver threshold CANNOT be approved by
    one PAYMENT_OFFICER.

These tests need the real Keycloak. They SKIP LOUDLY if it is not running:
a stand-in identity provider would only prove that Python agrees with Python.
"""
from __future__ import annotations

import pytest

from app.db.models.hitl import ApprovalDecision, ApprovalStatus
from app.enforcement.resources import (
    payment_execution_count,
    payment_instruction_status,
)

pytestmark = pytest.mark.asyncio


@pytest.fixture
def decide_as(session, keystore, approval_authority):
    """Record one human's sign-off, through the real approval service."""
    from app.hitl.service import ApprovalService
    from app.humans.oidc import OIDCValidator
    from app.core.config import get_settings

    async def run(approval, token, decision=ApprovalDecision.APPROVED, note=None):
        identity = OIDCValidator(get_settings()).validate(token)
        service = ApprovalService(session, keystore, get_settings())
        return await service.decide(record=approval, approver=identity,
                                    decision=decision, note=note)

    return run


@pytest.fixture
async def approval_for(session):
    from app.hitl.service import ApprovalService

    async def load(approval_id):
        return await ApprovalService(session).require(approval_id)

    return load


class TestTheMiddleBandUsesOneOfficer:
    async def test_it_escalates_and_nothing_moves(self, submit_a2a, a2a_envelope):
        result = await submit_a2a(a2a_envelope(resource_id="pay-3311",
                                               amount_inr=500_000))
        assert result.status == "PENDING_APPROVAL"
        assert result.required_approvals == 1
        assert payment_instruction_status("pay-3311") == "AWAITING_EXECUTION"

    async def test_the_approval_uses_the_existing_machinery(
        self, submit_a2a, a2a_envelope, approval_for
    ):
        """Same table, same binding, same artifact -- not a second system."""
        result = await submit_a2a(a2a_envelope(resource_id="pay-3311",
                                               amount_inr=500_000))
        approval = await approval_for(result.approval_id)
        assert approval.status is ApprovalStatus.PENDING
        assert approval.action == "execute_payment"
        assert approval.resource_type == "payment_instructions"
        assert approval.resource_id == "pay-3311"
        # The amount is IN THE BINDING, read server-side, exactly as Phase 5.5
        # puts it there for a loan.
        assert approval.binding["amount_inr"] == 500_000

    async def test_the_screen_shows_what_a_person_needs(
        self, submit_a2a, a2a_envelope, approval_for
    ):
        """An approval nobody could have understood is not an approval."""
        result = await submit_a2a(a2a_envelope(resource_id="pay-3311",
                                               amount_inr=500_000))
        presentation = (await approval_for(result.approval_id)).presentation
        assert presentation["amount_display"] == "₹5,00,000"
        assert presentation["beneficiary_ref"] == "cust-007-current"
        assert presentation["instructed_by"].endswith("risk-001")
        assert presentation["to_be_performed_by"].endswith("payments-001")
        assert presentation["required_approvals"] == 1
        assert presentation["amount_reconciled"] is True

    async def test_the_request_id_is_derived_from_the_transaction(
        self, submit_a2a, a2a_envelope, approval_for
    ):
        """DETERMINISTIC, and load-bearing: a retry must reproduce the SAME
        binding, or the human's decision could never be found."""
        result = await submit_a2a(a2a_envelope(resource_id="pay-3311",
                                               amount_inr=500_000,
                                               transaction_id="txn-stable"))
        approval = await approval_for(result.approval_id)
        assert approval.request_id == "a2a-txn-stable"

    async def test_a_retry_before_approval_still_waits(
        self, submit_a2a, a2a_envelope
    ):
        envelope = a2a_envelope(resource_id="pay-3311", amount_inr=500_000)
        await submit_a2a(envelope)
        again = await submit_a2a(envelope)
        assert again.status == "PENDING_APPROVAL"
        assert payment_execution_count("pay-3311") == 0


class TestOneOfficerReleasesTheMiddleBand:
    async def test_the_full_loop(
        self, submit_a2a, a2a_envelope, approval_for, decide_as,
        payment_officer_token, session,
    ):
        """escalate -> a human decides -> retry -> PDP RE-EVALUATION -> execute."""
        envelope = a2a_envelope(resource_id="pay-3311", amount_inr=500_000,
                                transaction_id="txn-mid")
        first = await submit_a2a(envelope)
        assert first.status == "PENDING_APPROVAL"

        approval = await approval_for(first.approval_id)
        await decide_as(approval, payment_officer_token)
        await session.flush()

        second = await submit_a2a(envelope)
        assert second.executed is True, (second.reason, second.detail)
        assert second.reason == "A2A_HUMAN_APPROVED_AND_POLICY_MATCH"
        assert payment_execution_count("pay-3311") == 1

    async def test_the_approval_is_consumed(
        self, submit_a2a, a2a_envelope, approval_for, decide_as,
        payment_officer_token, session,
    ):
        envelope = a2a_envelope(resource_id="pay-3311", amount_inr=500_000,
                                transaction_id="txn-mid")
        first = await submit_a2a(envelope)
        await decide_as(await approval_for(first.approval_id),
                        payment_officer_token)
        await session.flush()
        await submit_a2a(envelope)
        approval = await approval_for(first.approval_id)
        assert approval.status is ApprovalStatus.CONSUMED

    async def test_the_pdp_was_asked_again_with_the_approval_in_hand(
        self, submit_a2a, a2a_envelope, approval_for, decide_as,
        payment_officer_token, session,
    ):
        """A human decision is EVIDENCE POLICY WEIGHS, never an ALLOW on its
        own. This is the event that proves it."""
        from sqlalchemy import select

        from app.db.models.audit import AuditEvent

        envelope = a2a_envelope(resource_id="pay-3311", amount_inr=500_000,
                                transaction_id="txn-mid")
        first = await submit_a2a(envelope)
        await decide_as(await approval_for(first.approval_id),
                        payment_officer_token)
        await session.flush()
        await submit_a2a(envelope)

        events = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == "AUTHORIZATION_REEVALUATED"))).scalars().all()
        assert events, "the re-evaluation must be on the record"
        assert events[0].request_id == "a2a-txn-mid"

    async def test_a_rejection_stops_it(
        self, submit_a2a, a2a_envelope, approval_for, decide_as,
        payment_officer_token, session,
    ):
        envelope = a2a_envelope(resource_id="pay-3311", amount_inr=500_000,
                                transaction_id="txn-mid")
        first = await submit_a2a(envelope)
        await decide_as(await approval_for(first.approval_id),
                        payment_officer_token, decision=ApprovalDecision.REJECTED)
        await session.flush()
        second = await submit_a2a(envelope)
        assert second.executed is False
        assert payment_execution_count("pay-3311") == 0


class TestDualControlAboveTheThreshold:
    """THE NEGATIVE THE APPROVAL EXPLICITLY REQUIRED.

    Dual control on a payment is REAL, and it is real without one line of
    Phase 5.5 having changed. `a2a/transaction.rego` counts the distinct
    approvers inside the VERIFIED artifact directly, rather than routing
    through `approval_satisfied` -- which would consult `required_approvals`,
    a rule `loan/amount.rego` defines as 1 for any non-loan action, and dual
    control would silently have become single control.
    """

    async def test_policy_asks_for_TWO(self, submit_a2a, a2a_envelope):
        result = await submit_a2a(a2a_envelope(resource_id="pay-3312",
                                               amount_inr=5_000_000))
        assert result.status == "PENDING_APPROVAL"
        assert result.reason == "DUAL_APPROVAL_REQUIRED"
        assert result.required_approvals == 2

    async def test_the_approval_request_records_that_it_needs_two(
        self, submit_a2a, a2a_envelope, approval_for
    ):
        result = await submit_a2a(a2a_envelope(resource_id="pay-3312",
                                               amount_inr=5_000_000))
        approval = await approval_for(result.approval_id)
        assert approval.required_approvals == 2
        assert approval.presentation["required_approvals"] == 2
        assert "TWO DIFFERENT people" in approval.presentation["approvals_note"]

    async def test_ONE_officer_CANNOT_approve_an_above_threshold_payment(
        self, submit_a2a, a2a_envelope, approval_for, decide_as,
        payment_officer_token, session,
    ):
        """THE REQUIRED NEGATIVE, stated as plainly as it can be.

        One authorized PAYMENT_OFFICER signs off. The payment does not move,
        the approval does not complete, and no artifact is produced for the
        transaction to present.
        """
        envelope = a2a_envelope(resource_id="pay-3312", amount_inr=5_000_000,
                                transaction_id="txn-dual")
        first = await submit_a2a(envelope)
        approval = await approval_for(first.approval_id)

        await decide_as(approval, payment_officer_token)
        await session.flush()

        # The approval is STILL PENDING. One person is not two.
        approval = await approval_for(first.approval_id)
        assert approval.status is ApprovalStatus.PENDING
        assert approval.artifact is None

        second = await submit_a2a(envelope)
        assert second.executed is False, (
            "ONE officer must never release an above-threshold payment")
        assert second.status == "PENDING_APPROVAL"
        assert payment_execution_count("pay-3312") == 0
        assert payment_instruction_status("pay-3312") == "AWAITING_EXECUTION"

    async def test_the_SAME_officer_signing_twice_is_refused(
        self, submit_a2a, a2a_envelope, approval_for, decide_as,
        payment_officer_token, session,
    ):
        """The two-person rule is a UNIQUE CONSTRAINT, not an `if`."""
        from app.hitl.service import DuplicateApprover

        envelope = a2a_envelope(resource_id="pay-3312", amount_inr=5_000_000)
        first = await submit_a2a(envelope)
        approval = await approval_for(first.approval_id)
        await decide_as(approval, payment_officer_token)
        await session.flush()

        with pytest.raises(DuplicateApprover):
            await decide_as(await approval_for(first.approval_id),
                            payment_officer_token)
        assert payment_execution_count("pay-3312") == 0

    async def test_TWO_DISTINCT_officers_release_it(
        self, submit_a2a, a2a_envelope, approval_for, decide_as,
        payment_officer_token, second_payment_officer_token, session,
    ):
        """And the positive, without which the negative means nothing."""
        envelope = a2a_envelope(resource_id="pay-3312", amount_inr=5_000_000,
                                transaction_id="txn-dual")
        first = await submit_a2a(envelope)
        approval_id = first.approval_id

        await decide_as(await approval_for(approval_id), payment_officer_token)
        await session.flush()
        await decide_as(await approval_for(approval_id),
                        second_payment_officer_token)
        await session.flush()

        approval = await approval_for(approval_id)
        assert approval.status is ApprovalStatus.APPROVED
        assert approval.artifact is not None
        assert len(approval.artifact["credentialSubject"]["approvers"]) == 2

        second = await submit_a2a(envelope)
        assert second.executed is True, (second.reason, second.detail)
        assert second.reason == "A2A_DUAL_CONTROL_SATISFIED"
        assert payment_execution_count("pay-3312") == 1

    async def test_the_artifact_carries_two_distinct_people(
        self, submit_a2a, a2a_envelope, approval_for, decide_as,
        payment_officer_token, second_payment_officer_token, session,
    ):
        """Policy counts (issuer, subject) pairs inside the SIGNED artifact,
        not rows in a table an attacker might edit."""
        envelope = a2a_envelope(resource_id="pay-3312", amount_inr=5_000_000)
        first = await submit_a2a(envelope)
        await decide_as(await approval_for(first.approval_id),
                        payment_officer_token)
        await session.flush()
        await decide_as(await approval_for(first.approval_id),
                        second_payment_officer_token)
        await session.flush()

        approvers = (await approval_for(first.approval_id)
                     ).artifact["credentialSubject"]["approvers"]
        identities = {(a["issuer"], a["subject"]) for a in approvers}
        assert len(identities) == 2


class TestTheRoleSeparation:
    async def test_a_LOAN_OFFICER_may_not_approve_a_payment(
        self, submit_a2a, a2a_envelope, approval_for, pdp, loan_officer_token,
        control_plane, opa_ready,
    ):
        """PAYMENT_OFFICER != LOAN_OFFICER. Neither is a superset.

        Asked of the CONTROL-PLANE PDP, which is where "may this human
        approve THIS?" is decided.
        """
        from app.humans.oidc import OIDCValidator
        from app.core.config import get_settings

        result = await submit_a2a(a2a_envelope(resource_id="pay-3311",
                                               amount_inr=500_000))
        identity = OIDCValidator(get_settings()).validate(loan_officer_token)
        decision = await pdp.decide_control_plane(
            principal={"did": identity.principal_urn, "type": "human",
                       "roles": sorted(identity.roles),
                       "subject": identity.subject, "issuer": identity.issuer,
                       "username": identity.username},
            operation="approval_decide",
            target={"type": "approval", "id": result.approval_id,
                    "action": "execute_payment", "submitted_by": "iam.admin",
                    "existing_approvers": []},
            request_id="cp-test",
        )
        assert decision.allowed is False
        assert decision.reason == "HUMAN_MAY_NOT_APPROVE_THIS"

    async def test_a_PAYMENT_OFFICER_may_approve_a_payment(
        self, submit_a2a, a2a_envelope, pdp, payment_officer_token,
        control_plane, opa_ready,
    ):
        from app.humans.oidc import OIDCValidator
        from app.core.config import get_settings

        result = await submit_a2a(a2a_envelope(resource_id="pay-3311",
                                               amount_inr=500_000))
        identity = OIDCValidator(get_settings()).validate(payment_officer_token)
        decision = await pdp.decide_control_plane(
            principal={"did": identity.principal_urn, "type": "human",
                       "roles": sorted(identity.roles),
                       "subject": identity.subject, "issuer": identity.issuer,
                       "username": identity.username},
            operation="approval_decide",
            target={"type": "approval", "id": result.approval_id,
                    "action": "execute_payment", "submitted_by": "iam.admin",
                    "existing_approvers": []},
            request_id="cp-test",
        )
        assert decision.allowed is True
        assert decision.reason == "HUMAN_PAYMENT_OFFICER"

    async def test_a_PAYMENT_OFFICER_may_not_approve_a_LOAN(
        self, pdp, payment_officer_token, control_plane, opa_ready
    ):
        """The separation runs both ways, or it is not a separation."""
        from app.humans.oidc import OIDCValidator
        from app.core.config import get_settings

        identity = OIDCValidator(get_settings()).validate(payment_officer_token)
        decision = await pdp.decide_control_plane(
            principal={"did": identity.principal_urn, "type": "human",
                       "roles": sorted(identity.roles),
                       "subject": identity.subject, "issuer": identity.issuer,
                       "username": identity.username},
            operation="approval_decide",
            target={"type": "approval", "id": "approval-x",
                    "action": "approve_loan", "submitted_by": "iam.admin",
                    "existing_approvers": []},
            request_id="cp-test",
        )
        assert decision.allowed is False
        assert decision.reason == "HUMAN_MAY_NOT_APPROVE_THIS"

    @pytest.mark.parametrize("token_name", ["iam_admin_token", "auditor_token",
                                            "no_roles_token"])
    async def test_nobody_else_may_approve_a_payment(
        self, request, pdp, token_name, control_plane, opa_ready
    ):
        from app.humans.oidc import OIDCValidator
        from app.core.config import get_settings

        token = request.getfixturevalue(token_name)
        identity = OIDCValidator(get_settings()).validate(token)
        decision = await pdp.decide_control_plane(
            principal={"did": identity.principal_urn, "type": "human",
                       "roles": sorted(identity.roles),
                       "subject": identity.subject, "issuer": identity.issuer,
                       "username": identity.username},
            operation="approval_decide",
            target={"type": "approval", "id": "approval-x",
                    "action": "execute_payment", "submitted_by": "iam.admin",
                    "existing_approvers": []},
            request_id="cp-test",
        )
        assert decision.allowed is False

    async def test_a_PAYMENT_OFFICER_may_VIEW_the_approval_they_must_decide(
        self, submit_a2a, a2a_envelope, pdp, payment_officer_token,
        control_plane, opa_ready,
    ):
        """FOUND WHILE RUNNING THE GATE, and it is not cosmetic.

        Granting the decide authority without the read authority produces
        approvals that are technically valid and worthless: an approver who
        cannot OPEN the request cannot make an informed decision, and
        `APPROVAL_VIEWED` is the audit evidence that they did.
        """
        from app.humans.oidc import OIDCValidator
        from app.core.config import get_settings

        result = await submit_a2a(a2a_envelope(resource_id="pay-3311",
                                               amount_inr=500_000))
        identity = OIDCValidator(get_settings()).validate(payment_officer_token)
        decision = await pdp.decide_control_plane(
            principal={"did": identity.principal_urn, "type": "human",
                       "roles": sorted(identity.roles),
                       "subject": identity.subject, "issuer": identity.issuer,
                       "username": identity.username},
            operation="approval_view",
            target={"type": "approval", "id": result.approval_id,
                    "action": "execute_payment", "existing_approvers": []},
            request_id="cp-test",
        )
        assert decision.allowed is True
        assert decision.reason == "HUMAN_MAY_VIEW"

    async def test_viewing_is_a_LOWER_bar_than_deciding(
        self, pdp, auditor_token, control_plane, opa_ready
    ):
        """An auditor must be able to see what was asked without being able
        to answer it."""
        from app.humans.oidc import OIDCValidator
        from app.core.config import get_settings

        identity = OIDCValidator(get_settings()).validate(auditor_token)
        principal = {"did": identity.principal_urn, "type": "human",
                     "roles": sorted(identity.roles),
                     "subject": identity.subject, "issuer": identity.issuer,
                     "username": identity.username}
        target = {"type": "approval", "id": "approval-x",
                  "action": "execute_payment", "existing_approvers": []}
        may_view = await pdp.decide_control_plane(
            principal=principal, operation="approval_view", target=target,
            request_id="cp-view")
        may_decide = await pdp.decide_control_plane(
            principal=principal, operation="approval_decide", target=target,
            request_id="cp-decide")
        assert may_view.allowed is True
        assert may_decide.allowed is False

    async def test_an_AGENT_may_not_approve_a_payment(
        self, pdp, risk_agent, control_plane, opa_ready
    ):
        """The self-approval attack, refused by name."""
        decision = await pdp.decide_control_plane(
            principal={"did": risk_agent.did, "type": "agent", "roles": []},
            operation="approval_decide",
            target={"type": "approval", "id": "approval-x",
                    "action": "execute_payment", "existing_approvers": []},
            request_id="cp-test",
        )
        assert decision.allowed is False
        assert decision.reason == "AGENT_MAY_NOT_APPROVE"


class TestMakerChecker:
    async def test_the_officer_who_raised_it_may_not_sign_it_off(
        self, submit_a2a, a2a_envelope, pdp, payment_officer_token,
        control_plane, opa_ready,
    ):
        """pay-3313 was raised BY payment.officer. Maker and checker are
        different people, and the rule is the Phase 5.5 one, unchanged.
        """
        from app.humans.oidc import OIDCValidator
        from app.core.config import get_settings

        result = await submit_a2a(a2a_envelope(resource_id="pay-3313",
                                               amount_inr=750_000))
        assert result.status == "PENDING_APPROVAL"

        identity = OIDCValidator(get_settings()).validate(payment_officer_token)
        decision = await pdp.decide_control_plane(
            principal={"did": identity.principal_urn, "type": "human",
                       "roles": sorted(identity.roles),
                       "subject": identity.subject, "issuer": identity.issuer,
                       "username": identity.username},
            operation="approval_decide",
            target={"type": "approval", "id": result.approval_id,
                    "action": "execute_payment",
                    "submitted_by": "payment.officer",
                    "existing_approvers": []},
            request_id="cp-test",
        )
        assert decision.allowed is False
        assert decision.reason == "SELF_APPROVAL_PROHIBITED"


class TestAmountTamperingAfterApproval:
    async def test_amending_the_amount_invalidates_the_approval(
        self, submit_a2a, a2a_envelope, approval_for, decide_as,
        payment_officer_token, session,
    ):
        """PHASE 5.5's MECHANISM, REUSED WITHOUT A LINE OF NEW CODE.

        The officer approved Rs 5,00,000. The instruction is restated. The
        binding digest no longer matches, the approval stops applying, and
        the transaction is refused -- naming the field that moved.
        """
        from app.enforcement.resources import set_payment_amount

        envelope = a2a_envelope(resource_id="pay-3311", amount_inr=500_000,
                                transaction_id="txn-tamper")
        first = await submit_a2a(envelope)
        await decide_as(await approval_for(first.approval_id),
                        payment_officer_token)
        await session.flush()

        set_payment_amount("pay-3311", 900_000)

        second = await submit_a2a(envelope)
        assert second.executed is False
        assert payment_execution_count("pay-3311") == 0
        # The sender signed 5,00,000 and the record now reads 9,00,000, so
        # the amount reconciliation refuses it before the approval is even
        # weighed. Both controls hold; this one is simply first.
        assert second.reason in {"A2A_AMOUNT_MISMATCH",
                                 "APPROVAL_BINDING_MISMATCH"}


class TestAFabricatedApprovalIsRefused:
    async def test_an_approval_id_that_names_nothing(
        self, submit_a2a, a2a_envelope
    ):
        """An offered id is a CLAIM. It narrows which approval is considered;
        it can never make one apply."""
        result = await submit_a2a(a2a_envelope(
            resource_id="pay-3311", amount_inr=500_000,
            approval_id="approval-i-made-this-up"))
        assert result.executed is False
        assert payment_execution_count("pay-3311") == 0

    async def test_an_approval_for_a_DIFFERENT_transaction_does_not_apply(
        self, submit_a2a, a2a_envelope, approval_for, decide_as,
        payment_officer_token, session,
    ):
        """An approval is bound to ONE request. Carrying it to another is
        refused by the binding digest."""
        first = await submit_a2a(a2a_envelope(resource_id="pay-3311",
                                              amount_inr=500_000,
                                              transaction_id="txn-one"))
        await decide_as(await approval_for(first.approval_id),
                        payment_officer_token)
        await session.flush()

        other = await submit_a2a(a2a_envelope(
            resource_id="pay-3311", amount_inr=500_000,
            transaction_id="txn-two", approval_id=first.approval_id))
        assert other.executed is False
        assert payment_execution_count("pay-3311") == 0
