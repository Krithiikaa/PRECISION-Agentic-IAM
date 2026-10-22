"""What a human is SHOWN when an A2A payment escalates.

    "An agent wants to move money."      <- produces approvals that mean nothing
    "Loan Coordinator Agent instructed
     Payment Execution Agent to settle
     pay-3311 (Rs 5,00,000) to
     cust-007-current, and policy
     requires an authorized payment
     officer"                            <- produces a decision

The Phase 5 rules apply here unchanged, and for the same reasons:

1. NOTHING HERE IS TRUSTED. Everything shown comes from server-side state --
   the instruction record, the PDP's decision, the verified envelope. A sender
   cannot influence what a human is told about its own instruction.

2. NOTHING SENSITIVE IS SHOWN. The screen carries what is needed to judge the
   payment: who instructed it, who would carry it out, how much, to which
   beneficiary reference, and why it was stopped. Not a customer file.

3. THE AMOUNT SHOWN IS THE AMOUNT BOUND, and the amount reconciled. It is
   read from the instruction record, the approval's binding digest covers the
   same value read the same way, and the A2A service has already confirmed it
   matches what the sender signed. So the number a person agrees to is the
   number the PDP re-checks AND the number the sender committed to -- and if
   any of them moves afterwards the approval stops applying.

4. THE SCREEN SAYS HOW MANY PEOPLE ARE NEEDED. An approver who believes their
   click releases the payment, when a second officer is required, has been
   misinformed by the interface -- and dual control nobody realises is in
   force is dual control in name only.
"""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.enforcement.resources import (
    PAYMENT_INSTRUCTIONS,
    ResourceNotFoundError,
    format_inr,
    get_payment_instruction,
)

log = get_logger("a2a.presentation")


def describe_transaction(
    *,
    sender_did: str,
    receiver_did: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    purpose: str,
    signed_amount_inr: int | None,
    decision_reason: str,
    required_approvals: int,
    transaction_id: str,
) -> dict[str, Any]:
    """A view of one escalated A2A transaction, for a human to judge.

    A VIEW: it reads what the transaction and the record already say and adds
    nothing. Where the instruction cannot be read, that is reported as such
    rather than filled in -- nobody should be asked to approve a payment the
    system cannot describe.
    """
    presentation: dict[str, Any] = {
        "kind": "a2a_transaction",
        "transaction_id": transaction_id,
        "headline": f"{_action_label(action)} instructed by another agent",
        "instructed_by": sender_did,
        "to_be_performed_by": receiver_did,
        "action": _action_label(action),
        "purpose": purpose,
        "resource": {"type": resource_type, "id": resource_id},
        "why_you_are_being_asked": decision_reason,
        "required_approvals": required_approvals,
        "approvals_note": (
            "TWO DIFFERENT people must approve this. Your sign-off alone does "
            "not release it."
            if required_approvals > 1 else
            "One authorized approver is required."
        ),
        "signed_amount_inr": signed_amount_inr,
        "disclaimer": "SYNTHETIC DEMONSTRATION - no real funds move",
    }
    if resource_type != PAYMENT_INSTRUCTIONS or not resource_id:
        presentation["detail_available"] = False
        presentation["detail"] = (
            f"no presentable detail is defined for {resource_type!r}"
        )
        return presentation
    try:
        record = get_payment_instruction(resource_id)
    except ResourceNotFoundError:
        # Reported, never invented. An approver must be able to see that the
        # system could not read the instruction.
        presentation["detail_available"] = False
        presentation["detail"] = (
            f"payment instruction {resource_id!r} could not be read "
            f"server-side. Do not approve a payment nobody can state."
        )
        return presentation

    presentation.update({
        "detail_available": True,
        "amount_inr": record["amount_inr"],
        "amount_display": format_inr(record["amount_inr"]),
        "currency": record["currency"],
        "beneficiary_ref": record["beneficiary_ref"],
        "beneficiary_name": record["beneficiary_name"],
        "rail": record["rail"],
        "narrative": record["narrative"],
        "raised_by": record["submitted_by"],
        "raised_at": record["raised_at"],
        "instruction_status": record["status"],
        # Stated on the screen because it is the one thing a person cannot
        # check for themselves: the figure they are looking at is the figure
        # the sender cryptographically committed to.
        "amount_reconciled": (
            signed_amount_inr is None or signed_amount_inr == record["amount_inr"]
        ),
    })
    return presentation


_ACTION_LABELS = {
    "execute_payment": "EXECUTE_PAYMENT",
    "read": "READ",
}


def _action_label(action: str) -> str:
    return _ACTION_LABELS.get(action, action.upper())
