"""What the human is SHOWN.

    "An agent wants access."          <- produces approvals that mean nothing
    "Risk Analysis Agent wants to
     APPROVE_LOAN on loan-7842
     (Rs 25,00,000) for loan_decision,
     because policy requires a human"  <- produces a decision

An approval nobody could have understood is not a meaningful approval, so this
module exists to make the escalation legible. It is a VIEW: it reads what the
authorization request and the tool already declare, and adds nothing.

Two rules it must not break:

1. NOTHING HERE IS TRUSTED. Everything shown comes from server-side state --
   the tool's own spec, the resource record, the PDP's decision. A caller
   cannot influence what the human is told about it, because a request that
   could describe itself flatteringly would defeat the whole point of showing
   it to somebody.

2. NOTHING SENSITIVE IS SHOWN. The screen carries what is needed to judge the
   action. It is not a data-exfiltration route: an approver sees the loan
   amount and applicant reference, not a credit file.

3. (Phase 5.5) THE AMOUNT SHOWN IS THE AMOUNT BOUND. It is read from the
   resource record, and the approval's binding digest covers the same value
   read the same way. So the number a person agreed to is the number the PDP
   re-checks -- and if it moves afterwards, the approval stops applying rather
   than silently covering the new figure.

4. (Phase 5.5) THE SCREEN SAYS HOW MANY PEOPLE ARE NEEDED. An approver who
   believes their click releases the action, when in fact a second officer is
   required, has been misinformed by the interface -- and dual control that
   nobody realises is in force is dual control in name only.
"""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.enforcement.resources import (
    LOAN_APPLICATIONS,
    ResourceNotFoundError,
    get_loan_application,
)

log = get_logger("hitl.presentation")

# Human-readable labels for the resource types an approver can be shown.
_RESOURCE_LABELS = {
    LOAN_APPLICATIONS: "Loan application",
    "credit_records": "Credit record",
    "payroll_records": "Payroll record",
}

_ACTION_LABELS = {
    "approve_loan": "APPROVE_LOAN",
    "disburse_funds": "DISBURSE_FUNDS",
    "override_decision": "OVERRIDE_DECISION",
    "read": "READ",
}

# Why policy stopped this, in a sentence a person can act on. Keyed by the
# PDP's reason so the screen and the audit trail cannot drift apart.
_REASON_EXPLANATIONS = {
    "SENSITIVE_ACTION_REQUIRES_HUMAN": (
        "Policy classes this action as too consequential for an agent to take "
        "on its own authority. It requires a named human decision."
    ),
    "DUAL_APPROVAL_REQUIRED": (
        "The amount on this application is above the single-approver limit, so "
        "policy requires TWO different authorized people to approve it. The "
        "same person cannot provide both approvals."
    ),
}


def _resource_detail(resource_type: str, resource_id: str | None) -> dict[str, Any]:
    """Facts about the specific record, read server-side.

    A missing record is reported as such rather than left blank: "we cannot
    show you what this is" is important information for someone about to
    approve it.
    """
    if resource_type != LOAN_APPLICATIONS or not resource_id:
        return {"available": False,
                "detail": "no additional detail is available for this resource"}
    try:
        record = get_loan_application(resource_id)
    except ResourceNotFoundError:
        return {"available": False,
                "detail": f"loan application {resource_id} could not be read"}
    return {
        "available": True,
        "application_id": record["application_id"],
        "applicant": record["applicant_name"],
        "customer_id": record["customer_id"],
        "amount": record["amount_display"],
        "amount_value": record["amount_inr"],
        "currency": "INR",
        # The officer of record. Shown because an approver needs to see whose
        # application they are signing off -- and because the person named here
        # is precisely the person policy will refuse.
        "submitted_by": record["submitted_by"],
        "product": record["product"],
        "term_months": record["term_months"],
        "risk_band": record["risk_band"],
        "current_status": record["status"],
        "disclaimer": record["disclaimer"],
    }


def describe_for_human(request: Any, tool: Any, decision: Any) -> dict[str, Any]:
    """Build the approval screen's content from server-side state only."""
    agent_name = None
    pip = (decision.evaluation or {}).get("pip") or {}
    subject = pip.get("subject") or {}
    agent_name = subject.get("name") or subject.get("agent_type")

    document = (decision.evaluation or {}).get("opa_document") or {}
    required = document.get("required_approvals")
    required = required if isinstance(required, int) and required >= 1 else 1

    return {
        # HOW MANY PEOPLE, and why. An approver who does not know they are one
        # of two will reasonably assume their click completes the decision --
        # which is the misunderstanding that makes dual control decorative.
        "approval": {
            "required_approvals": required,
            "dual_control": required > 1,
            "explanation": (
                "Two different people must approve this. Your decision alone "
                "does not release the action, and you cannot provide both "
                "approvals."
                if required > 1 else
                "One authorized approver is required for this decision."
            ),
        },
        "agent": {
            "did": request.subject.did,
            "name": agent_name or request.subject.did.rsplit(":", 1)[-1],
            "type": subject.get("agent_type"),
            "status": subject.get("status"),
            # Capabilities ATTESTED by a valid credential, not declared. What
            # an agent says about itself is not evidence, and an approver
            # should not be shown a claim as though it were verified.
            "verified_capabilities": pip.get("verified_capabilities") or [],
        },
        "action": {
            "name": request.action,
            "label": _ACTION_LABELS.get(request.action, request.action.upper()),
            "tool": tool.spec.name,
            "description": tool.spec.description,
        },
        "resource": {
            "type": request.resource.type,
            "label": _RESOURCE_LABELS.get(request.resource.type, request.resource.type),
            "id": request.resource.id,
            "detail": _resource_detail(request.resource.type, request.resource.id),
        },
        "purpose": request.purpose,
        "request_id": request.request_id,
        "policy": {
            "decision": decision.decision.value,
            "reason": decision.reason,
            "policy": decision.policy_ref,
            "explanation": _REASON_EXPLANATIONS.get(
                decision.reason,
                "Policy referred this action to a human before it may proceed.",
            ),
        },
    }
