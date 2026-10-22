"""What a mandate says, in words a person can review.

An operator looking at a live mandate should not have to decode a binding
digest to find out what it permits. A grant that nobody can read is a grant
nobody can audit, and "some agent has temporary access to something" is exactly
the kind of record that looks like oversight without being any.

Nothing here decides anything. It is a description of a scope, rendered once at
issuance and stored alongside the grant so the audit trail keeps what the
mandate meant even if the underlying records later change.
"""
from __future__ import annotations

from typing import Any

from app.enforcement.resources import (
    LOAN_APPLICATIONS,
    ResourceNotFoundError,
    format_inr,
    get_loan_application,
)

# Plain-language names for the resources a mandate can cover. A resource type
# with no entry is rendered by its own name rather than guessed at.
_RESOURCE_LABELS = {
    "credit_records": "credit records",
    "loan_applications": "loan applications",
    "payroll_records": "payroll records",
}

_ACTION_LABELS = {
    "read": "read",
    "approve_loan": "record a decision on",
    "disburse_funds": "disburse funds for",
    "override_decision": "override the decision on",
}


def _describe_constraints(constraints: dict[str, Any]) -> list[str]:
    """One readable line per ceiling. An unrecognised key is still shown.

    Showing an unknown constraint verbatim is deliberate: silently dropping a
    ceiling from the human-readable description would make a mandate look
    broader than it is, which is the wrong direction to be imprecise in.
    """
    lines: list[str] = []
    for key, value in sorted(constraints.items()):
        if key == "max_amount_inr" and isinstance(value, int):
            lines.append(f"only records up to {format_inr(value)}")
        else:
            lines.append(f"{key}: {value}")
    return lines


def _describe_resources(resource_type: str, resource_ids: list[str]) -> dict[str, Any]:
    """The instances a mandate covers, with whatever detail is readable."""
    label = _RESOURCE_LABELS.get(resource_type, resource_type)
    if not resource_ids:
        return {
            "summary": f"any {label} policy permits",
            "scoped_to_instances": False,
            "instances": [],
        }

    instances: list[dict[str, Any]] = []
    for rid in resource_ids:
        entry: dict[str, Any] = {"id": rid}
        if resource_type == LOAN_APPLICATIONS:
            # A mandate may name an application that cannot be read -- it may
            # have been removed since. Described honestly rather than omitted,
            # because a scope line that silently drops an entry understates
            # what the mandate covers.
            try:
                record = get_loan_application(rid)
            except ResourceNotFoundError:
                entry["detail"] = "not readable"
            else:
                entry["applicant"] = record.get("applicant_name")
                entry["amount"] = record.get("amount_display")
        instances.append(entry)
    return {
        "summary": f"{len(resource_ids)} specific {label}",
        "scoped_to_instances": True,
        "instances": instances,
    }


def describe_mandate(
    *,
    binding: Any,
    max_uses: int,
    ttl_seconds: int,
    expires_at: str,
    justification: dict[str, Any],
) -> dict[str, Any]:
    """The human-readable form of a mandate, stored with the grant.

    `limits` is stated as a sentence as well as numbers, because "5 uses / 300
    seconds" and "at most 5 times in the next 5 minutes" are read very
    differently under time pressure.
    """
    action = _ACTION_LABELS.get(binding.action, binding.action)
    resources = _describe_resources(binding.resource_type, list(binding.resource_ids))
    constraints = _describe_constraints(binding.constraints)

    minutes = ttl_seconds // 60
    window = f"{minutes} minute{'s' if minutes != 1 else ''}" if minutes else f"{ttl_seconds} seconds"

    return {
        "headline": (
            f"{binding.agent_did} may {action} {resources['summary']} "
            f"for {binding.purpose.replace('_', ' ')}"
        ),
        "agent": binding.agent_did,
        "action": binding.action,
        "purpose": binding.purpose,
        "resources": resources,
        "constraints": constraints,
        "limits": {
            "sentence": f"at most {max_uses} time{'s' if max_uses != 1 else ''} "
                        f"within the next {window}",
            "max_uses": max_uses,
            "ttl_seconds": ttl_seconds,
            "expires_at": expires_at,
        },
        "basis": {
            "approval_id": justification.get("approval_id"),
            "approvers": justification.get("approvers") or [],
            "policy": justification.get("policy"),
            "decision_reason": justification.get("decision_reason"),
        },
        # Said on every mandate, because it is the single most misread thing
        # about this object.
        "note": (
            "This mandate is an INPUT to authorization, not a permission. Every "
            "use is re-decided by the PDP with every ordinary rule running -- "
            "credential validity, agent status, resource scope and amount "
            "bands are all re-checked. The mandate can only narrow what policy "
            "would allow at that moment; it can never widen it."
        ),
    }
