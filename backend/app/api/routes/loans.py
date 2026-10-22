"""Loan applications: the resource the HITL demonstration acts on.

    GET  /api/v1/loans                        the demonstration applications
    GET  /api/v1/loans/{id}                   one application
    POST /api/v1/loans/{id}/amount            amend the amount (Phase 5.5)

WHY AN AMENDMENT ENDPOINT EXISTS, and why it is not a back door.

A loan amount genuinely changes: an applicant revises what they are asking
for, an underwriter corrects a figure, an upstream core-banking system pushes
a restated application. Any real deployment has that path. Phase 5.5 needs it
to be REACHABLE so that the property in spec section 3 can be demonstrated end
to end rather than asserted:

    a human approves Rs 25,00,000
    the amount becomes Rs 2,50,00,000
    the approval STOPS APPLYING, by name, and the action is refused

Without a real amendment path that scenario can only be simulated, and a
simulated tamper proves nothing about the running system.

It is not a weakening, because it is not unguarded. Amending goes through the
SAME control-plane guard as every other mutation: the caller proves control of
a DID, the PDP decides, the attempt is audited, and only a machine principal
holding `loan_admin` is permitted. No human role reaches it -- a loan officer
who could amend an amount and then approve it would have defeated the amount
policy and maker-checker in one move.

READING is open, exactly as the approval queue is: the applications are
synthetic demonstration data and carry no personal information.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import SessionDep
from app.audit.service import AuditService
from app.controlplane.authenticator import ControlPlanePrincipalView
from app.controlplane.guard import ControlPlaneGuard, path_param
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.enforcement.resources import (
    ResourceNotFoundError,
    format_inr,
    get_loan_application,
    known_loan_applications,
    set_loan_amount,
)
from app.monitoring.events import Event, EventType

log = get_logger("api.loans")

router = APIRouter(prefix="/api/v1/loans", tags=["loans"])


class AmendAmountIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount_inr: int = Field(gt=0, le=10_000_000_000,
                            description="The revised amount, in whole rupees.")
    reason: str = Field(default="amended upstream", max_length=500)


@router.get("")
async def list_loans() -> list[dict[str, Any]]:
    """The demonstration applications. Synthetic, and labelled as such."""
    return [get_loan_application(id) for id in known_loan_applications()]


@router.get("/{application_id}")
async def read_loan(application_id: str) -> dict[str, Any]:
    try:
        return get_loan_application(application_id)
    except ResourceNotFoundError as exc:
        raise NotFoundError(str(exc)) from exc


@router.post("/{application_id}/amount", dependencies=[Depends(
    ControlPlaneGuard("loan_amend", target=path_param("application_id")))])
async def amend_amount(
    application_id: str, body: AmendAmountIn, request: Request,
    session: SessionDep,
) -> dict[str, Any]:
    """Amend the amount on an application.

    NOTE WHAT THIS DOES NOT DO: touch any approval. An approval that was bound
    to the previous amount is left exactly as it was -- still signed, still
    valid as a record of what that person agreed to, and no longer applicable
    to this application. Invalidating it here would be the wrong shape: the
    approval did not become false, the request stopped matching it. The PDP
    reaches that conclusion on its own at re-evaluation, and says which field
    moved.
    """
    principal: ControlPlanePrincipalView = request.state.control_plane_principal
    try:
        before = get_loan_application(application_id)
    except ResourceNotFoundError as exc:
        raise NotFoundError(str(exc)) from exc

    set_loan_amount(application_id, body.amount_inr)
    after = get_loan_application(application_id)

    await AuditService(session).record(
        Event(
            EventType.LOAN_AMOUNT_AMENDED,
            agent_did=principal.did,
            resource="loan_applications",
            action="AMEND_AMOUNT",
            decision="AMENDED",
            reason=body.reason,
            metadata={
                "application_id": application_id,
                "amount_before": before["amount_inr"],
                "amount_after": after["amount_inr"],
                "display_before": before["amount_display"],
                "display_after": after["amount_display"],
                "amended_by": principal.did,
                # Said explicitly, because this is the moment an auditor asks.
                "existing_approvals": (
                    "unchanged. An approval bound to the previous amount stays "
                    "signed and stays a true record; it simply no longer "
                    "applies, and the PDP says so at re-evaluation."
                ),
            },
        )
    )
    log.warning("loan_amount_amended", application_id=application_id,
                before=before["amount_inr"], after=after["amount_inr"],
                by=principal.did)
    return {
        "application_id": application_id,
        "amount_inr": after["amount_inr"],
        "amount_display": format_inr(after["amount_inr"]),
        "previous_amount_inr": before["amount_inr"],
        "amended_by": principal.did,
        "note": (
            "Any approval already granted for the previous amount no longer "
            "applies to this application. It is not revoked -- it is simply "
            "not about this request any more."
        ),
    }
