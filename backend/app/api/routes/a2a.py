"""Secure agent-to-agent transaction endpoints (Phase 7).

    POST /api/v1/a2a/transactions            submit an inbound envelope
    GET  /api/v1/a2a/transactions            list, by sender or receiver
    GET  /api/v1/a2a/transactions/{id}       one, with its envelope and attempts
    POST /api/v1/a2a/instructions/{id}/amount  amend a payment amount
    GET  /api/v1/a2a/instructions            the demonstration instructions
    POST /api/v1/a2a/sweep                   move overdue transactions to EXPIRED
    GET  /api/v1/a2a/health                  is the configuration loaded?

THE SUBMISSION ROUTE IS BEHIND THE CONTROL-PLANE GUARD, and the target
resolver reads the envelope's own `receiverDid`. That is not a detail: it is
how RECEIVER BINDING is enforced at the authentication layer.

    ControlPlaneGuard("a2a_submit", target=<envelope.receiverDid>)
        -> agent_self.rego: acts_on_self requires target.id == principal.did

So an agent may submit ONLY an envelope addressed to itself:

    A -> B, submitted by B    ALLOW
    A -> B, submitted by C    PRINCIPAL_IS_NOT_THE_SUBJECT   (the replay attack)
    A -> B, submitted by A    PRINCIPAL_IS_NOT_THE_SUBJECT   (no forced receipt)

and NO administrator holds `a2a_submit`, because one that did would be a
privileged bypass of exactly that binding.

WHAT THIS FILE DELIBERATELY DOES NOT CONTAIN: any decision about whether a
transaction may proceed. Not a signature check, not an amount comparison, not
a role check. `AEM.enforce_a2a()` verifies the envelope and then runs the full
PDP evaluation; this file unpacks a request and returns what those decided.

THE ENVELOPE IS RETURNED IN READS, and that is safe because an envelope is NOT
A BEARER INSTRUCTION: presenting one requires a control-plane proof signed by
the receiving agent's key, so the document alone buys an attacker nothing. Its
security is its signature and its binding, not its secrecy.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import KeyStoreDep, SessionDep, SettingsDep
from app.audit.service import AuditService
from app.controlplane.authenticator import ControlPlanePrincipalView
from app.controlplane.guard import ControlPlaneGuard, fixed, path_param
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.enforcement.aem import AdapterEnforcementMiddleware
from app.enforcement.resources import (
    ResourceNotFoundError,
    format_inr,
    get_payment_instruction,
    known_payment_instructions,
    set_payment_amount,
)
from app.monitoring.events import Event, EventType
from app.protocols.a2a.service import A2ATransactionService

log = get_logger("api.a2a")

router = APIRouter(prefix="/api/v1/a2a", tags=["a2a"])


def envelope_receiver(request: Request, body: Any) -> str | None:
    """The RECEIVER the envelope names, for the control-plane guard.

    Read from the signed envelope in the request body -- which is exactly
    right, because the guard then requires the authenticated principal to BE
    that DID. A caller that changes it is changing signed bytes and the
    signature fails; a caller that leaves it alone can only submit if it
    holds the named receiver's key.

    Returning None when the body is not an envelope is safe: `acts_on_self`
    requires a non-null target, so policy denies.
    """
    if not isinstance(body, dict):
        return None
    envelope = body.get("envelope")
    if not isinstance(envelope, dict):
        return None
    receiver = envelope.get("receiverDid")
    return receiver if isinstance(receiver, str) else None


class SubmitIn(BaseModel):
    """What a receiving agent relays inward.

    Note what is NOT here: a sender, an action, a resource, an amount or a
    decision. Every one of those is inside the SIGNED envelope, and reading
    them from anywhere else would let the relaying agent restate the
    instruction it was asked to carry out.
    """

    model_config = ConfigDict(extra="forbid")

    envelope: dict[str, Any] = Field(
        description="The signed A2A transaction envelope, exactly as the "
                    "sender produced it. Relaying it unchanged is the "
                    "receiver's only job.",
    )


class AmendAmountIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount_inr: int = Field(gt=0, le=10_000_000_000,
                            description="The revised amount, in whole rupees.")
    reason: str = Field(default="amended upstream", max_length=500)


@router.post("/transactions", dependencies=[Depends(
    ControlPlaneGuard("a2a_submit", target=envelope_receiver))])
async def submit_transaction(
    body: SubmitIn, request: Request,
    session: SessionDep, keystore: KeyStoreDep, settings: SettingsDep,
) -> dict[str, Any]:
    """Submit a signed transaction addressed to you.

    The guard has already established WHO is calling and that the envelope is
    addressed to them. What happens next is: verification, atomic
    registration, amount reconciliation, a full PDP evaluation with the
    SENDER as subject, and -- only on ALLOW -- execution.

    A refusal returns 200 with `accepted: false` or `executed: false` and the
    reason, rather than an error status. That is deliberate and matches the
    JIT route: "your instruction was refused" is a policy answer, and it
    carries the PDP decision alongside so a sender can tell "no" from "not
    yet" from "you may not instruct that at all".
    """
    principal: ControlPlanePrincipalView = request.state.control_plane_principal
    aem = AdapterEnforcementMiddleware(session, keystore, settings)
    result = await aem.enforce_a2a(
        envelope=body.envelope,
        submitted_by=principal.did,
        source_ip=request.client.host if request.client else None,
    )
    return result.to_dict()


@router.get("/transactions")
async def list_transactions(
    session: SessionDep,
    sender_did: str | None = Query(default=None),
    receiver_did: str | None = Query(default=None),
    limit: int = Query(default=50, le=200),
) -> list[dict[str, Any]]:
    """Transactions by sender or by receiver.

    Readable without a signed request, exactly as the JIT and approval
    listings are: what is in flight is not a secret, and an operator needs to
    see it without first assembling a control-plane proof. The ENVELOPE is
    omitted here -- it is available on the individual record.
    """
    service = A2ATransactionService(session)
    if sender_did:
        records = await service.for_sender(sender_did, limit=limit)
    elif receiver_did:
        records = await service.for_receiver(receiver_did, limit=limit)
    else:
        raise NotFoundError("Supply either sender_did or receiver_did.")
    return [r.to_dict() for r in records]


@router.get("/instructions")
async def list_instructions() -> list[dict[str, Any]]:
    """The demonstration payment instructions. Synthetic, and labelled so."""
    return [get_payment_instruction(i) for i in known_payment_instructions()]


@router.get("/health")
async def a2a_health(session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
    """Is the A2A layer configured, and what is in the ledger?

    Reports the CONFIGURATION honestly, because policy fails closed without
    it: an operator seeing every payment denied as A2A_POLICY_UNCONFIGURED
    should be able to confirm the cause here rather than infer it.
    """
    from app.authorization.opa import OPAClient, OPAUnavailableError

    opa = OPAClient(settings)
    try:
        configured = await opa.get_data("agentic_iam/config/a2a") is not None
        detail = "loaded" if configured else "ABSENT -- every payment will DENY"
    except OPAUnavailableError as exc:
        configured, detail = False, f"policy engine unreachable: {exc}"
    finally:
        await opa.aclose()
    return {
        "component": "a2a",
        "phase": 7,
        "domain": settings.a2a_domain,
        "freshness_seconds": settings.a2a_freshness_seconds,
        "max_ttl_seconds": settings.a2a_max_ttl_seconds,
        "verification_required": settings.a2a_verification_required,
        "policy_configuration": {"loaded": configured, "detail": detail},
        "transactions": await A2ATransactionService(session, settings).stats(),
        "note": "A valid signature is not authorization. Every transaction "
                "reaches the PDP.",
    }


@router.get("/transactions/{transaction_id}")
async def read_transaction(
    transaction_id: str, session: SessionDep,
) -> dict[str, Any]:
    """One transaction, its signed envelope, and every submission attempted.

    The ATTEMPTS matter as much as the record: a transaction with six
    rejected attempts against it was probed, and that is invisible if only
    the accepted row is shown.
    """
    service = A2ATransactionService(session)
    record = await service.get_by_id(transaction_id)
    if record is None:
        raise NotFoundError(f"No A2A transaction {transaction_id!r}")
    return {
        **record.to_dict(),
        "envelope": record.envelope,
        "response_envelope": record.response_envelope,
        "attempts": [a.to_dict() for a in await service.attempts_for(transaction_id)],
    }


@router.post("/instructions/{instruction_id}/amount", dependencies=[Depends(
    ControlPlaneGuard("loan_amend", target=path_param("instruction_id")))])
async def amend_amount(
    instruction_id: str, body: AmendAmountIn, request: Request,
    session: SessionDep,
) -> dict[str, Any]:
    """Amend the amount on a payment instruction.

    WHY THIS EXISTS, and why it is not a back door. An instruction's amount
    genuinely changes: an upstream core-banking system restates it, an
    operator corrects a figure. Phase 7 needs that path to be REACHABLE so
    the reconciliation properties can be demonstrated end to end rather than
    asserted -- an amount that moves after a sender signed it must stop the
    transaction, and simulating that by editing a request in flight would
    prove nothing about the running system.

    It is not a weakening, because it is not unguarded. It goes through the
    SAME control-plane guard as every other mutation, and reuses `loan_amend`
    -- held ONLY by the core-banking gateway principal and by NO human role.
    Reusing the operation rather than minting a second one is deliberate:
    "restate a monetary amount held server-side" is one authority, and
    splitting it would let a future operator grant one half without noticing
    they had granted the other.

    NOTE WHAT THIS DOES NOT DO: touch any transaction or any approval. A
    transaction bound to the previous amount is left exactly as it was. The
    reconciliation reaches the right conclusion on its own, and says which
    figure moved.
    """
    principal: ControlPlanePrincipalView = request.state.control_plane_principal
    try:
        before = get_payment_instruction(instruction_id)
    except ResourceNotFoundError as exc:
        raise NotFoundError(str(exc)) from exc

    set_payment_amount(instruction_id, body.amount_inr)
    after = get_payment_instruction(instruction_id)

    await AuditService(session).record(
        Event(
            EventType.LOAN_AMOUNT_AMENDED,
            agent_did=principal.did,
            resource="payment_instructions",
            action="AMEND_AMOUNT",
            decision="AMENDED",
            reason=body.reason,
            metadata={
                "instruction_id": instruction_id,
                "amount_before": before["amount_inr"],
                "amount_after": after["amount_inr"],
                "display_before": before["amount_display"],
                "display_after": after["amount_display"],
                "amended_by": principal.did,
                "existing_transactions": (
                    "unchanged. A transaction whose sender signed the previous "
                    "amount stays signed and stays a true record of what was "
                    "instructed; it simply no longer reconciles, and the A2A "
                    "layer says so."
                ),
            },
        )
    )
    log.warning("payment_amount_amended", instruction_id=instruction_id,
                before=before["amount_inr"], after=after["amount_inr"],
                by=principal.did)
    return {
        "instruction_id": instruction_id,
        "amount_inr": after["amount_inr"],
        "amount_display": format_inr(after["amount_inr"]),
        "previous_amount_inr": before["amount_inr"],
        "amended_by": principal.did,
        "note": (
            "Any transaction already signed for the previous amount no longer "
            "reconciles. It is not revoked -- the sender really did instruct "
            "that figure, and it is simply not the figure on the record now."
        ),
    }


@router.post("/sweep", dependencies=[Depends(
    ControlPlaneGuard("a2a_administer", target=fixed("a2a_ledger")))])
async def sweep(session: SessionDep) -> dict[str, Any]:
    """Move overdue transactions to EXPIRED.

    HOUSEKEEPING, NOT ENFORCEMENT. A transaction past its expiry is already
    unusable -- verification compares against the server clock and the
    execution claim folds expiry into its atomic condition, and neither waits
    for this. It exists so the stored status matches reality for anyone
    reading the table, and so A2A_EXPIRED is emitted at all.
    """
    service = A2ATransactionService(session)
    expired = await service.sweep_expired()
    return {
        "expired": expired,
        "count": len(expired),
        "note": "housekeeping only; an expired transaction was already unusable",
    }
