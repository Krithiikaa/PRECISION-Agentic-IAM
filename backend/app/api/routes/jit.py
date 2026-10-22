"""JIT temporary access endpoints (Phase 6).

    POST /api/v1/jit/request         ask for a mandate
    GET  /api/v1/jit/{grant_id}      read one, including its uses
    GET  /api/v1/jit                 list an agent's mandates
    POST /api/v1/jit/{id}/revoke     kill one early
    POST /api/v1/jit/keys/rotate     rotate the signing key
    GET  /api/v1/jit/keys            the public key register
    POST /api/v1/jit/sweep           move overdue mandates to EXPIRED

EVERY MUTATING ROUTE IS BEHIND THE CONTROL-PLANE GUARD, so the sequence is the
same one every other mutation in this system goes through:

    signed request -> authenticate -> control-plane authorize -> handler

and the handler only ever runs on the far side of both.

WHAT THIS FILE DELIBERATELY DOES NOT CONTAIN: any decision about whether a
mandate may be issued. Not a TTL comparison, not an eligibility list, not a
role check. `AEM.issue_jit_grant()` runs the full data-plane PDP evaluation and
then the JIT issuance policy; this file unpacks a request and returns what
those two decided. A privilege check here would be policy escaped into a route
handler where nobody reviews it.

THE GRANT IS RETURNED TO THE AGENT, artifact and all. That is safe because a
mandate is NOT A BEARER TOKEN: using it requires a control-plane proof signed
by the agent DID the mandate names, so the document alone buys an attacker
nothing. Its security is its signature and its binding, not its secrecy.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import KeyStoreDep, SessionDep, SettingsDep
from app.controlplane.authenticator import ControlPlanePrincipalView
from app.controlplane.guard import ControlPlaneGuard, body_key, fixed, path_param
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.enforcement.aem import AdapterEnforcementMiddleware
from app.jit.authority import JITAuthority
from app.jit.service import JITService

log = get_logger("api.jit")

router = APIRouter(prefix="/api/v1/jit", tags=["jit"])


class JITRequestIn(BaseModel):
    """What an agent asks for.

    Note what is NOT here: an expiry, a grant id, a signature, or anything
    resembling a verdict. A caller states what it wants to do and for how long;
    every one of those is a request, and policy is what answers.
    """

    model_config = ConfigDict(extra="forbid")

    subject_did: str = Field(description="The agent the mandate is for.")
    action: str = Field(description="The action to be mandated, e.g. 'read'.")
    resource_type: str = Field(description="The resource type, e.g. 'credit_records'.")
    resource_ids: list[str] = Field(
        default_factory=list,
        description="The specific instances this mandate covers. An empty list "
                    "requests a mandate over the resource TYPE, which is weaker "
                    "and which policy may refuse.",
    )
    purpose: str = Field(description="Why, e.g. 'loan_assessment'.")
    # Bounded here only to keep a nonsensical value out of the policy call.
    # The real ceilings are policy configuration and are enforced by Rego.
    ttl_seconds: int | None = Field(
        default=None, gt=0, le=86_400,
        description="Requested lifetime. Policy caps this; omitted means the "
                    "configured default.",
    )
    max_uses: int | None = Field(
        default=None, gt=0, le=1_000,
        description="Requested budget. Policy caps this; omitted means the "
                    "configured default.",
    )
    credentials: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = Field(
        default=None,
        description="An approval to carry forward, when the action needs one.",
    )


class RevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(max_length=500, description="Why this mandate is being killed.")


class RotateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(max_length=500)


@router.post("/request", dependencies=[Depends(
    ControlPlaneGuard("jit_request", target=body_key("subject_did")))])
async def request_grant(
    body: JITRequestIn, request: Request,
    session: SessionDep, keystore: KeyStoreDep, settings: SettingsDep,
) -> dict[str, Any]:
    """Ask for a mandate.

    The guard has already established WHO is calling and that they may use this
    endpoint at all; `agent_self.rego` additionally refuses an agent asking for
    a mandate naming a different agent. What happens next is two policy
    evaluations, in the AEM.

    A refusal returns 200 with `issued: false` and the reason, rather than an
    error status. That is deliberate: "you may not have a mandate for this" is
    a policy answer, and it carries the PDP decision alongside so a caller can
    tell "no mandate for you" from "you may not do this at all".
    """
    aem = AdapterEnforcementMiddleware(session, keystore, settings)
    result = await aem.issue_jit_grant(
        subject_did=body.subject_did,
        action=body.action,
        resource_type=body.resource_type,
        resource_ids=body.resource_ids,
        purpose=body.purpose,
        ttl_seconds=body.ttl_seconds or settings.jit_default_ttl_seconds,
        max_uses=body.max_uses or settings.jit_default_max_uses,
        context=body.context,
        credentials=body.credentials,
        approval_id=body.approval_id,
    )
    return result.to_dict()


@router.get("")
async def list_grants(
    session: SessionDep,
    agent_did: str = Query(description="Whose mandates to list."),
    active_only: bool = Query(default=False),
) -> list[dict[str, Any]]:
    """Mandates held by one agent.

    Readable without a signed request: a mandate's scope is not a secret, and
    an operator needs to be able to see what temporary authority is live
    without first assembling a control-plane proof. The ARTIFACT is omitted
    from the list -- it is available on the individual record.
    """
    service = JITService(session)
    return [record.to_dict() for record in
            await service.for_agent(agent_did, active_only=active_only)]


@router.get("/keys")
async def key_register(
    session: SessionDep, keystore: KeyStoreDep, settings: SettingsDep,
) -> dict[str, Any]:
    """The JIT authority's public key register.

    Public material only, and every row says so. A verifier needs the public
    key of whichever generation signed the mandate in front of it, which is why
    retired keys stay published.
    """
    authority = JITAuthority(session, keystore, settings)
    principal = await authority.get()
    keys = await authority.keys()
    active = await authority.active_key()
    return {
        "did": authority.did,
        "did_document": principal.did_document if principal else None,
        "active_kid": active.kid if active else None,
        "keys": [key.to_dict() for key in keys],
        "private_key": "NEVER EXPOSED - held by the KeyStore",
    }


@router.get("/{grant_id}")
async def read_grant(grant_id: str, session: SessionDep) -> dict[str, Any]:
    """One mandate, its signed artifact, and every use spent against it."""
    service = JITService(session)
    record = await service.get(grant_id)
    if record is None:
        raise NotFoundError(f"No JIT grant {grant_id!r}")
    return {
        **record.to_dict(),
        "artifact": record.artifact,
        "uses_recorded": [use.to_dict() for use in await service.uses_of(grant_id)],
    }


@router.post("/{grant_id}/revoke", dependencies=[Depends(
    ControlPlaneGuard("jit_revoke", target=path_param("grant_id")))])
async def revoke_grant(
    grant_id: str, body: RevokeIn, request: Request, session: SessionDep,
) -> dict[str, Any]:
    """Kill a mandate before its window closes.

    Takes effect IMMEDIATELY -- the next use re-reads the record, finds it
    REVOKED and is refused, because every use re-reads rather than trusting
    anything cached. Revoking an already-terminal mandate is a refusal rather
    than a silent success, so an operator cannot believe they have contained
    something they have not.
    """
    principal: ControlPlanePrincipalView = request.state.control_plane_principal
    service = JITService(session)
    record = await service.revoke(
        grant_id, reason=body.reason, revoked_by=principal.did,
    )
    return {
        **record.to_dict(),
        "effect": (
            "immediate: the next use re-reads this record and is refused. "
            "Nothing is cached between uses."
        ),
    }


@router.post("/agents/{agent_did}/revoke", dependencies=[Depends(
    ControlPlaneGuard("jit_revoke", target=path_param("agent_did")))])
async def revoke_agent_grants(
    agent_did: str, body: RevokeIn, request: Request, session: SessionDep,
) -> dict[str, Any]:
    """Revoke every live mandate held by one agent.

    THE CONTAINMENT INTEGRATION POINT. Phase 6 exposes the mechanism; Phase 10
    (threat detection) and Phase 12 (the kill switch) are the callers that do
    not exist yet, and this exists so they have something to call rather than a
    reason to invent a second revocation path.

    NOT NEEDED for an agent whose credential was revoked or whose identity was
    suspended -- those already stop every use, because every use re-runs the
    PDP. This is for containing an agent whose credentials are still valid.
    """
    principal: ControlPlanePrincipalView = request.state.control_plane_principal
    service = JITService(session)
    revoked = await service.revoke_for_agent(
        agent_did, reason=body.reason, revoked_by=principal.did,
    )
    return {
        "agent_did": agent_did,
        "revoked": revoked,
        "count": len(revoked),
        "reason": body.reason,
        "revoked_by": principal.did,
    }


@router.post("/keys/rotate", dependencies=[Depends(
    ControlPlaneGuard("jit_key_rotate", target=fixed("jit_authority")))])
async def rotate_key(
    body: RotateIn, request: Request,
    session: SessionDep, keystore: KeyStoreDep, settings: SettingsDep,
) -> dict[str, Any]:
    """Retire the active signing key and start signing with a new one.

    Mandates already issued stay verifiable: the retired key remains published
    and its grants are dated inside its window. A retired key cannot sign
    anything new, because signing resolves the ACTIVE row rather than a key id
    anyone supplies.
    """
    principal: ControlPlanePrincipalView = request.state.control_plane_principal
    authority = JITAuthority(session, keystore, settings)
    return await authority.rotate(reason=body.reason, actor=principal.did)


@router.post("/sweep", dependencies=[Depends(
    ControlPlaneGuard("jit_revoke", target=fixed("jit_grants")))])
async def sweep(session: SessionDep) -> dict[str, Any]:
    """Move overdue mandates to EXPIRED.

    HOUSEKEEPING, NOT ENFORCEMENT. A mandate past its expiry is already
    unusable -- both the use path and the verification path compare against the
    server clock and neither waits for this. This exists so the stored status
    matches reality for anyone reading the table, and so JIT_EXPIRED is
    emitted at all.
    """
    service = JITService(session)
    expired = await service.sweep_expired()
    return {
        "expired": expired,
        "count": len(expired),
        "note": "housekeeping only; an expired mandate was already unusable",
    }
