"""Human-in-the-Loop endpoints: the approval queue and the decision.

    GET  /api/v1/hitl/config       what the browser needs to start an OIDC login
    GET  /api/v1/hitl/me           who this token says you are, and what you may do
    GET  /api/v1/hitl/approvals    the queue
    GET  /api/v1/hitl/approvals/{id}  ONE approval, in full -- what §16 requires
    POST /api/v1/hitl/approvals/{id}/decide   approve or reject
    POST /api/v1/hitl/approvals/{id}/cancel   withdraw a pending request
    GET  /api/v1/hitl/authority/keys          the signing key register
    POST /api/v1/hitl/authority/keys/rotate   retire the active key (Phase 5.5)

Every route that changes anything goes through the PHASE 4.5 CONTROL-PLANE
GUARD, unchanged: authenticate the principal, then ask the PDP. Phase 5 did not
build a second administrative surface with its own rules -- it added a
principal type to the one that already exists.

WHAT THESE ROUTES DO NOT DO: touch a resource. Approving a loan here records a
decision. The loan is only ever changed by the AEM, later, after the PDP has
been asked again. A human decision and a resource mutation are kept a full
policy evaluation apart, on purpose.
"""
from __future__ import annotations

from typing import Any

from fastapi import Depends, Request, status as http_status
from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import KeyStoreDep, SessionDep, SettingsDep
from app.controlplane.authenticator import ControlPlanePrincipalView
from app.controlplane.guard import ControlPlaneGuard, attributes, fixed, path_param
from app.core.errors import ConflictError, IdentityError, NotFoundError
from app.db.models.hitl import ApprovalDecision, ApprovalStatus
from app.hitl.service import ApprovalNotPending, ApprovalService, InvalidTransition
from app.humans.oidc import OIDCValidator, TokenInvalid, bearer_token
from app.humans.principals import HumanPrincipalRegistry

router = APIRouter(prefix="/api/v1/hitl", tags=["hitl"])


class DecideIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(description="APPROVED or REJECTED")
    note: str | None = Field(default=None, max_length=1000)


class CancelIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="WITHDRAWN", max_length=200)


async def _approval_record(request: Request):
    """The approval row this request is about, from the guard's own session.

    Deliberately NOT read from the request body. A caller claiming
    `{"action": "read"}` to slip a loan approval past a weaker role check is
    exactly the attack these resolvers exist to prevent, so every attribute
    policy sees about the approval comes from server-held state.
    """
    approval_id = request.path_params.get("approval_id")
    session = getattr(request.state, "control_plane_session", None)
    if not approval_id or session is None:
        return None
    return await ApprovalService(session).get(approval_id)


async def _approval_action(request: Request, body: Any) -> str | None:
    """The ACTION the approval is about, read from SERVER-SIDE state.

    Policy needs this: "may this human approve THIS?" is a different question
    for a loan decision and for a policy change, and a loan officer is the
    right answer to only one of them.

    Returning None when the approval does not exist is safe: no role approves
    an unknown action, so policy denies with NO_ROLE_APPROVES_THIS_ACTION.
    """
    record = await _approval_record(request)
    return record.action if record else None


async def _approval_submitted_by(request: Request, body: Any) -> str | None:
    """The officer of record on the resource being approved (Phase 5.5).

    MAKER-CHECKER needs this: policy denies when the person deciding is the
    person who put the application forward. Resolved from the approval record
    to the resource record, both server-side -- a caller cannot influence who
    the system believes submitted an application.
    """
    from app.enforcement.resources import material_attributes

    record = await _approval_record(request)
    if record is None:
        return None
    return material_attributes(record.resource_type, record.resource_id).get(
        "submitted_by"
    )


async def _existing_approvers(request: Request, body: Any) -> list[dict[str, Any]]:
    """Who has ALREADY signed this approval (Phase 5.5).

    TWO-PERSON CONTROL needs this: policy denies a human who is already on the
    list. Identity is (issuer, subject) -- a username is a label, and a subject
    id is only unique within its issuer.

    The database refuses the duplicate INSERT as well. This refusal happens
    FIRST, so the attempt is denied by a named policy with a policy id an
    auditor can trace, rather than surfacing as a constraint violation.
    """
    record = await _approval_record(request)
    if record is None:
        return []
    session = request.state.control_plane_session
    return [
        {"issuer": s.approver_issuer, "subject": s.approver_subject}
        for s in await ApprovalService(session).signoffs(record.approval_id)
    ]


def _approval_target():
    return attributes(
        id=path_param("approval_id"),
        action=_approval_action,
        submitted_by=_approval_submitted_by,
        existing_approvers=_existing_approvers,
    )


def describe(record, signoffs: list | None = None) -> dict[str, Any]:
    """One approval, in full.

    Everything an approver needs is in `presentation`; the lifecycle fields are
    here too so a queue view can show what is still answerable. The signed
    artifact is included once decided -- it is a public document whose security
    is its signature, not its secrecy.

    `signoffs` (Phase 5.5) is every human decision recorded against this
    approval. A dual-control request sitting at 1 of 2 is still PENDING, and
    without this the queue could not tell "nobody has looked at it" from "one
    officer has signed and it is waiting for the second".
    """
    signoffs = list(signoffs or [])
    approved = [s for s in signoffs if s.decision.value == "APPROVED"]
    return {
        # --- dual control -------------------------------------------------
        "required_approvals": record.required_approvals,
        "approvals_recorded": len(approved),
        "awaiting_approvals": max(0, record.required_approvals - len(approved)),
        "dual_control": record.required_approvals > 1,
        # Every sign-off, in order. No secret: who decided and when.
        "signoffs": [s.to_dict() for s in signoffs],
        "approval_id": record.approval_id,
        "request_id": record.request_id,
        "status": record.status.value,
        "decision": record.decision.value if record.decision else None,
        "agent_did": record.agent_did,
        "action": record.action,
        "resource": {"type": record.resource_type, "id": record.resource_id},
        "purpose": record.purpose,
        "reason": record.reason,
        "presentation": record.presentation,
        "requested_at": record.requested_at.isoformat(),
        "request_expires_at": record.request_expires_at.isoformat(),
        "decided_at": record.decided_at.isoformat() if record.decided_at else None,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        "consumed_at": record.consumed_at.isoformat() if record.consumed_at else None,
        "first_viewed_at": (record.first_viewed_at.isoformat()
                            if record.first_viewed_at else None),
        "approver": {
            "subject": record.approver_subject,
            "username": record.approver_username,
            "issuer": record.approver_issuer,
            "roles": record.approver_roles,
        } if record.approver_subject else None,
        "binding_sha256": record.binding_sha256,
        # WHAT was bound, not just its digest. An approver -- and an auditor --
        # can see the exact amount and officer of record the decision covers.
        "binding": record.binding,
        "domain": record.domain,
        "artifact": record.artifact,
        "artifact_signed_by": record.artifact_signed_by,
        "session_id": record.session_id,
        "decision_latency_ms": record.decision_latency_ms,
    }


# --- public: what the browser needs to log in ------------------------------
@router.get("/config")
async def hitl_config(settings: SettingsDep) -> dict[str, Any]:
    """The OIDC parameters the console needs. Public, and carries no secret.

    The console is a PUBLIC client using Authorization Code + PKCE, so there is
    nothing confidential to leak here -- these values are already visible in
    any browser that completes a login.
    """
    return {
        "provider": "keycloak",
        "issuer": settings.keycloak_issuer,
        "realm": settings.keycloak_realm,
        "client_id": settings.oidc_client_id,
        "audience": settings.oidc_audience,
        "authorization_endpoint":
            f"{settings.keycloak_issuer}/protocol/openid-connect/auth",
        "token_endpoint": f"{settings.keycloak_issuer}/protocol/openid-connect/token",
        "end_session_endpoint":
            f"{settings.keycloak_issuer}/protocol/openid-connect/logout",
        "flow": "authorization_code+pkce",
        "roles": {
            "IAM_ADMIN": "Manage agents, credentials and identity. Cannot approve loans.",
            "LOAN_OFFICER": "Approve loan decisions. No authority over IAM.",
            "AUDITOR": "Read the audit trail. Approves nothing.",
        },
    }


@router.get("/health")
async def hitl_health(session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
    """Is the identity provider reachable, and is the signing authority present?

    Reported honestly. When Keycloak is down, no human can authenticate and
    every escalated action stays blocked -- the system does not degrade to
    letting agents proceed unapproved.
    """
    from app.hitl.authority import ApprovalAuthority

    provider = await OIDCValidator(settings).provider_health()
    authority = await ApprovalAuthority(session, None, settings).get()
    return {
        "component": "hitl",
        "phase": 5,
        "identity_provider": provider,
        "approval_authority": {
            "did": settings.approval_authority_did,
            "present": authority is not None,
            "verification_method": authority.kid if authority else None,
        },
        "approval_ttl_seconds": settings.approval_ttl_seconds,
        "request_ttl_seconds": settings.approval_request_ttl_seconds,
        "note": (
            "If the identity provider is unavailable, no approval can be made "
            "and every escalated action remains BLOCKED. "
            "HUMAN_APPROVAL_REQUIRED never becomes ALLOW."
        ),
    }


# --- authenticated: who am I -----------------------------------------------
@router.get("/me")
async def whoami(
    request: Request, session: SessionDep, settings: SettingsDep
) -> dict[str, Any]:
    """Identity only.

    Note what this endpoint deliberately does NOT return: any statement about
    what the caller may do. Roles are reported because the console shows them,
    but every permission question is answered by the PDP at the point of
    action, never by a client reading this response.
    """
    token = bearer_token(dict(request.headers))
    if not token:
        raise IdentityError("This endpoint requires an OIDC bearer token.")
    try:
        identity = OIDCValidator(settings).validate(token)
    except TokenInvalid as exc:
        raise IdentityError(f"{exc.reason}: {exc.detail}") from exc
    principal = await HumanPrincipalRegistry(session).upsert(identity)
    return {
        **identity.to_dict(),
        "status": principal.status.value,
        "first_seen_at": principal.first_seen_at.isoformat(),
        "authentications": principal.authentications,
        "note": "Roles are reported for display. Every permission is decided by the PDP.",
    }


# --- the queue --------------------------------------------------------------
@router.get("/approvals")
async def list_approvals(
    session: SessionDep,
    status: str | None = None,
    agent_did: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """The approval queue.

    Readable without a token: it is a work queue, and it exposes what an agent
    WANTS to do, never any resource data. Deciding requires authentication and
    authorization; seeing that a decision is outstanding does not.
    """
    parsed = None
    if status:
        try:
            parsed = ApprovalStatus(status.upper())
        except ValueError as exc:
            raise IdentityError(f"Unknown approval status {status!r}") from exc
    service = ApprovalService(session)
    records = await service.list_requests(
        status=parsed, agent_did=agent_did, limit=min(limit, 200)
    )
    signoffs = await service.signoffs_for([r.approval_id for r in records])
    return [describe(r, signoffs.get(r.approval_id)) for r in records]


@router.get("/approvals/{approval_id}", dependencies=[Depends(
    ControlPlaneGuard("approval_view", target=_approval_target()))])
async def read_approval(
    approval_id: str, request: Request, session: SessionDep
) -> dict[str, Any]:
    """One approval, in full -- and record that a human looked at it.

    Reading is authenticated because opening a request is what makes a decision
    INFORMED, and `APPROVAL_VIEWED` is the audit evidence that it was. An
    approval decided by someone who never opened it is visible as exactly that.
    """
    service = ApprovalService(session)
    record = await service.require(approval_id)
    principal: ControlPlanePrincipalView = request.state.control_plane_principal
    if principal.is_human:
        await service.mark_viewed(record, _viewer(principal))
    return describe(record, await service.signoffs(approval_id))


class _Viewer:
    """Adapts the authenticated principal to what the service records."""

    def __init__(self, principal: ControlPlanePrincipalView) -> None:
        self.subject = principal.subject
        self.issuer = principal.issuer
        self.username = principal.username
        self.roles = principal.roles
        self.provider = "keycloak-oidc"
        self.principal_urn = principal.did


def _viewer(principal: ControlPlanePrincipalView) -> _Viewer:
    return _Viewer(principal)


# --- the decision -----------------------------------------------------------
@router.post("/approvals/{approval_id}/decide", dependencies=[Depends(
    ControlPlaneGuard("approval_decide", target=_approval_target()))])
async def decide_approval(
    approval_id: str,
    body: DecideIn,
    request: Request,
    session: SessionDep,
    keystore: KeyStoreDep,
    settings: SettingsDep,
) -> dict[str, Any]:
    """Record a human decision.

    By the time this body runs, two things have already happened, both outside
    this function: the caller proved WHO they are (OIDC, validated against
    Keycloak's JWKS) and the PDP decided they MAY approve THIS action. Neither
    check lives here, and neither is re-implemented here.

    On APPROVED an artifact is signed by the approval authority. It permits
    nothing by itself -- the agent must come back through the AEM, and the PDP
    is asked again.
    """
    principal: ControlPlanePrincipalView = request.state.control_plane_principal
    if not principal.is_human:
        # Unreachable in practice: policy already refuses machine principals.
        # Kept as a hard stop, because "a machine approved on a human's behalf"
        # must fail loudly rather than depend on one rule staying correct.
        raise IdentityError(
            "Only an authenticated human may decide an approval. A machine "
            "principal cannot stand in for a person."
        )
    try:
        decision = ApprovalDecision(body.decision.upper())
    except ValueError as exc:
        raise IdentityError(
            f"decision must be APPROVED or REJECTED, got {body.decision!r}"
        ) from exc

    service = ApprovalService(session, keystore, settings)
    record = await service.require(approval_id)
    try:
        record = await service.decide(
            record=record, approver=_viewer(principal),
            decision=decision, note=body.note,
        )
    except (ApprovalNotPending, InvalidTransition) as exc:
        raise ConflictError(str(exc)) from exc
    # DuplicateApprover and SelfApprovalRefused are ConflictErrors in their own
    # right and are deliberately NOT flattened here: a caller told "409
    # CONFLICT" for a two-person violation learns nothing, and the specific
    # class is what the audit trail and the console both key on.
    return describe(record, await service.signoffs(approval_id))


@router.post("/approvals/{approval_id}/cancel", dependencies=[Depends(
    ControlPlaneGuard("approval_cancel", target=_approval_target()))])
async def cancel_approval(
    approval_id: str, body: CancelIn, session: SessionDep
) -> dict[str, Any]:
    """Withdraw a pending request without deciding it."""
    service = ApprovalService(session)
    record = await service.require(approval_id)
    try:
        record = await service.cancel(record, body.reason)
    except InvalidTransition as exc:
        raise ConflictError(str(exc)) from exc
    return describe(record, await service.signoffs(approval_id))


# --- the approval authority's signing keys (Phase 5.5) ----------------------
class RotateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(
        default="scheduled rotation", max_length=500,
        description="Why the key is being rotated. Recorded in the audit trail.",
    )


@router.get("/authority/keys")
async def list_authority_keys(
    session: SessionDep, keystore: KeyStoreDep, settings: SettingsDep
) -> dict[str, Any]:
    """The approval authority's key register. PUBLIC MATERIAL ONLY.

    Readable without a token, for the same reason a DID Document is: everything
    here is what a verifier needs to check a signature it has been handed. No
    private key is returned by this route or any other -- the KeyStore signs on
    request and does not export.
    """
    from app.hitl.authority import ApprovalAuthority

    authority = ApprovalAuthority(session, keystore, settings)
    keys = await authority.keys()
    active = await authority.active_key()
    return {
        "did": authority.did,
        "active": active.to_dict() if active else None,
        "keys": [k.to_dict() for k in keys],
        "generations": len(keys),
        "rotation": {
            "signing": (
                "Only the ACTIVE key signs. A RETIRED key cannot issue a new "
                "artifact: signing resolves the active register row, and there "
                "is no parameter for a caller to name a key with."
            ),
            "verification": (
                "A RETIRED key still verifies artifacts whose proof was created "
                "at or before its retirement, so rotating does not invalidate "
                "history. A REVOKED key verifies nothing, including its own "
                "history -- that is the difference between rotation and "
                "revocation."
            ),
            "private_key": "never leaves the KeyStore; no route returns one",
        },
    }


@router.post("/authority/keys/rotate", dependencies=[Depends(
    ControlPlaneGuard("approval_key_rotate", target=fixed("approval-authority")))])
async def rotate_authority_key(
    body: RotateIn, request: Request, session: SessionDep,
    keystore: KeyStoreDep, settings: SettingsDep,
) -> dict[str, Any]:
    """Retire the active signing key and start signing with a new one.

    HIGH-RISK ADMINISTRATION. Whoever controls this key controls what an
    approval means, so the guard requires a machine administrator holding
    `identity_admin` -- no human role reaches it, including IAM_ADMIN. Changing
    which key attests that a person agreed to something must require more than
    a browser session.

    Nothing already issued is invalidated. That is the whole reason rotation and
    revocation are separate operations.
    """
    from app.hitl.authority import ApprovalAuthority

    principal: ControlPlanePrincipalView = request.state.control_plane_principal
    authority = ApprovalAuthority(session, keystore, settings)
    try:
        return await authority.rotate(reason=body.reason, actor=principal.did)
    except ConflictError:
        raise
    except NotFoundError:
        raise


# --- human principals -------------------------------------------------------
@router.get("/humans")
async def list_humans(session: SessionDep) -> list[dict[str, Any]]:
    """Everyone who has authenticated. The MINIMUM this system stores.

    Note what is absent: no password, no token, no refresh token, no session.
    `last_seen_roles` is what a token carried, recorded for audit and never
    read when deciding anything.
    """
    principals = await HumanPrincipalRegistry(session).list_principals()
    return [
        {
            "principal": p.principal_urn,
            "subject": p.subject,
            "issuer": p.issuer,
            "provider": p.provider,
            "username": p.username,
            "display_name": p.display_name,
            "status": p.status.value,
            "last_seen_roles": p.last_seen_roles,
            "first_seen_at": p.first_seen_at.isoformat(),
            "last_seen_at": p.last_seen_at.isoformat(),
            "authentications": p.authentications,
            "note": "last_seen_roles is an audit record; authorization uses the live token.",
        }
        for p in principals
    ]
