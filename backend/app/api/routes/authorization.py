"""Authorization endpoints: the PDP, the AEM and policy administration.

    POST /api/v1/authorize   ask the PDP for a decision (decides nothing else)
    POST /api/v1/enforce     ask the AEM to perform a protected operation
    GET  /api/v1/policies    policy lifecycle (PAP)

A note on what `/authorize` is for: it returns a DECISION, not access. Calling
it and receiving ALLOW does not give the caller the resource -- only the AEM can
reach a protected tool, and it re-evaluates through the PDP when it does. The
endpoint exists so a decision can be inspected, audited and tested on its own.

PHASE 4.5. Every mutating route here now sits behind the control-plane guard.
The two that matter most:

  /authorize and /enforce  the caller must PROVE it is the subject it names, or
                           hold the `enforcement` role. Before this, anyone who
                           could reach the port could name risk-001 and receive
                           real credit data from /enforce -- the PDP decided
                           correctly about an identity nobody had checked.

  /policies/*              policy administration requires the `policy_admin`
                           role. An unauthenticated caller could previously
                           deactivate every policy. That failed CLOSED (the
                           combining algorithm then denies everything), so it
                           was denial of service rather than escalation -- but
                           a security control anyone can switch off is not one.

The READ routes stay open: a decision log, a policy listing and the engine's
health are diagnostic surfaces, and closing them would break the console
without protecting anything that can be changed.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, status as http_status
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import KeyStoreDep, SessionDep, SettingsDep
from app.authorization.contracts import (
    AuthorizationRequest,
    MalformedAuthorizationRequest,
    Resource,
    Subject,
    new_request_id,
)
from app.authorization.opa import OPAClient
from app.authorization.pap import PolicyAdministrationPoint, PolicyLoadError
from app.authorization.pdp import PolicyDecisionPoint
from app.controlplane.guard import ControlPlaneGuard, body_key, fixed, path_param
from app.core.errors import IdentityError, NotFoundError
from app.enforcement.aem import AdapterEnforcementMiddleware, UnknownToolError
from app.enforcement.tools import build_default_registry

router = APIRouter(prefix="/api/v1", tags=["authorization"])


# --- schemas ---------------------------------------------------------------
class SubjectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    did: str = Field(description="The agent DID asking to act")
    type: str = Field(default="agent", description="Phase 4 authorizes agents only")


class ResourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(description="e.g. credit_records, payroll_records")
    id: str | None = Field(default=None, description="The specific record")
    classification: str | None = None


class AuthorizeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: SubjectIn
    action: str
    resource: ResourceIn
    purpose: str = Field(
        description="Why the action is being taken. Required: an action name "
                    "alone does not describe purpose, and policy distinguishes them."
    )
    credentials: list[str] = Field(
        default_factory=list,
        description="Credential ids the subject offers. A claim, not evidence: "
                    "each one is verified by the PIP before policy sees it.",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Caller-supplied context. UNTRUSTED. Self-asserted verdict "
                    "keys (allow, decision, trust_score, approval, ...) are "
                    "stripped before policy evaluation and the attempt is recorded.",
    )
    approval_id: str | None = Field(
        default=None,
        description="A human approval the caller OFFERS. A claim, not evidence: "
                    "the artifact is verified and must be bound to this exact "
                    "request. When omitted, an approval bound to this request "
                    "is looked up by binding.",
    )
    request_id: str | None = Field(
        default=None,
        description="Reuse the request id from an escalated attempt to retry it. "
                    "An approval is bound to ONE request, so a retry under a new "
                    "id needs its own approval -- which is the point.",
    )
    jit_grant_id: str | None = Field(
        default=None,
        description="A JIT mandate the caller OFFERS. A claim, not evidence: the "
                    "grant is verified against the JIT authority and its scope "
                    "must cover this exact request. Unlike an approval, a mandate "
                    "is NOT bound to one request id -- it is reusable within its "
                    "budget and window, and every use is decided afresh.",
    )


class EnforceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: SubjectIn
    tool: str = Field(description="Name of the protected tool to invoke")
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str
    credentials: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = None
    request_id: str | None = None
    jit_grant_id: str | None = None


def _to_request(body: AuthorizeIn) -> AuthorizationRequest:
    return AuthorizationRequest(
        request_id=body.request_id or new_request_id(),
        subject=Subject(did=body.subject.did, type=body.subject.type),
        action=body.action,
        resource=Resource(
            type=body.resource.type,
            id=body.resource.id,
            classification=body.resource.classification,
        ),
        purpose=body.purpose,
        credentials=body.credentials,
        context=body.context,
        approval_id=body.approval_id,
        jit_grant_id=body.jit_grant_id,
    )


# --- PDP -------------------------------------------------------------------
@router.post("/authorize", dependencies=[Depends(
    ControlPlaneGuard("pdp_query", target=body_key("subject", "did")))])
async def authorize(
    body: AuthorizeIn, session: SessionDep, keystore: KeyStoreDep
) -> dict[str, Any]:
    """Evaluate an authorization request.

    Always HTTP 200 for an evaluated request: DENY is an answer, not an error --
    the same convention the Phase 2 verifier uses. A request that could not be
    evaluated at all (malformed) is 422.
    """
    request = _to_request(body)
    try:
        request.validate()
    except MalformedAuthorizationRequest as exc:
        raise IdentityError(str(exc)) from exc
    decision = await PolicyDecisionPoint(session, keystore).decide(request)
    return decision.to_dict()


# --- AEM -------------------------------------------------------------------
@router.post("/enforce", dependencies=[Depends(
    ControlPlaneGuard("aem_enforce", target=body_key("subject", "did")))])
async def enforce(
    body: EnforceIn, session: SessionDep, keystore: KeyStoreDep
) -> dict[str, Any]:
    """Attempt a protected operation through the enforcement boundary.

    This is the ONLY route to a protected tool. On DENY or
    HUMAN_APPROVAL_REQUIRED the tool is never called and no resource data is
    returned.
    """
    aem = AdapterEnforcementMiddleware(session, keystore)
    try:
        result = await aem.enforce(
            subject_did=body.subject.did,
            tool_name=body.tool,
            arguments=body.arguments,
            purpose=body.purpose,
            request_id=body.request_id,
            context=body.context,
            credentials=body.credentials,
            approval_id=body.approval_id,
            jit_grant_id=body.jit_grant_id,
        )
    except UnknownToolError as exc:
        raise NotFoundError(str(exc)) from exc
    return result.to_dict()


@router.get("/enforce/tools")
async def protected_tools() -> list[dict[str, Any]]:
    """The protected tools and the resource/action each is authorized against.

    These are NOT in any agent's own tool registry: an agent cannot select one
    directly, it can only ask the AEM.
    """
    return build_default_registry().describe()


# --- PAP -------------------------------------------------------------------
@router.get("/policies")
async def list_policies(session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
    """Policy lifecycle state, including drift between disk and the engine."""
    return await PolicyAdministrationPoint(session, settings).status_report()


@router.post("/policies/reload", status_code=http_status.HTTP_200_OK,
             dependencies=[Depends(
                 ControlPlaneGuard("policy_reload", target=fixed("policy_set")))])
async def reload_policies(session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
    pap = PolicyAdministrationPoint(session, settings)
    try:
        return await pap.load_all()
    except PolicyLoadError as exc:
        raise IdentityError(str(exc)) from exc


@router.post("/policies/{policy_id}/activate", dependencies=[Depends(
    ControlPlaneGuard("policy_activate", target=path_param("policy_id")))])
async def activate_policy(
    policy_id: str, session: SessionDep, settings: SettingsDep
) -> dict[str, Any]:
    record = await PolicyAdministrationPoint(session, settings).activate(policy_id)
    return {"policy_id": record.policy_id, "version": record.version,
            "status": record.status.value}


@router.post("/policies/{policy_id}/deactivate", dependencies=[Depends(
    ControlPlaneGuard("policy_deactivate", target=path_param("policy_id")))])
async def deactivate_policy(
    policy_id: str, session: SessionDep, settings: SettingsDep
) -> dict[str, Any]:
    """Remove a policy from OPA.

    Its rules genuinely stop being evaluated. Because the combining algorithm is
    default-deny, removing policy makes the system MORE restrictive, never less.
    """
    record = await PolicyAdministrationPoint(session, settings).deactivate(policy_id)
    return {"policy_id": record.policy_id, "version": record.version,
            "status": record.status.value}


# --- decisions -------------------------------------------------------------
@router.get("/authorize/decisions")
async def list_decisions(
    session: SessionDep,
    subject: str | None = None,
    decision: str | None = None,
    limit: int = Query(default=50, le=500),
) -> list[dict[str, Any]]:
    """The authorization decision log."""
    from sqlalchemy import select

    from app.db.models.authorization import AuthorizationDecisionRecord

    stmt = select(AuthorizationDecisionRecord).order_by(
        AuthorizationDecisionRecord.decided_at.desc()
    )
    if subject:
        stmt = stmt.where(AuthorizationDecisionRecord.subject_did == subject)
    if decision:
        stmt = stmt.where(AuthorizationDecisionRecord.decision == decision.upper())
    rows = (await session.execute(stmt.limit(limit))).scalars().all()
    return [
        {
            "request_id": r.request_id,
            "subject": r.subject_did,
            "action": r.action,
            "resource": {"type": r.resource_type, "id": r.resource_id},
            "purpose": r.purpose,
            "decision": r.decision,
            "reason": r.reason,
            "policy": f"{r.policy_id}:{r.policy_version}" if r.policy_id else None,
            "latency_ms": r.latency_ms,
            "stages": r.stages,
            "decided_at": r.decided_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/authorize/health")
async def authorization_health(settings: SettingsDep) -> dict[str, Any]:
    """Is the policy engine reachable?

    Reported honestly. When OPA is down every authorization DENIES -- the
    system does not degrade to permissive.
    """
    opa = OPAClient(settings)
    try:
        health = await opa.health()
    finally:
        await opa.aclose()
    return {
        "component": "authorization",
        "phase": 4,
        "opa": health,
        "fail_closed": settings.authorization_fail_closed,
        "note": "If OPA is unavailable, every decision is DENY "
                "(AUTHORIZATION_UNAVAILABLE). There is no permissive fallback.",
    }
