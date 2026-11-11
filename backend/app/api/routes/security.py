"""Security operations API: trust, anomalies, sessions, incidents (kill switch).

    GET  /api/v1/security/trust                     every scored agent, lowest first
    GET  /api/v1/security/trust/{did}               score, level and the signals behind it
    GET  /api/v1/security/alerts                    anomaly-detector output
    POST /api/v1/security/detector/run              process unread audit events now
    GET  /api/v1/security/sessions/{did}            the SSS ledger entry for one agent
    GET  /api/v1/security/impact/{did}              blast radius: what the agent can reach
    GET  /api/v1/security/incidents                 containments, newest first
    GET  /api/v1/security/incidents/{id}            one incident, with its frozen impact
    POST /api/v1/security/incidents                 CONTAIN an agent (the kill switch)
    POST /api/v1/security/incidents/{id}/reinstate  reverse it, with a written review

Every route is behind the same ControlPlaneGuard as the rest of the control
plane. Reads are `audit_read` (AUDITOR, IAM_ADMIN, the identity administrator
machine principal); the two mutations are HIGH_RISK operations held by the
identity administrator only.

The change is COMMITTED before the SSS push is sent, so a subscriber that
reacts to the push and re-reads the database sees the new state rather than
racing the commit.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.api.deps import KeyStoreDep, SessionDep, SettingsDep
from app.controlplane.authenticator import ControlPlanePrincipalView
from app.controlplane.guard import ControlPlaneGuard, body_key, fixed, path_param
from app.db.models.security import IncidentTrigger, SecurityAlert
from app.sessions.authority import ReinstatementRefused, SessionAuthority
from app.sessions.sss import SessionStateSynchronizer
from app.trust.detector import AnomalyDetector
from app.trust.engine import TrustEngine

router = APIRouter(prefix="/api/v1/security", tags=["security"])


class ContainIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_did: str = Field(min_length=8, max_length=255)
    justification: str = Field(min_length=10, max_length=2000)
    alert_id: str | None = Field(default=None, max_length=64)
    # Irreversible, so never the default: revoked VCs must be re-issued.
    revoke_credentials: bool = False


class ReinstateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    review: str = Field(min_length=20, max_length=5000)


def _principal(request: Request) -> str:
    principal: ControlPlanePrincipalView = request.state.control_plane_principal
    return principal.did


@router.get("/trust", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=fixed("trust_scores")))])
async def trust_overview(session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
    return {
        "bands": {"TRUSTED": f">= {settings.trust_reduced_below}",
                  "REDUCED": f">= {settings.trust_untrusted_below}",
                  "UNTRUSTED": f"< {settings.trust_untrusted_below}"},
        "note": "agents with no recorded signals are at 100 and are not listed",
        "agents": await TrustEngine(session, settings).overview(),
    }


@router.get("/trust/{did:path}", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=path_param("did")))])
async def trust_for(did: str, session: SessionDep, settings: SettingsDep,
                    include_expired: bool = False) -> dict[str, Any]:
    engine = TrustEngine(session, settings)
    assessment = await engine.assess(did)
    return {"agent_did": did, **assessment.to_fact(),
            "signals": await engine.signals(did, include_expired=include_expired)}


@router.get("/alerts", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=fixed("security_alerts")))])
async def alerts(session: SessionDep, agent_did: str | None = None,
                 limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, Any]]:
    query = select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(limit)
    if agent_did:
        query = query.where(SecurityAlert.agent_did == agent_did)
    rows = (await session.execute(query)).scalars()
    return [{"alert_id": r.alert_id, "agent_did": r.agent_did, "rule": r.rule,
             "severity": r.severity.value, "status": r.status.value,
             "summary": r.summary, "attributed": r.attributed,
             "evidence": r.evidence, "created_at": r.created_at.isoformat()} for r in rows]


@router.post("/detector/run", dependencies=[Depends(
    ControlPlaneGuard("anomaly_scan", target=fixed("audit_trail")))])
async def run_detector(session: SessionDep, keystore: KeyStoreDep,
                       settings: SettingsDep) -> dict[str, Any]:
    run = await AnomalyDetector(session, keystore, settings).run_once()
    await session.commit()
    pushes = [await SessionStateSynchronizer(session, settings).publish(c) for c in run.changes]
    return {**run.to_dict(), "sss_push": pushes}


@router.get("/sessions/{did:path}", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=path_param("did")))])
async def session_state(did: str, session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
    return {"agent_did": did, **await SessionStateSynchronizer(session, settings).fact(did)}


@router.get("/impact/{did:path}", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=path_param("did")))])
async def impact(did: str, session: SessionDep, keystore: KeyStoreDep,
                 settings: SettingsDep,
                 window_hours: int = Query(default=24, ge=1, le=720)) -> dict[str, Any]:
    return await SessionAuthority(session, keystore, settings).impact(
        did, window_hours=window_hours)


@router.get("/incidents", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=fixed("incidents")))])
async def incidents(session: SessionDep, keystore: KeyStoreDep,
                    settings: SettingsDep) -> list[dict[str, Any]]:
    return await SessionAuthority(session, keystore, settings).incidents()


@router.get("/incidents/{incident_id}", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=path_param("incident_id")))])
async def incident(incident_id: str, session: SessionDep, keystore: KeyStoreDep,
                   settings: SettingsDep) -> dict[str, Any]:
    return await SessionAuthority(session, keystore, settings).get_incident(incident_id)


@router.post("/incidents", status_code=201, dependencies=[Depends(
    ControlPlaneGuard("incident_contain", target=body_key("agent_did")))])
async def contain(body: ContainIn, request: Request, session: SessionDep,
                  keystore: KeyStoreDep, settings: SettingsDep) -> dict[str, Any]:
    report = await SessionAuthority(session, keystore, settings).contain(
        body.agent_did, justification=body.justification,
        opened_by=_principal(request), trigger=IncidentTrigger.MANUAL,
        alert_id=body.alert_id, revoke_credentials=body.revoke_credentials)
    await session.commit()
    sss = SessionStateSynchronizer(session, settings)
    return {**report.to_dict(), "sss_push": [await sss.publish(c) for c in report.changes]}


@router.post("/incidents/{incident_id}/reinstate", dependencies=[Depends(
    ControlPlaneGuard("incident_reinstate", target=path_param("incident_id")))])
async def reinstate(incident_id: str, body: ReinstateIn, request: Request,
                    session: SessionDep, keystore: KeyStoreDep,
                    settings: SettingsDep) -> dict[str, Any]:
    authority = SessionAuthority(session, keystore, settings)
    try:
        result, change = await authority.reinstate(
            incident_id, reinstated_by=_principal(request), review=body.review)
    except ReinstatementRefused as exc:
        # Audited (INCIDENT_REINSTATEMENT_REFUSED); keep that record. Same 409
        # and `CONFLICT` code as any conflict, plus the server's revalidation
        # results (Phase 12) so the console shows which check failed.
        await session.commit()
        return JSONResponse(status_code=409, content={
            "error": "CONFLICT", "detail": str(exc), "revalidation": exc.revalidation})
    except Exception:
        # A refusal is itself audited (INCIDENT_REINSTATEMENT_REFUSED); keep
        # that record even though the request fails.
        await session.commit()
        raise
    await session.commit()
    return {**result, "sss_push": await SessionStateSynchronizer(session, settings).publish(change)}
