"""Audit trail: query, and ingest from agent processes.

PHASE 5 -- S-7. Ingest is authenticated. An unauthenticated write into the
audit trail is audit FORGERY: an attacker could manufacture a record of events
that never happened, or bury real ones under noise. Reading stays open; the
trail is meant to be inspectable.

An agent may write its OWN activity (bound to self, exactly like a heartbeat).
Writing history for another principal requires `identity_admin`.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request, status

from app.api.deps import KeyStoreDep, SessionDep
from app.api.schemas import AuditEventIn
from app.controlplane.guard import ControlPlaneGuard, body_key, fixed
from app.audit.service import AuditService
from app.monitoring.events import Event

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=fixed("audit_trail")))])
async def query_audit(
    session: SessionDep,
    event_type: str | None = None,
    agent_did: str | None = None,
    decision: str | None = None,
    since: datetime | None = None,
    request_id: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=200, le=1000),
    offset: int = 0,
) -> list[dict]:
    return await AuditService(session).query(
        event_type=event_type,
        agent_did=agent_did,
        decision=decision,
        since=since,
        request_id=request_id,
        limit=limit,
        offset=offset,
    )


@router.post("/events", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(
    ControlPlaneGuard("audit_ingest", target=body_key("agent_did")))])
async def ingest_event(
    body: AuditEventIn, request: Request, session: SessionDep
) -> dict:
    """Accept telemetry from a running agent process.

    PHASE 5 CLOSED THE GAP that used to be documented here. Ingest was
    unauthenticated, so an event's `agent_did` was a claim rather than a proven
    fact -- which made the audit trail forgeable by anyone who could reach the
    port, in either direction: manufacturing events that never happened, or
    burying real ones under noise.

    The caller now proves control of the DID it writes under (an agent signing
    for itself, exactly like a heartbeat), or holds `identity_admin` to write
    on another principal's behalf. The recorded event says which.
    """
    principal = request.state.control_plane_principal
    known = set(AuditEventIn.model_fields)
    extra = {k: v for k, v in body.model_dump().items() if k not in known}
    await AuditService(session).record(
        Event(
            event_type=body.event_type,
            agent_did=body.agent_did,
            session_id=body.session_id,
            request_id=body.request_id,
            resource=body.resource,
            action=body.action,
            decision=body.decision,
            reason=body.reason,
            metadata={
                **extra,
                "source": "agent-process",
                # The event is now attributable. Recording WHO wrote it, and
                # under which principal type, so a reader can tell an agent's
                # own report from an administrator writing on its behalf.
                "ingested_by": principal.did,
                "ingested_by_type": principal.type,
            },
        )
    )
    return {"accepted": True}


# --- Phase 12: audit integrity --------------------------------------------
@router.get("/integrity", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=fixed("audit_integrity")))])
async def verify_integrity(session: SessionDep, keystore: KeyStoreDep) -> dict:
    """Verify the hash chain, every MAC and every signed checkpoint, now.

    Runs entirely server-side against the database. A failure is also
    raised as an AUDIT_INTEGRITY_VIOLATION event and a CRITICAL alert, so
    asking the question cannot hide the answer.
    """
    from app.audit.chain import AuditChain

    chain = AuditChain(session, keystore)
    report = await chain.verify()
    body = report.to_dict()
    if not report.ok:
        body["alert_id"] = await chain.report_violation(report)
        await session.commit()
    return body


@router.get("/integrity/checkpoints", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=fixed("audit_integrity")))])
async def integrity_checkpoints(
    session: SessionDep, keystore: KeyStoreDep, limit: int = Query(default=50, le=500)
) -> dict:
    """Signed checkpoints and the checkpoint public key, for external anchoring.

    An auditor who records a checkpoint (and the key) outside this system can
    later detect truncation of the chain together with its checkpoints, which
    the database alone cannot reveal.
    """
    from app.audit.chain import AuditChain

    chain = AuditChain(session, keystore)
    return {"trusted_keys": chain.trusted_keys(),
            "checkpoints": await chain.checkpoints(limit=limit)}
