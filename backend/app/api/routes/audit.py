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

from app.api.deps import SessionDep
from app.api.schemas import AuditEventIn
from app.controlplane.guard import ControlPlaneGuard, body_key
from app.audit.service import AuditService
from app.monitoring.events import Event

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("")
async def query_audit(
    session: SessionDep,
    event_type: str | None = None,
    agent_did: str | None = None,
    decision: str | None = None,
    since: datetime | None = None,
    limit: int = Query(default=200, le=1000),
    offset: int = 0,
) -> list[dict]:
    return await AuditService(session).query(
        event_type=event_type,
        agent_did=agent_did,
        decision=decision,
        since=since,
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
