"""Live event stream (SSE).

Tails the `audit_events` table.

Why the table and not the in-process event bus: the system is several
processes -- the IAM API, the ANS service, and one per agent. A bus inside the
API process can only see events the API itself produced, so ANS discovery and
agent runtime events would silently never appear. Every process writes to
`audit_events`, so tailing it is the only way the stream can be complete.

Nothing here generates events. If the backend is idle, the stream sends
keepalives and nothing else.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from app.db.database import session_scope
from app.db.models.audit import AuditEvent

router = APIRouter(prefix="/api/v1/events", tags=["events"])

POLL_SECONDS = 0.4
KEEPALIVE_SECONDS = 15.0


def _serialise(event: AuditEvent) -> dict:
    return {
        "seq": event.seq,
        "timestamp": event.occurred_at.isoformat(),
        "event_type": event.event_type,
        "agent_did": event.agent_did,
        "session_id": event.session_id,
        "request_id": event.request_id,
        "resource": event.resource,
        "action": event.action,
        "decision": event.decision,
        "reason": event.reason,
        "metadata": event.event_metadata,
    }


async def _latest_seq() -> int:
    async with session_scope() as session:
        result = await session.execute(select(AuditEvent.seq).order_by(AuditEvent.seq.desc()).limit(1))
        return result.scalar_one_or_none() or 0


async def _after(cursor: int, limit: int = 200) -> list[AuditEvent]:
    async with session_scope() as session:
        result = await session.execute(
            select(AuditEvent)
            .where(AuditEvent.seq > cursor)
            .order_by(AuditEvent.seq)
            .limit(limit)
        )
        return list(result.scalars().all())


@router.get("/stream")
async def stream(
    replay: int = Query(default=0, ge=0, le=500,
                        description="Replay this many recent events before going live."),
) -> StreamingResponse:
    async def generator() -> AsyncIterator[str]:
        cursor = await _latest_seq()
        if replay:
            cursor = max(0, cursor - replay)
        yield ": connected\n\n"

        idle = 0.0
        while True:
            events = await _after(cursor)
            if events:
                idle = 0.0
                for event in events:
                    cursor = event.seq
                    payload = json.dumps(_serialise(event))
                    yield f"event: {event.event_type}\ndata: {payload}\n\n"
            else:
                await asyncio.sleep(POLL_SECONDS)
                idle += POLL_SECONDS
                if idle >= KEEPALIVE_SECONDS:
                    idle = 0.0
                    yield ": keepalive\n\n"

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
