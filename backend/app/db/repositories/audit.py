"""Append-only audit event access."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.audit import AuditEvent


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self,
        *,
        event_type: str,
        agent_did: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        resource: str | None = None,
        action: str | None = None,
        decision: str | None = None,
        reason: str | None = None,
        metadata: dict | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            agent_did=agent_did,
            session_id=session_id,
            request_id=request_id,
            resource=resource,
            action=action,
            decision=decision,
            reason=reason,
            event_metadata=metadata or {},
        )
        self.session.add(event)
        await self.session.flush()
        return event

    async def query(
        self,
        *,
        event_type: str | None = None,
        agent_did: str | None = None,
        decision: str | None = None,
        since: datetime | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[AuditEvent]:
        stmt = select(AuditEvent).order_by(AuditEvent.occurred_at.desc())
        if event_type:
            stmt = stmt.where(AuditEvent.event_type == event_type)
        if agent_did:
            stmt = stmt.where(AuditEvent.agent_did == agent_did)
        if decision:
            stmt = stmt.where(AuditEvent.decision == decision)
        if since:
            stmt = stmt.where(AuditEvent.occurred_at >= since)
        result = await self.session.execute(stmt.limit(limit).offset(offset))
        return list(result.scalars().all())
