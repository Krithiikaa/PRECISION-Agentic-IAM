"""Audit service: persist every meaningful IAM event and fan it out live."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.repositories.audit import AuditRepository
from app.monitoring.events import Event, event_bus


class AuditService:
    def __init__(self, session: AsyncSession) -> None:
        self.repo = AuditRepository(session)

    async def record(self, event: Event) -> None:
        await self.repo.record(
            event_type=event.event_type,
            agent_did=event.agent_did,
            session_id=event.session_id,
            request_id=event.request_id,
            resource=event.resource,
            action=event.action,
            decision=event.decision,
            reason=event.reason,
            metadata=event.metadata,
        )
        event_bus.publish(event)

    async def query(self, **kwargs) -> list[dict]:
        events = await self.repo.query(**kwargs)
        return [
            {
                "id": str(e.id),
                # The MONOTONIC cursor. `occurred_at` defaults to the database
                # clock, which is transaction-start, so several events written
                # in one transaction share a timestamp exactly -- and a
                # consumer ordering by time alone gets them in an arbitrary
                # order. An audit trail whose steps can be read out of sequence
                # is worse than one that is merely coarse, so the total order
                # is published rather than left for a caller to guess at.
                "seq": e.seq,
                "timestamp": e.occurred_at.isoformat(),
                "event_type": e.event_type,
                "agent_did": e.agent_did,
                "session_id": e.session_id,
                "request_id": e.request_id,
                "resource": e.resource,
                "action": e.action,
                "decision": e.decision,
                "reason": e.reason,
                "metadata": e.event_metadata,
            }
            for e in events
        ]
