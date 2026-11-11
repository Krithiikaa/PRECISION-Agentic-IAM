"""Append-only audit event access."""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.integrity import compute_mac, derive_mac_key
from app.core.config import get_settings
from app.db.models.audit import AuditEvent


@lru_cache(maxsize=4)
def _mac_key(master_key: str) -> bytes:
    return derive_mac_key(master_key)


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
        # Phase 12: the row is MACed by the writer, over exactly what is
        # stored. The JSON round trip makes the metadata the MAC covers the
        # metadata the column will hold (a tuple becomes a list, and so on).
        event_id = uuid.uuid4()
        stored_metadata = json.loads(json.dumps(metadata or {}))
        fields = {"event_type": event_type, "agent_did": agent_did, "session_id": session_id,
                  "request_id": request_id, "resource": resource, "action": action,
                  "decision": decision, "reason": reason}
        mac = compute_mac(_mac_key(get_settings().keystore_master_key), event_id,
                          fields, stored_metadata)
        event = AuditEvent(
            id=event_id,
            integrity_mac=mac,
            event_type=event_type,
            agent_did=agent_did,
            session_id=session_id,
            request_id=request_id,
            resource=resource,
            action=action,
            decision=decision,
            reason=reason,
            event_metadata=stored_metadata,
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
        request_id: str | None = None,
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
        if request_id:
            # Exact match: one request, every event it produced across the
            # PDP, the AEM, the approval service and the tool (indexed).
            stmt = stmt.where(AuditEvent.request_id == request_id)
        result = await self.session.execute(stmt.limit(limit).offset(offset))
        return list(result.scalars().all())
