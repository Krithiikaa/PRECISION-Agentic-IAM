"""Audit / telemetry persistence.

Phase 1 records identity-lifecycle events. The full monitoring, anomaly and
trust tables land in Phase 10; this table is the append-only spine they will
hang off, so its shape already matches the event contract in the spec
(timestamp, event_type, agent_did, session_id, request_id, resource, action,
decision, metadata).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Identity, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.agent import JSONType


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_type_ts", "event_type", "occurred_at"),
        Index("ix_audit_events_did_ts", "agent_did", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # Monotonic cursor for tailing. The live event stream is served by the IAM
    # API, but events are written by several processes (ANS, agents), so the
    # stream tails this table rather than a single process's in-memory bus.
    seq: Mapped[int] = mapped_column(
        BigInteger, Identity(always=False), unique=True, index=True, nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_did: Mapped[str | None] = mapped_column(String(255))
    session_id: Mapped[str | None] = mapped_column(String(128), index=True)
    request_id: Mapped[str | None] = mapped_column(String(128), index=True)
    resource: Mapped[str | None] = mapped_column(String(128))
    action: Mapped[str | None] = mapped_column(String(64))
    decision: Mapped[str | None] = mapped_column(String(32))
    reason: Mapped[str | None] = mapped_column(String(512))
    event_metadata: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
