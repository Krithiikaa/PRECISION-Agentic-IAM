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

from sqlalchemy import BigInteger, DateTime, Identity, Index, String, Text, Uuid, func
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
    # Phase 12. HMAC-SHA256 over the event's content, computed by the writing
    # process with a key derived from the keystore master key (never stored in
    # the database). A row inserted by someone with database access but not
    # the key carries no valid MAC, so the integrity verifier reports it even
    # if the sealer has already chained it. NULL only for pre-Phase-12 rows.
    integrity_mac: Mapped[str | None] = mapped_column(String(64))


class AuditChainEntry(Base):
    """One link of the audit hash chain (Phase 12).

    APPEND-ONLY and SEPARATE from `audit_events`, so sealing never rewrites an
    audit row. Entry N commits to entry N-1 through `prev_hash`, and to its
    event through `content_hash` (SHA-256 of the canonical event, including
    `seq`, `occurred_at` and `integrity_mac`). Chain order is SEALING order,
    which is commit order as observed by the single sealer, not `seq` order:
    a transaction that commits late is chained late, never silently skipped.

    Entry 0 is the GENESIS. Its `detail.covers_from_seq` states the first
    audit seq the chain covers; anything earlier predates Phase 12 and is
    reported as outside coverage, never as verified.
    """

    __tablename__ = "audit_chain"

    chain_index: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)   # GENESIS | EVENT
    event_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, unique=True)
    event_seq: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    sealed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)
    detail: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)


class AuditCheckpoint(Base):
    """A signed statement "the chain had head H at index N" (Phase 12).

    Signed with an Ed25519 key held in the keystore, not the database. The
    verifier checks it against a PINNED public key (the keystore's, or one an
    external auditor recorded), so rewriting the whole chain from some index
    onwards -- which recomputing every later hash would otherwise allow --
    breaks every checkpoint after that index.
    """

    __tablename__ = "audit_checkpoints"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    chain_index: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    kid: Mapped[str] = mapped_column(String(320), nullable=False)
    public_key_b64: Mapped[str] = mapped_column(String(128), nullable=False)
    signature_b64: Mapped[str] = mapped_column(Text, nullable=False)
