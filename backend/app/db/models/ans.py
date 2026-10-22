"""Agent Naming Service persistence (Phase 3).

The registry is durable, not in-process memory: an agent that registered
survives an ANS restart, and discovery answers from PostgreSQL.

Design note on what ANS stores vs what it decides:

  ans_agent_credentials  is an INDEX of what an agent CLAIMED to hold at
                         registration time. It is a fast pre-filter, never a
                         verdict. Eligibility is always re-decided at query
                         time by the Phase 2 verifier against live credential
                         state, so a credential revoked one second ago cannot
                         be smuggled through a stale index row.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.db.models.agent import JSONType, _enum


class ANSStatus(str, enum.Enum):
    """Lifecycle state as the *registry* sees it.

    Distinct from `agents.status` (Phase 1), which is the identity authority's
    view. An agent can be ACTIVE as an identity while OFFLINE in the registry
    because its process stopped answering.
    """

    STARTING = "STARTING"
    ACTIVE = "ACTIVE"
    BUSY = "BUSY"
    DEGRADED = "DEGRADED"      # registered and heartbeating, endpoint unhealthy
    STALE = "STALE"            # heartbeat overdue
    OFFLINE = "OFFLINE"        # heartbeat long overdue, or deregistered
    DRAINING = "DRAINING"      # graceful shutdown in progress
    REVOKED = "REVOKED"        # identity revoked upstream
    TERMINATED = "TERMINATED"


# Statuses an agent may be handed out for by default. DEGRADED and BUSY are
# deliberately excluded from the default set but can be asked for explicitly.
DISCOVERABLE_STATUSES = (ANSStatus.ACTIVE,)

# Statuses that must never be returned for a protected workflow, whatever the
# caller asks for.
NEVER_DISCOVERABLE = (ANSStatus.REVOKED, ANSStatus.TERMINATED)


class ANSAgent(Base, TimestampMixin):
    __tablename__ = "ans_agents"
    __table_args__ = (
        Index("ix_ans_agents_status_org", "status", "organization_did"),
        Index("ix_ans_agents_last_seen", "last_seen"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    did: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_type: Mapped[str | None] = mapped_column(String(32))
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    organization_did: Mapped[str | None] = mapped_column(String(255), index=True)
    status: Mapped[ANSStatus] = mapped_column(
        _enum(ANSStatus, "ans_status"), nullable=False,
        default=ANSStatus.STARTING, index=True,
    )
    purpose: Mapped[str | None] = mapped_column(Text)

    # Liveness
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Ranking inputs that ANS genuinely observes or the agent genuinely reports.
    active_tasks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    health_latency_ms: Mapped[float | None] = mapped_column(Float)
    last_health_ok: Mapped[bool | None] = mapped_column(Boolean)
    last_health_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # NULL until Phase 10 owns a real trust/risk engine. Ranking treats NULL as
    # neutral rather than inventing a number.
    trust_score: Mapped[int | None] = mapped_column(Integer)

    agent_metadata: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)

    capabilities: Mapped[list["ANSCapability"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan", lazy="selectin"
    )
    credentials: Mapped[list["ANSAgentCredential"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def capability_names(self) -> list[str]:
        return sorted(c.capability for c in self.capabilities)


class ANSCapability(Base):
    __tablename__ = "ans_capabilities"
    __table_args__ = (
        UniqueConstraint("agent_did", "capability", name="uq_ans_capability"),
        Index("ix_ans_capabilities_capability", "capability"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_did: Mapped[str] = mapped_column(
        ForeignKey("ans_agents.did", ondelete="CASCADE"), nullable=False, index=True
    )
    capability: Mapped[str] = mapped_column(String(96), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    agent: Mapped[ANSAgent] = relationship(back_populates="capabilities")


class ANSAgentCredential(Base):
    """Index of credentials an agent claimed at registration. Never a verdict."""

    __tablename__ = "ans_agent_credentials"
    __table_args__ = (
        UniqueConstraint("agent_did", "credential_id", name="uq_ans_agent_credential"),
        Index("ix_ans_agent_credentials_type", "credential_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_did: Mapped[str] = mapped_column(
        ForeignKey("ans_agents.did", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_id: Mapped[str] = mapped_column(String(128), nullable=False)
    credential_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # Status as of the last index refresh. Discovery re-checks live state.
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    indexed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    agent: Mapped[ANSAgent] = relationship(back_populates="credentials")


class ANSHeartbeat(Base):
    __tablename__ = "ans_heartbeats"
    __table_args__ = (Index("ix_ans_heartbeats_did_ts", "agent_did", "occurred_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_did: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    endpoint: Mapped[str | None] = mapped_column(String(512))
    active_tasks: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[float | None] = mapped_column(Float)


class ANSRegistrationProof(Base):
    """Every registration attempt, accepted or rejected, with its proof.

    Nonces are unique: a captured registration payload cannot be replayed to
    move an agent's endpoint later.
    """

    __tablename__ = "ans_registration_proofs"
    __table_args__ = (
        # Partial unique index: only a SUCCESSFUL registration consumes a
        # nonce. Rejected attempts are still recorded in full for audit, and
        # an attacker cannot burn nonces by spamming failures.
        Index(
            "uq_ans_registration_nonce", "agent_did", "nonce",
            unique=True, postgresql_where=text("accepted"),
        ),
        Index("ix_ans_proofs_did_ts", "agent_did", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_did: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONType, nullable=False)
    signature: Mapped[str] = mapped_column(String(256), nullable=False)
    verification_method: Mapped[str | None] = mapped_column(String(320))
    accepted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ANSDiscoveryRequest(Base):
    __tablename__ = "ans_discovery_requests"
    __table_args__ = (Index("ix_ans_discovery_requests_ts", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    request_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    requester_did: Mapped[str | None] = mapped_column(String(255), index=True)
    query: Mapped[dict] = mapped_column(JSONType, nullable=False)
    candidate_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    matched_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    selected_did: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    results: Mapped[list["ANSDiscoveryResult"]] = relationship(
        back_populates="request", cascade="all, delete-orphan", lazy="selectin"
    )


class ANSDiscoveryResult(Base):
    __tablename__ = "ans_discovery_results"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    request_id: Mapped[str] = mapped_column(
        ForeignKey("ans_discovery_requests.request_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    candidate_did: Mapped[str] = mapped_column(String(255), nullable=False)
    matched: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rank: Mapped[int | None] = mapped_column(Integer)
    score: Mapped[float | None] = mapped_column(Float)
    # Per-check breakdown, the same shape the UI renders.
    reasons: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)

    request: Mapped[ANSDiscoveryRequest] = relationship(back_populates="results")
