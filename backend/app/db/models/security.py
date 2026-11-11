"""Security operations persistence: trust, anomalies, sessions, incidents.

Reference: CSA "Agentic AI IAM: A New Approach" (2025) sections 4.2 (Layer 4),
5.3 (real-time monitoring) and 5.4 (agile incident response).

    agent_session_states   the SESSION STATE SYNCHRONIZER ledger. One row per
                           agent DID: is its global session ACTIVE, running
                           under REDUCED_TRUST, or TERMINATED by a security
                           lockout? The PIP reads it on every decision, so it
                           is the source of truth the AEMs consult (R-159).
    trust_signals          one negative observation about one agent, with a
                           weight and an expiry. Scores are DERIVED from these,
                           never edited directly, so every score is explainable
                           by the rows that produced it.
    agent_trust            the current derived score per agent (a cache of the
                           computation over trust_signals, refreshed on change).
    security_alerts        anomaly-detector output, each citing the audit
                           sequence numbers that triggered it.
    security_incidents     a containment (kill switch) and its reinstatement,
                           including the impact analysis taken at the moment of
                           containment and the mandatory post-incident review.
    detector_cursors       how far the anomaly detector has read the audit
                           trail, so restarts neither skip nor double-count.

WHY POSTGRESQL IS AUTHORITATIVE AND REDIS IS ONLY THE PUSH CHANNEL. Every
authorization already re-reads the database, so a lockout written here is
effective on the very next decision in every process. Redis pub/sub carries
the change to processes that hold LOCAL state (agent runtimes, the ANS cache)
so they can drop it immediately. If Redis is down, enforcement is still
correct; only the push is late. A design where Redis held the lockout would
make an unreachable Redis a way to un-revoke an agent.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models.agent import JSONType, _enum


class SessionState(str, enum.Enum):
    ACTIVE = "ACTIVE"
    # Trust has dropped below the full-trust band. Policy applies stricter
    # rules (sensitive actions escalate to a human) but the agent keeps working.
    REDUCED_TRUST = "REDUCED_TRUST"
    # The kill switch. The paper's own state name (section 5.4, step 3).
    TERMINATED_IMMEDIATE_SECURITY_LOCKOUT = "TERMINATED_IMMEDIATE_SECURITY_LOCKOUT"


class TrustLevel(str, enum.Enum):
    TRUSTED = "TRUSTED"
    REDUCED = "REDUCED"
    UNTRUSTED = "UNTRUSTED"


class AlertSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    OPEN = "OPEN"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"


class IncidentStatus(str, enum.Enum):
    CONTAINED = "CONTAINED"
    REINSTATED = "REINSTATED"


class IncidentTrigger(str, enum.Enum):
    MANUAL = "MANUAL"
    AUTOMATED = "AUTOMATED"


class AgentSessionState(Base, TimestampMixin):
    __tablename__ = "agent_session_states"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_did: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    state: Mapped[SessionState] = mapped_column(
        # Its own length: the paper's state name is 37 characters, longer than
        # the 32 the shared helper allows.
        Enum(SessionState, name="session_state", native_enum=False, length=48,
             validate_strings=True),
        nullable=False, default=SessionState.ACTIVE
    )
    reason: Mapped[str | None] = mapped_column(String(512))
    incident_id: Mapped[str | None] = mapped_column(String(64))
    # Bumped on every change. Pushed with the change, so a subscriber that
    # receives messages out of order keeps the newest one.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    changed_by: Mapped[str | None] = mapped_column(String(255))
    changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TrustSignal(Base, TimestampMixin):
    __tablename__ = "trust_signals"
    __table_args__ = (Index("ix_trust_signals_did_expiry", "agent_did", "expires_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_did: Mapped[str] = mapped_column(String(255), nullable=False)
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    weight: Mapped[int] = mapped_column(Integer, nullable=False)
    alert_id: Mapped[str | None] = mapped_column(String(64), index=True)
    detail: Mapped[str | None] = mapped_column(String(512))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AgentTrust(Base, TimestampMixin):
    __tablename__ = "agent_trust"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_did: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    level: Mapped[TrustLevel] = mapped_column(_enum(TrustLevel, "trust_level"), nullable=False)
    active_signals: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SecurityAlert(Base, TimestampMixin):
    __tablename__ = "security_alerts"
    __table_args__ = (Index("ix_security_alerts_did_created", "agent_did", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    agent_did: Mapped[str | None] = mapped_column(String(255))
    rule: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[AlertSeverity] = mapped_column(
        _enum(AlertSeverity, "alert_severity"), nullable=False
    )
    status: Mapped[AlertStatus] = mapped_column(
        _enum(AlertStatus, "alert_status"), nullable=False, default=AlertStatus.OPEN
    )
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    # One alert per (rule, agent, window). The UNIQUE constraint makes the
    # detector idempotent across restarts and across concurrent workers.
    dedup_key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    # Whether the alert was attributed to an AUTHENTICATED subject. Only those
    # move a trust score: an unauthenticated request can name any DID, and
    # letting it lower that DID's trust would hand an attacker a way to get a
    # victim agent contained.
    attributed: Mapped[bool] = mapped_column(nullable=False, default=True)
    evidence: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)


class SecurityIncident(Base, TimestampMixin):
    __tablename__ = "security_incidents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    agent_did: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[IncidentStatus] = mapped_column(
        _enum(IncidentStatus, "incident_status"), nullable=False
    )
    trigger: Mapped[IncidentTrigger] = mapped_column(
        _enum(IncidentTrigger, "incident_trigger"), nullable=False
    )
    alert_id: Mapped[str | None] = mapped_column(String(64))
    opened_by: Mapped[str] = mapped_column(String(255), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    # What the kill switch did and what the agent could still reach at the
    # moment of containment: credentials, grants, sessions, children,
    # collaborators. Frozen at containment time for the post-incident review.
    containment: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    contained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    containment_ms: Mapped[float | None] = mapped_column()
    reinstated_by: Mapped[str | None] = mapped_column(String(255))
    reinstated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Mandatory before reinstatement: what happened, why it is now safe.
    review: Mapped[str | None] = mapped_column(Text)


class DetectorCursor(Base):
    __tablename__ = "detector_cursors"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
