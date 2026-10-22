"""Authorization persistence (Phase 4).

Two tables, mirroring the PAP/PDP split:

  policies                  policy LIFECYCLE, owned by the PAP. Identity,
                            version, owner, scope and status. The Rego source
                            lives on disk and in OPA; this table is what makes
                            "which policy, at which version, was active" an
                            answerable question rather than a git archaeology
                            exercise.

  authorization_decisions   one row per PDP evaluation, with the policy and
                            version that produced it and the context it was
                            decided on. This is the record an auditor reads.

Deliberately NOT stored: key material, proof values, credential documents. A
decision row carries credential ids, verdicts and CLAIMS only.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models.agent import JSONType, _enum


class PolicyStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"        # loaded into OPA and evaluated
    INACTIVE = "INACTIVE"    # removed from OPA; rules genuinely not in the engine


class PolicyRecord(Base, TimestampMixin):
    """A policy's identity and lifecycle. The PAP owns this; the PDP never writes it."""

    __tablename__ = "policies"
    __table_args__ = (
        Index("ix_policies_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    # The module id OPA knows it by (PUT /v1/policies/{module_id}).
    module_id: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    purpose: Mapped[str | None] = mapped_column(Text)
    scope: Mapped[str | None] = mapped_column(String(256))
    owner: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[PolicyStatus] = mapped_column(
        _enum(PolicyStatus, "policy_status"), nullable=False, default=PolicyStatus.ACTIVE
    )
    source_path: Mapped[str] = mapped_column(String(512), nullable=False)
    # Detects drift between what is on disk and what was loaded into OPA.
    source_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    loaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuthorizationDecisionRecord(Base):
    """One PDP evaluation. Append-only; a decision is history, not state."""

    __tablename__ = "authorization_decisions"
    __table_args__ = (
        Index("ix_authz_decisions_subject_ts", "subject_did", "decided_at"),
        Index("ix_authz_decisions_decision_ts", "decision", "decided_at"),
        Index("ix_authz_decisions_policy", "policy_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # Correlates this decision with the credential verification, discovery and
    # enforcement events for the same flow.
    request_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    subject_did: Mapped[str] = mapped_column(String(255), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, default="agent")
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128))
    purpose: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_id: Mapped[str | None] = mapped_column(String(128))
    policy_version: Mapped[str | None] = mapped_column(String(32))
    # Real measured latency. Never modelled or estimated.
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    stages: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    context_snapshot: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
