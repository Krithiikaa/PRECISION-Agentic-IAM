"""Control-plane persistence (Phase 4.5).

Two tables, each doing exactly one job.

  control_plane_principals   WHO may address the control plane. An administrator
                             identity: a DID, an Ed25519 key pair in the same
                             KeyStore as every other principal, a published DID
                             Document, and the roles it was granted. This is a
                             new KIND of principal, not a new identity system.

  control_plane_proofs       EVERY control-plane request proof, accepted or
                             rejected. Doubles as the replay ledger: a nonce is
                             consumed by an accepted proof and can never be
                             presented again.

Nothing here stores a private key, a signature that could be replayed
elsewhere, or the body of a request. The stored `signature` is truncated: it is
kept for forensic correlation, not for re-verification.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models.agent import JSONType, _enum


class PrincipalStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    # A principal can be stood down without deleting its history. A SUSPENDED
    # principal authenticates (its key still verifies) and is then denied every
    # action -- the distinction between "we do not know you" and "we know you
    # and you may not" is one an operator needs.
    SUSPENDED = "SUSPENDED"


class ControlPlanePrincipal(Base, TimestampMixin):
    """A control-plane administrator identity."""

    __tablename__ = "control_plane_principals"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    did: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kid: Mapped[str] = mapped_column(String(320), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key_multibase: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key_b64: Mapped[str] = mapped_column(String(128), nullable=False)
    keystore_backend: Mapped[str] = mapped_column(String(32), nullable=False)
    keystore_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    did_document: Mapped[dict] = mapped_column(JSONType, nullable=False)
    # Granted privileges. An empty list is a real state: the principal
    # authenticates and is denied everything.
    roles: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    status: Mapped[PrincipalStatus] = mapped_column(
        _enum(PrincipalStatus, "principal_status"),
        nullable=False, default=PrincipalStatus.ACTIVE,
    )


class ControlPlaneProof(Base):
    """One presented control-plane request proof.

    The partial unique index is the replay defence. It is a DATABASE
    constraint, not a read-then-write check in Python, so two concurrent
    presentations of the same nonce cannot both win a race.

    Only an ACCEPTED proof consumes its nonce: rejected attempts are recorded
    in full for audit, and an attacker cannot burn a legitimate agent's nonces
    by spamming failures with them.
    """

    __tablename__ = "control_plane_proofs"
    __table_args__ = (
        Index(
            "uq_control_plane_nonce", "principal_did", "nonce",
            unique=True, postgresql_where=text("accepted"),
        ),
        Index("ix_control_plane_proofs_principal_ts", "principal_did", "created_at"),
        Index("ix_control_plane_proofs_accepted", "accepted", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    principal_did: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str | None] = mapped_column(String(255))
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    body_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(64), nullable=False)
    # Truncated on purpose: enough to correlate two presentations of the same
    # proof in the audit trail, never enough to replay one.
    signature: Mapped[str] = mapped_column(String(256), nullable=False)
    verification_method: Mapped[str | None] = mapped_column(String(320))
    accepted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    latency_ms: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
