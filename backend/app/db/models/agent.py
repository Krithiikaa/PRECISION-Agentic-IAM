"""Agent identity persistence.

Table split mirrors the trust boundaries:

  agents              - who the agent is, what it may claim to do
  agent_keys          - PUBLIC key material + a *reference* to the keystore.
                        Private keys are never stored here (see identity/keys.py).
  did_documents       - the resolvable document served for the agent's DID
  agent_relationships - delegation edges (parent agent -> ephemeral helper)
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

# JSONB on PostgreSQL, plain JSON elsewhere (keeps the SQLite test path working).
JSONType = JSON().with_variant(JSONB(), "postgresql")


class AgentStatus(str, enum.Enum):
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    TERMINATED = "TERMINATED"


class AgentType(str, enum.Enum):
    COORDINATOR = "COORDINATOR"
    KYC = "KYC"
    RISK = "RISK"
    FRAUD = "FRAUD"
    DECISION = "DECISION"
    HELPER = "HELPER"


class KeyStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"


def _enum(py_enum, name: str):  # noqa: N802 - shared by app.db.models.credential
    # native_enum=False -> VARCHAR + CHECK. Avoids fragile ALTER TYPE migrations.
    return Enum(py_enum, name=name, native_enum=False, length=32, validate_strings=True)


class Agent(Base, TimestampMixin):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    did: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_type: Mapped[AgentType] = mapped_column(
        _enum(AgentType, "agent_type"), nullable=False
    )
    purpose: Mapped[str | None] = mapped_column(Text)
    controller_did: Mapped[str] = mapped_column(String(255), nullable=False)
    owner: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[AgentStatus] = mapped_column(
        _enum(AgentStatus, "agent_status"),
        nullable=False,
        default=AgentStatus.PROVISIONING,
        index=True,
    )
    endpoint: Mapped[str | None] = mapped_column(String(512))
    capabilities: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    agent_metadata: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)

    # Ephemeral helper agents point at the agent that delegated them into being.
    parent_agent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), index=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    terminated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    keys: Mapped[list["AgentKey"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan", lazy="selectin"
    )
    did_document: Mapped["DIDDocument | None"] = relationship(
        back_populates="agent", cascade="all, delete-orphan", uselist=False, lazy="selectin"
    )
    parent: Mapped["Agent | None"] = relationship(remote_side=[id], lazy="selectin")

    @property
    def active_key(self) -> "AgentKey | None":
        return next((k for k in self.keys if k.status == KeyStatus.ACTIVE), None)


class AgentKey(Base, TimestampMixin):
    """Public key material only.

    `keystore_ref` is an opaque locator (e.g. ``encrypted_file://...``,
    later ``kms://...``) telling the KeyStore where the private half lives.
    It is not itself a secret and cannot be used to recover the key.
    """

    __tablename__ = "agent_keys"
    __table_args__ = (
        Index("ix_agent_keys_agent_status", "agent_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    kid: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="Ed25519")
    public_key_multibase: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key_b64: Mapped[str] = mapped_column(String(128), nullable=False)
    keystore_backend: Mapped[str] = mapped_column(String(32), nullable=False)
    keystore_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[KeyStatus] = mapped_column(
        _enum(KeyStatus, "key_status"), nullable=False, default=KeyStatus.ACTIVE
    )
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    agent: Mapped[Agent] = relationship(back_populates="keys")


class DIDDocument(Base, TimestampMixin):
    __tablename__ = "did_documents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    did: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    document: Mapped[dict] = mapped_column(JSONType, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    agent: Mapped[Agent] = relationship(back_populates="did_document")


class AgentRelationship(Base, TimestampMixin):
    __tablename__ = "agent_relationships"
    __table_args__ = (
        UniqueConstraint(
            "parent_agent_id", "child_agent_id", "relationship_type",
            name="uq_agent_relationship",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    parent_agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    child_agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False, default="DELEGATES")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
