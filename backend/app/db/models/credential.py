"""Credential persistence (Phase 2).

Table split mirrors the trust boundaries, as in Phase 1:

  issuer_identities              issuing authorities and their PUBLIC keys
  credentials                    the signed credential document, immutable
  credential_status              mutable lifecycle state, separate on purpose
  credential_presentations       what a holder presented, and when
  credential_verification_events one row per verification, with per-check detail

Why status lives in its own table: the credential document is signed and must
never change, but revocation happens *after* signing. Mutable state therefore
cannot live inside the signed artefact -- a verifier has to look it up.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.db.models.agent import JSONType, _enum


class CredentialStatusValue(str, enum.Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class IssuerStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


class IssuerIdentity(Base, TimestampMixin):
    """A credential-issuing authority.

    Has its own Ed25519 key pair, in the same KeyStore abstraction agents use,
    but never shared with any agent: an agent cannot forge a credential about
    itself because it does not hold an issuer key.
    """

    __tablename__ = "issuer_identities"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    did: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    kid: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="Ed25519")
    public_key_multibase: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key_b64: Mapped[str] = mapped_column(String(128), nullable=False)
    keystore_backend: Mapped[str] = mapped_column(String(32), nullable=False)
    keystore_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    did_document: Mapped[dict] = mapped_column(JSONType, nullable=False)
    status: Mapped[IssuerStatus] = mapped_column(
        _enum(IssuerStatus, "issuer_status"), nullable=False, default=IssuerStatus.ACTIVE
    )


class Credential(Base, TimestampMixin):
    """A signed credential. The `document` column is the artefact itself."""

    __tablename__ = "credentials"
    __table_args__ = (
        Index("ix_credentials_subject_type", "subject_did", "credential_type"),
        Index("ix_credentials_issuer", "issuer_did"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    credential_id: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )
    issuer_did: Mapped[str] = mapped_column(String(255), nullable=False)
    subject_did: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    credential_type: Mapped[str] = mapped_column(String(64), nullable=False)
    claims: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    # The complete signed VC, proof included. This is what gets presented.
    document: Mapped[dict] = mapped_column(JSONType, nullable=False)
    proof: Mapped[dict] = mapped_column(JSONType, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    status_record: Mapped["CredentialStatus"] = relationship(
        back_populates="credential", cascade="all, delete-orphan",
        uselist=False, lazy="selectin",
    )


class CredentialStatus(Base):
    __tablename__ = "credential_status"

    credential_id: Mapped[str] = mapped_column(
        ForeignKey("credentials.credential_id", ondelete="CASCADE"),
        primary_key=True,
    )
    status: Mapped[CredentialStatusValue] = mapped_column(
        _enum(CredentialStatusValue, "credential_status_value"),
        nullable=False,
        default=CredentialStatusValue.ACTIVE,
        index=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(256))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    credential: Mapped[Credential] = relationship(back_populates="status_record")


class CredentialPresentation(Base):
    """A record that a holder presented credentials to a verifier."""

    __tablename__ = "credential_presentations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    presentation_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    holder_did: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    credential_ids: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    challenge: Mapped[str | None] = mapped_column(String(128))
    domain: Mapped[str | None] = mapped_column(String(255))
    document: Mapped[dict] = mapped_column(JSONType, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CredentialVerificationEvent(Base):
    """One row per verification attempt, with the per-check breakdown.

    Separate from `audit_events` because these rows are queried structurally
    (which check failed, how often) rather than read as a timeline, and because
    the PIP in Phase 4 will consume them as attributes.
    """

    __tablename__ = "credential_verification_events"
    __table_args__ = (
        Index("ix_cred_verif_credential_ts", "credential_id", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    credential_id: Mapped[str | None] = mapped_column(String(128), index=True)
    presentation_id: Mapped[str | None] = mapped_column(String(128), index=True)
    issuer_did: Mapped[str | None] = mapped_column(String(255))
    subject_did: Mapped[str | None] = mapped_column(String(255), index=True)
    credential_type: Mapped[str | None] = mapped_column(String(64))
    verifier: Mapped[str | None] = mapped_column(String(128))
    request_id: Mapped[str | None] = mapped_column(String(128))
    valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    checks: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
