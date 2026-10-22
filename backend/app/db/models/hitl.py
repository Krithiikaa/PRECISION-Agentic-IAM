"""Human-in-the-Loop persistence (Phase 5, hardened in Phase 5.5).

Four tables.

  human_principals   The MINIMUM this system needs to know about a person:
                     who Keycloak says they are, and whether we have locally
                     stood them down. Keycloak stays authoritative for identity
                     and roles -- `last_seen_roles` is an AUDIT record of what a
                     token carried, never the input to an authorization
                     decision. Authorizing from a stored copy of someone else's
                     decisions is how a revoked role keeps working.

  approval_requests  One human decision, its full lifecycle, and the signed
                     artifact that records it. `binding_sha256` is what makes an
                     approval un-reusable: it is a digest over the exact request
                     being approved, recomputed at re-evaluation.

  approval_signoffs  ONE HUMAN, ONE SIGN-OFF (Phase 5.5). Dual control lives
                     here, and its central rule is a UNIQUE CONSTRAINT rather
                     than an `if`: (approval_id, issuer, subject) means the
                     database refuses the same person a second time. Two
                     concurrent requests both reaching the check in Python
                     would both pass it; only one can win an INSERT.

  approval_authority_keys
                     THE SIGNING KEY REGISTER (Phase 5.5). Exactly one ACTIVE
                     key per authority signs; RETIRED keys keep verifying the
                     artifacts they signed while active, so rotating does not
                     invalidate history. Public material and lifecycle only --
                     the private key stays in the KeyStore and is referenced,
                     never stored.

NOTHING SECRET IS STORED HERE. No password, no access token, no refresh token,
no client secret, no private key. The artifact is a public, signed document; its
security comes from the signature, not from being hidden.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models.agent import JSONType, _enum


class HumanStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    # Locally stood down. The person's Keycloak token still verifies -- they
    # genuinely are who they say -- and they are refused everything. "We do not
    # know you" and "we know you and you may not" must stay distinguishable.
    SUSPENDED = "SUSPENDED"


class ApprovalStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    CONSUMED = "CONSUMED"


class ApprovalDecision(str, enum.Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class SigningKeyStatus(str, enum.Enum):
    """The lifecycle of one approval-authority signing key.

    ACTIVE   the single key that may SIGN new artifacts
    RETIRED  rotated out. Still verifies artifacts it signed while active, and
             cannot have signed anything dated after `retired_at`.
    REVOKED  compromised. Verifies NOTHING, including its own history -- which
             is the difference between rotation and revocation, and why they
             are separate states rather than one flag.
    """

    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


class HumanPrincipal(Base, TimestampMixin):
    """A person, as this application needs to know them."""

    __tablename__ = "human_principals"
    __table_args__ = (
        # A subject id is only unique WITHIN an issuer. Two realms can both
        # mint `sub=1234`, and treating those as one person would merge two
        # humans into one identity.
        UniqueConstraint("issuer", "subject", name="uq_human_issuer_subject"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    username: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))
    # AUDIT ONLY. What the last validated token carried. Never read when
    # deciding anything -- see the module docstring.
    last_seen_roles: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    status: Mapped[HumanStatus] = mapped_column(
        _enum(HumanStatus, "human_status"), nullable=False, default=HumanStatus.ACTIVE
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    authentications: Mapped[int] = mapped_column(nullable=False, default=0)

    @property
    def principal_urn(self) -> str:
        return f"urn:iam:human:{self.subject}"


class ApprovalRequest(Base, TimestampMixin):
    """One request for a human decision, and the decision itself."""

    __tablename__ = "approval_requests"
    __table_args__ = (
        Index("ix_approval_requests_status_expiry", "status", "expires_at"),
        Index("ix_approval_requests_request", "request_id"),
        Index("ix_approval_requests_subject", "agent_did", "created_at"),
        # The artifact nonce is single-use per approval. A unique constraint,
        # not a convention: it is the last line of defence if the state machine
        # were ever bypassed.
        UniqueConstraint("nonce", name="uq_approval_nonce"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    approval_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)

    # --- what is being approved (the binding) ---------------------------
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_did: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128))
    purpose: Mapped[str] = mapped_column(String(64), nullable=False)
    # Digest over the canonical tuple above. Recomputed from the LIVE
    # authorization request at re-evaluation and compared; this is what stops
    # an approval being carried to a different action.
    binding_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # THE BINDING ITSELF (Phase 5.5), as a document -- including the material
    # attributes (amount, currency, officer of record) the digest covers.
    #
    # Recorded rather than re-derived at signing time, for two reasons. First,
    # the artifact is then guaranteed to hash to `binding_sha256`: one resolver
    # runs once, and the signer cannot disagree with the request. Second, it
    # makes "what exactly did this person agree to?" a column an auditor can
    # read, instead of a value that has to be reconstructed from a resource
    # record which may since have changed -- which is precisely the change the
    # binding exists to detect.
    binding: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    # What the human was shown. Persisted so an auditor can answer "what did
    # they actually see?" -- an approval nobody could have understood is not a
    # meaningful approval.
    presentation: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    # Untrusted caller context at request time, kept for the audit trail.
    context: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    reason: Mapped[str | None] = mapped_column(Text)

    # --- how many humans (Phase 5.5) -------------------------------------
    # Set from the POLICY decision that escalated, never from a caller. It is
    # recorded so the queue and the audit trail can say "1 of 2"; the number
    # that actually GATES the action is recomputed live by Rego at
    # re-evaluation, so lowering it here cannot let a request through.
    required_approvals: Mapped[int] = mapped_column(nullable=False, default=1)

    # --- lifecycle --------------------------------------------------------
    status: Mapped[ApprovalStatus] = mapped_column(
        _enum(ApprovalStatus, "approval_status"),
        nullable=False, default=ApprovalStatus.PENDING, index=True,
    )
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # When the PENDING request stops being answerable.
    request_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # When the DECISION stops being usable. Distinct from the request expiry,
    # and distinct from JIT: it bounds a decision, not an agent's permission.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_by_request: Mapped[str | None] = mapped_column(String(128))
    first_viewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # --- who decided ------------------------------------------------------
    approver_subject: Mapped[str | None] = mapped_column(String(255))
    approver_issuer: Mapped[str | None] = mapped_column(String(512))
    approver_username: Mapped[str | None] = mapped_column(String(255))
    approver_roles: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    decision: Mapped[ApprovalDecision | None] = mapped_column(
        _enum(ApprovalDecision, "approval_decision")
    )

    # --- the signed artifact ----------------------------------------------
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    domain: Mapped[str] = mapped_column(String(128), nullable=False)
    # The full signed document. Public by design: an artifact's security is its
    # signature, not its secrecy.
    artifact: Mapped[dict | None] = mapped_column(JSONType)
    artifact_signed_by: Mapped[str | None] = mapped_column(String(255))

    # --- forward compatibility -------------------------------------------
    # Phase 9 owns sessions. Present and NULL so a session can be bound later
    # without a migration, and so policy can tell "no session layer exists"
    # from "session lookup failed".
    session_id: Mapped[str | None] = mapped_column(String(128))

    decision_latency_ms: Mapped[float | None] = mapped_column(Float)


class ApprovalSignoff(Base, TimestampMixin):
    """One human's decision on one approval request (Phase 5.5).

    THE TWO-PERSON RULE IS THE UNIQUE CONSTRAINT. Not a comparison in Python:
    two requests arriving together would both read "this person has not signed
    yet" and both proceed. Only one can win the INSERT, and the loser is told
    exactly why.

    A REJECTION is recorded here too. One person refusing ends the request --
    dual control means two people must agree, so it cannot mean "keep asking
    until somebody says yes".
    """

    __tablename__ = "approval_signoffs"
    __table_args__ = (
        # The two-person rule.
        UniqueConstraint("approval_id", "approver_issuer", "approver_subject",
                         name="uq_approval_signoff_person"),
        # And a sign-off cannot claim a position another already holds.
        UniqueConstraint("approval_id", "sequence",
                         name="uq_approval_signoff_sequence"),
        Index("ix_approval_signoffs_approval", "approval_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    approval_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("approval_requests.approval_id", ondelete="CASCADE"),
        nullable=False,
    )
    sequence: Mapped[int] = mapped_column(nullable=False)

    # WHO. (issuer, subject) is the identity; username is for display and for
    # the maker-checker comparison against the resource's officer of record.
    approver_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    approver_issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    approver_username: Mapped[str | None] = mapped_column(String(255))
    approver_provider: Mapped[str | None] = mapped_column(String(64))
    # AUDIT record of what the token carried at decision time. Never read when
    # deciding anything -- policy re-checks authority against the live token.
    approver_roles: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)

    decision: Mapped[ApprovalDecision] = mapped_column(
        _enum(ApprovalDecision, "approval_decision"), nullable=False
    )
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    decision_latency_ms: Mapped[float | None] = mapped_column(Float)

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "subject": self.approver_subject,
            "issuer": self.approver_issuer,
            "username": self.approver_username,
            "provider": self.approver_provider,
            "roles": list(self.approver_roles or []),
            "decision": self.decision.value,
            "decided_at": self.decided_at.isoformat(),
        }


class ApprovalAuthorityKey(Base, TimestampMixin):
    """One signing key of the approval authority, and its lifecycle.

    PUBLIC MATERIAL ONLY. `keystore_ref` names where the private key lives; the
    private key itself never reaches this table, this process's responses, or
    anything else outside the KeyStore.

    ROTATION vs REVOCATION, kept apart on purpose:

        rotate   this key stops SIGNING. Everything it already signed stays
                 verifiable, because those artifacts are dated before its
                 retirement. Routine hygiene.
        revoke   this key stops being TRUSTED AT ALL, including for artifacts
                 it signed while active. Compromise, and destructive -- so it
                 is a separate state that nothing does by accident.
    """

    __tablename__ = "approval_authority_keys"
    __table_args__ = (
        UniqueConstraint("did", "generation", name="uq_authority_key_generation"),
        Index("ix_authority_keys_did_status", "did", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    did: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    kid: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    # 1, 2, 3... so an operator can say "we are on the third key" without
    # parsing a key id.
    generation: Mapped[int] = mapped_column(nullable=False)

    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key_multibase: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key_b64: Mapped[str] = mapped_column(String(128), nullable=False)
    keystore_backend: Mapped[str] = mapped_column(String(64), nullable=False)
    keystore_ref: Mapped[str] = mapped_column(String(512), nullable=False)

    status: Mapped[SigningKeyStatus] = mapped_column(
        _enum(SigningKeyStatus, "signing_key_status"),
        nullable=False, default=SigningKeyStatus.ACTIVE, index=True,
    )
    # The window this key may have signed in. `not_before` is when it was
    # created; `retired_at` is when it stopped signing. An artifact whose proof
    # is dated outside that window did not come from this key doing its job.
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str | None] = mapped_column(Text)

    def to_dict(self) -> dict:
        return {
            "kid": self.kid,
            "did": self.did,
            "generation": self.generation,
            "algorithm": self.algorithm,
            "public_key_multibase": self.public_key_multibase,
            "status": self.status.value,
            "not_before": self.not_before.isoformat(),
            "retired_at": self.retired_at.isoformat() if self.retired_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "reason": self.reason,
            "keystore_backend": self.keystore_backend,
            # Stated on every response so nothing can mistake this for an
            # exportable key.
            "private_key": "NEVER EXPOSED - held by the KeyStore",
        }
