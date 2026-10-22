"""JIT temporary access persistence (Phase 6).

WHY A GRANT IS PERSISTED AT ALL, given it is signed and self-describing.

A signed document can be verified offline, which is exactly why it cannot be
revoked offline. Two properties need server-side state and nothing else can
supply them:

    revocation      a signature cannot be un-made. "This mandate is dead" is a
                    fact about the present, and only a lookup can carry it.
    use counting    a bounded budget has to be decremented somewhere both
                    concurrent callers can see.

So verification is two halves, exactly as a credential's is: the SIGNATURE says
what was granted and by whom, and the RECORD says whether it is still alive.
Neither half is sufficient.

WHAT IS NOT STORED: private key material, of any kind, anywhere here.

    jit_grants            one mandate: its scope, its bounds, its lifecycle
    jit_grant_uses        one row per use -- what a budget was actually spent on
    jit_authority_keys    the signing key register, mirroring Phase 5.5

THE SHAPE OF `jit_authority_keys` DUPLICATES `approval_authority_keys` ON
PURPOSE, and the duplication is recorded rather than hidden. Generalising the
Phase 5.5 table into a shared register is the cleaner design; it also edits a
table three green gates depend on. The copy is the lower-risk move now, and a
consolidation stays available later.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.db.models.agent import JSONType, _enum
from app.db.models.hitl import SigningKeyStatus


class JITGrantStatus(str, enum.Enum):
    """The lifecycle of a mandate.

    Four terminal states, and they are terminal in the same way the approval
    states are: the transition table has empty sets for all of them, so
    `EXPIRED -> ACTIVE` is refused by name rather than by nobody happening to
    write that code.

    EXHAUSTED is deliberately distinct from EXPIRED. "You spent your budget"
    and "your window closed" are different operator situations, and collapsing
    them would make a grant that ran out look like one that timed out.
    """

    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    EXHAUSTED = "EXHAUSTED"
    REVOKED = "REVOKED"


class JITGrant(Base, TimestampMixin):
    """One time-bounded, use-bounded mandate.

    WHAT THIS IS NOT: a permission. Every use is still decided by the PDP with
    every ordinary rule running -- credential state, resource scope, purpose,
    amount band. The grant carries forward only the EXPENSIVE precondition (a
    human decision), and it can only ever NARROW what policy would already
    allow at that instant.
    """

    __tablename__ = "jit_grants"
    __table_args__ = (
        # The artifact nonce is single-use. A unique constraint rather than a
        # convention: it is the last line of defence if issuance were ever
        # driven twice from the same signed payload.
        UniqueConstraint("nonce", name="uq_jit_grant_nonce"),
        # A budget that can be overspent is not a budget. Enforced by the
        # database so it holds even if every caller is wrong.
        CheckConstraint("uses <= max_uses", name="ck_jit_uses_within_max"),
        CheckConstraint("max_uses >= 1", name="ck_jit_max_uses_positive"),
        Index("ix_jit_grants_agent_status", "agent_did", "status"),
        Index("ix_jit_grants_status_expiry", "status", "expires_at"),
        Index("ix_jit_grants_request", "issuing_request_id"),
        Index("ix_jit_grants_approval", "approval_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    grant_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )

    # --- the scope (the binding) -----------------------------------------
    agent_did: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # A SET of permitted instances, not one id. A mandate over several
    # applications is the point of Phase 6; an empty list means the mandate
    # covers the resource TYPE and policy decides the instances, which is
    # weaker and is why issuance policy may refuse it.
    resource_ids: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    purpose: Mapped[str] = mapped_column(String(64), nullable=False)
    # Additional ceilings -- e.g. {"max_amount_inr": 1000000}. Compared against
    # the LIVE resource attributes on every use, never against a caller's claim.
    constraints: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)

    # Digest over the canonical binding tuple. Recomputed from the live request
    # at use time and compared; this is what stops a mandate being carried to a
    # different action or agent.
    binding_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # The binding itself, as a document. Recorded rather than re-derived for
    # the same reason the approval binding is: it makes "what exactly was
    # mandated?" a column an auditor reads, instead of a value reconstructed
    # from records that may have changed since.
    binding: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)

    # --- why this mandate exists -----------------------------------------
    # The policy decision that permitted issuance, the approval it carries
    # forward, and the credentials it was predicated on. The credential ids are
    # here so policy can assert they are STILL valid at use time -- defence in
    # depth behind the PIP re-verifying them anyway.
    justification: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    # What a person would read. An operator reviewing a live mandate should not
    # have to decode a binding to see what it permits.
    presentation: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)

    # --- bounds -----------------------------------------------------------
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    max_uses: Mapped[int] = mapped_column(nullable=False, default=1)
    uses: Mapped[int] = mapped_column(nullable=False, default=0)

    # --- lifecycle --------------------------------------------------------
    status: Mapped[JITGrantStatus] = mapped_column(
        _enum(JITGrantStatus, "jit_grant_status"),
        nullable=False, default=JITGrantStatus.ACTIVE, index=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(255))
    revocation_reason: Mapped[str | None] = mapped_column(Text)
    exhausted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # --- correlation ------------------------------------------------------
    # The request that ASKED for the mandate. Informational: it correlates the
    # issuance with its decision in the audit trail, and is deliberately NOT
    # compared at use time -- a reusable mandate spans many requests, each with
    # its own id, and comparing it would make the grant single-use by accident.
    issuing_request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # The human approval this mandate carries forward, when there was one.
    approval_id: Mapped[str | None] = mapped_column(String(64))

    # --- the signed artifact ----------------------------------------------
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    domain: Mapped[str] = mapped_column(String(128), nullable=False)
    # Public by design: a grant's security is its signature, not its secrecy.
    # It is still not a bearer token -- using it requires a control-plane
    # signature from the bound agent DID.
    artifact: Mapped[dict | None] = mapped_column(JSONType)
    signed_by_kid: Mapped[str | None] = mapped_column(String(255))
    issuer_did: Mapped[str] = mapped_column(String(255), nullable=False)

    # --- forward compatibility -------------------------------------------
    # Phase 9 owns sessions. Present and NULL so a session can be bound later
    # without a migration, matching `approval_requests.session_id`.
    session_id: Mapped[str | None] = mapped_column(String(128))

    grant_uses: Mapped[list["JITGrantUse"]] = relationship(
        back_populates="grant", cascade="all, delete-orphan", lazy="selectin",
    )

    def to_dict(self) -> dict:
        return {
            "grant_id": self.grant_id,
            "agent_did": self.agent_did,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_ids": list(self.resource_ids or []),
            "purpose": self.purpose,
            "constraints": dict(self.constraints or {}),
            "status": self.status.value,
            "issued_at": self.issued_at.isoformat(),
            "not_before": self.not_before.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "max_uses": self.max_uses,
            "uses": self.uses,
            "uses_remaining": max(self.max_uses - self.uses, 0),
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_by": self.revoked_by,
            "revocation_reason": self.revocation_reason,
            "issuing_request_id": self.issuing_request_id,
            "approval_id": self.approval_id,
            "issuer": self.issuer_did,
            "signed_by_kid": self.signed_by_kid,
            "domain": self.domain,
            "binding_sha256": self.binding_sha256,
            "binding": dict(self.binding or {}),
            "justification": dict(self.justification or {}),
            "presentation": dict(self.presentation or {}),
            "session_id": self.session_id,
        }


class JITGrantUse(Base, TimestampMixin):
    """One spend against a mandate's budget.

    `UNIQUE (grant_id, request_id)` is load-bearing rather than tidy: it makes a
    single request IDEMPOTENT against a grant. A retry of the same request --
    a network timeout, a client that did not see the response -- cannot
    silently burn a second use out of a budget a human authorised.
    """

    __tablename__ = "jit_grant_uses"
    __table_args__ = (
        UniqueConstraint("grant_id", "sequence", name="uq_jit_use_sequence"),
        UniqueConstraint("grant_id", "request_id", name="uq_jit_use_request"),
        Index("ix_jit_uses_grant", "grant_id", "used_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    grant_id: Mapped[str] = mapped_column(
        ForeignKey("jit_grants.grant_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    # 1, 2, 3... so "the third use of this mandate" is answerable without
    # sorting timestamps that can collide.
    sequence: Mapped[int] = mapped_column(nullable=False)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128))
    action: Mapped[str | None] = mapped_column(String(64))
    decision: Mapped[str | None] = mapped_column(String(32))
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    grant: Mapped[JITGrant] = relationship(back_populates="grant_uses")

    def to_dict(self) -> dict:
        return {
            "grant_id": self.grant_id,
            "sequence": self.sequence,
            "request_id": self.request_id,
            "resource_id": self.resource_id,
            "action": self.action,
            "decision": self.decision,
            "used_at": self.used_at.isoformat(),
        }


class JITAuthorityKey(Base, TimestampMixin):
    """One signing key of the JIT authority, and its lifecycle.

    PUBLIC MATERIAL ONLY, exactly as `approval_authority_keys` holds only
    public material. `keystore_ref` names where the private key lives; the
    private key never reaches this table or any response.

    The rotate/revoke distinction is the same one Phase 5.5 drew, and it
    matters here for the same reason: rotating a key must not invalidate the
    mandates it already issued, while revoking one must.
    """

    __tablename__ = "jit_authority_keys"
    __table_args__ = (
        UniqueConstraint("did", "generation", name="uq_jit_authority_key_generation"),
        Index("ix_jit_authority_keys_did_status", "did", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    did: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    kid: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    generation: Mapped[int] = mapped_column(nullable=False)

    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key_multibase: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key_b64: Mapped[str] = mapped_column(String(128), nullable=False)
    keystore_backend: Mapped[str] = mapped_column(String(64), nullable=False)
    keystore_ref: Mapped[str] = mapped_column(String(512), nullable=False)

    # Reuses the Phase 5.5 enum type: ACTIVE / RETIRED / REVOKED mean exactly
    # the same things here, and inventing a parallel vocabulary for the same
    # three states would be a second thing to keep in sync.
    status: Mapped[SigningKeyStatus] = mapped_column(
        _enum(SigningKeyStatus, "signing_key_status"),
        nullable=False, default=SigningKeyStatus.ACTIVE, index=True,
    )
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
            "private_key": "NEVER EXPOSED - held by the KeyStore",
        }
