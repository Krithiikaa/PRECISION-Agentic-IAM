"""A2A transaction persistence (Phase 7).

WHY A TRANSACTION IS PERSISTED AT ALL, given the envelope is signed and
self-describing.

A signed document can be verified offline, which is exactly why it cannot be
DEDUPLICATED offline. Two properties need server-side state and nothing else
can supply them:

    exactly-once        "this instruction has already been carried out" is a
                        fact about the present, and only a lookup can carry
                        it. Two processes cannot agree on it in memory.
    idempotent replay   a sender that did not see the response must be able to
                        ask again and learn what happened, without a second
                        payment. That needs the OUTCOME to have been recorded.

So verification is two halves, exactly as a credential's and a mandate's are:
the SIGNATURE says what was instructed and by whom, and the RECORD says
whether it has already been done. Neither half is sufficient.

    a2a_transactions           one instruction: what it binds, what policy
                               decided, and what happened
    a2a_transaction_attempts   EVERY submission, accepted or not

WHY THE TWO TABLES ARE SPLIT, and it is the most important decision here.

`a2a_transactions` carries `UNIQUE (sender_did, transaction_id)`. If a REJECTED
submission wrote a row, an attacker could submit a garbage envelope claiming
`(sender=coordinator-001, transaction_id=txn-0001)` and permanently burn that
id for the legitimate sender. So a row is written here ONLY once the signature
has verified. Everything else -- missing, malformed, forged, stale, addressed
to somebody else -- is recorded in `a2a_transaction_attempts` and nowhere else.

That is the same reasoning `control_plane_proofs` and `ans_registration_proofs`
apply with their partial unique indexes: only a SUCCESSFUL presentation
consumes the scarce name, and failures are still recorded in full for audit.

WHY THE UNIQUENESS IS COMPOSITE. A global unique on `transaction_id` would let
one sender squat on another's id namespace -- pre-register `txn-0001` and the
legitimate holder of that id is denied forever. The transaction id is the
SENDER'S business identifier, so it is unique WITHIN a sender.

WHAT IS NOT STORED: private key material, of any kind, anywhere here. The
`signature` column is TRUNCATED -- enough to correlate two presentations of the
same envelope in the audit trail, never enough to replay one. The full signed
envelope IS stored, deliberately: its security is its signature, not its
secrecy, exactly as a JIT grant's is.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models.agent import JSONType, _enum


class A2ATransactionStatus(str, enum.Enum):
    """The lifecycle of one instruction.

    Six terminal states, and they are terminal in the same way the approval
    and mandate states are: the transition table has empty sets for all of
    them, so `EXECUTED -> EXECUTING` is refused BY NAME rather than by nobody
    happening to write that code. A payment cannot be un-made.

    REJECTED and DENIED are deliberately distinct, and the distinction is the
    one this whole system draws everywhere else: "we could not accept what you
    presented" and "we accepted it, evaluated it, and policy said no" are
    different incidents. An operator filtering for forgery attempts must not
    have to read through ordinary policy refusals.

    EXECUTING exists so the window between "policy allowed this" and "the money
    moved" is a state a concurrent caller can observe and lose against, rather
    than a gap.
    """

    RECEIVED = "RECEIVED"
    VERIFIED = "VERIFIED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"      # terminal
    DENIED = "DENIED"          # terminal
    REJECTED = "REJECTED"      # terminal
    FAILED = "FAILED"          # terminal
    EXPIRED = "EXPIRED"        # terminal


class A2ATransaction(Base, TimestampMixin):
    """One signed agent-to-agent instruction and everything that happened to it.

    WHAT THIS IS NOT: a permission. Every column below the binding is a RECORD
    of a decision made elsewhere -- by Rego, by a human, by the database. The
    row confers nothing; re-presenting the same transaction re-reads it and is
    refused or answered idempotently, never re-decided.
    """

    __tablename__ = "a2a_transactions"
    __table_args__ = (
        # THE EXACTLY-ONCE INVARIANT. A unique constraint rather than a check
        # in Python: two concurrent submissions of the same instruction both
        # reach the INSERT, and only one can win it. Composite so one sender
        # cannot squat on another's id namespace.
        UniqueConstraint("sender_did", "transaction_id",
                         name="uq_a2a_transaction_sender_id"),
        # The second, independent replay ledger. PARTIAL: only a
        # signature-verified submission consumes a nonce, so an attacker
        # cannot burn a legitimate sender's nonces by spamming failures.
        Index("uq_a2a_transaction_nonce", "sender_did", "nonce",
              unique=True, postgresql_where=text("signature_verified")),
        # Money that can be negative is not money. A DOMAIN constraint on the
        # value, never a risk threshold -- what a sum MEANS is decided by Rego
        # against `data.agentic_iam.config.a2a`, and no threshold exists in
        # Python or in this schema.
        #
        # Written as `= abs(...)` rather than `>= 0` for the reason
        # `is_wellformed_amount` is: Phase 5.5 guards against amount
        # thresholds leaking into the application by grepping for a
        # comparison between an amount and a numeric literal, and a domain
        # check should not require that guard to be loosened.
        CheckConstraint("amount_inr IS NULL OR amount_inr = abs(amount_inr)",
                        name="ck_a2a_amount_non_negative"),
        CheckConstraint(
            "server_amount_inr IS NULL OR server_amount_inr = abs(server_amount_inr)",
            name="ck_a2a_server_amount_non_negative"),
        CheckConstraint(
            "executed_amount_inr IS NULL OR executed_amount_inr = abs(executed_amount_inr)",
            name="ck_a2a_executed_amount_non_negative"),
        # An amount without a unit is not an amount.
        CheckConstraint("(amount_inr IS NULL) = (currency IS NULL)",
                        name="ck_a2a_amount_has_currency"),
        Index("ix_a2a_txn_receiver_ts", "receiver_did", "received_at"),
        Index("ix_a2a_txn_sender_ts", "sender_did", "received_at"),
        Index("ix_a2a_txn_status_expiry", "status", "expires_at"),
        Index("ix_a2a_txn_authz_request", "authorization_request_id"),
        Index("ix_a2a_txn_approval", "approval_id"),
        Index("ix_a2a_txn_correlation", "correlation_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    transaction_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    # --- the parties ------------------------------------------------------
    # Both read from the SIGNED envelope. `submitted_by` is the principal that
    # authenticated the submission -- equal to `receiver_did` past the guard,
    # and stored anyway so an auditor confirms it rather than trusting it.
    sender_did: Mapped[str] = mapped_column(String(255), nullable=False)
    receiver_did: Mapped[str] = mapped_column(String(255), nullable=False)
    submitted_by: Mapped[str] = mapped_column(String(255), nullable=False)

    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    protocol_version: Mapped[str] = mapped_column(String(16), nullable=False)

    # --- the binding, as indexed lookup copies of SIGNED fields ----------
    # The signed copy in `envelope` is the one that decides; these exist so the
    # table is queryable, and `binding_sha256` is what ties them together.
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128))
    purpose: Mapped[str] = mapped_column(String(64), nullable=False)

    # --- money, in THREE independent representations ---------------------
    # They exist separately because each answers a different question, and the
    # security property is that they AGREE:
    #
    #   amount_inr           what the SENDER signed         "what was instructed?"
    #   server_amount_inr    what the PIP read from the record  "what is true?"
    #   authorized_amount_inr what the PDP decided on       "what was permitted?"
    #   executed_amount_inr  what the tool actually moved   "what happened?"
    #
    # A single column could not express a disagreement, and a disagreement is
    # precisely the incident worth detecting.
    amount_inr: Mapped[int | None] = mapped_column(BigInteger)
    currency: Mapped[str | None] = mapped_column(String(3))
    server_amount_inr: Mapped[int | None] = mapped_column(BigInteger)
    authorized_amount_inr: Mapped[int | None] = mapped_column(BigInteger)
    executed_amount_inr: Mapped[int | None] = mapped_column(BigInteger)
    amount_reconciled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    binding_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # --- the signed artifact ---------------------------------------------
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    domain: Mapped[str] = mapped_column(String(128), nullable=False)
    key_id: Mapped[str | None] = mapped_column(String(320))
    # TRUNCATED on purpose: enough to correlate two presentations of the same
    # envelope, never enough to replay one.
    signature: Mapped[str] = mapped_column(String(256), nullable=False)
    signature_verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    # Public by design: an envelope's security is its signature, not its
    # secrecy. Stored so a verification can be repeated years later.
    envelope: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    response_envelope: Mapped[dict | None] = mapped_column(JSONType)

    # --- time -------------------------------------------------------------
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # --- lifecycle --------------------------------------------------------
    status: Mapped[A2ATransactionStatus] = mapped_column(
        _enum(A2ATransactionStatus, "a2a_transaction_status"),
        nullable=False, default=A2ATransactionStatus.RECEIVED, index=True,
    )
    reason: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(Text)

    # --- what policy decided ---------------------------------------------
    decision: Mapped[str | None] = mapped_column(String(32))
    decision_reason: Mapped[str | None] = mapped_column(String(64))
    policy_id: Mapped[str | None] = mapped_column(String(128))
    policy_version: Mapped[str | None] = mapped_column(String(32))
    # `a2a-{transaction_id}`. DETERMINISTIC, so a retry after a human approval
    # reproduces the SAME approval binding and finds the decision. A freshly
    # generated id would make every escalated transaction unapprovable.
    authorization_request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    approval_id: Mapped[str | None] = mapped_column(String(64))
    jit_grant_id: Mapped[str | None] = mapped_column(String(64))
    required_approvals: Mapped[int | None] = mapped_column()

    # --- what happened ----------------------------------------------------
    # A DIGEST and a summary, never raw resource data. The audit trail is not
    # a data-exfiltration route.
    execution_result: Mapped[dict | None] = mapped_column(JSONType)
    result_sha256: Mapped[str | None] = mapped_column(String(64))
    executing_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    denied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # --- correlation ------------------------------------------------------
    correlation_id: Mapped[str | None] = mapped_column(String(128))
    # Phase 9 owns sessions. Present and NULL so one can be bound later
    # without a migration, matching approval_requests and jit_grants.
    session_id: Mapped[str | None] = mapped_column(String(128))
    latency_ms: Mapped[float | None] = mapped_column(Float)

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def to_dict(self) -> dict:
        return {
            "transaction_id": self.transaction_id,
            "sender_did": self.sender_did,
            "receiver_did": self.receiver_did,
            "submitted_by": self.submitted_by,
            "protocol": self.protocol,
            "protocol_version": self.protocol_version,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "purpose": self.purpose,
            "amount": {
                "signed_inr": self.amount_inr,
                "server_inr": self.server_amount_inr,
                "authorized_inr": self.authorized_amount_inr,
                "executed_inr": self.executed_amount_inr,
                "currency": self.currency,
                "reconciled": self.amount_reconciled,
            },
            "payload_sha256": self.payload_sha256,
            "binding_sha256": self.binding_sha256,
            "status": self.status.value,
            "reason": self.reason,
            "detail": self.detail,
            "decision": self.decision,
            "decision_reason": self.decision_reason,
            "policy": (f"{self.policy_id}:{self.policy_version}"
                       if self.policy_id else None),
            "authorization_request_id": self.authorization_request_id,
            "approval_id": self.approval_id,
            "jit_grant_id": self.jit_grant_id,
            "required_approvals": self.required_approvals,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "received_at": self.received_at.isoformat(),
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "denied_at": self.denied_at.isoformat() if self.denied_at else None,
            "failed_at": self.failed_at.isoformat() if self.failed_at else None,
            "expired_at": self.expired_at.isoformat() if self.expired_at else None,
            "result_sha256": self.result_sha256,
            "execution_result": self.execution_result,
            "correlation_id": self.correlation_id,
            "session_id": self.session_id,
            "signing_key": self.key_id,
            "domain": self.domain,
            "latency_ms": self.latency_ms,
        }


# Terminal states, named once so the transition table and `is_terminal` cannot
# disagree about which they are.
TERMINAL_STATUSES = frozenset({
    A2ATransactionStatus.EXECUTED,
    A2ATransactionStatus.DENIED,
    A2ATransactionStatus.REJECTED,
    A2ATransactionStatus.FAILED,
    A2ATransactionStatus.EXPIRED,
})


class A2ATransactionAttempt(Base):
    """EVERY submission, accepted or rejected, with why.

    Doubles as the forensic record for envelopes that never became
    transactions. A rejected submission must be visible -- an attacker probing
    receiver binding or forging signatures leaves a trail here even though it
    leaves no transaction.

    Every `claimed_*` column is named that way on purpose: on a rejected
    submission those values are ASSERTIONS that failed verification, not facts.
    Calling the column `sender_did` would invite a reader to treat a forged
    claim as an attribution.
    """

    __tablename__ = "a2a_transaction_attempts"
    __table_args__ = (
        Index("ix_a2a_attempts_sender_ts", "claimed_sender_did", "created_at"),
        Index("ix_a2a_attempts_accepted_ts", "accepted", "created_at"),
        Index("ix_a2a_attempts_submitted_by", "submitted_by", "created_at"),
        Index("ix_a2a_attempts_txn", "claimed_transaction_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    claimed_transaction_id: Mapped[str | None] = mapped_column(String(128))
    claimed_sender_did: Mapped[str | None] = mapped_column(String(255))
    claimed_receiver_did: Mapped[str | None] = mapped_column(String(255))
    # The one attributable field: the principal that actually authenticated.
    submitted_by: Mapped[str] = mapped_column(String(255), nullable=False)

    payload_sha256: Mapped[str | None] = mapped_column(String(64))
    nonce: Mapped[str | None] = mapped_column(String(128))
    key_id: Mapped[str | None] = mapped_column(String(320))
    signature: Mapped[str | None] = mapped_column(String(256))

    accepted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    latency_ms: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def to_dict(self) -> dict:
        return {
            "claimed_transaction_id": self.claimed_transaction_id,
            "claimed_sender_did": self.claimed_sender_did,
            "claimed_receiver_did": self.claimed_receiver_did,
            "submitted_by": self.submitted_by,
            "payload_sha256": self.payload_sha256,
            "accepted": self.accepted,
            "stage": self.stage,
            "reason": self.reason,
            "detail": self.detail,
            "source_ip": self.source_ip,
            "latency_ms": self.latency_ms,
            "created_at": self.created_at.isoformat(),
        }
