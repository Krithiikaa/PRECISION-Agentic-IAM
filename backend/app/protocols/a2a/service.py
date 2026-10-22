"""The A2A transaction service: verify, register, reconcile, record.

WHAT THIS FILE IS NOT ALLOWED TO DO, stated first because it is the whole risk
of the phase: it does not decide whether a transaction is permitted. There is
no `if signature_valid: allow()` here, no threshold comparison, no eligibility
list and no role check. Every one of those is in Rego
(`policies/a2a/transaction.rego`) reading configuration
(`data.agentic_iam.config.a2a`). This file establishes FACTS, records what
happened, and lets the database arbitrate what two processes cannot.

THE THREE THINGS THE DATABASE DECIDES, not Python:

    exactly-once     `UNIQUE (sender_did, transaction_id)` in the WHERE of an
                     INSERT, so twenty concurrent submissions of one
                     instruction produce exactly one processing path
    execution entry  a conditional `UPDATE ... WHERE status = 'AUTHORIZED'`,
                     so even the winner cannot enter execution twice
    nonce reuse      a PARTIAL unique index, consumed only by a
                     signature-verified submission

STATE MACHINE. Transitions are an explicit table, not a convention:

    RECEIVED ──verified───────▶ VERIFIED
             └─refused────────▶ REJECTED    (terminal)

    VERIFIED ──ALLOW──────────▶ AUTHORIZED
             ├─DENY───────────▶ DENIED      (terminal)
             ├─needs a human──▶ PENDING_APPROVAL
             └─expiry─────────▶ EXPIRED     (terminal)

    PENDING_APPROVAL ──retry, ALLOW──▶ AUTHORIZED
                     ├─retry, DENY───▶ DENIED   (terminal)
                     └─expiry────────▶ EXPIRED  (terminal)

    AUTHORIZED ──atomic UPDATE──▶ EXECUTING ──▶ EXECUTED (terminal)
               │                              └─▶ FAILED   (terminal)
               └─reconciliation refused──────────▶ FAILED   (terminal)

Every terminal state has an EMPTY transition set, so `EXECUTED -> EXECUTING`
is refused BY NAME rather than by nobody happening to write that code. A
payment cannot be un-made.

WHY AN ENVELOPE IS NOT A BEARER INSTRUCTION. Holding the signed document is
necessary and NEVER sufficient. An envelope names a receiver, and submitting
it requires a control-plane proof signed by THAT DID's private key. Theft of
the envelope alone therefore buys nothing -- which is what makes returning it
to the sender, storing it, and logging its digest defensible.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.credentials.canonical import canonical_bytes
from app.db.models.a2a import (
    TERMINAL_STATUSES,
    A2ATransaction,
    A2ATransactionAttempt,
    A2ATransactionStatus,
)
from app.db.models.agent import AgentStatus
from app.db.repositories.agents import AgentRepository
from app.protocols.a2a.envelope import (
    A2ABinding,
    A2AReason,
    EnvelopeReport,
    verify_envelope,
)
from app.monitoring.events import Event, EventType

log = get_logger("a2a.service")

# Identity states that make an agent unable to SEND a transaction at all. The
# same set the control plane refuses, for the same reason: a terminated agent
# must not be able to instruct anybody to do anything.
INELIGIBLE_SENDER_STATES = (AgentStatus.TERMINATED, AgentStatus.SUSPENDED)

# `agent_keys.created_at` is a DATABASE server default, while a proof's
# `created` comes from the signing process's clock. A key generated and used
# in the same instant can therefore look as though it signed microseconds
# before it existed. This tolerance absorbs that, and nothing more: it is far
# smaller than the freshness window, so it cannot widen any real acceptance.
KEY_CREATION_TOLERANCE_SECONDS = 120

# The only permitted transitions. Anything absent is refused by name.
ALLOWED_TRANSITIONS: dict[A2ATransactionStatus, frozenset[A2ATransactionStatus]] = {
    A2ATransactionStatus.RECEIVED: frozenset({
        A2ATransactionStatus.VERIFIED,
        A2ATransactionStatus.REJECTED,
        A2ATransactionStatus.EXPIRED,
    }),
    A2ATransactionStatus.VERIFIED: frozenset({
        A2ATransactionStatus.AUTHORIZED,
        A2ATransactionStatus.PENDING_APPROVAL,
        A2ATransactionStatus.DENIED,
        A2ATransactionStatus.EXPIRED,
    }),
    A2ATransactionStatus.PENDING_APPROVAL: frozenset({
        A2ATransactionStatus.AUTHORIZED,
        A2ATransactionStatus.PENDING_APPROVAL,
        A2ATransactionStatus.DENIED,
        A2ATransactionStatus.EXPIRED,
    }),
    A2ATransactionStatus.AUTHORIZED: frozenset({
        A2ATransactionStatus.EXECUTING,
        A2ATransactionStatus.DENIED,
        A2ATransactionStatus.EXPIRED,
        # AUTHORIZED -> FAILED is reachable and must be, for a reason worth
        # naming: policy can say yes and the action still not happen. The
        # third amount reconciliation runs AFTER the decision and before
        # anything is claimed -- if the figure policy authorized is not the
        # figure the sender signed, nothing may move, and that is a FAILURE
        # rather than a DENIAL. Collapsing it into DENIED would tell an
        # operator that policy refused, when policy did not.
        A2ATransactionStatus.FAILED,
    }),
    A2ATransactionStatus.EXECUTING: frozenset({
        A2ATransactionStatus.EXECUTED,
        A2ATransactionStatus.FAILED,
    }),
    # Terminal. All empty, so nothing can bring a settled transaction back.
    A2ATransactionStatus.EXECUTED: frozenset(),
    A2ATransactionStatus.DENIED: frozenset(),
    A2ATransactionStatus.REJECTED: frozenset(),
    A2ATransactionStatus.FAILED: frozenset(),
    A2ATransactionStatus.EXPIRED: frozenset(),
}


class InvalidTransactionTransition(ConflictError):
    """A transaction was asked to move somewhere the table does not permit."""


def result_digest(result: Any) -> str:
    """SHA-256 over the canonical execution result.

    A DIGEST goes into the signed response and the audit trail, never the
    result itself: a receipt must be verifiable without being a copy of
    whatever the tool returned.
    """
    if result is None:
        return hashlib.sha256(b"null").hexdigest()
    try:
        return hashlib.sha256(canonical_bytes(result)).hexdigest()
    except Exception:  # noqa: BLE001 - a non-canonicalisable result still gets a digest
        return hashlib.sha256(repr(result).encode("utf-8")).hexdigest()


@dataclass
class A2AFact:
    """What the PIP reports to policy about an A2A transaction.

    A VERDICT plus its reason -- the same shape the credential, approval and
    mandate facts use, so Rego consumes transactions the way it consumes
    everything else and never sees a signature.
    """

    present: bool
    valid: bool
    reason: str
    transaction_id: str | None = None
    status: str | None = None
    sender_did: str | None = None
    receiver_did: str | None = None
    submitted_by: str | None = None
    action: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    purpose: str | None = None
    protocol: str | None = None
    protocol_version: str | None = None
    # The amount the SENDER signed. Present so policy can see that a signed
    # amount exists at all; the amount policy DECIDES on is
    # `input.pip.resource.attributes.amount_inr`, read server-side.
    signed_amount_inr: int | None = None
    server_amount_inr: int | None = None
    currency: str | None = None
    # Whether the two agree. FALSE is never a permissive default: an
    # unreconciled amount denies.
    amount_reconciled: bool = False
    payload_verified: bool = False
    receiver_bound: bool = False
    payload_sha256: str | None = None
    binding_sha256: str | None = None
    signing_key: str | None = None
    issued_at: str | None = None
    expires_at: str | None = None
    correlation_id: str | None = None
    offered_credentials: list[str] = field(default_factory=list)
    offered_approval_id: str | None = None
    offered_jit_grant_id: str | None = None
    checks: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "valid": self.valid,
            "reason": self.reason,
            "transaction_id": self.transaction_id,
            "status": self.status,
            "sender_did": self.sender_did,
            "receiver_did": self.receiver_did,
            "submitted_by": self.submitted_by,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "purpose": self.purpose,
            "protocol": self.protocol,
            "protocol_version": self.protocol_version,
            "signed_amount_inr": self.signed_amount_inr,
            "server_amount_inr": self.server_amount_inr,
            "currency": self.currency,
            "amount_reconciled": self.amount_reconciled,
            "payload_verified": self.payload_verified,
            "receiver_bound": self.receiver_bound,
            "payload_sha256": self.payload_sha256,
            "binding_sha256": self.binding_sha256,
            "signing_key": self.signing_key,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "correlation_id": self.correlation_id,
            "offered_credentials": list(self.offered_credentials),
            "offered_approval_id": self.offered_approval_id,
            "offered_jit_grant_id": self.offered_jit_grant_id,
            "checks": list(self.checks),
        }

    @classmethod
    def absent(cls) -> "A2AFact":
        """No A2A envelope applies to this request.

        A FACT, not an omission, and never a permissive default. Every rule in
        `a2a/transaction.rego` guards on `present == true`, so an ordinary
        Phase 1-6 authorization request is decided exactly as it was before
        Phase 7 existed.
        """
        return cls(present=False, valid=False, reason=A2AReason.MISSING)

    @classmethod
    def from_report(
        cls, report: EnvelopeReport, *, submitted_by: str,
        status: str | None = None, server_amount_inr: int | None = None,
        amount_reconciled: bool = False,
    ) -> "A2AFact":
        return cls(
            present=True,
            valid=report.valid and amount_reconciled,
            reason=report.reason,
            transaction_id=report.transaction_id,
            status=status,
            sender_did=report.sender_did,
            receiver_did=report.receiver_did,
            submitted_by=submitted_by,
            action=report.action,
            resource_type=report.resource_type,
            resource_id=report.resource_id,
            purpose=report.purpose,
            protocol=report.protocol,
            protocol_version=report.protocol_version,
            signed_amount_inr=report.amount_inr,
            server_amount_inr=server_amount_inr,
            currency=report.currency,
            amount_reconciled=amount_reconciled,
            payload_verified=report.payload_verified,
            receiver_bound=report.receiver_bound,
            payload_sha256=report.payload_sha256,
            binding_sha256=report.binding_sha256,
            signing_key=report.signing_key,
            issued_at=report.issued_at,
            expires_at=report.expires_at,
            correlation_id=report.correlation_id,
            offered_credentials=list(report.credential_ids),
            offered_approval_id=report.approval_id,
            offered_jit_grant_id=report.jit_grant_id,
            checks=[c.to_dict() for c in report.checks],
        )


@dataclass
class RegistrationOutcome:
    """What happened when a verified envelope was offered to the ledger.

    FOUR genuinely different results, and collapsing any two of them would
    hide something:

        registered   first time. Processing continues.
        resumed      the same instruction, and it is WAITING FOR A HUMAN.
                     Processing continues, because this is the retry that
                     lets an approval take effect.
        idempotent   the same instruction, already settled or already in
                     flight. The recorded outcome is returned; nothing is
                     re-decided and nothing re-executes.
        conflict     the same transaction id carrying DIFFERENT content. An
                     attack, not a retry.

    WHY `resumed` HAS TO EXIST, and it is the subtlest thing in this file.

    An escalated transaction is retried under the SAME transaction id -- that
    is the whole point of deriving the authorization request id from it, so
    the approval binding is reproducible. If every duplicate were answered
    idempotently, a payment a human had just approved would be told "still
    pending" forever and the approval could never be used.

    So a PENDING_APPROVAL record re-enters the pipeline: reconciliation runs
    again, the PDP is asked again, and the approval is weighed. Exactly-once
    is not weakened by this, because execution is gated separately by the
    atomic `claim_execution` -- a transaction that reached EXECUTED is
    terminal and can never be resumed.

    Everything NOT terminal and NOT pending -- RECEIVED, VERIFIED,
    AUTHORIZED, EXECUTING -- is a concurrent duplicate racing a submission
    that is still in progress. Those are answered idempotently rather than
    duplicating the work.
    """

    registered: bool
    idempotent: bool
    conflict: bool
    record: A2ATransaction | None
    reason: str | None = None
    detail: str | None = None
    resumed: bool = False


class A2ATransactionService:
    def __init__(
        self,
        session: AsyncSession,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.agents = AgentRepository(session)
        self.audit = AuditService(session)

    # --- lookup -----------------------------------------------------------
    async def get(self, sender_did: str, transaction_id: str) -> A2ATransaction | None:
        result = await self.session.execute(
            select(A2ATransaction).where(
                A2ATransaction.sender_did == sender_did,
                A2ATransaction.transaction_id == transaction_id,
            )
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, transaction_id: str) -> A2ATransaction | None:
        """Look one up by transaction id alone, for the read API.

        Ambiguous in principle -- two senders may legitimately use the same id
        -- so it returns the most recent. Never used on a decision path; the
        decision path always knows the sender, because the sender is signed.
        """
        result = await self.session.execute(
            select(A2ATransaction)
            .where(A2ATransaction.transaction_id == transaction_id)
            .order_by(A2ATransaction.received_at.desc())
        )
        return result.scalars().first()

    async def require(self, sender_did: str, transaction_id: str) -> A2ATransaction:
        record = await self.get(sender_did, transaction_id)
        if record is None:
            raise NotFoundError(f"No A2A transaction {transaction_id!r} from {sender_did}")
        return record

    async def for_receiver(
        self, receiver_did: str, *, limit: int = 50
    ) -> list[A2ATransaction]:
        result = await self.session.execute(
            select(A2ATransaction)
            .where(A2ATransaction.receiver_did == receiver_did)
            .order_by(A2ATransaction.received_at.desc())
            .limit(limit)
        )
        return list(result.scalars().unique().all())

    async def for_sender(
        self, sender_did: str, *, limit: int = 50
    ) -> list[A2ATransaction]:
        result = await self.session.execute(
            select(A2ATransaction)
            .where(A2ATransaction.sender_did == sender_did)
            .order_by(A2ATransaction.received_at.desc())
            .limit(limit)
        )
        return list(result.scalars().unique().all())

    async def attempts_for(self, transaction_id: str) -> list[A2ATransactionAttempt]:
        result = await self.session.execute(
            select(A2ATransactionAttempt)
            .where(A2ATransactionAttempt.claimed_transaction_id == transaction_id)
            .order_by(A2ATransactionAttempt.created_at)
        )
        return list(result.scalars().all())

    # --- 1. sender resolution --------------------------------------------
    async def resolve_sender(
        self, sender_did: str
    ) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]] | None, str | None]:
        """Resolve the sender to a published DID Document and its key register.

        THE SAME TRUST PATH A THIRD PARTY WOULD TAKE, and deliberately NOT the
        ANS: the registry holds a routing directory whose own docstring calls
        its credential index "never a verdict". Public keys come from
        `did_documents`, which the ANS does not control. An ANS compromise
        therefore degrades to denial of service -- it can send a sender to the
        wrong endpoint, and the wrong endpoint holds no key to submit with.

        Returns `(document, key_register, error_reason)`.
        """
        if not sender_did:
            return None, None, A2AReason.MALFORMED
        agent = await self.agents.get_by_did(sender_did)
        if agent is None:
            return None, None, A2AReason.SENDER_UNKNOWN
        if agent.status in INELIGIBLE_SENDER_STATES:
            # Checked here as a fast structural refusal, and AGAIN by
            # `credential_state.rego` against `input.pip.subject.active`. Two
            # independent refusals, because "suspend the agent" is the first
            # move in an incident and it has to mean something on its own.
            return None, None, A2AReason.SENDER_NOT_ELIGIBLE
        if agent.status is not AgentStatus.ACTIVE:
            return None, None, A2AReason.SENDER_NOT_ELIGIBLE
        document = await self.agents.get_did_document(sender_did)
        if document is None:
            return None, None, A2AReason.SENDER_NOT_RESOLVABLE

        tolerance = timedelta(seconds=KEY_CREATION_TOLERANCE_SECONDS)
        register: dict[str, dict[str, Any]] = {}
        for key in agent.keys:
            created = key.created_at
            if created is not None and created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            retired = key.rotated_at
            if retired is not None and retired.tzinfo is None:
                retired = retired.replace(tzinfo=timezone.utc)
            register[key.kid] = {
                "status": key.status.value,
                "not_before": (created - tolerance) if created else None,
                "retired_at": retired,
            }
        return document.document, register, None

    # --- 2. verify --------------------------------------------------------
    async def verify(
        self,
        envelope: dict[str, Any] | None,
        *,
        expected_receiver_did: str,
        now: datetime | None = None,
    ) -> EnvelopeReport:
        """Establish the facts about an envelope. Decides nothing.

        Resolution failures are folded into the report rather than raised, so
        the caller records ONE refusal with ONE named reason whatever went
        wrong -- the same shape the credential, approval and grant verifiers
        produce.
        """
        now = now or datetime.now(timezone.utc)
        sender_did = (envelope or {}).get("senderDid") if isinstance(envelope, dict) else None

        document = keys = None
        if isinstance(sender_did, str) and sender_did:
            document, keys, error = await self.resolve_sender(sender_did)
            if error is not None:
                # Reported through the verifier so the check list is complete
                # and consistent, rather than short-circuiting with a bare
                # reason the caller has to special-case.
                report = verify_envelope(
                    envelope, expected_receiver_did=expected_receiver_did,
                    sender_document=None, sender_keys=None,
                    expected_domain=self.settings.a2a_domain, now=now,
                    freshness_seconds=self.settings.a2a_freshness_seconds,
                    max_ttl_seconds=self.settings.a2a_max_ttl_seconds,
                )
                # Keep the more specific sender reason when the envelope was
                # otherwise well formed enough to have got that far.
                if report.reason == A2AReason.SENDER_NOT_RESOLVABLE:
                    report.reason = error
                return report

        return verify_envelope(
            envelope,
            expected_receiver_did=expected_receiver_did,
            sender_document=document,
            sender_keys=keys,
            expected_domain=self.settings.a2a_domain,
            now=now,
            freshness_seconds=self.settings.a2a_freshness_seconds,
            max_ttl_seconds=self.settings.a2a_max_ttl_seconds,
        )

    # --- 3. register (the atomic step) -----------------------------------
    async def register(
        self,
        envelope: dict[str, Any],
        report: EnvelopeReport,
        *,
        submitted_by: str,
        now: datetime | None = None,
    ) -> RegistrationOutcome:
        """Put a VERIFIED envelope into the ledger, exactly once.

        ONLY CALLED AFTER THE SIGNATURE HAS VERIFIED. That ordering is the
        security property: `UNIQUE (sender_did, transaction_id)` makes a
        transaction id scarce, and if a forged submission could write a row it
        could burn a legitimate sender's id. Rejected submissions go to
        `a2a_transaction_attempts` and nowhere else.

        THE INSERT IS THE ARBITER. Deliberately not a read-then-write: twenty
        concurrent submissions of one instruction all reach this line, and the
        database picks one. The nineteen losers re-read and are answered
        idempotently.
        """
        now = now or datetime.now(timezone.utc)
        proof = envelope.get("proof") or {}

        record = A2ATransaction(
            transaction_id=report.transaction_id,
            sender_did=report.sender_did,
            receiver_did=report.receiver_did,
            submitted_by=submitted_by,
            protocol=report.protocol,
            protocol_version=report.protocol_version,
            action=report.action,
            resource_type=report.resource_type,
            resource_id=report.resource_id,
            purpose=report.purpose,
            amount_inr=report.amount_inr,
            currency=report.currency,
            payload_sha256=report.payload_sha256,
            binding_sha256=report.binding_sha256,
            nonce=report.nonce or "",
            domain=envelope.get("domain") or self.settings.a2a_domain,
            key_id=report.signing_key,
            signature=(proof.get("signatureValue") or "")[:256],
            signature_verified=True,
            envelope=envelope,
            issued_at=_parse(report.issued_at, now),
            expires_at=_parse(report.expires_at, now),
            received_at=now,
            status=A2ATransactionStatus.RECEIVED,
            authorization_request_id=authorization_request_id(report.transaction_id),
            approval_id=None,
            jit_grant_id=report.jit_grant_id,
            correlation_id=report.correlation_id,
        )
        try:
            async with self.session.begin_nested():
                self.session.add(record)
                await self.session.flush()
        except IntegrityError:
            existing = await self.get(report.sender_did, report.transaction_id)
            if existing is None:
                # The unique that fired was the NONCE index, not the id: a
                # fresh transaction id reusing a nonce already spent. Named
                # as a replay, because that is what it is.
                log.warning("a2a_nonce_replayed", sender=report.sender_did,
                            transaction_id=report.transaction_id)
                return RegistrationOutcome(
                    registered=False, idempotent=False, conflict=True, record=None,
                    reason=A2AReason.REPLAY_BLOCKED,
                    detail="this nonce has already been presented by this sender",
                )
            # SAME ID -- is it the same instruction?
            #
            # `binding_sha256` covers the transaction id, both parties, the
            # action, the resource, the purpose, the amount and the payload
            # digest. If it matches, this is the same instruction arriving
            # again: a retry, and the recorded outcome is the honest answer.
            # If it differs, somebody is reusing an accepted id to carry
            # different content, which is an attack and not a retry.
            if existing.binding_sha256 != report.binding_sha256:
                log.error("a2a_transaction_id_reuse",
                          sender=report.sender_did,
                          transaction_id=report.transaction_id,
                          recorded=existing.binding_sha256[:16],
                          presented=(report.binding_sha256 or "")[:16])
                return RegistrationOutcome(
                    registered=False, idempotent=False, conflict=True,
                    record=existing,
                    reason=A2AReason.TRANSACTION_ID_REUSE,
                    detail="this transaction id is already recorded against "
                           "different content",
                )
            if existing.status is A2ATransactionStatus.PENDING_APPROVAL:
                # THE HITL RETRY. Not a replay: the sender is asking again
                # because it was told to, once the humans had decided.
                log.info("a2a_resumed_after_escalation",
                         transaction_id=existing.transaction_id,
                         approval_id=existing.approval_id)
                return RegistrationOutcome(
                    registered=False, idempotent=False, conflict=False,
                    record=existing, resumed=True,
                    detail="re-entering the pipeline with any human decision "
                           "now in hand",
                )
            return RegistrationOutcome(
                registered=False, idempotent=True, conflict=False, record=existing,
                reason=A2AReason.REPLAY_BLOCKED,
                detail=f"already recorded; status {existing.status.value}",
            )

        await self.audit.record(
            Event(
                EventType.A2A_SIGNATURE_VERIFIED,
                agent_did=report.sender_did,
                request_id=record.authorization_request_id,
                resource=report.resource_type,
                action=report.action,
                decision="VERIFIED",
                reason=A2AReason.VALID,
                metadata={
                    "transaction_id": report.transaction_id,
                    "sender": report.sender_did,
                    "receiver": report.receiver_did,
                    "submitted_by": submitted_by,
                    "signing_key": report.signing_key,
                    "payload_sha256": report.payload_sha256,
                    "binding_sha256": report.binding_sha256,
                    "correlation_id": report.correlation_id,
                    "signature_is_not_authorization": (
                        "the PDP has not been asked yet"
                    ),
                },
            )
        )
        log.info("a2a_registered", transaction_id=report.transaction_id,
                 sender=report.sender_did, receiver=report.receiver_did,
                 action=report.action, resource=report.resource_type)
        return RegistrationOutcome(True, False, False, record)

    # --- 4. amount reconciliation ----------------------------------------
    def reconcile_amount(
        self, report: EnvelopeReport, attributes: dict[str, Any] | None
    ) -> tuple[bool, int | None, str | None]:
        """Compare the SIGNED amount against what the server independently holds.

        THE RULE THIS METHOD EXISTS FOR:

            NEVER TRUST A CLIENT-PROVIDED AMOUNT MERELY BECAUSE IT IS
            CRYPTOGRAPHICALLY SIGNED.

        A signature proves the sender committed to a number. It proves nothing
        about whether that number is the number on the record. Those are
        different facts and both are needed:

            signed   "A instructed Rs 50,000"    -- tamper-evident in flight
            server   "the instruction reads Rs 50,000" -- what policy decides on

        Disagreement is an incident, not a rounding difference, and it DENIES.
        Silently preferring the server value would let a sender commit to one
        figure while the system acted on another, and the audit trail would
        show a signature over a number nobody acted on.

        Returns `(reconciled, server_amount, reason)`.
        """
        signed = report.amount_inr
        attributes = attributes or {}
        available = attributes.get("available") is True
        server = attributes.get("amount_inr") if available else None

        if signed is None:
            # A non-financial transaction. Reconciled vacuously -- there is no
            # amount to disagree about. It is NOT treated as "amount zero".
            return True, None, None
        if not available or not isinstance(server, int):
            # A signed amount against a record the server cannot read. Nobody
            # should move a sum nobody can state.
            return False, None, A2AReason.AMOUNT_UNAVAILABLE
        if signed != server:
            return False, server, A2AReason.AMOUNT_MISMATCH
        return True, server, None

    # --- 5. state transitions --------------------------------------------
    def _assert_transition(
        self, record: A2ATransaction, target: A2ATransactionStatus
    ) -> None:
        """Refuse an impossible transition BY NAME.

        Terminal is terminal: EXECUTED, DENIED, REJECTED, FAILED and EXPIRED
        all have empty permitted-target sets, so nothing can bring a settled
        transaction back.
        """
        permitted = ALLOWED_TRANSITIONS.get(record.status, frozenset())
        if target not in permitted:
            raise InvalidTransactionTransition(
                f"Transaction {record.transaction_id} is {record.status.value}; "
                f"{record.status.value} -> {target.value} is not a permitted "
                f"transition. Permitted from here: "
                f"{sorted(s.value for s in permitted) or 'nothing (terminal)'}."
            )

    async def mark_verified(
        self, record: A2ATransaction, *, server_amount_inr: int | None,
        amount_reconciled: bool,
    ) -> A2ATransaction:
        """Record the reconciliation, and move RECEIVED -> VERIFIED.

        On a RESUME the record is already past RECEIVED, so only the amount
        facts are refreshed. Re-reconciling on every attempt is deliberate:
        the record may have moved while the transaction waited for a human,
        and a stale `amount_reconciled` would let it through on a figure
        nobody checked.
        """
        record.server_amount_inr = server_amount_inr
        record.amount_reconciled = amount_reconciled
        if record.status is A2ATransactionStatus.RECEIVED:
            self._assert_transition(record, A2ATransactionStatus.VERIFIED)
            record.status = A2ATransactionStatus.VERIFIED
        await self.session.flush()
        return record

    async def mark_decided(
        self,
        record: A2ATransaction,
        *,
        decision: str,
        reason: str,
        policy_id: str | None,
        policy_version: str | None,
        authorized_amount_inr: int | None = None,
        approval_id: str | None = None,
        required_approvals: int | None = None,
        detail: str | None = None,
        now: datetime | None = None,
    ) -> A2ATransaction:
        """Record what the PDP said. Does not execute anything."""
        now = now or datetime.now(timezone.utc)
        record.decision = decision
        record.decision_reason = reason
        record.policy_id = policy_id
        record.policy_version = policy_version
        record.approval_id = approval_id or record.approval_id
        record.required_approvals = required_approvals or record.required_approvals
        if detail:
            record.detail = detail

        if decision == "ALLOW":
            self._assert_transition(record, A2ATransactionStatus.AUTHORIZED)
            record.status = A2ATransactionStatus.AUTHORIZED
            # WHAT POLICY ACTUALLY PERMITTED, recorded before anything moves.
            # The execution is reconciled against THIS, not against the
            # envelope and not against the record -- so a change between the
            # decision and the execution is caught even if both of those
            # agreed at decision time.
            record.authorized_amount_inr = authorized_amount_inr
        elif decision == "HUMAN_APPROVAL_REQUIRED":
            self._assert_transition(record, A2ATransactionStatus.PENDING_APPROVAL)
            record.status = A2ATransactionStatus.PENDING_APPROVAL
        else:
            self._assert_transition(record, A2ATransactionStatus.DENIED)
            record.status = A2ATransactionStatus.DENIED
            record.reason = reason
            record.denied_at = now
        await self.session.flush()
        return record

    async def claim_execution(
        self, record: A2ATransaction, *, now: datetime | None = None
    ) -> bool:
        """Enter execution. Exactly one concurrent caller can win.

        A single conditional UPDATE: the WHERE clause is the guard, so the
        DATABASE decides the winner. This is the SECOND independent layer --
        the unique INSERT already ensured one processing path, and this
        ensures that even a single path cannot execute twice if it were
        somehow re-entered.

        Expiry is folded into the SAME atomic condition, so there is no window
        in which a transaction expires between the check and the execution.
        """
        now = now or datetime.now(timezone.utc)
        result = await self.session.execute(
            update(A2ATransaction)
            .where(
                A2ATransaction.id == record.id,
                A2ATransaction.status == A2ATransactionStatus.AUTHORIZED,
                A2ATransaction.expires_at > now,
            )
            .values(status=A2ATransactionStatus.EXECUTING, executing_at=now)
            .returning(A2ATransaction.id)
        )
        won = result.scalar_one_or_none() is not None
        await self.session.flush()
        if won:
            await self.session.refresh(record)
        else:
            log.warning("a2a_execution_claim_lost",
                        transaction_id=record.transaction_id,
                        status=record.status.value)
        return won

    async def mark_executed(
        self, record: A2ATransaction, *, result: Any,
        executed_amount_inr: int | None = None, now: datetime | None = None,
    ) -> A2ATransaction:
        now = now or datetime.now(timezone.utc)
        self._assert_transition(record, A2ATransactionStatus.EXECUTED)
        record.status = A2ATransactionStatus.EXECUTED
        record.executed_at = now
        record.executed_amount_inr = executed_amount_inr
        record.execution_result = result if isinstance(result, dict) else {"result": result}
        record.result_sha256 = result_digest(result)
        record.reason = A2AReason.VALID
        await self.session.flush()

        await self.audit.record(
            Event(
                EventType.A2A_EXECUTED,
                agent_did=record.sender_did,
                request_id=record.authorization_request_id,
                resource=record.resource_type,
                action=record.action,
                decision="EXECUTED",
                reason=record.decision_reason,
                metadata={
                    "transaction_id": record.transaction_id,
                    "sender": record.sender_did,
                    "receiver": record.receiver_did,
                    "resource_id": record.resource_id,
                    "signed_amount_inr": record.amount_inr,
                    "server_amount_inr": record.server_amount_inr,
                    "authorized_amount_inr": record.authorized_amount_inr,
                    "executed_amount_inr": record.executed_amount_inr,
                    "result_sha256": record.result_sha256,
                    "approval_id": record.approval_id,
                    "policy": (f"{record.policy_id}:{record.policy_version}"
                               if record.policy_id else None),
                    "correlation_id": record.correlation_id,
                },
            )
        )
        log.info("a2a_executed", transaction_id=record.transaction_id,
                 sender=record.sender_did, receiver=record.receiver_did,
                 amount_inr=record.executed_amount_inr)
        return record

    async def mark_failed(
        self, record: A2ATransaction, *, reason: str, detail: str,
        now: datetime | None = None,
    ) -> A2ATransaction:
        """The tool faulted, or the last reconciliation refused.

        A DISTINCT terminal state from DENIED: policy said yes and the action
        did not happen. An operator needs to tell "you may not" from "you may,
        and it broke" -- and, in the reconciliation case, from "you may, and
        the figure moved underneath you".
        """
        now = now or datetime.now(timezone.utc)
        self._assert_transition(record, A2ATransactionStatus.FAILED)
        record.status = A2ATransactionStatus.FAILED
        record.failed_at = now
        record.reason = reason
        record.detail = detail
        await self.session.flush()
        await self.audit.record(
            Event(
                EventType.A2A_FAILED,
                agent_did=record.sender_did,
                request_id=record.authorization_request_id,
                resource=record.resource_type,
                action=record.action,
                decision="FAILED",
                reason=reason,
                metadata={
                    "transaction_id": record.transaction_id,
                    "detail": detail,
                    "resource_id": record.resource_id,
                    "authorized_amount_inr": record.authorized_amount_inr,
                    "correlation_id": record.correlation_id,
                },
            )
        )
        log.error("a2a_failed", transaction_id=record.transaction_id,
                  reason=reason, detail=detail)
        return record

    # --- 6. refusals that never became transactions ----------------------
    async def record_attempt(
        self,
        *,
        envelope: dict[str, Any] | None,
        submitted_by: str,
        accepted: bool,
        stage: str,
        reason: str,
        detail: str | None = None,
        source_ip: str | None = None,
        latency_ms: float | None = None,
        now: datetime | None = None,
    ) -> A2ATransactionAttempt:
        """Record one submission, whatever became of it.

        EVERY submission lands here, including the ones that never become
        transactions. Without it, an attacker probing receiver binding or
        forging signatures would leave no trace at all -- their attempts write
        no transaction row by design, and a refusal nobody can see is a
        refusal nobody can respond to.
        """
        now = now or datetime.now(timezone.utc)
        envelope = envelope if isinstance(envelope, dict) else {}
        transaction = envelope.get("transaction") or {}
        proof = envelope.get("proof") or {}
        attempt = A2ATransactionAttempt(
            claimed_transaction_id=_as_str(envelope.get("transactionId"), 128),
            claimed_sender_did=_as_str(envelope.get("senderDid"), 255),
            claimed_receiver_did=_as_str(envelope.get("receiverDid"), 255),
            submitted_by=submitted_by[:255],
            payload_sha256=_as_str(transaction.get("payloadSha256"), 64),
            nonce=_as_str(envelope.get("nonce"), 128),
            key_id=_as_str(proof.get("verificationMethod"), 320),
            signature=_as_str(proof.get("signatureValue"), 256),
            accepted=accepted,
            stage=stage[:32],
            reason=reason[:64],
            detail=detail,
            source_ip=source_ip,
            latency_ms=latency_ms,
            created_at=now,
        )
        self.session.add(attempt)
        await self.session.flush()
        return attempt

    async def record_rejection(
        self,
        *,
        envelope: dict[str, Any] | None,
        submitted_by: str,
        report: EnvelopeReport | None,
        reason: str,
        detail: str | None = None,
        source_ip: str | None = None,
        latency_ms: float | None = None,
    ) -> None:
        """Audit a refusal, and record the attempt. Never silently."""
        await self.record_attempt(
            envelope=envelope, submitted_by=submitted_by, accepted=False,
            stage="verification", reason=reason, detail=detail,
            source_ip=source_ip, latency_ms=latency_ms,
        )
        claimed = (envelope or {}).get("transactionId") if isinstance(envelope, dict) else None
        await self.audit.record(
            Event(
                EventType.A2A_REJECTED,
                # The claimed sender is NOT used as `agent_did`: a forged
                # envelope must not attribute an event to the agent it names.
                # The principal that actually authenticated is recorded below.
                agent_did=None,
                request_id=authorization_request_id(claimed) if claimed else None,
                resource=(report.resource_type if report else None),
                action=(report.action if report else None),
                decision="REJECTED",
                reason=reason,
                metadata={
                    "claimed_transaction_id": claimed,
                    "claimed_sender": (envelope or {}).get("senderDid")
                    if isinstance(envelope, dict) else None,
                    "claimed_receiver": (envelope or {}).get("receiverDid")
                    if isinstance(envelope, dict) else None,
                    "submitted_by": submitted_by,
                    "detail": detail,
                    "source_ip": source_ip,
                    "checks": [c.to_dict() for c in report.checks] if report else [],
                },
            )
        )
        log.warning("a2a_rejected", reason=reason, submitted_by=submitted_by,
                    claimed_transaction_id=claimed, detail=detail)

    async def record_replay(
        self, outcome: RegistrationOutcome, *, submitted_by: str,
        envelope: dict[str, Any] | None = None,
    ) -> None:
        """A duplicate or a reused id. Its own event, never a generic denial.

        An operator filtering the trail for reuse should not have to
        reconstruct it from decision rows -- the same reasoning
        `APPROVAL_REPLAY_REJECTED` and `JIT_REPLAY_BLOCKED` follow.
        """
        record = outcome.record
        await self.record_attempt(
            envelope=envelope, submitted_by=submitted_by, accepted=False,
            stage="registration", reason=outcome.reason or A2AReason.REPLAY_BLOCKED,
            detail=outcome.detail,
        )
        await self.audit.record(
            Event(
                EventType.A2A_REPLAY_BLOCKED,
                agent_did=record.sender_did if record else None,
                request_id=record.authorization_request_id if record else None,
                resource=record.resource_type if record else None,
                action=record.action if record else None,
                decision="DENY" if outcome.conflict else "IDEMPOTENT",
                reason=outcome.reason,
                metadata={
                    "transaction_id": record.transaction_id if record else None,
                    "status": record.status.value if record else None,
                    "idempotent": outcome.idempotent,
                    "conflict": outcome.conflict,
                    "submitted_by": submitted_by,
                    "detail": outcome.detail,
                    "executions_unchanged": (
                        "the recorded outcome was returned; nothing was "
                        "re-decided and nothing re-executed"
                    ) if outcome.idempotent else None,
                },
            )
        )
        if outcome.conflict:
            log.error("a2a_replay_conflict", submitted_by=submitted_by,
                      reason=outcome.reason, detail=outcome.detail)
        else:
            log.info("a2a_replay_idempotent",
                     transaction_id=record.transaction_id if record else None,
                     status=record.status.value if record else None)

    # --- 7. expiry sweep --------------------------------------------------
    async def sweep_expired(self, *, now: datetime | None = None) -> list[str]:
        """Move overdue transactions to EXPIRED.

        HOUSEKEEPING, NOT ENFORCEMENT. A transaction past its expiry is
        already unusable -- verification compares against the server clock and
        `claim_execution` folds expiry into its atomic condition, and neither
        waits for this. This exists so the stored status matches reality for
        anyone reading the table, and so A2A_EXPIRED is emitted at all.
        """
        now = now or datetime.now(timezone.utc)
        sweepable = (
            A2ATransactionStatus.RECEIVED,
            A2ATransactionStatus.VERIFIED,
            A2ATransactionStatus.PENDING_APPROVAL,
            A2ATransactionStatus.AUTHORIZED,
        )
        result = await self.session.execute(
            update(A2ATransaction)
            .where(
                A2ATransaction.status.in_(sweepable),
                A2ATransaction.expires_at <= now,
            )
            .values(status=A2ATransactionStatus.EXPIRED, expired_at=now,
                    reason=A2AReason.EXPIRED)
            .returning(A2ATransaction.transaction_id)
        )
        expired = [row[0] for row in result.all()]
        await self.session.flush()

        for transaction_id in expired:
            record = await self.get_by_id(transaction_id)
            await self.audit.record(
                Event(
                    EventType.A2A_EXPIRED,
                    agent_did=record.sender_did if record else None,
                    request_id=record.authorization_request_id if record else None,
                    resource=record.resource_type if record else None,
                    action=record.action if record else None,
                    decision="EXPIRED",
                    reason=A2AReason.EXPIRED,
                    metadata={
                        "transaction_id": transaction_id,
                        "expires_at": record.expires_at.isoformat() if record else None,
                        "detail": "the window closed before the transaction settled",
                    },
                )
            )
        if expired:
            log.info("a2a_swept_expired", count=len(expired))
        return expired

    # --- reporting --------------------------------------------------------
    async def stats(self) -> dict[str, int]:
        """Counts by status, for the gate and the health endpoint."""
        result = await self.session.execute(
            select(A2ATransaction.status, func.count()).group_by(A2ATransaction.status)
        )
        counts = {status.value: 0 for status in A2ATransactionStatus}
        for status, count in result.all():
            counts[status.value] = count
        return counts


def authorization_request_id(transaction_id: str | None) -> str:
    """`a2a-{transaction_id}`. DETERMINISTIC, and that is load-bearing.

    `ApprovalBinding` includes `request_id`. If a retry after a human approval
    generated a fresh `authz-...` id, the binding digest would change, the
    approval would not be found, and the transaction would loop forever asking
    for an approval that already exists. Deriving it from the SIGNED
    transaction id makes it stable across retries AND means the approval is
    bound to something the sender cryptographically committed to.

    It is deliberately NOT a field in the envelope: signing it would let a
    sender choose it independently of the transaction it belongs to.
    """
    return f"a2a-{transaction_id}"


def _parse(value: str | None, fallback: datetime) -> datetime:
    from app.credentials.vc import parse_iso

    try:
        return parse_iso(value)
    except (ValueError, TypeError):
        return fallback


def _as_str(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value[:limit]
