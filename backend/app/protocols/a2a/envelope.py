"""The A2A transaction envelope: what it binds, and how it is verified.

    "Agent A sent Agent B a message"               <- USELESS, and dangerous
    "Agent A instructs Agent B to perform action X
     on resource R for purpose P, moving amount N,
     once, before T, and nobody else may present
     this"                                         <- what this file builds

THE ONE SENTENCE THIS FILE EXISTS TO ENFORCE:

    A VALID A2A SIGNATURE IS NOT AUTHORIZATION. IT MAKES THE TRANSACTION
    EVALUABLE.

That is the same position the human approval artifact and the JIT grant
occupy, and it is not a stylistic choice. A signature establishes that the
holder of a particular private key produced particular bytes. It says nothing
about whether the sender holds a valid credential, whether the resource is in
scope, whether the purpose matches, what the amount means, or whether a human
must be asked. Every one of those is decided afterwards, by Rego, on facts the
PIP established -- and any one of them still denies.

WHAT IS BOUND, and which attack each field stops:

    protocol+version  protocol confusion; silent downgrade when v2 lands
    transactionId     duplicate execution -- THE idempotency key (see service)
    senderDid         sender substitution
    receiverDid       receiver substitution; cross-agent forwarding
    action            action substitution (a `read` instruction is not a payment)
    resourceType      resource-class substitution
    resourceId        resource-instance substitution
    purpose           purpose substitution
    amountInr         AMOUNT ESCALATION
    currency          unit confusion
    payload           payload modification
    payloadSha256     payload substitution behind a matching id
    bindingHash       lets policy ask "is this about THIS request?" once
    offered.*         approval/mandate/credential injection by a relay
    issuanceDate      forward-dating
    expirationDate    stale replay
    nonce             see the note below -- weakly relevant, and said so
    domain            cross-service replay (the Phase 2 S-2 protection)
    proofPurpose      cross-proof confusion -- the SEVENTH domain separator

ON THE NONCE, stated honestly rather than dressed up. It is NOT the primary
replay defence here. `transactionId` is inside the signature, and
`UNIQUE (sender_did, transaction_id)` in the database is what makes an
exact-envelope replay impossible. The nonce catches nothing the transaction id
does not. It is kept for two secondary but real reasons: it puts unpredictable
bytes inside the signed payload, and all six existing proof types carry one --
a seventh that did not would be a thing a reviewer has to stop and think about.

WHAT IS DELIBERATELY *NOT* IN THE ENVELOPE:

    senderPublicKey       a self-supplied key is not evidence. Resolution is
                          from the DID Document, always.
    senderCapabilities    an agent asserting its own capabilities.
    requestId             derived as `a2a-{transactionId}` so a retry
                          reproduces the SAME approval binding. Signing it
                          would let a sender choose it independently.
    sessionId             Phase 9. NULL on the row, absent here.
    trustScore            Phase 10. Never a caller-supplied number.

CRYPTOGRAPHY: the project's existing shape, not a new one. Canonical JSON
(RFC 8785 style, floats refused) + Ed25519 + `PocEd25519Signature2026`, with a
proof purpose of `a2aTransaction` (requests) or `a2aResponse` (answers). Those
purposes are INSIDE the signed bytes, so a credential proof, a holder proof, an
ANS registration, a control-plane proof, a human approval or a JIT grant can
never verify as an A2A transaction -- and an A2A transaction can never be
presented as any of them. A response can never be replayed as a request.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from app.credentials.canonical import canonical_bytes
from app.credentials.vc import build_proof_options, parse_iso, signing_payload, to_iso
from app.identity.did_document import public_key_from_document
from app.identity.signer import Signer, verify_signature

# Domain separators. Distinct from assertionMethod (issuer), authentication
# (holder), ansRegistration (ANS), controlPlaneRequest (control plane),
# humanApproval (approval authority) and jitGrant (JIT authority).
A2A_PROOF_PURPOSE = "a2aTransaction"
A2A_RESPONSE_PROOF_PURPOSE = "a2aResponse"

TRANSACTION_TYPE = "A2ATransaction"
RESPONSE_TYPE = "A2AResponse"

PROTOCOL = "agentic-iam-a2a"
PROTOCOL_VERSION = "1.0"
SUPPORTED_VERSIONS = frozenset({"1.0"})

ENVELOPE_CONTEXT = [
    "https://www.w3.org/2018/credentials/v1",
    "https://agentic-iam.poc/a2a/v1",
]

# How far in the future an issuance timestamp may sit before it is refused.
# Matches `verify_grant` exactly so the two never disagree about "the future".
FUTURE_TOLERANCE_SECONDS = 60


class A2AReason:
    """Why an envelope was accepted or refused.

    Coarse on purpose, exactly as `ArtifactReason` and `GrantReason` are: a
    reason names the CLASS of failure, never which record or key was involved.
    An attacker probing the endpoint learns that its envelope was refused, not
    what the server expected instead.
    """

    VALID = "A2A_TRANSACTION_VALID"

    # --- shape ------------------------------------------------------------
    MISSING = "A2A_ENVELOPE_MISSING"
    MALFORMED = "A2A_ENVELOPE_MALFORMED"
    PROTOCOL_UNSUPPORTED = "A2A_PROTOCOL_UNSUPPORTED"
    PROOF_PURPOSE_INVALID = "A2A_PROOF_PURPOSE_INVALID"

    # --- binding ----------------------------------------------------------
    RECEIVER_MISMATCH = "A2A_RECEIVER_MISMATCH"
    DOMAIN_MISMATCH = "A2A_DOMAIN_MISMATCH"

    # --- the sender -------------------------------------------------------
    SENDER_UNKNOWN = "A2A_SENDER_UNKNOWN"
    SENDER_NOT_ELIGIBLE = "A2A_SENDER_NOT_ELIGIBLE"
    SENDER_NOT_RESOLVABLE = "A2A_SENDER_NOT_RESOLVABLE"

    # --- the signing key --------------------------------------------------
    KEY_UNKNOWN = "A2A_KEY_UNKNOWN"
    KEY_RETIRED = "A2A_KEY_RETIRED"
    KEY_REVOKED = "A2A_KEY_REVOKED"

    # --- the signature ----------------------------------------------------
    SIGNATURE_INVALID = "A2A_SIGNATURE_INVALID"

    # --- time -------------------------------------------------------------
    STALE = "A2A_TRANSACTION_STALE"
    EXPIRED = "A2A_TRANSACTION_EXPIRED"
    NOT_YET_VALID = "A2A_TRANSACTION_NOT_YET_VALID"
    TTL_EXCEEDS_MAXIMUM = "A2A_TTL_EXCEEDS_MAXIMUM"

    # --- replay and idempotency (settled by the service and the database) --
    REPLAY_BLOCKED = "A2A_REPLAY_BLOCKED"
    TRANSACTION_ID_REUSE = "A2A_TRANSACTION_ID_REUSE"

    # --- money ------------------------------------------------------------
    AMOUNT_MISMATCH = "A2A_AMOUNT_MISMATCH"
    AMOUNT_UNAVAILABLE = "A2A_AMOUNT_UNAVAILABLE"

    # --- enforcement ------------------------------------------------------
    NO_ENFORCEMENT_PATH = "A2A_NO_ENFORCEMENT_PATH"
    EXECUTION_FAILED = "A2A_EXECUTION_FAILED"


def is_wellformed_amount(value: Any) -> bool:
    """Is this a well-formed number of whole rupees?

    A DOMAIN check on the type, NOT a risk threshold. The distinction matters
    enough to write carefully, because Phase 5.5 established -- and a test
    enforces by grepping this package -- that no amount threshold may exist in
    Python. What a sum MEANS (autonomous, one approver, two) is decided by
    Rego against `data.agentic_iam.config.a2a`. What a sum IS -- a whole,
    non-negative integer of rupees -- is a property of the value itself, and
    has to be checked before the value can be signed at all.

    Written as `value == abs(value)` rather than `value >= 0` deliberately: it
    expresses "this equals its own magnitude" with no numeric literal in it,
    so the grep that guards against thresholds is not weakened to accommodate
    a check that is not one. A reader who pauses here should read this comment
    and find the reasoning, rather than find an exemption bolted onto a test.

    `bool` is excluded because it is an `int` subclass, and True is not a sum
    of money.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return value == abs(value)


def new_transaction_id() -> str:
    return f"txn-{uuid.uuid4().hex[:16]}"


def new_nonce() -> str:
    return secrets.token_urlsafe(18)


def payload_digest(payload: dict[str, Any] | None) -> str:
    """SHA-256 over the CANONICAL payload, not over raw bytes.

    Canonical rather than raw because the envelope crosses a process boundary
    (A -> B -> IAM) and any hop may deserialise and re-serialise it. Hashing
    raw bytes would make the digest depend on whitespace nobody controls,
    which is the problem the control-plane proof has to solve with
    `content=` instead of `json=` on every client.
    """
    return hashlib.sha256(canonical_bytes(payload or {})).hexdigest()


@dataclass(frozen=True)
class A2ABinding:
    """Exactly what an A2A transaction is ABOUT.

    Frozen and rebuilt from the envelope on every verification, so neither
    side can reinterpret it. The digest is belt and braces -- every bound
    field is also inside the signed document, so tampering with one is already
    a signature failure -- but it lets policy and the audit trail express "is
    this about THIS request?" as one comparison rather than ten.
    """

    transaction_id: str
    sender_did: str
    receiver_did: str
    action: str
    resource_type: str
    resource_id: str | None
    purpose: str
    # Money is optional because not every A2A action moves any. It defaults to
    # None rather than 0: "this transaction has no amount" and "this
    # transaction is for nothing" are different statements, and a defaulted
    # zero would be an amount nobody stated.
    amount_inr: int | None = None
    currency: str | None = None
    payload_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "sender_did": self.sender_did,
            "receiver_did": self.receiver_did,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "purpose": self.purpose,
            "amount_inr": self.amount_inr,
            "currency": self.currency,
            "payload_sha256": self.payload_sha256,
        }

    def digest(self) -> str:
        """SHA-256 over the canonical binding. Order-independent."""
        return hashlib.sha256(canonical_bytes(self.to_dict())).hexdigest()

    def differences(self, other: "A2ABinding") -> list[str]:
        """Which bound fields disagree. Named, so a denial is diagnostic."""
        mine, theirs = self.to_dict(), other.to_dict()
        return sorted(k for k in mine if mine[k] != theirs[k])

    @classmethod
    def from_envelope(cls, envelope: dict[str, Any]) -> "A2ABinding":
        transaction = envelope.get("transaction") or {}
        return cls(
            transaction_id=envelope.get("transactionId") or "",
            sender_did=envelope.get("senderDid") or "",
            receiver_did=envelope.get("receiverDid") or "",
            action=transaction.get("action") or "",
            resource_type=transaction.get("resourceType") or "",
            resource_id=transaction.get("resourceId"),
            purpose=transaction.get("purpose") or "",
            amount_inr=transaction.get("amountInr"),
            currency=transaction.get("currency"),
            payload_sha256=transaction.get("payloadSha256") or "",
        )


def build_envelope(
    *,
    transaction_id: str,
    sender_did: str,
    receiver_did: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    purpose: str,
    payload: dict[str, Any] | None = None,
    amount_inr: int | None = None,
    currency: str | None = None,
    issued_at: datetime,
    expires_at: datetime,
    nonce: str,
    domain: str,
    credential_ids: list[str] | None = None,
    approval_id: str | None = None,
    jit_grant_id: str | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """The unsigned transaction envelope.

    `offered` carries CLAIMS -- credential ids, an approval id, a mandate id.
    They are inside the signed bytes so a relay cannot add or swap one, and
    they are still only claims: the PIP verifies each independently and an
    offered id can never make an approval or a mandate apply.
    """
    if (amount_inr is None) != (currency is None):
        raise ValueError(
            "amount_inr and currency must be supplied together or not at all: "
            "an amount without a unit is not an amount."
        )
    if amount_inr is not None and not is_wellformed_amount(amount_inr):
        raise ValueError(
            "amount_inr must be a whole, non-negative number of rupees. "
            "Canonical JSON refuses floats, so a fractional amount cannot be "
            "signed at all."
        )

    body = dict(payload or {})
    binding = A2ABinding(
        transaction_id=transaction_id,
        sender_did=sender_did,
        receiver_did=receiver_did,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        purpose=purpose,
        amount_inr=amount_inr,
        currency=currency,
        payload_sha256=payload_digest(body),
    )
    return {
        "@context": ENVELOPE_CONTEXT,
        "type": ["VerifiableCredential", TRANSACTION_TYPE],
        "id": f"urn:a2a:{transaction_id}",
        "protocol": PROTOCOL,
        "protocolVersion": PROTOCOL_VERSION,
        "transactionId": transaction_id,
        "senderDid": sender_did,
        "receiverDid": receiver_did,
        "issuanceDate": to_iso(issued_at),
        "expirationDate": to_iso(expires_at),
        "transaction": {
            "action": action,
            "resourceType": resource_type,
            "resourceId": resource_id,
            "purpose": purpose,
            "amountInr": amount_inr,
            "currency": currency,
            "payload": body,
            "payloadSha256": binding.payload_sha256,
            "bindingHash": binding.digest(),
        },
        "offered": {
            "credentialIds": sorted(credential_ids or []),
            "approvalId": approval_id,
            "jitGrantId": jit_grant_id,
        },
        "correlationId": correlation_id,
        "nonce": nonce,
        # Audience binding, preserving the Phase 2 S-2 protection: an envelope
        # minted for this enforcement boundary cannot be relayed to another.
        "domain": domain,
    }


def build_response(
    *,
    transaction_id: str,
    sender_did: str,
    receiver_did: str,
    status: str,
    decision: str | None,
    reason: str | None,
    policy: str | None,
    authorization_request_id: str | None,
    result_sha256: str | None,
    approval_id: str | None,
    issued_at: datetime,
    nonce: str,
    domain: str,
) -> dict[str, Any]:
    """B's signed answer.

    Signed for a reason that is easy to miss: without it a third party can
    fabricate "your payment succeeded", and the sender has no way to tell. The
    outcome is a fact about what the IAM plane decided, and B attests to having
    relayed it faithfully.

    `senderDid` here is B -- the party ANSWERING -- and `receiverDid` is A. The
    field names describe this document, not the transaction it answers.
    """
    return {
        "@context": ENVELOPE_CONTEXT,
        "type": ["VerifiableCredential", RESPONSE_TYPE],
        "id": f"urn:a2a:response:{transaction_id}",
        "protocol": PROTOCOL,
        "protocolVersion": PROTOCOL_VERSION,
        "transactionId": transaction_id,
        "senderDid": sender_did,
        "receiverDid": receiver_did,
        "issuanceDate": to_iso(issued_at),
        "outcome": {
            "status": status,
            "decision": decision,
            "reason": reason,
            "policy": policy,
            "authorizationRequestId": authorization_request_id,
            "resultSha256": result_sha256,
            "approvalId": approval_id,
        },
        "nonce": nonce,
        "domain": domain,
    }


def signing_bytes(document: dict[str, Any], proof_options: dict[str, Any]) -> bytes:
    """The exact bytes that get signed.

    Uses the Phase 2 `signing_payload`, so the proof options -- `created`,
    `verificationMethod`, `proofPurpose`, `domain` -- are INSIDE the signature.
    Flipping `a2aTransaction` to `jitGrant` on a signed envelope invalidates it
    rather than silently repurposing it.
    """
    return canonical_bytes(signing_payload(document, proof_options))


def proof_options_for(
    document: dict[str, Any], kid: str, *, purpose: str = A2A_PROOF_PURPOSE,
    moment: datetime | None = None,
) -> dict[str, Any]:
    return build_proof_options(
        verification_method=kid,
        proof_purpose=purpose,
        created=moment or datetime.now(timezone.utc),
        domain=document.get("domain"),
    )


def sign_envelope(
    document: dict[str, Any], signer: Signer, kid: str, *,
    purpose: str = A2A_PROOF_PURPOSE, moment: datetime | None = None,
) -> dict[str, Any]:
    """Attach the SENDER AGENT's Ed25519 proof.

    Signed by the agent's Phase 1 key -- the same key that already signs ANS
    registrations, control-plane proofs and holder proofs. NOT by the approval
    authority, NOT by the JIT authority, NOT by a control-plane administrator
    and NOT by a credential issuer: an A2A transaction attests to what the
    SENDER instructed, and the sender is the only correct signer.
    """
    options = proof_options_for(document, kid, purpose=purpose, moment=moment)
    signature = signer.sign(kid, signing_bytes(document, options))
    return {**document, "proof": {**options, "signatureValue": signature.signature_b64}}


@dataclass
class A2ACheck:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class EnvelopeReport:
    """Every check, reported. Never a bare boolean.

    The same discipline the Phase 2 credential verifier, the Phase 5 approval
    verifier and the Phase 6 grant verifier use: a caller that cannot see WHICH
    check failed cannot fix the cause, and an auditor cannot review it.
    """

    valid: bool
    reason: str
    checks: list[A2ACheck] = field(default_factory=list)
    transaction_id: str | None = None
    sender_did: str | None = None
    receiver_did: str | None = None
    action: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    purpose: str | None = None
    amount_inr: int | None = None
    currency: str | None = None
    payload_sha256: str | None = None
    binding_sha256: str | None = None
    nonce: str | None = None
    signing_key: str | None = None
    issued_at: str | None = None
    expires_at: str | None = None
    protocol: str | None = None
    protocol_version: str | None = None
    correlation_id: str | None = None
    credential_ids: list[str] = field(default_factory=list)
    approval_id: str | None = None
    jit_grant_id: str | None = None
    receiver_bound: bool = False
    payload_verified: bool = False
    binding_differences: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "transaction_id": self.transaction_id,
            "sender_did": self.sender_did,
            "receiver_did": self.receiver_did,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "purpose": self.purpose,
            "amount_inr": self.amount_inr,
            "currency": self.currency,
            "payload_sha256": self.payload_sha256,
            "binding_sha256": self.binding_sha256,
            "nonce": self.nonce,
            "signing_key": self.signing_key,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "protocol": self.protocol,
            "protocol_version": self.protocol_version,
            "correlation_id": self.correlation_id,
            "credential_ids": list(self.credential_ids),
            "approval_id": self.approval_id,
            "jit_grant_id": self.jit_grant_id,
            "receiver_bound": self.receiver_bound,
            "payload_verified": self.payload_verified,
            "binding_differences": list(self.binding_differences),
            "checks": [c.to_dict() for c in self.checks],
        }


def verify_envelope(
    envelope: dict[str, Any] | None,
    *,
    expected_receiver_did: str,
    sender_document: dict[str, Any] | None,
    expected_domain: str,
    sender_keys: dict[str, dict[str, Any]] | None = None,
    now: datetime | None = None,
    freshness_seconds: int = 300,
    max_ttl_seconds: int = 300,
) -> EnvelopeReport:
    """Verify an envelope against the receiver presenting it.

    This function does NOT decide whether the transaction is permitted -- that
    is Rego's job, and it reads the verdict below. It establishes facts: is the
    signature real, is it from the sender it names, was the key allowed to sign
    it then, is it addressed to THIS receiver, is it still fresh, and does the
    payload match the digest it carries?

    CHECK ORDER IS A SECURITY PROPERTY. The signature is verified BEFORE the
    caller is allowed to register the transaction, so an attacker cannot burn
    a legitimate sender's transaction id by submitting garbage under it. That
    is the same reasoning the control-plane authenticator applies to nonces.

    THE AMOUNT IS NOT RECONCILED HERE. Reconciliation compares the signed
    amount against what the PIP read from the resource record server-side, and
    this function has no database. It is done by the service, immediately
    after registration, and again against the executed amount.

    `sender_keys` is the sender's key REGISTER keyed by `kid`. It is what makes
    rotation safe in both directions: a rotated key still verifies the
    envelopes it signed while active, and cannot have signed one dated after
    its retirement. Passing None skips the window check -- used only where the
    register genuinely cannot be resolved, and the caller must then treat the
    result as weaker.
    """
    now = now or datetime.now(timezone.utc)
    checks: list[A2ACheck] = []

    def check(name: str, passed: bool, detail: str) -> bool:
        checks.append(A2ACheck(name, passed, detail))
        return passed

    def fail(reason: str, **kw: Any) -> EnvelopeReport:
        return EnvelopeReport(False, reason, checks, **kw)

    # --- 1. present -------------------------------------------------------
    if not envelope or not isinstance(envelope, dict):
        check("present", False, "no A2A envelope was supplied")
        return fail(A2AReason.MISSING)
    check("present", True, "envelope supplied")

    # --- 2. structure -----------------------------------------------------
    transaction = envelope.get("transaction")
    proof = envelope.get("proof")
    offered = envelope.get("offered") or {}
    if not isinstance(transaction, dict) or not isinstance(proof, dict):
        check("structure", False, "transaction or proof is missing")
        return fail(A2AReason.MALFORMED)
    types = envelope.get("type") or []
    if TRANSACTION_TYPE not in types:
        # A credential, a presentation, a JIT grant, an approval artifact or an
        # A2A RESPONSE presented where a transaction is required. Refused on
        # shape before anything else is considered.
        check("structure", False,
              f"document is not an {TRANSACTION_TYPE}; got type {types!r}")
        return fail(A2AReason.MALFORMED)
    if not isinstance(offered, dict):
        check("structure", False, "offered must be an object")
        return fail(A2AReason.MALFORMED)
    check("structure", True, f"{TRANSACTION_TYPE} with a proof")

    transaction_id = envelope.get("transactionId")
    sender_did = envelope.get("senderDid")
    receiver_did = envelope.get("receiverDid")
    if not isinstance(transaction_id, str) or not transaction_id:
        check("structure", False, "transactionId is missing or not a string")
        return fail(A2AReason.MALFORMED)
    if not isinstance(sender_did, str) or not isinstance(receiver_did, str):
        check("structure", False, "senderDid or receiverDid is missing")
        return fail(A2AReason.MALFORMED, transaction_id=transaction_id)

    binding = A2ABinding.from_envelope(envelope)
    common: dict[str, Any] = {
        "transaction_id": transaction_id,
        "sender_did": sender_did,
        "receiver_did": receiver_did,
        "action": binding.action,
        "resource_type": binding.resource_type,
        "resource_id": binding.resource_id,
        "purpose": binding.purpose,
        "amount_inr": binding.amount_inr,
        "currency": binding.currency,
        "payload_sha256": binding.payload_sha256,
        "binding_sha256": binding.digest(),
        "nonce": envelope.get("nonce"),
        "issued_at": envelope.get("issuanceDate"),
        "expires_at": envelope.get("expirationDate"),
        "protocol": envelope.get("protocol"),
        "protocol_version": envelope.get("protocolVersion"),
        "correlation_id": envelope.get("correlationId"),
        "credential_ids": list(offered.get("credentialIds") or []),
        "approval_id": offered.get("approvalId"),
        "jit_grant_id": offered.get("jitGrantId"),
    }

    # An amount without a unit, or a unit without an amount, is not money.
    if (binding.amount_inr is None) != (binding.currency is None):
        check("amount_shape", False,
              "amountInr and currency must be present together or not at all")
        return fail(A2AReason.MALFORMED, **common)
    if binding.amount_inr is not None and not is_wellformed_amount(binding.amount_inr):
        check("amount_shape", False,
              "amountInr must be a whole, non-negative number of rupees")
        return fail(A2AReason.MALFORMED, **common)
    check("amount_shape", True,
          "no amount" if binding.amount_inr is None
          else f"{binding.amount_inr} {binding.currency}")

    # --- 3. protocol ------------------------------------------------------
    if envelope.get("protocol") != PROTOCOL:
        check("protocol", False,
              f"protocol must be {PROTOCOL!r}, got {envelope.get('protocol')!r}")
        return fail(A2AReason.PROTOCOL_UNSUPPORTED, **common)
    if envelope.get("protocolVersion") not in SUPPORTED_VERSIONS:
        # Refused rather than best-effort parsed. A version this build does not
        # understand may bind fields it does not check, and accepting it would
        # silently downgrade every guarantee below.
        check("protocol", False,
              f"protocolVersion {envelope.get('protocolVersion')!r} is not "
              f"supported by this build")
        return fail(A2AReason.PROTOCOL_UNSUPPORTED, **common)
    check("protocol", True, f"{PROTOCOL} v{envelope.get('protocolVersion')}")

    # --- 4. proof purpose -------------------------------------------------
    if proof.get("proofPurpose") != A2A_PROOF_PURPOSE:
        # Domain separation, enforced. Without this a JIT grant or a human
        # approval could in principle be reshaped into a transaction; with it,
        # they cannot. An A2A RESPONSE lands here too.
        check("proof_purpose", False,
              f"proofPurpose must be {A2A_PROOF_PURPOSE!r}, "
              f"got {proof.get('proofPurpose')!r}")
        return fail(A2AReason.PROOF_PURPOSE_INVALID, **common)
    check("proof_purpose", True, A2A_PROOF_PURPOSE)

    # --- 5. RECEIVER BINDING ---------------------------------------------
    # The envelope says who it is for. The caller says who it authenticated as.
    # They must be the same principal, and the HTTP destination has no say in
    # it -- which is what makes an envelope for B unusable by C.
    if receiver_did != expected_receiver_did:
        check("receiver_binding", False,
              f"envelope is addressed to another agent, not to the "
              f"authenticated submitter")
        return fail(A2AReason.RECEIVER_MISMATCH, **common)
    check("receiver_binding", True, f"addressed to {receiver_did}")

    # --- 6. the sender's published key -----------------------------------
    if not sender_document:
        check("sender_document", False,
              "the sender's DID Document could not be resolved")
        return fail(A2AReason.SENDER_NOT_RESOLVABLE, **common)
    if sender_document.get("id") != sender_did:
        check("sender_document", False,
              "the resolved DID Document does not belong to the claimed sender")
        return fail(A2AReason.SENDER_NOT_RESOLVABLE, **common)
    check("sender_document", True, f"resolved {sender_did}")

    kid = proof.get("verificationMethod")
    if not isinstance(kid, str) or not kid:
        check("verification_method", False, "the proof names no verification method")
        return fail(A2AReason.MALFORMED, **common)

    # --- 7. the signing key's own lifecycle ------------------------------
    if sender_keys is not None:
        record = sender_keys.get(kid)
        if record is None:
            check("signing_key", False, f"{kid!r} is not a registered key for this sender")
            return fail(A2AReason.KEY_UNKNOWN, **common)
        if record.get("status") == "REVOKED":
            # Unlike retirement, revocation DOES invalidate what the key
            # signed -- a compromised key's history is exactly what cannot be
            # relied on.
            check("signing_key", False, f"{kid!r} has been revoked")
            return fail(A2AReason.KEY_REVOKED, signing_key=kid, **common)
        try:
            signed_at = parse_iso(proof.get("created"))
        except (ValueError, TypeError) as exc:
            check("signing_key", False, f"unparseable proof creation time: {exc}")
            return fail(A2AReason.MALFORMED, signing_key=kid, **common)
        not_before = record.get("not_before")
        retired_at = record.get("retired_at")
        if not_before is not None and signed_at < not_before:
            check("signing_key", False, f"{kid!r} did not exist at {proof.get('created')}")
            return fail(A2AReason.KEY_UNKNOWN, signing_key=kid, **common)
        if retired_at is not None and signed_at > retired_at:
            # The envelope claims to have been signed by a key already rotated
            # out. Envelopes it really did sign are dated before the
            # retirement and are unaffected -- that is exactly the distinction
            # between rotation and revocation.
            check("signing_key", False,
                  f"{kid!r} was retired at {retired_at.isoformat()} and cannot "
                  f"have signed an envelope created at {proof.get('created')}")
            return fail(A2AReason.KEY_RETIRED, signing_key=kid, **common)
        check("signing_key", True,
              f"{kid} ({record.get('status')}), valid for a proof created "
              f"{proof.get('created')}")

    try:
        public_key = public_key_from_document(sender_document, kid)
    except (ValueError, KeyError) as exc:
        check("verification_method", False, f"unusable sender DID Document: {exc}")
        return fail(A2AReason.SENDER_NOT_RESOLVABLE, signing_key=kid, **common)
    check("verification_method", True, kid)

    # --- 8. THE SIGNATURE -------------------------------------------------
    # The proof options are reconstructed from the presented proof and folded
    # back into the signed payload, so ANY change -- purpose, key id, domain,
    # creation time -- breaks the signature rather than being ignored.
    options = {k: v for k, v in proof.items() if k != "signatureValue"}
    result = verify_signature(
        public_key, signing_bytes(envelope, options),
        proof.get("signatureValue") or "", kid,
    )
    if not check("signature", result.valid,
                 "signature verifies against the sender's DID Document"
                 if result.valid else result.reason):
        return fail(A2AReason.SIGNATURE_INVALID, signing_key=kid, **common)

    # --- 9. audience ------------------------------------------------------
    if envelope.get("domain") != expected_domain:
        check("domain", False,
              f"envelope is addressed to {envelope.get('domain')!r}, "
              f"not {expected_domain!r}")
        return fail(A2AReason.DOMAIN_MISMATCH, signing_key=kid, **common)
    check("domain", True, expected_domain)

    # --- 10. time, against the SERVER clock -------------------------------
    try:
        issued = parse_iso(envelope["issuanceDate"])
        expires = parse_iso(envelope["expirationDate"])
    except (KeyError, ValueError, TypeError) as exc:
        check("validity_window", False, f"unparseable dates: {exc}")
        return fail(A2AReason.MALFORMED, signing_key=kid, **common)

    if issued > now + timedelta(seconds=FUTURE_TOLERANCE_SECONDS):
        check("validity_window", False, "issued in the future")
        return fail(A2AReason.NOT_YET_VALID, signing_key=kid, **common)
    if expires <= issued:
        check("validity_window", False, "expirationDate is not after issuanceDate")
        return fail(A2AReason.MALFORMED, signing_key=kid, **common)
    # THE TTL IS CLAMPED. A sender does not get to choose how long its own
    # envelope stays presentable; an envelope minted with a one-year window
    # would be a bearer instruction with a year to be stolen in.
    ttl = (expires - issued).total_seconds()
    if ttl > max_ttl_seconds:
        check("validity_window", False,
              f"envelope lifetime {int(ttl)}s exceeds the maximum {max_ttl_seconds}s")
        return fail(A2AReason.TTL_EXCEEDS_MAXIMUM, signing_key=kid, **common)
    # Bounded freshness in BOTH directions, as the control-plane proof is: an
    # envelope timestamped far in the past is a capture, and one timestamped
    # far in the future would stay valid for as long as an attacker chose.
    drift = abs((now - issued).total_seconds())
    if drift > freshness_seconds:
        check("validity_window", False,
              f"issued {int(drift)}s from the server clock, outside the "
              f"{freshness_seconds}s window")
        return fail(A2AReason.STALE, signing_key=kid, **common)
    if now >= expires:
        check("validity_window", False, f"expired at {envelope['expirationDate']}")
        return fail(A2AReason.EXPIRED, signing_key=kid, **common)
    check("validity_window", True,
          f"valid until {envelope['expirationDate']} "
          f"({int((expires - now).total_seconds())}s left)")

    # --- 11. the payload is the payload that was signed -------------------
    recomputed = payload_digest(transaction.get("payload"))
    if binding.payload_sha256 != recomputed:
        # Both are inside the signature, so disagreement means the envelope was
        # BUILT wrong rather than tampered with -- and either way it is not
        # usable, because the digest is what downstream records refer to.
        check("payload_digest", False, "payloadSha256 does not match the payload")
        return fail(A2AReason.MALFORMED, signing_key=kid, **common)
    check("payload_digest", True, recomputed[:16] + "...")

    # --- 12. the binding hash agrees with the bound fields ----------------
    if transaction.get("bindingHash") != binding.digest():
        check("binding_hash", False, "bindingHash does not match the bound fields")
        return fail(A2AReason.MALFORMED, signing_key=kid, **common)
    check("binding_hash", True, binding.digest()[:16] + "...")

    report = EnvelopeReport(True, A2AReason.VALID, checks, signing_key=kid, **common)
    report.receiver_bound = True
    report.payload_verified = True
    return report


def verify_response(
    response: dict[str, Any] | None,
    *,
    expected_transaction_id: str,
    expected_responder_did: str,
    responder_document: dict[str, Any] | None,
    expected_domain: str,
) -> EnvelopeReport:
    """Verify B's signed answer, from the SENDER's side.

    Exists so a sender can prove the outcome came from the agent it addressed,
    rather than from whoever answered the socket. Deliberately does not check
    freshness: an answer is about a transaction whose own window already
    bounded it, and a sender reading a recorded receipt later must still be
    able to verify it.
    """
    checks: list[A2ACheck] = []

    def check(name: str, passed: bool, detail: str) -> bool:
        checks.append(A2ACheck(name, passed, detail))
        return passed

    if not response or not isinstance(response, dict):
        check("present", False, "no A2A response was supplied")
        return EnvelopeReport(False, A2AReason.MISSING, checks)
    proof = response.get("proof")
    outcome = response.get("outcome")
    if not isinstance(proof, dict) or not isinstance(outcome, dict):
        check("structure", False, "outcome or proof is missing")
        return EnvelopeReport(False, A2AReason.MALFORMED, checks)
    if RESPONSE_TYPE not in (response.get("type") or []):
        check("structure", False, f"document is not an {RESPONSE_TYPE}")
        return EnvelopeReport(False, A2AReason.MALFORMED, checks)
    check("structure", True, RESPONSE_TYPE)

    if proof.get("proofPurpose") != A2A_RESPONSE_PROOF_PURPOSE:
        # A TRANSACTION replayed as a RESPONSE lands here. The two purposes are
        # what keep a request and an answer from being interchangeable.
        check("proof_purpose", False,
              f"proofPurpose must be {A2A_RESPONSE_PROOF_PURPOSE!r}")
        return EnvelopeReport(False, A2AReason.PROOF_PURPOSE_INVALID, checks)
    check("proof_purpose", True, A2A_RESPONSE_PROOF_PURPOSE)

    if response.get("transactionId") != expected_transaction_id:
        check("transaction", False, "the response answers a different transaction")
        return EnvelopeReport(False, A2AReason.MALFORMED, checks)
    check("transaction", True, expected_transaction_id)

    if response.get("senderDid") != expected_responder_did:
        check("responder", False, "the response is not from the addressed receiver")
        return EnvelopeReport(False, A2AReason.RECEIVER_MISMATCH, checks)
    check("responder", True, expected_responder_did)

    if not responder_document:
        check("responder_document", False, "the responder's DID Document is unresolvable")
        return EnvelopeReport(False, A2AReason.SENDER_NOT_RESOLVABLE, checks)
    kid = proof.get("verificationMethod")
    try:
        public_key = public_key_from_document(responder_document, kid)
    except (ValueError, KeyError) as exc:
        check("responder_document", False, f"unusable DID Document: {exc}")
        return EnvelopeReport(False, A2AReason.SENDER_NOT_RESOLVABLE, checks)
    check("responder_document", True, str(kid))

    options = {k: v for k, v in proof.items() if k != "signatureValue"}
    result = verify_signature(
        public_key, signing_bytes(response, options),
        proof.get("signatureValue") or "", kid,
    )
    if not check("signature", result.valid,
                 "signature verifies" if result.valid else result.reason):
        return EnvelopeReport(False, A2AReason.SIGNATURE_INVALID, checks, signing_key=kid)

    if response.get("domain") != expected_domain:
        check("domain", False, f"response is addressed to {response.get('domain')!r}")
        return EnvelopeReport(False, A2AReason.DOMAIN_MISMATCH, checks, signing_key=kid)
    check("domain", True, expected_domain)

    return EnvelopeReport(
        True, A2AReason.VALID, checks,
        transaction_id=expected_transaction_id,
        sender_did=response.get("senderDid"),
        receiver_did=response.get("receiverDid"),
        signing_key=kid,
    )
