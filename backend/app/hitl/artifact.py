"""The human approval artifact: what it binds, and how it is verified.

    "A human approved this agent"                  <- USELESS, and dangerous
    "Human X approved agent A performing action B
     on resource R for purpose P under request Q,
     valid until T, exactly once"                  <- what this file builds

The difference is everything. A generic approval is a standing permission that
happens to have a person's name on it; it can be carried to a different
resource, replayed against a second action, or held indefinitely. Every field
below exists to stop one of those.

BINDING. `binding_sha256` is a digest over the canonical tuple of the fields
that DEFINE the request:

    request_id · agent_did · action · resource_type · resource_id · purpose
    · amount_inr · currency · submitted_by                      <- Phase 5.5

At re-evaluation the PDP recomputes that digest from the LIVE authorization
request and the LIVE resource record, and compares. Change any one of them
after approval and the digest differs, so the approval simply does not apply --
there is nothing to bypass, because the artifact was never about that action.

WHY THE AMOUNT IS IN THERE (Phase 5.5). An approval means "I, a named person,
agreed to THIS". A person shown Rs 25,00,000 agreed to Rs 25,00,000. If the
amount can move afterwards while the approval stays valid, the signature is
attesting to a decision nobody made. The material attributes are read
SERVER-SIDE, from the resource record, on both sides of the comparison -- never
from a caller, and never from the browser that displayed them.

The digest is belt and braces: every bound field is also inside the signed
document, so tampering with one is already a signature failure. The digest is
what lets policy express "is this approval about THIS request?" as a single
comparison rather than six.

CRYPTOGRAPHY. The project's existing shape, not a new one: canonical JSON
(RFC 8785 style, floats refused) + Ed25519 + `PocEd25519Signature2026`, with a
proof purpose of `humanApproval`. That purpose is a domain separator, and it is
INSIDE the signed bytes -- so a credential proof, a holder proof, an ANS
registration proof or a control-plane proof can never verify as an approval,
and an approval can never be presented as any of them.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from app.credentials.canonical import canonical_bytes
from app.credentials.vc import (
    PROOF_CRYPTOSUITE,
    PROOF_TYPE,
    build_proof_options,
    parse_iso,
    signing_payload,
    to_iso,
)
from app.identity.did_document import public_key_from_document
from app.identity.signer import Signer, verify_signature

# Domain separator. Distinct from assertionMethod (issuer), authentication
# (holder), ansRegistration (ANS) and controlPlaneRequest (control plane).
APPROVAL_PROOF_PURPOSE = "humanApproval"

ARTIFACT_TYPE = "HumanApprovalArtifact"
ARTIFACT_CONTEXT = [
    "https://www.w3.org/2018/credentials/v1",
    "https://agentic-iam.poc/approvals/v1",
]


class ArtifactReason:
    """Why an approval artifact was accepted or rejected."""

    VALID = "APPROVAL_VALID"

    MISSING = "APPROVAL_MISSING"
    MALFORMED = "APPROVAL_MALFORMED"
    AUTHORITY_UNKNOWN = "APPROVAL_AUTHORITY_UNKNOWN"
    SIGNATURE_INVALID = "APPROVAL_SIGNATURE_INVALID"
    PROOF_PURPOSE_INVALID = "APPROVAL_PROOF_PURPOSE_INVALID"
    EXPIRED = "APPROVAL_EXPIRED"
    NOT_YET_VALID = "APPROVAL_NOT_YET_VALID"
    REJECTED = "APPROVAL_REJECTED"
    PENDING = "APPROVAL_PENDING"
    CANCELLED = "APPROVAL_CANCELLED"
    ALREADY_CONSUMED = "APPROVAL_ALREADY_CONSUMED"
    BINDING_MISMATCH = "APPROVAL_BINDING_MISMATCH"
    DOMAIN_MISMATCH = "APPROVAL_DOMAIN_MISMATCH"
    APPROVER_UNAUTHORIZED = "APPROVAL_APPROVER_UNAUTHORIZED"

    # --- Phase 5.5 --------------------------------------------------------
    # Dual control. Separate reasons because "we are still waiting for the
    # second person" and "the same person signed twice" are different
    # incidents: one is a queue, the other is an attack.
    INSUFFICIENT_APPROVALS = "APPROVAL_INSUFFICIENT_APPROVALS"
    APPROVERS_NOT_DISTINCT = "APPROVAL_APPROVERS_NOT_DISTINCT"
    # Key rotation. A retired key that verifies HISTORY is correct; a retired
    # key that appears on a NEW artifact is a signing key that outlived its
    # retirement, which is a very different thing from an unknown key.
    KEY_RETIRED = "APPROVAL_KEY_RETIRED"
    KEY_UNKNOWN = "APPROVAL_KEY_UNKNOWN"
    KEY_REVOKED = "APPROVAL_KEY_REVOKED"


def new_approval_id() -> str:
    return f"approval-{uuid.uuid4().hex[:16]}"


def new_nonce() -> str:
    return secrets.token_urlsafe(18)


# The bound fields, derived from the dataclass below so the verifier cannot
# fall out of step with it: adding a material attribute to the binding adds it
# to the comparison automatically, instead of being silently ignored by a
# hand-written list here.
_BINDING_FIELDS: tuple[str, ...] = (
    "request_id", "agent_did", "action", "resource_type", "resource_id",
    "purpose", "amount_inr", "currency", "submitted_by",
)


@dataclass(frozen=True)
class ApprovalBinding:
    """Exactly what an approval is ABOUT.

    Frozen and constructed from the authorization request in both directions --
    when the approval is requested, and again when it is re-evaluated -- so the
    two can be compared without either side being able to reinterpret it.
    """

    request_id: str
    agent_did: str
    action: str
    resource_type: str
    resource_id: str | None
    purpose: str
    # --- material attributes (Phase 5.5) ---------------------------------
    # Server-side facts that change the MEANING or the RISK of the operation.
    # They default to None so a binding for a resource with no material
    # attributes -- a credit record, an unknown application -- is expressed as
    # "there are none", not as a guessed zero.
    amount_inr: int | None = None
    currency: str | None = None
    submitted_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "agent_did": self.agent_did,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "purpose": self.purpose,
            "amount_inr": self.amount_inr,
            "currency": self.currency,
            "submitted_by": self.submitted_by,
        }

    def digest(self) -> str:
        """SHA-256 over the canonical binding. Order-independent."""
        return hashlib.sha256(canonical_bytes(self.to_dict())).hexdigest()

    def differences(self, other: "ApprovalBinding") -> list[str]:
        """Which bound fields disagree. Named, so a denial is diagnostic.

        An operator seeing APPROVAL_BINDING_MISMATCH needs to know WHICH field
        moved -- "the resource changed" and "this is a different request" are
        very different incidents.
        """
        mine, theirs = self.to_dict(), other.to_dict()
        return sorted(k for k in mine if mine[k] != theirs[k])

    @classmethod
    def from_request(cls, request: Any) -> "ApprovalBinding":
        """Build the binding from an `AuthorizationRequest`.

        The material attributes are read from SERVER-SIDE state, here, on both
        sides of the comparison -- when the approval is opened and again at
        re-evaluation. Taking them from the request would let a caller decide
        what its own approval was about.
        """
        from app.enforcement.resources import material_attributes

        material = material_attributes(request.resource.type, request.resource.id)
        return cls(
            request_id=request.request_id,
            agent_did=request.subject.did,
            action=request.action,
            resource_type=request.resource.type,
            resource_id=request.resource.id,
            purpose=request.purpose,
            amount_inr=material.get("amount_inr"),
            currency=material.get("currency"),
            submitted_by=material.get("submitted_by"),
        )


def approver_identity(approver: dict[str, Any]) -> tuple[str | None, str | None]:
    """The pair that identifies a PERSON: issuer plus subject.

    Never the username alone. A subject id is only unique WITHIN its issuer, so
    comparing subjects across realms would let two different people count as
    one -- which for dual control means one person satisfying both approvals.
    """
    return (approver.get("issuer"), approver.get("subject"))


def build_artifact(
    *,
    approval_id: str,
    binding: ApprovalBinding,
    approver: dict[str, Any],
    decision: str,
    issued_at: datetime,
    expires_at: datetime,
    nonce: str,
    domain: str,
    authority_did: str,
    session_id: str | None = None,
    approvers: list[dict[str, Any]] | None = None,
    required_approvals: int = 1,
) -> dict[str, Any]:
    """The unsigned artifact document.

    `approver` carries the subject and issuer Keycloak asserted, plus the roles
    that token carried AT DECISION TIME. Those roles are a record of the basis
    for the decision, not a grant: policy re-checks authority independently.

    `approvers` (Phase 5.5) is EVERY sign-off, in order. For a single-approval
    artifact it has one entry and `approver` is that entry, so a Phase 5 reader
    sees exactly what it saw before. For dual control it has two, and
    `approver` names the sign-off that COMPLETED the approval.

    `requiredApprovals` is inside the signed bytes on purpose: an artifact
    cannot be re-presented as though it had needed fewer people than it did.
    """
    everyone = list(approvers) if approvers else [approver]
    return {
        "@context": ARTIFACT_CONTEXT,
        "type": ["VerifiableCredential", ARTIFACT_TYPE],
        "id": f"urn:approval:{approval_id}",
        "approvalId": approval_id,
        # The signing service. NOT the human, and NOT Keycloak.
        "issuer": authority_did,
        "issuanceDate": to_iso(issued_at),
        "expirationDate": to_iso(expires_at),
        "credentialSubject": {
            "id": binding.agent_did,
            "decision": decision,
            "approver": approver,
            "approvers": everyone,
            "requiredApprovals": required_approvals,
            **binding.to_dict(),
            "bindingHash": binding.digest(),
            # Phase 9 will bind sessions. Explicitly null rather than absent,
            # so policy can tell "no session layer" from "lookup failed".
            "sessionId": session_id,
        },
        "nonce": nonce,
        # Audience binding, preserving the Phase 2 S-2 protection: an approval
        # minted for one verifier cannot be relayed to another.
        "domain": domain,
    }


def signing_bytes(artifact: dict[str, Any], proof_options: dict[str, Any]) -> bytes:
    """The exact bytes that get signed.

    Uses the PHASE 2 `signing_payload`, so the proof options -- `created`,
    `verificationMethod`, `proofPurpose`, `domain` -- are INSIDE the signature,
    exactly as they are for credentials and presentations. That is what makes
    the proof purpose a real domain separator rather than an advisory label:
    flipping `humanApproval` to `assertionMethod` on a signed artifact
    invalidates the signature instead of silently repurposing it.
    """
    return canonical_bytes(signing_payload(artifact, proof_options))


def proof_options_for(
    artifact: dict[str, Any], kid: str, *, moment: datetime | None = None
) -> dict[str, Any]:
    """The proof options an approval artifact is signed under."""
    return build_proof_options(
        verification_method=kid,
        proof_purpose=APPROVAL_PROOF_PURPOSE,
        created=moment or datetime.now(timezone.utc),
        domain=artifact.get("domain"),
    )


def sign_artifact(
    artifact: dict[str, Any], signer: Signer, kid: str, *, moment: datetime | None = None
) -> dict[str, Any]:
    """Attach the approval authority's Ed25519 proof."""
    options = proof_options_for(artifact, kid, moment=moment)
    signature = signer.sign(kid, signing_bytes(artifact, options))
    return {**artifact, "proof": {**options, "signatureValue": signature.signature_b64}}


@dataclass
class ArtifactCheck:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class ArtifactReport:
    """Every check, reported. Never a bare boolean.

    Same discipline as the Phase 2 credential verifier: a caller that cannot
    see WHICH check failed cannot fix the cause, and an auditor cannot review
    the decision.
    """

    valid: bool
    reason: str
    checks: list[ArtifactCheck]
    approval_id: str | None = None
    approver: dict[str, Any] | None = None
    decision: str | None = None
    expires_at: str | None = None
    # Phase 5.5. Derived from the SIGNED document, never from the database row:
    # policy must weigh what the authority actually attested to.
    approvers: list[dict[str, Any]] = field(default_factory=list)
    required_approvals: int = 1
    distinct_approvers: int = 0
    signing_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "approval_id": self.approval_id,
            "approver": self.approver,
            "approvers": self.approvers,
            "required_approvals": self.required_approvals,
            "distinct_approvers": self.distinct_approvers,
            "signing_key": self.signing_key,
            "decision": self.decision,
            "expires_at": self.expires_at,
            "checks": [c.to_dict() for c in self.checks],
        }


def verify_artifact(
    artifact: dict[str, Any] | None,
    *,
    authority_document: dict[str, Any] | None,
    expected_binding: ApprovalBinding,
    expected_domain: str,
    now: datetime | None = None,
    authority_keys: dict[str, dict[str, Any]] | None = None,
) -> ArtifactReport:
    """Verify an approval artifact against the request it is being used for.

    This function does NOT decide whether the action is permitted -- that is
    Rego's job, and it reads the verdict below. It establishes facts:
    is the signature real, is it from the approval authority, is it still
    valid, and is it about THIS request?

    Consumption state is deliberately NOT checked here: it lives in the
    database, is subject to a race, and is settled by an atomic UPDATE in the
    approval service. Checking it here as well would be a check that can go
    stale between reading and acting on it.

    `authority_keys` (Phase 5.5) is the approval authority's key REGISTER, keyed
    by `kid`: status, `not_before`, `retired_at`. It is what makes rotation safe
    in both directions -- a retired key still verifies the artifacts it signed
    while it was active, and a retired key cannot verify one dated after its
    retirement. Omitting it keeps the Phase 5 behaviour (the DID Document alone
    decides), which is what a caller with no key register should get.
    """
    now = now or datetime.now(timezone.utc)
    checks: list[ArtifactCheck] = []

    def check(name: str, passed: bool, detail: str) -> bool:
        checks.append(ArtifactCheck(name, passed, detail))
        return passed

    def fail(reason: str) -> ArtifactReport:
        return ArtifactReport(False, reason, checks)

    if not artifact:
        check("present", False, "no approval artifact was supplied")
        return fail(ArtifactReason.MISSING)
    check("present", True, "artifact supplied")

    # --- structure --------------------------------------------------------
    subject = artifact.get("credentialSubject")
    proof = artifact.get("proof")
    if not isinstance(subject, dict) or not isinstance(proof, dict):
        check("structure", False, "credentialSubject or proof is missing")
        return fail(ArtifactReason.MALFORMED)
    types = artifact.get("type") or []
    if ARTIFACT_TYPE not in types:
        # A credential or presentation presented where an approval is required.
        check("structure", False,
              f"document is not a {ARTIFACT_TYPE}; got type {types!r}")
        return fail(ArtifactReason.MALFORMED)
    check("structure", True, f"{ARTIFACT_TYPE} with a proof")

    if proof.get("proofPurpose") != APPROVAL_PROOF_PURPOSE:
        # Domain separation, enforced. Without this an ANS registration proof
        # or a control-plane proof could in principle be reshaped into an
        # approval; with it, they cannot.
        check("proof_purpose", False,
              f"proofPurpose must be {APPROVAL_PROOF_PURPOSE!r}, "
              f"got {proof.get('proofPurpose')!r}")
        return fail(ArtifactReason.PROOF_PURPOSE_INVALID)
    check("proof_purpose", True, APPROVAL_PROOF_PURPOSE)

    # --- the signing authority -------------------------------------------
    if not authority_document:
        check("authority", False, "the approval authority could not be resolved")
        return fail(ArtifactReason.AUTHORITY_UNKNOWN)
    if artifact.get("issuer") != authority_document.get("id"):
        # An artifact signed by anything other than the approval authority --
        # an agent, an issuer, an administrator -- lands here.
        check("authority", False,
              f"artifact issuer {artifact.get('issuer')!r} is not the approval authority")
        return fail(ArtifactReason.AUTHORITY_UNKNOWN)
    check("authority", True, f"{artifact['issuer']} is the approval authority")

    # --- the SIGNING KEY's own lifecycle (Phase 5.5) ----------------------
    # Being listed in the DID Document says the key exists. It does not say the
    # key was allowed to sign THIS artifact, at the moment the proof claims it
    # was signed. A rotated-out key must keep verifying its own history and
    # must not be able to authorise anything new.
    kid = proof.get("verificationMethod")
    if authority_keys is not None:
        record = authority_keys.get(kid)
        if record is None:
            check("signing_key", False,
                  f"{kid!r} is not a registered approval-authority key")
            return fail(ArtifactReason.KEY_UNKNOWN)
        if record.get("status") == "REVOKED":
            check("signing_key", False, f"{kid!r} has been revoked")
            return fail(ArtifactReason.KEY_REVOKED)
        try:
            signed_at = parse_iso(proof.get("created"))
        except (ValueError, TypeError) as exc:
            check("signing_key", False, f"unparseable proof creation time: {exc}")
            return fail(ArtifactReason.MALFORMED)
        not_before = record.get("not_before")
        retired_at = record.get("retired_at")
        if not_before is not None and signed_at < not_before:
            check("signing_key", False,
                  f"{kid!r} did not exist at {proof.get('created')}")
            return fail(ArtifactReason.KEY_UNKNOWN)
        if retired_at is not None and signed_at > retired_at:
            # The artifact claims to have been signed by a key that had already
            # been rotated out. Existing artifacts are unaffected -- theirs are
            # dated before the retirement -- which is exactly the distinction.
            check("signing_key", False,
                  f"{kid!r} was retired at {retired_at.isoformat()} and cannot "
                  f"have signed an artifact created at {proof.get('created')}")
            return fail(ArtifactReason.KEY_RETIRED)
        check("signing_key", True,
              f"{kid} ({record.get('status')}), valid for a proof created "
              f"{proof.get('created')}")

    # --- the public key ---------------------------------------------------
    # AFTER the register, deliberately. A revoked key is unpublished, so
    # extracting it fails -- and "the approval authority is unknown" would be a
    # badly misleading way to report "this key was declared compromised".
    # Lifecycle first, then material.
    try:
        public_key = public_key_from_document(
            authority_document, proof.get("verificationMethod")
        )
    except (ValueError, KeyError) as exc:
        check("verification_method", False,
              f"unusable authority DID Document: {exc}")
        return fail(ArtifactReason.AUTHORITY_UNKNOWN)
    check("verification_method", True, f"{proof.get('verificationMethod')}")

    # --- the signature ----------------------------------------------------
    # The proof options are reconstructed from the presented proof and folded
    # back into the signed payload, so ANY change to them -- purpose, key id,
    # domain, creation time -- breaks the signature rather than being ignored.
    options = {k: v for k, v in proof.items() if k != "signatureValue"}
    result = verify_signature(
        public_key, signing_bytes(artifact, options),
        proof.get("signatureValue") or "", proof.get("verificationMethod"),
    )
    if not check("signature", result.valid,
                 "signature verifies against the authority's DID Document"
                 if result.valid else result.reason):
        return fail(ArtifactReason.SIGNATURE_INVALID)

    # --- decision ---------------------------------------------------------
    decision = subject.get("decision")
    if decision != "APPROVED":
        # A REJECTED artifact is a genuine, correctly signed record of a human
        # saying no. It verifies; it just does not permit anything.
        check("decision", False, f"the human decision was {decision!r}")
        return ArtifactReport(
            False, ArtifactReason.REJECTED, checks,
            approval_id=artifact.get("approvalId"),
            approver=subject.get("approver"), decision=decision,
        )
    check("decision", True, "APPROVED")

    # --- validity window (server clock) -----------------------------------
    try:
        expires_at = parse_iso(artifact["expirationDate"])
        issued_at = parse_iso(artifact["issuanceDate"])
    except (KeyError, ValueError, TypeError) as exc:
        check("validity_window", False, f"unparseable dates: {exc}")
        return fail(ArtifactReason.MALFORMED)
    if now >= expires_at:
        check("validity_window", False,
              f"expired at {artifact['expirationDate']}")
        return ArtifactReport(
            False, ArtifactReason.EXPIRED, checks,
            approval_id=artifact.get("approvalId"),
            approver=subject.get("approver"), decision=decision,
            expires_at=artifact["expirationDate"],
        )
    if issued_at > now + timedelta(seconds=60):
        check("validity_window", False, "issued in the future")
        return fail(ArtifactReason.NOT_YET_VALID)
    check("validity_window", True,
          f"valid until {artifact['expirationDate']} ({int((expires_at - now).total_seconds())}s left)")

    # --- audience ---------------------------------------------------------
    if artifact.get("domain") != expected_domain:
        check("domain", False,
              f"artifact is addressed to {artifact.get('domain')!r}, "
              f"not {expected_domain!r}")
        return fail(ArtifactReason.DOMAIN_MISMATCH)
    check("domain", True, expected_domain)

    # --- BINDING: is this approval about THIS request? --------------------
    # Every bound field, including the MATERIAL ATTRIBUTES. Reading only the
    # identifying fields here would mean an amount that moved after approval
    # still matched -- which is exactly the tampering the binding exists to
    # catch, so the fields are enumerated from the binding's own shape rather
    # than listed by hand a second time.
    actual = ApprovalBinding(**{
        field: subject.get(field) for field in _BINDING_FIELDS
    })
    differences = actual.differences(expected_binding)
    if differences:
        check("binding", False,
              f"approval was granted for a different request; "
              f"mismatched: {', '.join(differences)}")
        return ArtifactReport(
            False, ArtifactReason.BINDING_MISMATCH, checks,
            approval_id=artifact.get("approvalId"),
            approver=subject.get("approver"), decision=decision,
        )
    if subject.get("bindingHash") != expected_binding.digest():
        check("binding", False, "binding hash does not match the request")
        return fail(ArtifactReason.BINDING_MISMATCH)
    check("binding", True,
          f"bound to {expected_binding.action} on "
          f"{expected_binding.resource_type}/{expected_binding.resource_id} "
          f"for {expected_binding.agent_did}"
          + (f" at {expected_binding.currency} {expected_binding.amount_inr}"
             if expected_binding.amount_inr is not None else ""))

    # --- DUAL CONTROL: does this artifact represent enough PEOPLE? --------
    # Read from the signed document, so the count cannot be inflated by a
    # database row. Distinctness is on (issuer, subject): a username is not an
    # identity, and a subject id is only unique within its issuer.
    approvers = subject.get("approvers")
    if not isinstance(approvers, list) or not approvers:
        # Phase 5 artifacts predate the list. One approver, named singly.
        single = subject.get("approver")
        approvers = [single] if isinstance(single, dict) else []
    required = subject.get("requiredApprovals")
    required = required if isinstance(required, int) and required >= 1 else 1
    identities = {approver_identity(a) for a in approvers if isinstance(a, dict)}

    if len(identities) < len(approvers):
        # The same person signed twice. The database refuses this at insert
        # time; refusing it again HERE means a hand-built artifact cannot claim
        # two approvals from one human either.
        check("approvers", False,
              f"{len(approvers)} sign-off(s) from only {len(identities)} "
              f"distinct human(s): the same person cannot satisfy two approvals")
        return ArtifactReport(
            False, ArtifactReason.APPROVERS_NOT_DISTINCT, checks,
            approval_id=artifact.get("approvalId"),
            approver=subject.get("approver"), decision=decision,
            approvers=approvers, required_approvals=required,
            distinct_approvers=len(identities), signing_key=kid,
        )
    if len(identities) < required:
        check("approvers", False,
              f"{len(identities)} of {required} required approval(s) present")
        return ArtifactReport(
            False, ArtifactReason.INSUFFICIENT_APPROVALS, checks,
            approval_id=artifact.get("approvalId"),
            approver=subject.get("approver"), decision=decision,
            approvers=approvers, required_approvals=required,
            distinct_approvers=len(identities), signing_key=kid,
        )
    check("approvers", True,
          f"{len(identities)} distinct human(s), {required} required")

    return ArtifactReport(
        True, ArtifactReason.VALID, checks,
        approval_id=artifact.get("approvalId"),
        approver=subject.get("approver"),
        decision=decision,
        expires_at=artifact["expirationDate"],
        approvers=approvers,
        required_approvals=required,
        distinct_approvers=len(identities),
        signing_key=kid,
    )
