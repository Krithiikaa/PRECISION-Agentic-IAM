"""The JIT grant artifact: what it binds, and how it is verified.

    "This agent has temporary access"              <- USELESS, and dangerous
    "Agent A may perform action B on resources
     {R1,R2} for purpose P, under constraints C,
     at most N times, until T"                     <- what this file builds

THE ONE SENTENCE THIS FILE EXISTS TO ENFORCE:

    A JIT GRANT IS AN INPUT TO AUTHORIZATION, NEVER A SUBSTITUTE FOR ONE.

That is the same position the human approval artifact occupies, and it is not a
stylistic choice. This system already has no standing permission: every
protected call runs the full AEM -> PIP -> OPA path with nothing cached. A
grant that authorised resource access on its own would therefore not add a
capability -- it would INTRODUCE standing permission where none existed, and
credential revocation, amount bands and dual control would all stop applying
for the life of the grant.

So what a grant actually carries is the EXPENSIVE precondition -- a human
decision -- forward across a bounded window. Everything cheap is re-established
live on every single use.

WHAT IS BOUND, and which attack each field stops:

    grant_id        grant substitution
    agent_did       agent substitution; lending a mandate to another agent
    action          action substitution (a `read` mandate is not a `write` one)
    resource_type   resource-class substitution (credit_records != payroll_records)
    resource_ids    resource substitution OUTSIDE the mandate -- a SET, because
                    a mandate over several records is the point of the phase
    purpose         purpose substitution
    constraints     scope escalation (e.g. an amount ceiling)
    max_uses        unbounded reuse
    not_before      forward-dating
    expires_at      expiry bypass
    issuer + kid    forgery; and makes key rotation safe
    nonce           duplicate issuance
    domain          cross-service replay
    proofPurpose    cross-proof confusion -- the SIXTH domain separator here

WHAT IS DELIBERATELY *NOT* BOUND: the use-time `request_id`. The approval
artifact binds it because an approval authorises exactly one request. A mandate
is reusable by definition and spans several requests, each with its own id;
binding it would make every grant single-use by accident, which is just the
Phase 5 approval with extra steps. The ISSUING request id is carried inside the
signed body for audit correlation and is never compared at use time.

SCOPE IS A CEILING, AND IS INTERSECTED -- NEVER UNIONED. At use time the
effective authority is `grant.scope INTERSECT live_policy_decision`. A grant
can only ever narrow. If policy would deny the action now, the grant does not
rescue it; if the grant's `max_amount_inr` is below the live band, the grant's
number wins. That is what makes "scope expansion" structurally impossible
rather than a thing somebody remembered to check.

CRYPTOGRAPHY: the project's existing shape, not a new one. Canonical JSON
(RFC 8785 style, floats refused) + Ed25519 + `PocEd25519Signature2026`, with a
proof purpose of `jitGrant`. That purpose is INSIDE the signed bytes, so a
credential proof, a holder proof, an ANS registration proof, a control-plane
proof or a human approval can never verify as a grant -- and a grant can never
be presented as any of them.
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
    build_proof_options,
    parse_iso,
    signing_payload,
    to_iso,
)
from app.identity.did_document import public_key_from_document
from app.identity.signer import Signer, verify_signature

# Domain separator. Distinct from assertionMethod (issuer), authentication
# (holder), ansRegistration (ANS), controlPlaneRequest (control plane) and
# humanApproval (approval authority).
JIT_PROOF_PURPOSE = "jitGrant"

ARTIFACT_TYPE = "JITAccessGrant"
ARTIFACT_CONTEXT = [
    "https://www.w3.org/2018/credentials/v1",
    "https://agentic-iam.poc/jit/v1",
]


class GrantReason:
    """Why a grant was accepted or rejected.

    Coarse on purpose, exactly as `ArtifactReason` is: a reason names the CLASS
    of failure, never which record or key was involved.
    """

    VALID = "JIT_GRANT_VALID"

    MISSING = "JIT_GRANT_MISSING"
    MALFORMED = "JIT_GRANT_MALFORMED"
    UNKNOWN = "JIT_GRANT_UNKNOWN"
    AUTHORITY_UNKNOWN = "JIT_AUTHORITY_UNKNOWN"
    SIGNATURE_INVALID = "JIT_GRANT_SIGNATURE_INVALID"
    PROOF_PURPOSE_INVALID = "JIT_GRANT_PROOF_PURPOSE_INVALID"
    DOMAIN_MISMATCH = "JIT_GRANT_DOMAIN_MISMATCH"
    EXPIRED = "JIT_GRANT_EXPIRED"
    NOT_YET_VALID = "JIT_GRANT_NOT_YET_VALID"
    REVOKED = "JIT_GRANT_REVOKED"
    EXHAUSTED = "JIT_GRANT_EXHAUSTED"
    BINDING_MISMATCH = "JIT_GRANT_BINDING_MISMATCH"
    CONSTRAINT_VIOLATED = "JIT_CONSTRAINT_VIOLATED"

    KEY_UNKNOWN = "JIT_KEY_UNKNOWN"
    KEY_RETIRED = "JIT_KEY_RETIRED"
    KEY_REVOKED = "JIT_KEY_REVOKED"


def new_grant_id() -> str:
    return f"jit-{uuid.uuid4().hex[:16]}"


def new_nonce() -> str:
    return secrets.token_urlsafe(18)


@dataclass(frozen=True)
class JITBinding:
    """Exactly what a mandate is ABOUT.

    Frozen and built from the authorization request in both directions -- when
    the grant is issued, and again on every use -- so neither side can
    reinterpret it.

    NOTE the asymmetry with `ApprovalBinding`, and that it is deliberate:
    `resource_ids` is a SET and there is no `request_id`. A mandate is a scope,
    not a single authorisation.
    """

    agent_did: str
    action: str
    resource_type: str
    # Sorted on construction so two mandates over the same records produce the
    # same digest regardless of the order they were asked for in.
    resource_ids: tuple[str, ...]
    purpose: str
    constraints: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_did": self.agent_did,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_ids": list(self.resource_ids),
            "purpose": self.purpose,
            "constraints": dict(self.constraints),
        }

    def digest(self) -> str:
        """SHA-256 over the canonical binding. Order-independent."""
        return hashlib.sha256(canonical_bytes(self.to_dict())).hexdigest()

    def covers_resource(self, resource_id: str | None) -> bool:
        """Is this instance inside the mandate?

        An EMPTY `resource_ids` means the mandate covers the resource TYPE and
        leaves instances to policy. That is genuinely weaker, which is why
        issuance policy is the thing that decides whether an unscoped mandate
        may be issued at all -- this method only reports the fact.
        """
        if not self.resource_ids:
            return True
        return resource_id in self.resource_ids

    def differences(self, other: "JITBinding") -> list[str]:
        """Which SCOPE fields disagree. Named, so a denial is diagnostic.

        An operator seeing JIT_GRANT_BINDING_MISMATCH needs to know WHICH field
        moved -- "this mandate is for another agent" and "this mandate is for a
        different action" are very different incidents.

        TWO FIELDS ARE DELIBERATELY EXCLUDED, and both for the same underlying
        reason -- they are properties of the MANDATE, which the live request
        knows nothing about, so comparing them for equality would deny every
        grant that had any.

        `resource_ids`  a mandate over three applications legitimately covers a
                        request about one of them: a containment question, not
                        an equality one. Answered by `covers_resource()`
                        against the instance actually being acted on, which
                        also yields a more precise refusal.
        `constraints`   a ceiling the grant carries. Evaluated by
                        `evaluate_constraints()` against the LIVE server-side
                        resource attributes, which is the only comparison that
                        means anything.

        What is left -- agent, action, resource type, purpose -- must match
        exactly, and those are precisely the substitution attacks.
        """
        skip = {"resource_ids", "constraints"}
        mine, theirs = self.to_dict(), other.to_dict()
        return sorted(
            key for key in mine
            if key not in skip and mine[key] != theirs[key]
        )

    @classmethod
    def from_request(cls, request: Any, *, constraints: dict[str, Any] | None = None,
                     resource_ids: list[str] | None = None) -> "JITBinding":
        """Build the binding from an `AuthorizationRequest`.

        When `resource_ids` is not given, the request's own resource id is the
        whole mandate -- the narrowest reading, which is the right default for
        anything derived from a single request.
        """
        if resource_ids is None:
            ids = (request.resource.id,) if request.resource.id else ()
        else:
            ids = tuple(sorted(str(r) for r in resource_ids))
        return cls(
            agent_did=request.subject.did,
            action=request.action,
            resource_type=request.resource.type,
            resource_ids=ids,
            purpose=request.purpose,
            constraints=dict(constraints or {}),
        )


def build_grant(
    *,
    grant_id: str,
    binding: JITBinding,
    issued_at: datetime,
    not_before: datetime,
    expires_at: datetime,
    max_uses: int,
    nonce: str,
    domain: str,
    authority_did: str,
    issuing_request_id: str,
    justification: dict[str, Any],
    session_id: str | None = None,
) -> dict[str, Any]:
    """The unsigned grant document.

    `justification` records WHY the mandate exists: the policy decision that
    permitted it, the approval it carries forward and its approvers, and the
    credential ids it was predicated on. It is inside the signed bytes because
    an auditor asking "on whose authority?" must not be answered by a mutable
    row.

    `maxUses` is signed for the same reason `requiredApprovals` is on an
    approval: a mandate must not be re-presentable as though it had been
    granted a larger budget than it was.
    """
    return {
        "@context": ARTIFACT_CONTEXT,
        "type": ["VerifiableCredential", ARTIFACT_TYPE],
        "id": f"urn:jit:{grant_id}",
        "grantId": grant_id,
        # The signing service. NOT the agent, NOT the approval authority.
        "issuer": authority_did,
        "issuanceDate": to_iso(issued_at),
        "notBefore": to_iso(not_before),
        "expirationDate": to_iso(expires_at),
        "credentialSubject": {
            "id": binding.agent_did,
            **binding.to_dict(),
            "bindingHash": binding.digest(),
            "maxUses": max_uses,
            # Correlation only. Never compared at use time -- see the module
            # docstring.
            "issuingRequestId": issuing_request_id,
            "justification": justification,
            # Phase 9 will bind sessions. Explicitly null rather than absent.
            "sessionId": session_id,
        },
        "nonce": nonce,
        # Audience binding, preserving the Phase 2 S-2 protection: a grant
        # minted for this enforcement boundary cannot be relayed to another.
        "domain": domain,
    }


def signing_bytes(grant: dict[str, Any], proof_options: dict[str, Any]) -> bytes:
    """The exact bytes that get signed.

    Uses the Phase 2 `signing_payload`, so the proof options -- `created`,
    `verificationMethod`, `proofPurpose`, `domain` -- are INSIDE the signature.
    Flipping `jitGrant` to `humanApproval` on a signed grant invalidates it
    rather than silently repurposing it.
    """
    return canonical_bytes(signing_payload(grant, proof_options))


def proof_options_for(
    grant: dict[str, Any], kid: str, *, moment: datetime | None = None
) -> dict[str, Any]:
    return build_proof_options(
        verification_method=kid,
        proof_purpose=JIT_PROOF_PURPOSE,
        created=moment or datetime.now(timezone.utc),
        domain=grant.get("domain"),
    )


def sign_grant(
    grant: dict[str, Any], signer: Signer, kid: str, *, moment: datetime | None = None
) -> dict[str, Any]:
    """Attach the JIT authority's Ed25519 proof."""
    options = proof_options_for(grant, kid, moment=moment)
    signature = signer.sign(kid, signing_bytes(grant, options))
    return {**grant, "proof": {**options, "signatureValue": signature.signature_b64}}


@dataclass
class GrantCheck:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class GrantReport:
    """Every check, reported. Never a bare boolean.

    Same discipline as the Phase 2 credential verifier and the Phase 5
    approval verifier: a caller that cannot see WHICH check failed cannot fix
    the cause, and an auditor cannot review it.
    """

    valid: bool
    reason: str
    checks: list[GrantCheck] = field(default_factory=list)
    grant_id: str | None = None
    expires_at: str | None = None
    not_before: str | None = None
    max_uses: int | None = None
    bound_to_request: bool = False
    covers_resource: bool = False
    binding_differences: list[str] = field(default_factory=list)
    signing_key: str | None = None
    issuer: str | None = None
    approval_id: str | None = None
    justification: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "grant_id": self.grant_id,
            "expires_at": self.expires_at,
            "not_before": self.not_before,
            "max_uses": self.max_uses,
            "bound_to_request": self.bound_to_request,
            "covers_resource": self.covers_resource,
            "binding_differences": list(self.binding_differences),
            "signing_key": self.signing_key,
            "issuer": self.issuer,
            "approval_id": self.approval_id,
            "justification": dict(self.justification),
            "checks": [c.to_dict() for c in self.checks],
        }


def verify_grant(
    grant: dict[str, Any] | None,
    *,
    authority_document: dict[str, Any] | None,
    expected_binding: JITBinding,
    expected_domain: str,
    resource_id: str | None = None,
    resource_attributes: dict[str, Any] | None = None,
    now: datetime | None = None,
    authority_keys: dict[str, dict[str, Any]] | None = None,
) -> GrantReport:
    """Verify a grant against the request it is being used for.

    This function does NOT decide whether the action is permitted -- that is
    Rego's job, and it reads the verdict below. It establishes facts: is the
    signature real, is it from the JIT authority, was the key allowed to sign
    it then, is it still within its window, and does it cover THIS request?

    CONSUMPTION AND REVOCATION STATE ARE DELIBERATELY NOT CHECKED HERE. Both
    live in the database, both are subject to a race, and both are settled by
    an atomic UPDATE in the service. Checking them here as well would be a
    check that goes stale between reading it and acting on it.

    `authority_keys` is the key REGISTER keyed by `kid`. It is what makes
    rotation safe in both directions: a retired key still verifies the grants
    it issued while active, and cannot have issued one dated after retirement.
    """
    now = now or datetime.now(timezone.utc)
    checks: list[GrantCheck] = []

    def check(name: str, passed: bool, detail: str) -> bool:
        checks.append(GrantCheck(name, passed, detail))
        return passed

    def fail(reason: str, **kw: Any) -> GrantReport:
        return GrantReport(False, reason, checks, **kw)

    if not grant:
        check("present", False, "no JIT grant was supplied")
        return fail(GrantReason.MISSING)
    check("present", True, "grant supplied")

    # --- structure --------------------------------------------------------
    subject = grant.get("credentialSubject")
    proof = grant.get("proof")
    if not isinstance(subject, dict) or not isinstance(proof, dict):
        check("structure", False, "credentialSubject or proof is missing")
        return fail(GrantReason.MALFORMED)
    types = grant.get("type") or []
    if ARTIFACT_TYPE not in types:
        # A credential, a presentation or an APPROVAL presented where a grant
        # is required. Refused on shape before anything else is considered.
        check("structure", False,
              f"document is not a {ARTIFACT_TYPE}; got type {types!r}")
        return fail(GrantReason.MALFORMED)
    check("structure", True, f"{ARTIFACT_TYPE} with a proof")

    grant_id = grant.get("grantId")

    if proof.get("proofPurpose") != JIT_PROOF_PURPOSE:
        # Domain separation, enforced. Without this a human approval artifact
        # could in principle be reshaped into a mandate; with it, it cannot.
        check("proof_purpose", False,
              f"proofPurpose must be {JIT_PROOF_PURPOSE!r}, "
              f"got {proof.get('proofPurpose')!r}")
        return fail(GrantReason.PROOF_PURPOSE_INVALID, grant_id=grant_id)
    check("proof_purpose", True, JIT_PROOF_PURPOSE)

    # --- the signing authority -------------------------------------------
    if not authority_document:
        check("authority", False, "the JIT authority could not be resolved")
        return fail(GrantReason.AUTHORITY_UNKNOWN, grant_id=grant_id)
    if grant.get("issuer") != authority_document.get("id"):
        # A grant signed by anything other than the JIT authority -- an agent,
        # an issuer, the APPROVAL authority -- lands here.
        check("authority", False,
              f"grant issuer {grant.get('issuer')!r} is not the JIT authority")
        return fail(GrantReason.AUTHORITY_UNKNOWN, grant_id=grant_id)
    check("authority", True, f"{grant['issuer']} is the JIT authority")

    # --- the SIGNING KEY's own lifecycle ---------------------------------
    kid = proof.get("verificationMethod")
    if authority_keys is not None:
        record = authority_keys.get(kid)
        if record is None:
            check("signing_key", False, f"{kid!r} is not a registered JIT-authority key")
            return fail(GrantReason.KEY_UNKNOWN, grant_id=grant_id)
        if record.get("status") == "REVOKED":
            check("signing_key", False, f"{kid!r} has been revoked")
            return fail(GrantReason.KEY_REVOKED, grant_id=grant_id)
        try:
            signed_at = parse_iso(proof.get("created"))
        except (ValueError, TypeError) as exc:
            check("signing_key", False, f"unparseable proof creation time: {exc}")
            return fail(GrantReason.MALFORMED, grant_id=grant_id)
        not_before_key = record.get("not_before")
        retired_at = record.get("retired_at")
        if not_before_key is not None and signed_at < not_before_key:
            check("signing_key", False, f"{kid!r} did not exist at {proof.get('created')}")
            return fail(GrantReason.KEY_UNKNOWN, grant_id=grant_id)
        if retired_at is not None and signed_at > retired_at:
            # The grant claims to have been signed by a key already rotated
            # out. Grants it really did issue are dated before the retirement
            # and are unaffected -- that is exactly the distinction.
            check("signing_key", False,
                  f"{kid!r} was retired at {retired_at.isoformat()} and cannot "
                  f"have signed a grant created at {proof.get('created')}")
            return fail(GrantReason.KEY_RETIRED, grant_id=grant_id)
        check("signing_key", True,
              f"{kid} ({record.get('status')}), valid for a proof created "
              f"{proof.get('created')}")

    # --- the public key ---------------------------------------------------
    # AFTER the register, deliberately: a revoked key is unpublished, so
    # extracting it would fail, and "the authority is unknown" is a misleading
    # way to report "this key was declared compromised".
    try:
        public_key = public_key_from_document(authority_document, kid)
    except (ValueError, KeyError) as exc:
        check("verification_method", False, f"unusable authority DID Document: {exc}")
        return fail(GrantReason.AUTHORITY_UNKNOWN, grant_id=grant_id)
    check("verification_method", True, f"{kid}")

    # --- the signature ----------------------------------------------------
    # The proof options are reconstructed from the presented proof and folded
    # back into the signed payload, so ANY change -- purpose, key id, domain,
    # creation time -- breaks the signature rather than being ignored.
    options = {k: v for k, v in proof.items() if k != "signatureValue"}
    result = verify_signature(
        public_key, signing_bytes(grant, options),
        proof.get("signatureValue") or "", kid,
    )
    if not check("signature", result.valid,
                 "signature verifies against the authority's DID Document"
                 if result.valid else result.reason):
        return fail(GrantReason.SIGNATURE_INVALID, grant_id=grant_id, signing_key=kid)

    # --- audience ---------------------------------------------------------
    if grant.get("domain") != expected_domain:
        check("domain", False,
              f"grant is addressed to {grant.get('domain')!r}, not {expected_domain!r}")
        return fail(GrantReason.DOMAIN_MISMATCH, grant_id=grant_id, signing_key=kid)
    check("domain", True, expected_domain)

    # --- validity window (SERVER clock, never the agent's) ----------------
    try:
        expires_at = parse_iso(grant["expirationDate"])
        not_before = parse_iso(grant["notBefore"])
        issued_at = parse_iso(grant["issuanceDate"])
    except (KeyError, ValueError, TypeError) as exc:
        check("validity_window", False, f"unparseable dates: {exc}")
        return fail(GrantReason.MALFORMED, grant_id=grant_id, signing_key=kid)

    common = {
        "grant_id": grant_id, "signing_key": kid,
        "expires_at": grant["expirationDate"], "not_before": grant["notBefore"],
        "max_uses": subject.get("maxUses"), "issuer": grant.get("issuer"),
        "justification": subject.get("justification") or {},
        "approval_id": (subject.get("justification") or {}).get("approval_id"),
    }

    # `now >= expires_at` is expired. The boundary instant is DENIED, matching
    # the approval artifact exactly so the two never disagree about what "the
    # moment it expires" means.
    if now >= expires_at:
        check("validity_window", False, f"expired at {grant['expirationDate']}")
        return fail(GrantReason.EXPIRED, **common)
    if now < not_before:
        check("validity_window", False, f"not valid until {grant['notBefore']}")
        return fail(GrantReason.NOT_YET_VALID, **common)
    if issued_at > now + timedelta(seconds=60):
        check("validity_window", False, "issued in the future")
        return fail(GrantReason.NOT_YET_VALID, **common)
    check("validity_window", True,
          f"valid until {grant['expirationDate']} "
          f"({int((expires_at - now).total_seconds())}s left)")

    # --- the binding ------------------------------------------------------
    presented = JITBinding(
        agent_did=subject.get("agent_did") or "",
        action=subject.get("action") or "",
        resource_type=subject.get("resource_type") or "",
        resource_ids=tuple(subject.get("resource_ids") or ()),
        purpose=subject.get("purpose") or "",
        constraints=subject.get("constraints") or {},
    )
    # The digest inside the signed body must agree with the fields inside the
    # signed body. They are both signed, so disagreement means the grant was
    # built wrong rather than tampered with -- and either way it is not usable.
    if subject.get("bindingHash") != presented.digest():
        check("binding_hash", False, "bindingHash does not match the bound fields")
        return fail(GrantReason.MALFORMED, **common)
    check("binding_hash", True, presented.digest()[:16] + "...")

    differences = presented.differences(expected_binding)
    if differences:
        check("binding", False,
              f"the mandate does not cover this request; differing: "
              f"{', '.join(differences)}")
        report = fail(GrantReason.BINDING_MISMATCH, **common)
        report.binding_differences = differences
        return report
    check("binding", True, "agent, action, resource type and purpose all match")

    # --- the resource INSTANCE -------------------------------------------
    if not presented.covers_resource(resource_id):
        check("resource_scope", False,
              f"{resource_id!r} is not one of the mandated resources")
        report = fail(GrantReason.BINDING_MISMATCH, **common)
        report.binding_differences = ["resource_ids"]
        return report
    check("resource_scope", True,
          f"{resource_id!r} is inside the mandate"
          if presented.resource_ids else "mandate covers the resource type")

    # --- constraints against LIVE server-side attributes ------------------
    violated = evaluate_constraints(presented.constraints, resource_attributes or {})
    if violated:
        check("constraints", False, "; ".join(violated))
        return fail(GrantReason.CONSTRAINT_VIOLATED, **common)
    check("constraints", True,
          "within every ceiling" if presented.constraints else "no constraints set")

    report = GrantReport(True, GrantReason.VALID, checks, **common)
    report.bound_to_request = True
    report.covers_resource = True
    return report


def evaluate_constraints(
    constraints: dict[str, Any], attributes: dict[str, Any]
) -> list[str]:
    """Compare a mandate's ceilings against LIVE resource attributes.

    The attributes come from the PIP, which read them server-side. A caller
    never supplies them, which is the whole reason a ceiling here means
    anything.

    FAIL CLOSED: a ceiling on an attribute that cannot be established is a
    violation, not a pass. A mandate that says "up to Rs 10,00,000" must not be
    usable on a record whose amount nobody can state.
    """
    violations: list[str] = []
    if not constraints:
        return violations

    if "max_amount_inr" in constraints:
        ceiling = constraints["max_amount_inr"]
        if not attributes.get("available"):
            violations.append(
                "max_amount_inr is set but the resource amount could not be "
                "established server-side"
            )
        else:
            amount = attributes.get("amount_inr")
            if not isinstance(amount, int):
                violations.append("max_amount_inr is set but no amount is available")
            elif amount > ceiling:
                violations.append(
                    f"amount {amount} exceeds the mandate ceiling {ceiling}"
                )
    return violations
