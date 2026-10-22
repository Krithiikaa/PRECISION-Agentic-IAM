"""Verifiable Credential and Verifiable Presentation documents.

POC SCOPE NOTE
--------------
The document *shape* follows the W3C Verifiable Credentials data model
(`@context`, `id`, `type`, `issuer`, `issuanceDate`, `expirationDate`,
`credentialSubject`, `credentialStatus`, `proof`) so a real implementation
could replace this one without changing consumers.

It is **not** a standards-compliant implementation:
  * the proof is `PocEd25519Signature2026` over JCS-canonical JSON, not the
    W3C `Ed25519Signature2020` suite over URDNA2015-canonicalised JSON-LD;
  * `@context` URLs are not dereferenceable;
  * `did:poc:` is not a registered DID method.

Nothing in this module claims otherwise, and the proof type name is
deliberately distinct so a real W3C verifier cannot mistake it for the suite.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

W3C_VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
POC_CONTEXT = "https://agentic-iam.poc/credentials/v1"

PROOF_TYPE = "PocEd25519Signature2026"
PROOF_CRYPTOSUITE = "poc-jcs-eddsa-2026"
STATUS_TYPE = "PocCredentialStatusEndpoint2026"

# Proof purposes. These are the system's domain separators: a signature is made
# FOR a purpose, and `proofPurpose` sits inside the signed payload
# (`signing_payload`), so a proof produced for one purpose cannot be presented
# as a proof for another. The ANS registration proof carries its own purpose
# (`app.ans.proof.PROOF_PURPOSE`) for the same reason.
#
# Named here rather than inline so the credential verifier and the presentation
# verifier enforce the *same* constants instead of two hardcoded strings that
# could drift apart.
CREDENTIAL_PROOF_PURPOSE = "assertionMethod"    # an issuer asserting claims
PRESENTATION_PROOF_PURPOSE = "authentication"   # a holder proving it is the subject

BASE_CREDENTIAL_TYPE = "VerifiableCredential"
BASE_PRESENTATION_TYPE = "VerifiablePresentation"


class CredentialType:
    AGENT_CAPABILITY = "AgentCapabilityCredential"
    COMPLIANCE = "ComplianceCredential"
    AGENT_ROLE = "AgentRoleCredential"


# Claims a credential of each type must carry to be well formed. Verifiers
# check these; the issuer refuses to mint a credential that violates them.
REQUIRED_CLAIMS: dict[str, tuple[str, ...]] = {
    CredentialType.AGENT_CAPABILITY: (
        "capability", "allowedActions", "allowedResources", "purpose",
    ),
    CredentialType.COMPLIANCE: ("framework", "status", "scope"),
    CredentialType.AGENT_ROLE: ("role", "department"),
}

# Claim keys that would collide with data-model fields.
RESERVED_CLAIM_KEYS = {"id"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(moment: datetime) -> str:
    """RFC 3339 in UTC with a trailing Z, as the VC data model expects."""
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def snake_to_camel(key: str) -> str:
    head, *rest = key.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def normalize_claims(claims: dict[str, Any]) -> dict[str, Any]:
    """Accept snake_case claim keys and emit the camelCase the data model uses.

    The API is documented with `allowed_actions`; the credential carries
    `allowedActions`. Normalising here keeps one spelling inside the signed
    document, which matters because the signature is over exact bytes.
    """
    return {snake_to_camel(key): value for key, value in claims.items()}


@dataclass(frozen=True)
class CredentialDraft:
    """Everything needed to mint a credential, before it is signed."""

    issuer_did: str
    subject_did: str
    credential_type: str
    claims: dict[str, Any]
    ttl_seconds: int
    credential_id: str | None = None
    issued_at: datetime | None = None


def new_credential_id() -> str:
    return f"urn:uuid:{uuid.uuid4()}"


def build_credential_document(
    *,
    credential_id: str,
    credential_type: str,
    issuer_did: str,
    subject_did: str,
    claims: dict[str, Any],
    issued_at: datetime,
    expires_at: datetime,
    status_endpoint: str | None = None,
) -> dict[str, Any]:
    """Build the unsigned credential document."""
    document: dict[str, Any] = {
        "@context": [W3C_VC_CONTEXT, POC_CONTEXT],
        "id": credential_id,
        "type": [BASE_CREDENTIAL_TYPE, credential_type],
        "issuer": issuer_did,
        "issuanceDate": to_iso(issued_at),
        "expirationDate": to_iso(expires_at),
        "credentialSubject": {"id": subject_did, **claims},
    }
    if status_endpoint:
        # Status is deliberately a live lookup, not a boolean baked into the
        # signed document: revocation must be able to happen *after* signing.
        document["credentialStatus"] = {"id": status_endpoint, "type": STATUS_TYPE}
    return document


def build_presentation_document(
    *,
    presentation_id: str,
    holder_did: str,
    credentials: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "@context": [W3C_VC_CONTEXT, POC_CONTEXT],
        "id": presentation_id,
        "type": [BASE_PRESENTATION_TYPE],
        "holder": holder_did,
        "verifiableCredential": list(credentials),
    }


def build_proof_options(
    *,
    verification_method: str,
    proof_purpose: str,
    created: datetime,
    challenge: str | None = None,
    domain: str | None = None,
) -> dict[str, Any]:
    options: dict[str, Any] = {
        "type": PROOF_TYPE,
        "cryptosuite": PROOF_CRYPTOSUITE,
        "created": to_iso(created),
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }
    if challenge is not None:
        options["challenge"] = challenge
    if domain is not None:
        options["domain"] = domain
    return options


def signing_payload(document: dict[str, Any], proof_options: dict[str, Any]) -> dict[str, Any]:
    """The exact structure that gets canonicalised and signed.

    The proof options are inside the payload, so `created`,
    `verificationMethod`, `proofPurpose`, `challenge` and `domain` are covered
    by the signature too. Swapping a proof's verificationMethod to point at a
    different key therefore invalidates it, rather than silently redirecting
    the verifier.
    """
    body = {key: value for key, value in document.items() if key != "proof"}
    return {**body, "proof": proof_options}


def credential_subject_did(document: dict[str, Any]) -> str | None:
    subject = document.get("credentialSubject")
    return subject.get("id") if isinstance(subject, dict) else None


def credential_claims(document: dict[str, Any]) -> dict[str, Any]:
    subject = document.get("credentialSubject") or {}
    return {key: value for key, value in subject.items() if key != "id"}


def specific_type(document: dict[str, Any]) -> str | None:
    """The concrete credential type, i.e. the one that is not the base type."""
    types = document.get("type") or []
    for entry in types:
        if entry != BASE_CREDENTIAL_TYPE:
            return entry
    return None


def default_expiry(issued_at: datetime, ttl_seconds: int) -> datetime:
    return issued_at + timedelta(seconds=ttl_seconds)
