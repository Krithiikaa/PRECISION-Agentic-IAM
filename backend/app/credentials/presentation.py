"""Verifiable Presentations: the holder proving it controls the subject DID.

Two distinct proofs are involved, and keeping them apart is the point:

  ISSUER proof (on each credential)
      "The bank authority attests these claims about did:poc:agent:risk-001."

  HOLDER proof (on the presentation)
      "I am did:poc:agent:risk-001, and I am handing you these credentials now."

Without the holder proof, anyone who obtained a copy of a credential could
present it as their own -- credentials are meant to be shown, so copies are
expected. The holder proof is made with the agent's OWN Phase 1 Ed25519 key;
no new key material is introduced.

KNOWN GAP: `challenge` is checked for equality when the verifier supplies an
expected value, but used challenges are not recorded, so a captured
presentation can be replayed against a verifier that reuses a challenge.
Single-use nonces need shared state across processes, which arrives with the
Session State Synchroniser in Phase 9.
"""
from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from app.credentials.canonical import canonical_bytes
from app.credentials.vc import (
    BASE_PRESENTATION_TYPE,
    PRESENTATION_PROOF_PURPOSE,
    PROOF_TYPE,
    build_presentation_document,
    build_proof_options,
    signing_payload,
    utcnow,
)


def new_presentation_id() -> str:
    return f"urn:uuid:{uuid.uuid4()}"


def new_challenge() -> str:
    return secrets.token_urlsafe(16)


@dataclass(frozen=True)
class UnsignedPresentation:
    document: dict[str, Any]
    proof_options: dict[str, Any]
    payload: bytes

    @property
    def presentation_id(self) -> str:
        return self.document["id"]


def build_unsigned_presentation(
    *,
    holder_did: str,
    holder_kid: str,
    credentials: list[dict[str, Any]],
    challenge: str | None = None,
    domain: str | None = None,
    presentation_id: str | None = None,
) -> UnsignedPresentation:
    document = build_presentation_document(
        presentation_id=presentation_id or new_presentation_id(),
        holder_did=holder_did,
        credentials=credentials,
    )
    options = build_proof_options(
        verification_method=holder_kid,
        proof_purpose=PRESENTATION_PROOF_PURPOSE,
        created=utcnow(),
        challenge=challenge,
        domain=domain,
    )
    return UnsignedPresentation(
        document=document,
        proof_options=options,
        payload=canonical_bytes(signing_payload(document, options)),
    )


def attach_proof(
    unsigned: UnsignedPresentation, proof_value_b64: str
) -> dict[str, Any]:
    return {**unsigned.document, "proof": {**unsigned.proof_options, "proofValue": proof_value_b64}}


def presentation_structure_problems(document: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if BASE_PRESENTATION_TYPE not in (document.get("type") or []):
        problems.append(f"type does not include {BASE_PRESENTATION_TYPE}")
    if not document.get("holder"):
        problems.append("holder is missing")
    credentials = document.get("verifiableCredential")
    if not isinstance(credentials, list) or not credentials:
        problems.append("verifiableCredential must be a non-empty array")
    proof = document.get("proof")
    if not isinstance(proof, dict):
        problems.append("proof is missing or not an object")
    else:
        if proof.get("type") != PROOF_TYPE:
            problems.append(f"unsupported proof type {proof.get('type')!r}")
        if not proof.get("proofValue"):
            problems.append("proof.proofValue is empty")
        if not proof.get("verificationMethod"):
            problems.append("proof.verificationMethod is empty")
        if proof.get("proofPurpose") != PRESENTATION_PROOF_PURPOSE:
            problems.append(
                f"proofPurpose must be {PRESENTATION_PROOF_PURPOSE!r}, got "
                f"{proof.get('proofPurpose')!r}"
            )
    return problems


def holder_signing_payload(document: dict[str, Any]) -> bytes:
    """Rebuild the exact bytes the holder signed, for verification."""
    proof = document.get("proof") or {}
    options = {k: v for k, v in proof.items() if k != "proofValue"}
    return canonical_bytes(signing_payload(document, options))
