"""What a control-plane request proof IS, and what it binds.

    CONTROL-PLANE REQUEST -> AUTHENTICATION -> AUTHORIZATION -> OPERATION
                             ^^^^^^^^^^^^^^
                             this module

The problem being solved (S-4): before this, anyone who could reach the ANS
could POST `{"did": "did:poc:agent:risk-001"}` to /heartbeat and keep an agent
that had actually died looking alive -- or, with a status value, move it out of
discovery. Liveness was an assertion by whoever spoke first, not an observation
about the agent.

The fix reuses the PHASE 1 machine identity. No bearer token, no shared secret,
no API key, no IP allowlist, no "trust the DID in the body". The caller signs
with the same Ed25519 key it has held since Phase 1, and the server resolves
the public key from the published DID Document -- the same path a third party
would take.

WHAT IS SIGNED, and why each field is load-bearing:

    principal      the identity being claimed
    method + path  binds the proof to ONE operation. A captured heartbeat proof
                   cannot be presented to /unregister.
    body_sha256    binds the proof to the EXACT bytes of the body. The `did`
                   inside a heartbeat body cannot be swapped after signing.
    nonce          single-use, enforced by a unique index
    timestamp      bounded freshness, so a captured proof dies on its own even
                   if the nonce ledger were pruned
    proofPurpose   domain separation

That last field matters more than it looks. This system has four kinds of
Ed25519 proof over canonical JSON -- issuer assertions (`assertionMethod`),
holder proofs (`authentication`), ANS registrations (`ansRegistration`) and now
control-plane requests. Because the purpose is INSIDE the signed payload, a
signature made for one can never verify as another. There is no path where a
credential proof becomes a heartbeat.

Canonicalisation is `app.credentials.canonical`, unchanged and shared, so all
four proof types canonicalise identically. Nothing here re-implements
canonicalisation, signing or verification.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.credentials.canonical import canonical_bytes
from app.credentials.vc import parse_iso, to_iso

PROOF_PURPOSE = "controlPlaneRequest"

# Header names. Headers rather than body fields on purpose: several request
# schemas are `extra="forbid"`, and -- more importantly -- the body must stay
# byte-identical to what was hashed and signed.
HEADER_PRINCIPAL = "X-CP-Principal"
HEADER_KEY_ID = "X-CP-Key-Id"
HEADER_NONCE = "X-CP-Nonce"
HEADER_TIMESTAMP = "X-CP-Timestamp"
HEADER_SIGNATURE = "X-CP-Signature"

REQUIRED_HEADERS = (HEADER_PRINCIPAL, HEADER_NONCE, HEADER_TIMESTAMP, HEADER_SIGNATURE)


class AuthReason:
    """Why a control-plane request was accepted or refused.

    Coarse on purpose: a reason names the CLASS of failure, never which record,
    key or internal identifier was involved. An attacker probing the endpoint
    learns that its proof was refused, not why the server thinks so in detail.
    """

    # accepted
    VALID = "CONTROL_PLANE_PROOF_VALID"

    # 401 -- the caller did not authenticate
    PROOF_MISSING = "CONTROL_PLANE_PROOF_MISSING"
    PROOF_MALFORMED = "CONTROL_PLANE_PROOF_MALFORMED"

    # 403 -- the caller authenticated badly, or is not permitted
    PRINCIPAL_UNKNOWN = "PRINCIPAL_UNKNOWN"
    PRINCIPAL_NOT_RESOLVABLE = "PRINCIPAL_NOT_RESOLVABLE"
    PRINCIPAL_NOT_ELIGIBLE = "PRINCIPAL_NOT_ELIGIBLE"
    SIGNATURE_INVALID = "CONTROL_PLANE_SIGNATURE_INVALID"
    TIMESTAMP_STALE = "CONTROL_PLANE_TIMESTAMP_STALE"
    NONCE_REPLAYED = "CONTROL_PLANE_NONCE_REPLAYED"
    BODY_MISMATCH = "CONTROL_PLANE_BODY_MISMATCH"
    NOT_AUTHORIZED = "CONTROL_PLANE_NOT_AUTHORIZED"
    AUTHORIZATION_UNAVAILABLE = "CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE"


def new_nonce() -> str:
    return secrets.token_urlsafe(18)


def body_digest(body: bytes) -> str:
    """SHA-256 of the exact request body bytes. An empty body hashes too."""
    return hashlib.sha256(body or b"").hexdigest()


@dataclass(frozen=True)
class ControlPlanePayload:
    """Exactly what gets signed. Order-independent: canonicalisation sorts."""

    principal: str
    method: str
    path: str
    body_sha256: str
    nonce: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "method": self.method.upper(),
            "path": self.path,
            "body_sha256": self.body_sha256,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "proofPurpose": PROOF_PURPOSE,
        }

    def signing_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())

    @classmethod
    def build(
        cls,
        *,
        principal: str,
        method: str,
        path: str,
        body: bytes = b"",
        nonce: str | None = None,
        moment: datetime | None = None,
    ) -> "ControlPlanePayload":
        return cls(
            principal=principal,
            method=method.upper(),
            path=path,
            body_sha256=body_digest(body),
            nonce=nonce or new_nonce(),
            timestamp=to_iso(moment or datetime.now(timezone.utc)),
        )


def timestamp_is_fresh(
    timestamp: str,
    *,
    now: datetime | None = None,
    window_seconds: int = 300,
) -> tuple[bool, str]:
    """Bounded freshness in BOTH directions.

    `abs()` is deliberate: a proof timestamped far in the future is as
    suspicious as one timestamped far in the past, and accepting it would hand
    an attacker a proof that stays valid for as long as they chose.
    """
    now = now or datetime.now(timezone.utc)
    try:
        moment = parse_iso(timestamp)
    except (ValueError, TypeError) as exc:
        return False, f"unparseable timestamp: {exc}"
    delta = abs((now - moment).total_seconds())
    if delta > window_seconds:
        return False, (
            f"timestamp is {int(delta)}s from the server clock, outside the "
            f"{window_seconds}s window"
        )
    return True, f"within {window_seconds}s of the server clock"
