"""Registration proof: proving control of a DID before claiming it in ANS.

Without this, anyone who can reach the ANS could register
`did:poc:agent:risk-001` pointing at an endpoint they control, and every
coordinator that discovers "the risk agent" would be routed to the attacker.
That is the single most damaging attack against a naming service, so
registration is authenticated by the same Ed25519 key the agent already has
from Phase 1. No new key material is introduced.

The signed payload binds five things:

    did          the identity being claimed
    endpoint     where traffic will be sent -- the actual target of the attack
    capabilities what the agent claims it can do
    nonce        single-use, so a captured registration cannot be replayed
    timestamp    bounded freshness, so an old capture expires even if the
                 nonce table were lost

Reuses `app.credentials.canonical` so issuer proofs, holder proofs and
registration proofs all canonicalise identically.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from app.credentials.canonical import canonical_bytes
from app.credentials.vc import parse_iso, to_iso

# How far a registration timestamp may be from the ANS clock. Generous enough
# for container clock drift, tight enough that a stolen payload dies quickly.
DEFAULT_FRESHNESS_SECONDS = 300

PROOF_PURPOSE = "ansRegistration"


class ProofReason:
    VALID = "REGISTRATION_PROOF_VALID"
    MALFORMED = "MALFORMED_REGISTRATION"
    DID_UNKNOWN = "DID_UNKNOWN"
    DID_NOT_RESOLVABLE = "DID_NOT_RESOLVABLE"
    AGENT_NOT_ELIGIBLE = "AGENT_NOT_ELIGIBLE"
    INVALID_PROOF = "INVALID_REGISTRATION_PROOF"
    STALE_TIMESTAMP = "STALE_REGISTRATION_TIMESTAMP"
    NONCE_REPLAYED = "REGISTRATION_NONCE_REPLAYED"
    ENDPOINT_INVALID = "ENDPOINT_INVALID"
    CAPABILITIES_INVALID = "CAPABILITIES_INVALID"


def new_nonce() -> str:
    return secrets.token_urlsafe(18)


@dataclass(frozen=True)
class RegistrationPayload:
    """Exactly what gets signed. Order-independent: canonicalisation sorts."""

    did: str
    endpoint: str
    capabilities: list[str]
    organization: str | None
    nonce: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "did": self.did,
            "endpoint": self.endpoint,
            # Sorted so the agent and ANS agree regardless of declaration order.
            "capabilities": sorted(self.capabilities),
            "organization": self.organization,
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
        did: str,
        endpoint: str,
        capabilities: list[str],
        organization: str | None = None,
        nonce: str | None = None,
        moment: datetime | None = None,
    ) -> "RegistrationPayload":
        return cls(
            did=did,
            endpoint=endpoint,
            capabilities=sorted(capabilities),
            organization=organization,
            nonce=nonce or new_nonce(),
            timestamp=to_iso(moment or datetime.now(timezone.utc)),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegistrationPayload":
        return cls(
            did=data["did"],
            endpoint=data["endpoint"],
            capabilities=sorted(data.get("capabilities") or []),
            organization=data.get("organization"),
            nonce=data["nonce"],
            timestamp=data["timestamp"],
        )


def timestamp_is_fresh(
    timestamp: str,
    *,
    now: datetime | None = None,
    window_seconds: int = DEFAULT_FRESHNESS_SECONDS,
) -> tuple[bool, str]:
    now = now or datetime.now(timezone.utc)
    try:
        moment = parse_iso(timestamp)
    except (ValueError, TypeError) as exc:
        return False, f"unparseable timestamp: {exc}"
    delta = abs((now - moment).total_seconds())
    if delta > window_seconds:
        return False, (
            f"timestamp is {int(delta)}s from the registry clock, "
            f"outside the {window_seconds}s window"
        )
    return True, f"within {window_seconds}s of the registry clock"


def endpoint_is_valid(endpoint: str) -> tuple[bool, str]:
    """Syntactic check only. Reachability is a separate, observable question."""
    from urllib.parse import urlparse

    if not endpoint or len(endpoint) > 512:
        return False, "endpoint is empty or too long"
    parsed = urlparse(endpoint)
    if parsed.scheme not in ("http", "https"):
        return False, f"scheme {parsed.scheme!r} is not http or https"
    if not parsed.hostname:
        return False, "endpoint has no host"
    return True, f"{parsed.scheme}://{parsed.hostname}:{parsed.port or ''}"


def capabilities_are_valid(capabilities: list[str]) -> tuple[bool, str]:
    import re

    if not capabilities:
        return False, "at least one capability is required"
    if len(capabilities) > 32:
        return False, "too many capabilities"
    pattern = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
    bad = [c for c in capabilities if not pattern.match(c)]
    if bad:
        return False, f"malformed capability names: {bad}"
    return True, f"{len(capabilities)} capability name(s) well formed"
