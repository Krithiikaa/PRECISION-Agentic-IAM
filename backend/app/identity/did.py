"""POC DID namespace.

    did:poc:agent:<agent-slug>          e.g. did:poc:agent:risk-001
    did:poc:organization:<org-slug>     e.g. did:poc:organization:bank-demo
    did:poc:administrator:<slug>        e.g. did:poc:administrator:platform-security
    did:poc:service:<slug>              e.g. did:poc:service:approval-authority

NOTE (honesty): this is a *DID-like* identifier scheme built for this POC.
There is no DID resolver network, no universal resolver driver and no
registered `poc` method in the W3C DID method registry. The structure,
the DID Document shape and the key encoding follow the W3C conventions so
that a real method (did:web, did:key, did:ion) could replace it later.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.errors import IdentityError

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
DID_RE = re.compile(
    r"^did:(?P<method>[a-z0-9]+):(?P<kind>agent|organization|administrator|service):"
    r"(?P<slug>[a-z0-9][a-z0-9-]*)$"
)


@dataclass(frozen=True)
class ParsedDID:
    did: str
    method: str
    kind: str
    slug: str


def validate_slug(slug: str) -> str:
    if not SLUG_RE.match(slug):
        raise IdentityError(
            f"Invalid slug {slug!r}: use lowercase alphanumerics and hyphens, 3-64 chars"
        )
    return slug


def build_agent_did(slug: str, method: str = "poc") -> str:
    return f"did:{method}:agent:{validate_slug(slug)}"


def build_organization_did(slug: str, method: str = "poc") -> str:
    return f"did:{method}:organization:{validate_slug(slug)}"


def build_administrator_did(slug: str, method: str = "poc") -> str:
    """A control-plane administrator (Phase 4.5).

    A distinct KIND rather than a distinct identity SYSTEM: the same Ed25519
    key material, the same KeyStore, the same DID Document shape and the same
    signature verification path as every other principal here. Only the
    namespace differs, so a reader can tell at a glance that
    `did:poc:administrator:platform-security` is not an agent and not an issuer.
    """
    return f"did:{method}:administrator:{validate_slug(slug)}"


def is_administrator_did(did: str) -> bool:
    try:
        return parse_did(did).kind == "administrator"
    except IdentityError:
        return False


def build_service_did(slug: str, method: str = "poc") -> str:
    """A platform service that signs on its own authority (Phase 5).

    Distinct from an agent (which acts on a task), an organization (which
    issues credentials) and an administrator (which operates the control
    plane). The approval authority is the first of these: it attests that an
    authenticated human made a decision, and nothing else.
    """
    return f"did:{method}:service:{validate_slug(slug)}"


def is_service_did(did: str) -> bool:
    try:
        return parse_did(did).kind == "service"
    except IdentityError:
        return False


def parse_did(did: str) -> ParsedDID:
    m = DID_RE.match(did or "")
    if not m:
        raise IdentityError(f"Malformed DID: {did!r}")
    return ParsedDID(did=did, method=m["method"], kind=m["kind"], slug=m["slug"])


def is_agent_did(did: str) -> bool:
    try:
        return parse_did(did).kind == "agent"
    except IdentityError:
        return False


def key_id(did: str, fragment: str = "key-1") -> str:
    """Verification method id, e.g. did:poc:agent:risk-001#key-1."""
    return f"{did}#{fragment}"
