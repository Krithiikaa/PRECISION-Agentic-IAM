"""Control-plane request signing for the gate scripts.

The gates talk to a RUNNING system over HTTP, so they need to produce real
proofs. Rather than reimplementing the payload here -- which would drift the
first time the signed fields changed -- this imports the same
`app.controlplane.client` the agent runtime uses.

That means the gate needs the KeyStore the API is using. For a host run that is
`backend/.keystore` (the default). Pass KEYSTORE_DIR to point elsewhere.
"""
from __future__ import annotations

import os
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

os.environ.setdefault("KEYSTORE_DIR", str(REPO / "backend" / ".keystore"))

from app.controlplane.client import (  # noqa: E402
    canonical_body,
    control_plane_headers,
)
from app.core.config import get_settings  # noqa: E402
from app.identity.keys import build_keystore  # noqa: E402
from app.identity.signer import Signer  # noqa: E402

GATEWAY = "did:poc:administrator:enforcement-gateway"
POLICY_ADMIN = "did:poc:administrator:platform-security"
IDENTITY_ADMIN = "did:poc:administrator:identity-authority"
# Phase 5.5. The only principal that may restate a loan amount, and the only
# thing it may do.
CORE_BANKING = "did:poc:administrator:core-banking"


def signer() -> Signer:
    return Signer(build_keystore(get_settings()))


def signed(principal: str, method: str, path: str, body=None):
    """Return (body bytes, headers). Sign exactly the bytes that will be sent."""
    payload = canonical_body(body)
    headers = control_plane_headers(
        signer(), principal_did=principal, kid=f"{principal}#key-1",
        method=method, path=path, body=payload,
    )
    headers["Content-Type"] = "application/json"
    return payload, headers
