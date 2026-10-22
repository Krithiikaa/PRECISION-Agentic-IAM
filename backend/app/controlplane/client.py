"""Producing a control-plane proof, from the caller's side.

One implementation, used by the agent runtime, the test suite and the gate
scripts. If each of those built its own headers, a change to what is signed
would be caught only by whichever of them happened to be exercised.

The private key never leaves the KeyStore: this asks the Signer for a
signature over the canonical payload and nothing more.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from app.controlplane.proof import (
    HEADER_KEY_ID,
    HEADER_NONCE,
    HEADER_PRINCIPAL,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    ControlPlanePayload,
)
from app.identity.signer import Signer


def canonical_body(body: Any) -> bytes:
    """Serialise a JSON body EXACTLY as it will go on the wire.

    The proof binds `sha256(body)`, so the bytes signed and the bytes sent must
    be identical. `separators` is pinned because the default `json.dumps`
    spacing differs from what most HTTP clients emit, and a single space would
    change the digest and fail every request in a way that looks like a
    signature bug.
    """
    if body is None:
        return b""
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def control_plane_headers(
    signer: Signer,
    *,
    principal_did: str,
    kid: str,
    method: str,
    path: str,
    body: bytes = b"",
    nonce: str | None = None,
    moment: datetime | None = None,
) -> dict[str, str]:
    """Build the five proof headers for one request.

    Single-use: a fresh nonce per call. Reusing the returned headers for a
    second request is exactly the replay the server refuses.
    """
    payload = ControlPlanePayload.build(
        principal=principal_did, method=method, path=path,
        body=body, nonce=nonce, moment=moment,
    )
    signature = signer.sign(kid, payload.signing_bytes())
    return {
        HEADER_PRINCIPAL: principal_did,
        HEADER_KEY_ID: kid,
        HEADER_NONCE: payload.nonce,
        HEADER_TIMESTAMP: payload.timestamp,
        HEADER_SIGNATURE: signature.signature_b64,
    }
