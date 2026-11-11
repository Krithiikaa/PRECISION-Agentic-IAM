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
# `.env` declares KEYSTORE_DIR=./.keystore, relative to backend/. A gate run
# from the repository root with `.env` exported would otherwise look for the
# administrators' keys in the wrong directory and fail with KEYSTORE_ERROR --
# which happened, and cost a whole gate sweep.
for _var in ("KEYSTORE_DIR", "AGENT_KEYSTORE_DIR"):
    _value = os.environ.get(_var)
    if _value and not os.path.isabs(_value):
        os.environ[_var] = str((REPO / "backend" / _value).resolve())

# --- Respect the server's rate limits (Phase 10) ----------------------------
# The gates were written before rate limiting existed and send bursts that
# exceed it. Rather than switching the limiter off, every gate now HONOURS it:
# a 429 is retried after the server's own Retry-After. Safe for signed
# requests: the limiter runs before authentication, so a refused request's
# nonce was never recorded and the identical proof is still unspent.
#
# NOT applied to anything testing the limiter itself -- that is
# tests/test_rate_limiting.py, which talks to the app directly. A gate that
# wants to see a raw 429 sets GATE_RESPECT_RATE_LIMITS=false.
import time as _time                                       # noqa: E402
import urllib.error as _urlerror                           # noqa: E402
import urllib.request as _urlrequest                       # noqa: E402

_ORIGINAL_URLOPEN = _urlrequest.urlopen
RATE_LIMIT_WAITS = {"count": 0, "seconds": 0}


def _urlopen_respecting_limits(request, *args, **kwargs):
    for attempt in range(8):
        try:
            return _ORIGINAL_URLOPEN(request, *args, **kwargs)
        except _urlerror.HTTPError as exc:
            if exc.code != 429 or attempt == 7:
                raise
            wait = min(max(int(exc.headers.get("Retry-After") or 5), 1), 65)
            RATE_LIMIT_WAITS["count"] += 1
            RATE_LIMIT_WAITS["seconds"] += wait
            _time.sleep(wait)


def fresh_window(seconds: int = 62) -> None:
    """Start a TIMING-SENSITIVE scenario with a full rate-limit budget.

    Honouring Retry-After keeps a gate correct but can insert a minute-long
    pause anywhere -- fatal to a scenario that asserts something works inside
    a 2-second window. Such a scenario calls this first, so no limit is hit
    mid-scenario. Only waits if this gate has actually been rate limited.
    """
    if RATE_LIMIT_WAITS["count"]:
        _time.sleep(seconds)


if os.environ.get("GATE_RESPECT_RATE_LIMITS", "true").lower() == "true":
    _urlrequest.urlopen = _urlopen_respecting_limits

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
