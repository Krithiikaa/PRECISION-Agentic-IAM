"""Establishing the PURPOSE of an MCP invocation (Phase 8).

THE PROBLEM. Phase 4 made purpose a required authorization input: "an action
name alone does not describe why it is being taken", and
`AuthorizationRequest.validate()` refuses a request without one. MCP's
`tools/call` has no purpose field. So a purpose must be carried somehow, and
the obvious options are all wrong in instructive ways:

    infer it from the tool        A tool is an action. Deriving purpose from
                                  it collapses the two concepts Phase 4
                                  deliberately separated, and makes
                                  `PURPOSE_NOT_ALLOWED` unreachable.
    default it                    A default purpose is a purpose nobody
                                  asserted, authorising reads for a reason
                                  the caller never claimed.
    trust the client              A client-supplied purpose is a claim by the
                                  party being authorized.

WHAT IS ACTUALLY DONE, and why it is none of those three.

The client states a purpose in `_meta`, and that statement is treated as a
SELECTOR, never as a grant. The authoritative set of purposes an agent may
act for is `allowed_purposes` in `policies/decision.rego`, which is derived
ONLY from credentials the Phase 2 verifier marked valid:

    allowed_purposes contains p if {
        some c in valid_credentials      # c.valid == true
        p := c.claims.purpose
    }

Policy then either requires the requested purpose to be in that set, or
matches it against a specific credential (`c.claims.purpose ==
input.purpose`). A purpose the agent holds no credential for produces
`PURPOSE_NOT_ALLOWED`, and the combining algorithm is default-deny, so a
purpose nobody attested cannot authorise anything no matter what the client
wrote.

So the trusted source for purpose is the VERIFIABLE CREDENTIAL. This module
only has to do two things, and does nothing else: read the claim out of a
protocol-legal location, and refuse the request when there isn't one.

ON THE `_meta` KEY, and the line this phase was told not to cross: there is
no purpose field in MCP and this module does not pretend to add one. `_meta`
is the specification's sanctioned place for implementation metadata --
"reserved by MCP to allow clients and servers to attach additional metadata
to their interactions" -- with a documented key-naming rule. The key used
here carries a non-reserved prefix (reserved prefixes are those whose labels
include `modelcontextprotocol` or `mcp`), so it cannot collide with a future
protocol-level key. It is an EXTENSION of this deployment, documented as one
in the conformance matrix, and never described as part of MCP.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.config import Settings, get_settings

# The same shape `AuthorizationRequest.validate()` enforces. Checked here too
# so a malformed purpose is refused as a protocol error with a useful
# message, rather than reaching the PDP and coming back as the much vaguer
# MALFORMED_REQUEST.
_PURPOSE_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


class PurposeReason:
    MISSING = "MCP_PURPOSE_MISSING"
    MALFORMED = "MCP_PURPOSE_MALFORMED"


@dataclass(frozen=True)
class PurposeResolution:
    """The outcome of trying to establish a purpose.

    `purpose` is populated only when `established` is True. There is no
    partial state and no fallback value: a caller cannot accidentally use an
    empty string as a purpose, because the field is None whenever the
    resolution failed.
    """

    established: bool
    purpose: str | None = None
    reason: str | None = None
    detail: str | None = None


def resolve_purpose(
    params: dict | None, settings: Settings | None = None
) -> PurposeResolution:
    """Read the requested purpose out of a tools/call `params._meta`.

    FAILS CLOSED. Absent, empty, non-string or malformed all return
    `established=False`, and the caller refuses the invocation. Nothing in
    this function has a default branch that produces a usable purpose.

    Note what is NOT validated here: whether the agent may actually act for
    this purpose. That is not knowable without the agent's verified
    credentials, it is decided in Rego, and duplicating the check in Python
    would create a second opinion that could disagree with policy.
    """
    settings = settings or get_settings()
    key = settings.mcp_purpose_meta_key

    meta = (params or {}).get("_meta")
    if not isinstance(meta, dict):
        return PurposeResolution(
            established=False,
            reason=PurposeReason.MISSING,
            detail=(
                f"this server requires a purpose for every invocation; supply "
                f"it as params._meta[{key!r}]"
            ),
        )

    raw = meta.get(key)
    if raw is None or not isinstance(raw, str) or not raw.strip():
        return PurposeResolution(
            established=False,
            reason=PurposeReason.MISSING,
            detail=(
                f"this server requires a purpose for every invocation; supply "
                f"it as params._meta[{key!r}]"
            ),
        )

    purpose = raw.strip()
    if not _PURPOSE_RE.match(purpose):
        return PurposeResolution(
            established=False,
            reason=PurposeReason.MALFORMED,
            detail=(
                "purpose must be a lower_snake_case token of 2-64 characters"
            ),
        )

    return PurposeResolution(established=True, purpose=purpose)
