"""Canonical serialisation for signing.

A signature is over *bytes*. Issuer and verifier must therefore agree, exactly,
on how a credential becomes bytes -- otherwise a credential that is genuinely
untampered fails to verify because the two sides serialised it differently.

We use JCS-style canonicalisation (RFC 8785): object keys sorted, no
insignificant whitespace, UTF-8 output.

HONEST SCOPE NOTE
-----------------
This is **not** W3C Data Integrity / `Ed25519Signature2020`. That suite
canonicalises JSON-LD with URDNA2015, which requires a full JSON-LD processor
and dereferenceable contexts. We do neither. Our proof type is therefore named
`PocEd25519Signature2026` and never claims to be the W3C suite.

Floats are rejected rather than serialised. RFC 8785 mandates ECMAScript
number formatting, which Python's `repr` does not reproduce for every value; a
verifier written in another language could then compute different bytes for the
same credential and reject a valid one. Refusing floats at issuance keeps the
canonical form reproducible across languages. Integers, strings, booleans,
null, arrays and objects are all supported.
"""
from __future__ import annotations

import json
from typing import Any


class CanonicalizationError(ValueError):
    pass


def _validate(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise CanonicalizationError(
            f"Floating point value at {path} is not allowed in a credential: "
            f"canonical JSON number formatting is not reproducible across "
            f"languages. Use a string or an integer."
        )
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"Non-string object key at {path}: {key!r}")
            _validate(item, f"{path}.{key}")
        return
    raise CanonicalizationError(f"Unserialisable value at {path}: {type(value).__name__}")


def canonicalize(document: dict[str, Any]) -> str:
    """Return the canonical JSON string for `document`."""
    _validate(document)
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def canonical_bytes(document: dict[str, Any]) -> bytes:
    return canonicalize(document).encode("utf-8")
