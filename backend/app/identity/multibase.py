"""Multibase / multicodec encoding for Ed25519 public keys.

Follows the same encoding the `did:key` specification uses so the values in
our DID Documents are interoperable in shape:

    multibase(base58btc, multicodec(ed25519-pub) || raw_public_key)
    => "z" + base58btc(0xed 0x01 || 32 raw bytes)
"""
from __future__ import annotations

import base58

# Varint encoding of the multicodec code 0xed (ed25519-pub).
ED25519_PUB_MULTICODEC = b"\xed\x01"
BASE58BTC_PREFIX = "z"


def encode_ed25519_public_key(raw: bytes) -> str:
    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return BASE58BTC_PREFIX + base58.b58encode(ED25519_PUB_MULTICODEC + raw).decode()


def decode_ed25519_public_key(multibase_value: str) -> bytes:
    if not multibase_value.startswith(BASE58BTC_PREFIX):
        raise ValueError("Only base58btc ('z') multibase values are supported")
    decoded = base58.b58decode(multibase_value[1:])
    if not decoded.startswith(ED25519_PUB_MULTICODEC):
        raise ValueError("Value is not a multicodec ed25519-pub key")
    raw = decoded[len(ED25519_PUB_MULTICODEC):]
    if len(raw) != 32:
        raise ValueError(f"Decoded Ed25519 public key must be 32 bytes, got {len(raw)}")
    return raw
