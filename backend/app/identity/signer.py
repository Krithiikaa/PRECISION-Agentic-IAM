"""Ed25519 signing and verification.

Signing goes through the KeyStore (private key stays inside).
Verification needs only the public key, so anyone holding the DID Document
can verify — which is exactly what the A2A and VC layers will do later.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from app.core.errors import IdentityError
from app.identity.keys import KeyStore, load_public_key
from app.identity.multibase import decode_ed25519_public_key


def to_bytes(message: str | bytes) -> bytes:
    return message.encode("utf-8") if isinstance(message, str) else message


@dataclass(frozen=True)
class SignatureResult:
    kid: str
    algorithm: str
    signature_b64: str
    signature_multibase: str | None = None


class Signer:
    def __init__(self, keystore: KeyStore) -> None:
        self.keystore = keystore

    def sign(self, kid: str, message: str | bytes) -> SignatureResult:
        signature = self.keystore.sign(kid, to_bytes(message))
        return SignatureResult(
            kid=kid,
            algorithm="Ed25519",
            signature_b64=base64.b64encode(signature).decode(),
        )


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str
    verification_method: str | None = None

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.valid


def verify_signature(
    public_key_multibase: str,
    message: str | bytes,
    signature_b64: str,
    verification_method: str | None = None,
) -> VerificationResult:
    """Real Ed25519 verification.

    Returns a result object rather than raising, because "invalid" is a normal,
    expected outcome in this system (tampered message, wrong key, replayed
    signature) and callers must record it rather than crash.
    """
    try:
        raw_public = decode_ed25519_public_key(public_key_multibase)
    except Exception as exc:  # noqa: BLE001
        return VerificationResult(False, f"INVALID_PUBLIC_KEY: {exc}", verification_method)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        return VerificationResult(False, f"MALFORMED_SIGNATURE: {exc}", verification_method)

    try:
        load_public_key(raw_public).verify(signature, to_bytes(message))
    except InvalidSignature:
        return VerificationResult(
            False, "SIGNATURE_MISMATCH: message, signature and key do not agree",
            verification_method,
        )
    except Exception as exc:  # noqa: BLE001
        return VerificationResult(False, f"VERIFICATION_ERROR: {exc}", verification_method)
    return VerificationResult(True, "SIGNATURE_VALID", verification_method)


def require_valid(result: VerificationResult) -> None:
    if not result.valid:
        raise IdentityError(result.reason)
