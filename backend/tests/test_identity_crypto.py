"""Ed25519 key custody, signing and verification.

These are the tests that make the phrase "real cryptography" checkable.
"""
from __future__ import annotations

import base64
import json
import os
import stat

import pytest

from app.core.errors import KeyStoreError
from app.identity.keys import ALGORITHM, EncryptedFileKeyStore
from app.identity.multibase import (
    decode_ed25519_public_key,
    encode_ed25519_public_key,
)
from app.identity.signer import Signer, verify_signature

MESSAGE = "I am the Risk Analysis Agent"
TAMPERED = "I am the Payroll Agent"


class TestKeyGeneration:
    def test_generates_a_real_ed25519_key(self, keystore):
        handle = keystore.generate_key("did:poc:agent:risk-001#key-1")
        assert handle.algorithm == ALGORITHM
        assert len(handle.public_key_raw) == 32
        # did:key convention for Ed25519 public keys
        assert handle.public_key_multibase.startswith("z6Mk")
        assert decode_ed25519_public_key(handle.public_key_multibase) == handle.public_key_raw

    def test_every_agent_gets_a_distinct_key_pair(self, keystore):
        first = keystore.generate_key("did:poc:agent:risk-001#key-1")
        second = keystore.generate_key("did:poc:agent:fraud-001#key-1")
        assert first.public_key_multibase != second.public_key_multibase
        assert first.public_key_raw != second.public_key_raw

    def test_refuses_to_overwrite_an_existing_key(self, keystore):
        keystore.generate_key("did:poc:agent:risk-001#key-1")
        with pytest.raises(KeyStoreError, match="already exists"):
            keystore.generate_key("did:poc:agent:risk-001#key-1")

    def test_multibase_roundtrip_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            encode_ed25519_public_key(os.urandom(31))


class TestKeyAtRest:
    """The private key must not be recoverable from the stored artefacts."""

    def test_private_key_is_encrypted_on_disk(self, keystore, tmp_path):
        handle = keystore.generate_key("did:poc:agent:risk-001#key-1")
        files = list((tmp_path / "keystore").iterdir())
        assert len(files) == 1
        record = json.loads(files[0].read_text())

        assert record["cipher"] == "AES-256-GCM"
        assert "private" not in json.dumps(record).lower().replace("privateformat", "")
        # The stored public key is present; nothing decrypts to it by accident.
        assert record["public_key"] == handle.public_key_b64
        # The ciphertext is not the raw key: AES-GCM adds a 16-byte tag.
        assert len(base64.b64decode(record["ciphertext"])) == 32 + 16

    def test_key_file_is_not_world_readable(self, keystore, tmp_path):
        keystore.generate_key("did:poc:agent:risk-001#key-1")
        path = next((tmp_path / "keystore").iterdir())
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_a_different_master_key_cannot_decrypt(self, keystore, tmp_path):
        kid = "did:poc:agent:risk-001#key-1"
        keystore.generate_key(kid)
        attacker = EncryptedFileKeyStore(
            tmp_path / "keystore", base64.b64encode(os.urandom(32)).decode()
        )
        with pytest.raises(KeyStoreError, match="Unable to decrypt"):
            attacker.sign(kid, b"anything")

    def test_key_file_cannot_be_renamed_onto_another_identity(self, keystore, tmp_path):
        """kid is bound as AES-GCM associated data, so relabelling fails."""
        keystore.generate_key("did:poc:agent:risk-001#key-1")
        directory = tmp_path / "keystore"
        original = next(directory.iterdir())
        original.rename(directory / "did_poc_agent_payroll-001__key-1.key.json")
        with pytest.raises(KeyStoreError, match="Unable to decrypt"):
            keystore.sign("did:poc:agent:payroll-001#key-1", b"anything")


class TestSigningAndVerification:
    def test_signature_verifies(self, keystore):
        handle = keystore.generate_key("did:poc:agent:risk-001#key-1")
        signature = Signer(keystore).sign(handle.kid, MESSAGE)
        result = verify_signature(handle.public_key_multibase, MESSAGE, signature.signature_b64)
        assert result.valid
        assert result.reason == "SIGNATURE_VALID"

    def test_tampered_message_fails(self, keystore):
        """Phase 1 gate test 5: reuse a valid signature over changed text."""
        handle = keystore.generate_key("did:poc:agent:risk-001#key-1")
        signature = Signer(keystore).sign(handle.kid, MESSAGE)
        result = verify_signature(handle.public_key_multibase, TAMPERED, signature.signature_b64)
        assert not result.valid
        assert result.reason.startswith("SIGNATURE_MISMATCH")

    def test_wrong_key_fails(self, keystore):
        signer = Signer(keystore)
        risk = keystore.generate_key("did:poc:agent:risk-001#key-1")
        fraud = keystore.generate_key("did:poc:agent:fraud-001#key-1")
        signature = signer.sign(risk.kid, MESSAGE)
        assert not verify_signature(
            fraud.public_key_multibase, MESSAGE, signature.signature_b64
        ).valid

    def test_flipped_signature_bit_fails(self, keystore):
        handle = keystore.generate_key("did:poc:agent:risk-001#key-1")
        signature = Signer(keystore).sign(handle.kid, MESSAGE)
        raw = bytearray(base64.b64decode(signature.signature_b64))
        raw[0] ^= 0x01
        result = verify_signature(
            handle.public_key_multibase, MESSAGE, base64.b64encode(raw).decode()
        )
        assert not result.valid

    def test_malformed_inputs_are_reported_not_raised(self, keystore):
        handle = keystore.generate_key("did:poc:agent:risk-001#key-1")
        assert not verify_signature(handle.public_key_multibase, MESSAGE, "not-base64!!").valid
        assert not verify_signature("not-a-multibase-key", MESSAGE, "AAAA").valid

    def test_signing_an_unknown_key_fails(self, keystore):
        with pytest.raises(KeyStoreError, match="No key material"):
            Signer(keystore).sign("did:poc:agent:ghost-001#key-1", MESSAGE)
