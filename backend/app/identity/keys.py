"""Key material abstraction.

Design rule: **private key bytes never leave the KeyStore.** Callers ask the
keystore to sign; they never retrieve a private key. That is what makes the
interface swappable for a KMS / HSM / Vault / secure enclave in production,
where the private key is physically non-exportable.

Consequently the private key never appears in:
  * API responses      (no route returns one)
  * the frontend       (it never receives one)
  * logs               (nothing here logs key material)
  * PostgreSQL         (the DB stores only public keys + a keystore reference)
  * Git                (the keystore directory is gitignored)
"""
from __future__ import annotations

import abc
import base64
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.errors import KeyStoreError
from app.identity.multibase import encode_ed25519_public_key

ALGORITHM = "Ed25519"
_HKDF_SALT = b"agentic-iam-keystore-v1"


@dataclass(frozen=True)
class KeyHandle:
    """Everything a caller may know about a key. Public material only."""

    kid: str
    algorithm: str
    public_key_raw: bytes
    public_key_multibase: str
    keystore_ref: str
    created_at: datetime

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_raw).decode()


class KeyStore(abc.ABC):
    """Signing oracle. Generates keys and signs with them; never exports them."""

    backend_name: str = "abstract"

    @abc.abstractmethod
    def generate_key(self, kid: str) -> KeyHandle: ...

    @abc.abstractmethod
    def get_public_key(self, kid: str) -> KeyHandle: ...

    @abc.abstractmethod
    def sign(self, kid: str, message: bytes) -> bytes: ...

    @abc.abstractmethod
    def exists(self, kid: str) -> bool: ...

    @abc.abstractmethod
    def delete(self, kid: str) -> None: ...


def _safe_filename(kid: str) -> str:
    """kids contain ':' and '#'; map them to a flat, traversal-safe filename."""
    if "/" in kid or ".." in kid:
        raise KeyStoreError(f"Illegal key id: {kid!r}")
    return kid.replace(":", "_").replace("#", "__") + ".key.json"


class EncryptedFileKeyStore(KeyStore):
    """Development keystore: Ed25519 private keys sealed with AES-256-GCM.

    The data-encryption key is derived per-kid via HKDF-SHA256 from a master
    key supplied through the environment (KEYSTORE_MASTER_KEY), so the master
    key itself is never used directly as a cipher key and one leaked file
    cannot decrypt another.

    This is a *development* backend. It protects key material at rest against
    casual disclosure (repo checkout, database dump, log scrape). It does NOT
    provide the guarantees of an HSM: the master key lives in the process
    environment, so a full host compromise defeats it. Production should bind
    `KeyStore` to a KMS/HSM implementation instead.
    """

    backend_name = "encrypted_file"

    def __init__(self, directory: str | Path, master_key_b64: str) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, stat.S_IRWXU)  # 0700
        try:
            self._master_key = base64.b64decode(master_key_b64)
        except Exception as exc:  # noqa: BLE001
            raise KeyStoreError("KEYSTORE_MASTER_KEY is not valid base64") from exc
        if len(self._master_key) < 32:
            raise KeyStoreError("KEYSTORE_MASTER_KEY must decode to at least 32 bytes")

    # --- internals -------------------------------------------------------
    def _path(self, kid: str) -> Path:
        return self.directory / _safe_filename(kid)

    def _derive(self, kid: str) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=kid.encode()
        ).derive(self._master_key)

    def _load_private_key(self, kid: str) -> Ed25519PrivateKey:
        path = self._path(kid)
        if not path.exists():
            raise KeyStoreError(f"No key material for kid {kid!r}")
        record = json.loads(path.read_text())
        nonce = base64.b64decode(record["nonce"])
        ciphertext = base64.b64decode(record["ciphertext"])
        try:
            plaintext = AESGCM(self._derive(kid)).decrypt(nonce, ciphertext, kid.encode())
        except Exception as exc:  # noqa: BLE001
            raise KeyStoreError(
                f"Unable to decrypt key {kid!r}: wrong master key or tampered file"
            ) from exc
        return Ed25519PrivateKey.from_private_bytes(plaintext)

    def _handle_from_record(self, kid: str, record: dict) -> KeyHandle:
        raw = base64.b64decode(record["public_key"])
        return KeyHandle(
            kid=kid,
            algorithm=record["algorithm"],
            public_key_raw=raw,
            public_key_multibase=record["public_key_multibase"],
            keystore_ref=f"{self.backend_name}://{_safe_filename(kid)}",
            created_at=datetime.fromisoformat(record["created_at"]),
        )

    # --- KeyStore --------------------------------------------------------
    def generate_key(self, kid: str) -> KeyHandle:
        path = self._path(kid)
        if path.exists():
            raise KeyStoreError(f"Key {kid!r} already exists; refusing to overwrite")

        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        nonce = os.urandom(12)
        # kid is bound as AAD: a key file cannot be renamed onto another kid.
        ciphertext = AESGCM(self._derive(kid)).encrypt(nonce, private_bytes, kid.encode())

        record = {
            "kid": kid,
            "algorithm": ALGORITHM,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "kdf": "HKDF-SHA256",
            "cipher": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "public_key": base64.b64encode(public_raw).decode(),
            "public_key_multibase": encode_ed25519_public_key(public_raw),
        }
        # Write 0600 from the start, never world-readable even briefly.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(record, fh, indent=2)
        return self._handle_from_record(kid, record)

    def get_public_key(self, kid: str) -> KeyHandle:
        path = self._path(kid)
        if not path.exists():
            raise KeyStoreError(f"No key material for kid {kid!r}")
        return self._handle_from_record(kid, json.loads(path.read_text()))

    def sign(self, kid: str, message: bytes) -> bytes:
        return self._load_private_key(kid).sign(message)

    def exists(self, kid: str) -> bool:
        return self._path(kid).exists()

    def delete(self, kid: str) -> None:
        self._path(kid).unlink(missing_ok=True)


class InMemoryKeyStore(KeyStore):
    """Ephemeral keystore for unit tests. Same contract, no persistence."""

    backend_name = "memory"

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PrivateKey] = {}
        self._created: dict[str, datetime] = {}

    def generate_key(self, kid: str) -> KeyHandle:
        if kid in self._keys:
            raise KeyStoreError(f"Key {kid!r} already exists; refusing to overwrite")
        self._keys[kid] = Ed25519PrivateKey.generate()
        self._created[kid] = datetime.now(timezone.utc)
        return self.get_public_key(kid)

    def get_public_key(self, kid: str) -> KeyHandle:
        if kid not in self._keys:
            raise KeyStoreError(f"No key material for kid {kid!r}")
        raw = self._keys[kid].public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return KeyHandle(
            kid=kid,
            algorithm=ALGORITHM,
            public_key_raw=raw,
            public_key_multibase=encode_ed25519_public_key(raw),
            keystore_ref=f"{self.backend_name}://{kid}",
            created_at=self._created[kid],
        )

    def sign(self, kid: str, message: bytes) -> bytes:
        if kid not in self._keys:
            raise KeyStoreError(f"No key material for kid {kid!r}")
        return self._keys[kid].sign(message)

    def exists(self, kid: str) -> bool:
        return kid in self._keys

    def delete(self, kid: str) -> None:
        self._keys.pop(kid, None)
        self._created.pop(kid, None)


def load_public_key(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def build_keystore(settings) -> KeyStore:
    """Factory. Production would branch to a KMS/HSM implementation here."""
    if settings.keystore_backend == "encrypted_file":
        return EncryptedFileKeyStore(settings.keystore_dir, settings.keystore_master_key)
    raise KeyStoreError(f"Unknown keystore backend: {settings.keystore_backend}")
