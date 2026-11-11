"""Tamper-evident audit trail (Phase 12): MAC, hash chain, signed checkpoints.

THREE MECHANISMS, each closing a different hole. None of them is a UI check;
all of them run server-side, and the verifier also runs as a standalone
script against the database (scripts/verify_audit_chain.py).

  1. WRITE-TIME MAC (`audit_events.integrity_mac`)
     HMAC-SHA256 over the event's content, computed by the process that
     writes it, with a key derived from the keystore master key. The key is
     never in the database. A row INSERTED by someone with database access
     but not the key carries no valid MAC -- so forged insertion is detected
     even after the sealer has innocently chained the forged row.

  2. HASH CHAIN (`audit_chain`, append-only, separate table)
     The sealer takes committed, unsealed events and links each to the
     previous entry: entry_hash = SHA-256(index, kind, seq, id, content_hash,
     prev_hash). content_hash covers seq, occurred_at, every field, the
     metadata and the MAC. Modification, deletion, reordering and insertion
     of SEALED rows break the chain.

  3. SIGNED CHECKPOINTS (`audit_checkpoints`)
     Ed25519 signature over (index, entry_hash) with a key held in the
     keystore. Someone who can write the database can recompute every hash
     after the point they edit; they cannot re-sign the checkpoints. The
     verifier trusts the keystore's key (or a key an auditor pinned out of
     band), never a key read from the database.

CONCURRENCY. Audit rows are written by many transactions at once and commit
in an order unrelated to `seq`. Chaining at insert time would serialise
every transaction that writes an audit event -- including ones that wait on
OPA or Keycloak -- behind one lock until commit. Instead ONE sealer chains
rows after they commit, under a transaction-scoped advisory lock, in a short
transaction with no I/O. Chain order is therefore SEALING order. A row that
commits late is chained late (its seq is lower than its neighbours'), never
skipped: each pass looks back over a seq window, and a full sweep runs at
start-up and periodically.

WHAT THIS DOES NOT CLAIM (stated so nobody infers it):
  * Not immutable storage. A database superuser can still delete rows; the
    point is that the verifier will report it.
  * A row deleted in the seconds between its commit and its sealing leaves
    no trace in the chain. The window is `audit_seal_interval_seconds`.
  * Truncating the chain's tail AND every checkpoint after it is detectable
    only against a checkpoint retained outside the database. Checkpoints
    are therefore also logged and served by the API for external anchoring.
  * The MAC key is only as safe as the keystore master key. Without an
    HSM/KMS (BLOCKED_EXTERNAL) an attacker who holds both the database and
    the master key can forge history. Legal-grade non-repudiation is not
    claimed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DOMAIN = "precision-audit/v1"
CHECKPOINT_DOMAIN = "precision-audit-checkpoint/v1"
GENESIS_PREV = "0" * 64
# pg_advisory_xact_lock key for the sealer. Any constant; it only has to be
# the same in every process that seals.
SEALER_LOCK_KEY = 0x50524543_41554431 & 0x7FFFFFFFFFFFFFFF
LOOKBACK_SEQ = 5_000

EVENT_FIELDS = ("event_type", "agent_did", "session_id", "request_id", "resource",
                "action", "decision", "reason")

# The append-only guard. Shared by the migration and by the test that proves
# it, so the two can never drift. A trigger stops ordinary writes; it does
# not stop the table OWNER, who can disable it -- which is exactly the case
# the hash chain exists for.
APPEND_ONLY_FUNCTION_DDL = """
CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'AUDIT_APPEND_ONLY: % on % is not permitted; the audit trail is append-only',
        TG_OP, TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql
"""
APPEND_ONLY_TABLES = ("audit_events", "audit_chain", "audit_checkpoints")


def append_only_trigger_ddl(table: str) -> str:
    return (f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION audit_append_only()")


# ---------------------------------------------------------------------------
# Canonical encoding
# ---------------------------------------------------------------------------
def _canon(value: Any) -> Any:
    """A representation that survives a round trip through JSONB unchanged.

    JSONB may re-render numbers (5.0 vs 5, 1e+20 vs 100000000000000000000)
    and reorders keys. Numbers become their normalised decimal text; keys
    are sorted by the encoder. Anything else JSON cannot hold is refused
    rather than stringified, so a hash can never depend on a repr().
    """
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        normal = Decimal(repr(value)).normalize()
        return {"#n": format(normal, "f") if normal == normal.to_integral() and
                abs(normal) < Decimal(10) ** 30 else str(normal)}
    if isinstance(value, dict):
        return {str(k): _canon(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canon(v) for v in value]
    raise TypeError(f"audit metadata holds a non-JSON value of type {type(value).__name__}")


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(_canon(obj), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ts(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


# ---------------------------------------------------------------------------
# 1. Write-time MAC
# ---------------------------------------------------------------------------
def derive_mac_key(master_key: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"precision/audit-event-mac/v1").derive(master_key.encode("utf-8"))


def mac_payload(event_id: uuid.UUID | str, fields: dict[str, Any],
                metadata: dict[str, Any]) -> bytes:
    return canonical_bytes({"domain": DOMAIN, "id": str(event_id),
                            **{k: fields.get(k) for k in EVENT_FIELDS},
                            "metadata": metadata or {}})


def compute_mac(key: bytes, event_id, fields: dict[str, Any], metadata: dict[str, Any]) -> str:
    return hmac.new(key, mac_payload(event_id, fields, metadata), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# 2. Chain
# ---------------------------------------------------------------------------
def event_dict(row: Any) -> dict[str, Any]:
    """Plain dict from an AuditEvent ORM row or a DB mapping."""
    get = (lambda k: getattr(row, k)) if not isinstance(row, dict) else row.get
    return {"id": str(get("id")), "seq": int(get("seq")), "occurred_at": get("occurred_at"),
            **{k: get(k) for k in EVENT_FIELDS},
            "metadata": get("event_metadata") if not isinstance(row, dict)
            else row.get("event_metadata", row.get("metadata")) or {},
            "integrity_mac": get("integrity_mac")}


def event_content_hash(ev: dict[str, Any]) -> str:
    return sha256_hex(canonical_bytes({
        "domain": DOMAIN, "id": ev["id"], "seq": ev["seq"],
        "occurred_at": _ts(ev["occurred_at"]),
        **{k: ev.get(k) for k in EVENT_FIELDS},
        "metadata": ev.get("metadata") or {}, "integrity_mac": ev.get("integrity_mac")}))


def genesis_content_hash(detail: dict[str, Any]) -> str:
    return sha256_hex(canonical_bytes({"domain": DOMAIN, "genesis": detail}))


def entry_hash(*, chain_index: int, kind: str, event_seq: int | None,
               event_id: str | None, content_hash: str, prev_hash: str) -> str:
    return sha256_hex(canonical_bytes({
        "domain": DOMAIN, "chain_index": chain_index, "kind": kind,
        "event_seq": event_seq, "event_id": event_id,
        "content_hash": content_hash, "prev_hash": prev_hash}))


# ---------------------------------------------------------------------------
# 3. Checkpoints
# ---------------------------------------------------------------------------
def checkpoint_payload(*, chain_index: int, entry_hash_value: str, signed_at: datetime,
                       kid: str) -> bytes:
    return canonical_bytes({"domain": CHECKPOINT_DOMAIN, "chain_index": chain_index,
                            "entry_hash": entry_hash_value, "signed_at": _ts(signed_at),
                            "kid": kid})


def verify_checkpoint_signature(public_key_b64: str, payload: bytes, signature_b64: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        key.verify(base64.b64decode(signature_b64), payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Verification core: pure, fed rows by an async (API) or sync (CLI) reader
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    kind: str
    detail: str
    chain_index: int | None = None
    event_seq: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "detail": self.detail,
                "chain_index": self.chain_index, "event_seq": self.event_seq}


@dataclass
class IntegrityReport:
    ok: bool
    entries_checked: int
    head_index: int | None
    head_hash: str | None
    covers_from_seq: int | None
    events_before_coverage: int
    unsealed_within_grace: int
    checkpoints_verified: int
    last_checkpoint_index: int | None
    entries_after_last_checkpoint: int
    mac_checked: bool
    findings: list[Finding] = field(default_factory=list)
    verified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "status": "VERIFIED" if self.ok else "INTEGRITY_VIOLATION",
            "entries_checked": self.entries_checked, "head_index": self.head_index,
            "head_hash": self.head_hash, "covers_from_seq": self.covers_from_seq,
            "events_before_coverage": self.events_before_coverage,
            "unsealed_within_grace": self.unsealed_within_grace,
            "checkpoints_verified": self.checkpoints_verified,
            "last_checkpoint_index": self.last_checkpoint_index,
            "entries_after_last_checkpoint": self.entries_after_last_checkpoint,
            "mac_checked": self.mac_checked,
            "findings": [f.to_dict() for f in self.findings[:200]],
            "finding_count": len(self.findings),
            "verified_at": self.verified_at.isoformat(),
            "scope_note": ("Detects modification, deletion, reordering and insertion of "
                           "sealed audit rows, forged rows lacking a valid MAC, and chain "
                           "rewrites behind a signed checkpoint. Not immutable storage."),
        }


class ChainVerifier:
    """Walks the chain in index order. Feed entries, then checkpoints."""

    def __init__(self, *, trusted_keys: dict[str, str], mac_key: bytes | None) -> None:
        self.trusted_keys = trusted_keys          # kid -> base64 public key
        self.mac_key = mac_key
        self.findings: list[Finding] = []
        self.expected_index = 0
        self.prev_hash: str | None = None
        self.hashes: dict[int, str] = {}
        self.covers_from_seq: int | None = None
        self.head: tuple[int, str] | None = None
        self.checkpoints_ok = 0
        self.last_checkpoint: int | None = None

    def _find(self, kind: str, detail: str, **kw) -> None:
        self.findings.append(Finding(kind, detail, **kw))

    def check_mac(self, ev: dict[str, Any]) -> None:
        if self.mac_key is None:
            return
        if not ev.get("integrity_mac"):
            self._find("EVENT_MAC_MISSING",
                       "event inside chain coverage carries no integrity MAC "
                       "(written outside the application)", event_seq=ev["seq"])
            return
        expected = compute_mac(self.mac_key, ev["id"], ev, ev.get("metadata") or {})
        if not hmac.compare_digest(expected, ev["integrity_mac"]):
            self._find("EVENT_MAC_INVALID",
                       "event content does not match its write-time MAC "
                       "(forged insertion or modification)", event_seq=ev["seq"])

    def feed(self, entry: dict[str, Any], event: dict[str, Any] | None) -> None:
        idx = int(entry["chain_index"])
        if idx != self.expected_index:
            self._find("CHAIN_GAP", f"expected entry {self.expected_index}, found {idx} "
                       "(entries deleted or reordered)", chain_index=idx)
        recomputed = entry_hash(chain_index=idx, kind=entry["kind"],
                                event_seq=entry.get("event_seq"),
                                event_id=str(entry["event_id"]) if entry.get("event_id") else None,
                                content_hash=entry["content_hash"], prev_hash=entry["prev_hash"])
        if recomputed != entry["entry_hash"]:
            self._find("ENTRY_HASH_MISMATCH", "chain entry was altered", chain_index=idx)
        if idx == 0 or entry["kind"] == "GENESIS":
            if entry["prev_hash"] != GENESIS_PREV or entry["kind"] != "GENESIS" or idx != 0:
                self._find("GENESIS_INVALID", "entry 0 must be the only GENESIS and link "
                           "to the zero hash", chain_index=idx)
            detail = entry.get("detail") or {}
            if genesis_content_hash(detail) != entry["content_hash"]:
                self._find("GENESIS_INVALID", "genesis detail was altered", chain_index=idx)
            self.covers_from_seq = detail.get("covers_from_seq")
        else:
            if self.prev_hash is not None and entry["prev_hash"] != self.prev_hash:
                self._find("CHAIN_LINK_BROKEN", "prev_hash does not match the previous "
                           "entry (insertion, deletion or reordering)", chain_index=idx)
            if event is None:
                self._find("EVENT_DELETED", "the chained audit event no longer exists",
                           chain_index=idx, event_seq=entry.get("event_seq"))
            else:
                if event["seq"] != entry.get("event_seq"):
                    self._find("EVENT_MODIFIED", "event seq differs from the sealed seq",
                               chain_index=idx, event_seq=event["seq"])
                if event_content_hash(event) != entry["content_hash"]:
                    self._find("EVENT_MODIFIED", "event content differs from what was sealed",
                               chain_index=idx, event_seq=event["seq"])
                self.check_mac(event)
        self.hashes[idx] = entry["entry_hash"]
        self.prev_hash = entry["entry_hash"]
        self.head = (idx, entry["entry_hash"])
        self.expected_index = idx + 1

    def check_checkpoint(self, cp: dict[str, Any]) -> None:
        idx = int(cp["chain_index"])
        trusted = self.trusted_keys.get(cp["kid"])
        if trusted is None or trusted != cp["public_key_b64"]:
            self._find("CHECKPOINT_UNTRUSTED_KEY", f"checkpoint at {idx} is signed by a key "
                       "that is not the pinned audit checkpoint key", chain_index=idx)
            return
        payload = checkpoint_payload(chain_index=idx, entry_hash_value=cp["entry_hash"],
                                     signed_at=cp["signed_at"], kid=cp["kid"])
        if not verify_checkpoint_signature(trusted, payload, cp["signature_b64"]):
            self._find("CHECKPOINT_SIGNATURE_INVALID", f"checkpoint at {idx} has an invalid "
                       "signature", chain_index=idx)
            return
        actual = self.hashes.get(idx)
        if actual is None:
            self._find("CHECKPOINT_MISMATCH", f"signed checkpoint names entry {idx}, which no "
                       "longer exists (chain truncated)", chain_index=idx)
            return
        if actual != cp["entry_hash"]:
            self._find("CHECKPOINT_MISMATCH", f"entry {idx} differs from the signed checkpoint "
                       "(chain rewritten)", chain_index=idx)
            return
        self.checkpoints_ok += 1
        self.last_checkpoint = max(self.last_checkpoint or -1, idx)

    def report(self, *, events_before_coverage: int, unsealed_within_grace: int) -> IntegrityReport:
        head_idx = self.head[0] if self.head else None
        if head_idx is None:
            self._find("GENESIS_MISSING", "the audit chain has no genesis entry")
        after = (head_idx - self.last_checkpoint) if (head_idx is not None and
                                                       self.last_checkpoint is not None) \
            else (head_idx or 0)
        return IntegrityReport(
            ok=not self.findings, entries_checked=self.expected_index, head_index=head_idx,
            head_hash=self.head[1] if self.head else None, covers_from_seq=self.covers_from_seq,
            events_before_coverage=events_before_coverage,
            unsealed_within_grace=unsealed_within_grace,
            checkpoints_verified=self.checkpoints_ok, last_checkpoint_index=self.last_checkpoint,
            entries_after_last_checkpoint=after, mac_checked=self.mac_key is not None,
            findings=self.findings)


def rows_to_entries(rows: Iterable[Any]) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        get = (lambda k, r=r: getattr(r, k)) if not isinstance(r, dict) else r.get
        out.append({"chain_index": get("chain_index"), "kind": get("kind"),
                    "event_id": get("event_id"), "event_seq": get("event_seq"),
                    "content_hash": get("content_hash"), "prev_hash": get("prev_hash"),
                    "entry_hash": get("entry_hash"), "detail": get("detail")})
    return out


def unsealed_grace_cutoff(now: datetime, grace_seconds: float) -> datetime:
    return now - timedelta(seconds=grace_seconds)
