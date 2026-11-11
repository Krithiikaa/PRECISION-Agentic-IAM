#!/usr/bin/env python3
"""Independently verify the PRECISION audit trail (Phase 12).

Runs OUTSIDE the IAM API, against the database, in a READ ONLY transaction.
It trusts nothing the database says about keys: the checkpoint public key is
PINNED on the command line (from an earlier `GET /api/v1/audit/integrity/
checkpoints`, recorded out of band). It can also check a checkpoint you kept
yourself, which is the only way to detect truncation of the chain's tail
together with every checkpoint after it.

    python3 scripts/verify_audit_chain.py --public-key <b64> \
        [--expect-checkpoint 1234:<entry_hash>] [--check-macs] [--json]

--check-macs needs KEYSTORE_MASTER_KEY in the environment (the MAC key is
derived from it). Without it, MACs are reported as NOT CHECKED, never as
passed.

Exit status: 0 verified, 1 integrity violation, 2 usage or connection error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.audit import integrity as ig  # noqa: E402  (pure module: no app state)

DEFAULT_KID = "did:poc:service:audit-integrity#checkpoint-1"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", ""))
    parser.add_argument("--public-key", required=True,
                        help="pinned base64 Ed25519 checkpoint public key")
    parser.add_argument("--kid", default=os.environ.get("AUDIT_CHECKPOINT_KID", DEFAULT_KID))
    parser.add_argument("--expect-checkpoint", action="append", default=[],
                        metavar="INDEX:ENTRY_HASH",
                        help="a checkpoint retained outside the database")
    parser.add_argument("--check-macs", action="store_true")
    parser.add_argument("--grace-seconds", type=float, default=120.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.database_url:
        print("DATABASE_URL is required", file=sys.stderr)
        return 2
    mac_key = None
    if args.check_macs:
        master = os.environ.get("KEYSTORE_MASTER_KEY")
        if not master:
            print("--check-macs needs KEYSTORE_MASTER_KEY", file=sys.stderr)
            return 2
        mac_key = ig.derive_mac_key(master)

    import psycopg
    from psycopg.rows import dict_row

    dsn = args.database_url.replace("postgresql+psycopg://", "postgresql://") \
                           .replace("postgresql+asyncpg://", "postgresql://")
    verifier = ig.ChainVerifier(trusted_keys={args.kid: args.public_key}, mac_key=mac_key)
    try:
        conn = psycopg.connect(dsn, row_factory=dict_row)
    except psycopg.OperationalError as exc:
        print(f"cannot connect: {exc}", file=sys.stderr)
        return 2
    with conn:
        conn.execute("SET TRANSACTION READ ONLY")
        last = -1
        while True:
            rows = conn.execute(
                "SELECT c.chain_index, c.kind, c.event_id, c.event_seq, c.content_hash, "
                "c.prev_hash, c.entry_hash, c.detail, e.id, e.seq, e.occurred_at, e.event_type, "
                "e.agent_did, e.session_id, e.request_id, e.resource, e.action, e.decision, "
                "e.reason, e.event_metadata, e.integrity_mac "
                "FROM audit_chain c LEFT JOIN audit_events e ON e.id = c.event_id "
                "WHERE c.chain_index > %s ORDER BY c.chain_index LIMIT 5000", (last,)).fetchall()
            if not rows:
                break
            for r in rows:
                event = ig.event_dict(r) if r["id"] is not None else None
                verifier.feed(ig.rows_to_entries([r])[0], event)
                last = r["chain_index"]
        for cp in conn.execute("SELECT chain_index, entry_hash, signed_at, kid, public_key_b64, "
                               "signature_b64 FROM audit_checkpoints ORDER BY chain_index"):
            verifier.check_checkpoint(cp)
        for spec in args.expect_checkpoint:
            index, _, expected = spec.partition(":")
            actual = verifier.hashes.get(int(index))
            if actual != expected:
                verifier.findings.append(ig.Finding(
                    "EXTERNAL_CHECKPOINT_MISMATCH",
                    f"externally retained checkpoint {index} does not match the chain "
                    f"({'missing' if actual is None else 'different hash'})",
                    chain_index=int(index)))
        before = within = 0
        if verifier.covers_from_seq is not None:
            before = conn.execute("SELECT count(*) AS n FROM audit_events WHERE seq < %s",
                                  (verifier.covers_from_seq,)).fetchone()["n"]
            now = datetime.now(timezone.utc)
            for r in conn.execute(
                    "SELECT * FROM audit_events e WHERE e.seq >= %s AND NOT EXISTS "
                    "(SELECT 1 FROM audit_chain c WHERE c.event_id = e.id)",
                    (verifier.covers_from_seq,)):
                ev = ig.event_dict(r)
                verifier.check_mac(ev)
                if (now - r["occurred_at"]).total_seconds() > args.grace_seconds:
                    verifier.findings.append(ig.Finding(
                        "UNSEALED_STALE", "event not in the chain after the grace period",
                        event_seq=r["seq"]))
                else:
                    within += 1
    report = verifier.report(events_before_coverage=before, unsealed_within_grace=within)
    body = report.to_dict()
    if args.json:
        print(json.dumps(body, indent=2, default=str))
    else:
        print(f"status:                 {body['status']}")
        print(f"entries checked:        {body['entries_checked']} (head {body['head_index']})")
        print(f"head hash:              {body['head_hash']}")
        print(f"checkpoints verified:   {body['checkpoints_verified']} "
              f"(last at {body['last_checkpoint_index']}, "
              f"{body['entries_after_last_checkpoint']} entries after it)")
        print(f"MACs:                   {'checked' if body['mac_checked'] else 'NOT CHECKED'}")
        print(f"before coverage:        {body['events_before_coverage']} legacy event(s), "
              f"not verified")
        print(f"unsealed (in grace):    {body['unsealed_within_grace']}")
        for f in body["findings"]:
            print(f"  FINDING {f['kind']}: {f['detail']} "
                  f"(entry {f['chain_index']}, seq {f['event_seq']})")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
