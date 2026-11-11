"""Phase 12: tamper-evident audit trail.

  * audit_events.integrity_mac   write-time HMAC (nullable: legacy rows have none)
  * audit_chain                  append-only hash chain, entry 0 = GENESIS
  * audit_checkpoints            Ed25519-signed chain heads
  * audit_append_only()          trigger refusing UPDATE/DELETE on all three

THE BACKFILL DECISION. Existing rows (about 620k on the development host)
were written with no integrity protection. Sealing them now would only attest
to their state TODAY while looking like protection they never had. So the
genesis entry records `covers_from_seq` = the first seq written after this
migration, and the verifier reports earlier rows as "before coverage" -- a
count, never a pass.

Revision ID: d12a0c4e7b51
Revises: 9fdec14fe3da
"""
from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

from app.audit import integrity as ig

revision = "d12a0c4e7b51"
down_revision = "9fdec14fe3da"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("integrity_mac", sa.String(length=64), nullable=True))
    op.create_table(
        "audit_chain",
        sa.Column("chain_index", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=True),
        sa.Column("event_seq", sa.BigInteger(), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("sealed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
                  nullable=False),
        sa.Column("detail", sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql"),
                  nullable=False),
        sa.PrimaryKeyConstraint("chain_index"),
        sa.UniqueConstraint("event_id"),
        sa.UniqueConstraint("event_seq"),
        sa.UniqueConstraint("entry_hash"),
    )
    op.create_table(
        "audit_checkpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("chain_index", sa.BigInteger(), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kid", sa.String(length=320), nullable=False),
        sa.Column("public_key_b64", sa.String(length=128), nullable=False),
        sa.Column("signature_b64", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_checkpoints_chain_index", "audit_checkpoints", ["chain_index"])

    bind = op.get_bind()
    max_seq, legacy = bind.execute(sa.text(
        "SELECT coalesce(max(seq), 0), count(*) FROM audit_events")).one()
    detail = {"covers_from_seq": int(max_seq) + 1, "legacy_events_not_covered": int(legacy),
              "created": "by migration d12a0c4e7b51",
              "created_at": datetime.now(timezone.utc).isoformat()}
    content = ig.genesis_content_hash(detail)
    entry = ig.entry_hash(chain_index=0, kind="GENESIS", event_seq=None, event_id=None,
                          content_hash=content, prev_hash=ig.GENESIS_PREV)
    chain = sa.table("audit_chain", sa.column("chain_index", sa.BigInteger),
                     sa.column("kind", sa.String), sa.column("content_hash", sa.String),
                     sa.column("prev_hash", sa.String), sa.column("entry_hash", sa.String),
                     sa.column("detail", sa.JSON))
    op.bulk_insert(chain, [{"chain_index": 0, "kind": "GENESIS", "content_hash": content,
                            "prev_hash": ig.GENESIS_PREV, "entry_hash": entry,
                            "detail": detail}])

    op.execute(ig.APPEND_ONLY_FUNCTION_DDL)
    for table in ig.APPEND_ONLY_TABLES:
        op.execute(ig.append_only_trigger_ddl(table))


def downgrade() -> None:
    for table in ig.APPEND_ONLY_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {table}_append_only ON {table}")
    op.execute("DROP FUNCTION IF EXISTS audit_append_only()")
    op.drop_index("ix_audit_checkpoints_chain_index", table_name="audit_checkpoints")
    op.drop_table("audit_checkpoints")
    op.drop_table("audit_chain")
    op.drop_column("audit_events", "integrity_mac")
