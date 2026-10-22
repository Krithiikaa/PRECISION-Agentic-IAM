"""phase6 just-in-time temporary access

Three new tables. Nothing existing is altered, so every prior phase's schema is
untouched and this migration cannot regress them.

`jit_grants` -- one time-bounded, use-bounded mandate. The scope columns
(agent_did, action, resource_type, resource_ids, purpose, constraints) are
indexed lookup copies of what is inside the SIGNED artifact; the signed copy is
the one that decides, and `binding_sha256` is what ties them together. Two
CHECK constraints carry invariants that must hold even if every caller is
wrong: `uses <= max_uses` (a budget that can be overspent is not a budget) and
`max_uses >= 1`.

`jit_grant_uses` -- one row per spend. `UNIQUE (grant_id, sequence)` makes the
budget countable; `UNIQUE (grant_id, request_id)` makes a retried request
IDEMPOTENT, so a client that did not see a response cannot burn a second use
out of a budget a human authorised.

`jit_authority_keys` -- the JIT signing key register. Deliberately a SEPARATE
key from the approval authority: attesting that a human decided something and
minting temporary machine authority are different powers, and sharing a key
would mean compromising it yields both. The shape mirrors
`approval_authority_keys` on purpose; generalising that table into a shared
register is cleaner and also edits a table three green gates depend on, so the
duplication is the lower-risk move and is recorded rather than hidden.

PUBLIC KEY MATERIAL ONLY, in every table here. Private keys stay in the
KeyStore and are referenced by `keystore_ref`. The JIT authority's first key is
registered at the next startup by `JITAuthority.ensure()` rather than here,
because only the running application knows its KeyStore reference.

Enums are `native_enum=False` (VARCHAR + CHECK), matching every other table in
this schema and avoiding fragile ALTER TYPE migrations.

Revision ID: c9e4b81f2a37
Revises: b3f7c21a9d40
Create Date: 2026-09-18 10:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = 'c9e4b81f2a37'
down_revision = 'b3f7c21a9d40'
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    # --- the mandate ------------------------------------------------------
    op.create_table(
        'jit_grants',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('grant_id', sa.String(length=64), nullable=False),

        # scope -- the binding, as indexed columns
        sa.Column('agent_did', sa.String(length=255), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('resource_type', sa.String(length=64), nullable=False),
        sa.Column('resource_ids', JSONType, nullable=False),
        sa.Column('purpose', sa.String(length=64), nullable=False),
        sa.Column('constraints', JSONType, nullable=False),
        sa.Column('binding_sha256', sa.String(length=64), nullable=False),
        sa.Column('binding', JSONType, nullable=False),

        # why it exists
        sa.Column('justification', JSONType, nullable=False),
        sa.Column('presentation', JSONType, nullable=False),

        # bounds
        sa.Column('issued_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('max_uses', sa.Integer(), nullable=False),
        sa.Column('uses', sa.Integer(), nullable=False, server_default='0'),

        # lifecycle
        sa.Column('status',
                  sa.Enum('ACTIVE', 'EXPIRED', 'EXHAUSTED', 'REVOKED',
                          name='jit_grant_status', native_enum=False, length=32),
                  nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_by', sa.String(length=255), nullable=True),
        sa.Column('revocation_reason', sa.Text(), nullable=True),
        sa.Column('exhausted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expired_at', sa.DateTime(timezone=True), nullable=True),

        # correlation
        sa.Column('issuing_request_id', sa.String(length=128), nullable=False),
        sa.Column('approval_id', sa.String(length=64), nullable=True),

        # the signed artifact
        sa.Column('nonce', sa.String(length=128), nullable=False),
        sa.Column('domain', sa.String(length=128), nullable=False),
        sa.Column('artifact', JSONType, nullable=True),
        sa.Column('signed_by_kid', sa.String(length=255), nullable=True),
        sa.Column('issuer_did', sa.String(length=255), nullable=False),

        # Phase 9 owns sessions. Present and NULL so one can be bound later
        # without a migration, matching approval_requests.session_id.
        sa.Column('session_id', sa.String(length=128), nullable=True),

        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),

        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('grant_id'),
        sa.UniqueConstraint('nonce', name='uq_jit_grant_nonce'),
        sa.CheckConstraint('uses <= max_uses', name='ck_jit_uses_within_max'),
        sa.CheckConstraint('max_uses >= 1', name='ck_jit_max_uses_positive'),
    )
    op.create_index('ix_jit_grants_grant_id', 'jit_grants', ['grant_id'], unique=True)
    op.create_index('ix_jit_grants_status', 'jit_grants', ['status'])
    op.create_index('ix_jit_grants_expires_at', 'jit_grants', ['expires_at'])
    op.create_index('ix_jit_grants_agent_status', 'jit_grants', ['agent_did', 'status'])
    op.create_index('ix_jit_grants_status_expiry', 'jit_grants', ['status', 'expires_at'])
    op.create_index('ix_jit_grants_request', 'jit_grants', ['issuing_request_id'])
    op.create_index('ix_jit_grants_approval', 'jit_grants', ['approval_id'])

    # --- what the budget was spent on -------------------------------------
    op.create_table(
        'jit_grant_uses',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('grant_id', sa.String(length=64), nullable=False),
        sa.Column('sequence', sa.Integer(), nullable=False),
        sa.Column('request_id', sa.String(length=128), nullable=False),
        sa.Column('resource_id', sa.String(length=128), nullable=True),
        sa.Column('action', sa.String(length=64), nullable=True),
        sa.Column('decision', sa.String(length=32), nullable=True),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['grant_id'], ['jit_grants.grant_id'],
                                ondelete='CASCADE'),
        sa.UniqueConstraint('grant_id', 'sequence', name='uq_jit_use_sequence'),
        # Idempotency, not tidiness: a retry of the same request must not burn
        # a second use.
        sa.UniqueConstraint('grant_id', 'request_id', name='uq_jit_use_request'),
    )
    op.create_index('ix_jit_grant_uses_grant_id', 'jit_grant_uses', ['grant_id'])
    op.create_index('ix_jit_uses_grant', 'jit_grant_uses', ['grant_id', 'used_at'])

    # --- the signing key register -----------------------------------------
    op.create_table(
        'jit_authority_keys',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('did', sa.String(length=255), nullable=False),
        sa.Column('kid', sa.String(length=255), nullable=False),
        sa.Column('generation', sa.Integer(), nullable=False),
        sa.Column('algorithm', sa.String(length=32), nullable=False),
        sa.Column('public_key_multibase', sa.String(length=128), nullable=False),
        sa.Column('public_key_b64', sa.String(length=128), nullable=False),
        sa.Column('keystore_backend', sa.String(length=64), nullable=False),
        sa.Column('keystore_ref', sa.String(length=512), nullable=False),
        sa.Column('status',
                  sa.Enum('ACTIVE', 'RETIRED', 'REVOKED',
                          name='signing_key_status', native_enum=False, length=32),
                  nullable=False),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=False),
        sa.Column('retired_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('kid'),
        sa.UniqueConstraint('did', 'generation',
                            name='uq_jit_authority_key_generation'),
    )
    op.create_index('ix_jit_authority_keys_did', 'jit_authority_keys', ['did'])
    op.create_index('ix_jit_authority_keys_kid', 'jit_authority_keys', ['kid'],
                    unique=True)
    op.create_index('ix_jit_authority_keys_status', 'jit_authority_keys', ['status'])
    op.create_index('ix_jit_authority_keys_did_status', 'jit_authority_keys',
                    ['did', 'status'])


def downgrade() -> None:
    # Dropped in dependency order: the uses reference the grants.
    op.drop_index('ix_jit_authority_keys_did_status', table_name='jit_authority_keys')
    op.drop_index('ix_jit_authority_keys_status', table_name='jit_authority_keys')
    op.drop_index('ix_jit_authority_keys_kid', table_name='jit_authority_keys')
    op.drop_index('ix_jit_authority_keys_did', table_name='jit_authority_keys')
    op.drop_table('jit_authority_keys')

    op.drop_index('ix_jit_uses_grant', table_name='jit_grant_uses')
    op.drop_index('ix_jit_grant_uses_grant_id', table_name='jit_grant_uses')
    op.drop_table('jit_grant_uses')

    op.drop_index('ix_jit_grants_approval', table_name='jit_grants')
    op.drop_index('ix_jit_grants_request', table_name='jit_grants')
    op.drop_index('ix_jit_grants_status_expiry', table_name='jit_grants')
    op.drop_index('ix_jit_grants_agent_status', table_name='jit_grants')
    op.drop_index('ix_jit_grants_expires_at', table_name='jit_grants')
    op.drop_index('ix_jit_grants_status', table_name='jit_grants')
    op.drop_index('ix_jit_grants_grant_id', table_name='jit_grants')
    op.drop_table('jit_grants')
