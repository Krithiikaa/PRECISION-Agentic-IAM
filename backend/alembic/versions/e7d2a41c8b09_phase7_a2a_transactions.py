"""phase7 secure agent-to-agent transactions

Two new tables. Nothing existing is altered -- no ALTER TABLE appears in this
file at all -- so every prior phase's schema is untouched and this migration
cannot regress them.

`a2a_transactions` -- one signed instruction one agent sent another, and
everything that happened to it. The scope columns (sender, receiver, action,
resource, purpose, amount) are indexed lookup copies of what is inside the
SIGNED envelope; the signed copy in `envelope` is the one that decides, and
`binding_sha256` is what ties them together.

    UNIQUE (sender_did, transaction_id)
        THE EXACTLY-ONCE INVARIANT, and the reason a payment cannot be made
        twice. A constraint rather than a check in Python: twenty concurrent
        submissions of one instruction all reach the INSERT and exactly one
        wins it. COMPOSITE rather than global so one sender cannot squat on
        another sender's id namespace -- a global unique would let an
        attacker pre-register `txn-0001` and permanently deny it to whoever
        legitimately uses that id.

    UNIQUE (sender_did, nonce) WHERE signature_verified
        The second, independent replay ledger. PARTIAL for the reason
        `uq_control_plane_nonce` and `uq_ans_registration_nonce` are: only a
        signature-verified submission consumes a nonce, so an attacker cannot
        burn a legitimate sender's nonces by spamming failures.

    CHECK (... = abs(...))
        Money that can be negative is not money. A DOMAIN constraint on the
        value, never a risk threshold -- what a sum MEANS is decided by Rego
        against `data.agentic_iam.config.a2a`, and no threshold exists in this
        schema or anywhere in Python. Written with `abs()` rather than `>= 0`
        so the Phase 5.5 guard against amount thresholds leaking into the
        application does not have to be loosened for a check that is not one.

    CHECK ((amount_inr IS NULL) = (currency IS NULL))
        An amount without a unit is not an amount.

FOUR AMOUNT COLUMNS, and they are four on purpose:

    amount_inr            what the SENDER signed
    server_amount_inr     what the PIP read from the record
    authorized_amount_inr what the PDP decided on
    executed_amount_inr   what actually moved

The security property is that they AGREE. A single column could not express a
disagreement, and a disagreement is precisely the incident worth detecting.

`a2a_transaction_attempts` -- EVERY submission, accepted or not. Rejected
envelopes are recorded ONLY here and never in `a2a_transactions`, because that
table's unique constraint makes a transaction id scarce: if a forged
submission could write a row, it could burn a legitimate sender's id. Every
column there is named `claimed_*` because on a rejected submission those
values are assertions that failed verification, not facts.

PUBLIC MATERIAL ONLY. No private key anywhere. The `signature` column is
truncated to 256 characters by the application -- enough to correlate two
presentations of the same envelope, never enough to replay one. The full
signed envelope IS stored, deliberately: its security is its signature, not
its secrecy, exactly as a JIT grant's is.

Enums are `native_enum=False` (VARCHAR + CHECK), matching every other table in
this schema and avoiding fragile ALTER TYPE migrations.

Revision ID: e7d2a41c8b09
Revises: c9e4b81f2a37
Create Date: 2026-09-22 09:30:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = 'e7d2a41c8b09'
down_revision = 'c9e4b81f2a37'
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(JSONB(), "postgresql")

A2A_STATUS = sa.Enum(
    'RECEIVED', 'VERIFIED', 'PENDING_APPROVAL', 'AUTHORIZED', 'EXECUTING',
    'EXECUTED', 'DENIED', 'REJECTED', 'FAILED', 'EXPIRED',
    name='a2a_transaction_status', native_enum=False, length=32,
)


def upgrade() -> None:
    # --- the instruction --------------------------------------------------
    op.create_table(
        'a2a_transactions',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('transaction_id', sa.String(length=128), nullable=False),

        # the parties. Both from the SIGNED envelope; `submitted_by` is the
        # principal that authenticated, stored so an auditor confirms the
        # receiver binding rather than trusting it.
        sa.Column('sender_did', sa.String(length=255), nullable=False),
        sa.Column('receiver_did', sa.String(length=255), nullable=False),
        sa.Column('submitted_by', sa.String(length=255), nullable=False),

        sa.Column('protocol', sa.String(length=32), nullable=False),
        sa.Column('protocol_version', sa.String(length=16), nullable=False),

        # the binding, as indexed lookup copies of signed fields
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('resource_type', sa.String(length=64), nullable=False),
        sa.Column('resource_id', sa.String(length=128), nullable=True),
        sa.Column('purpose', sa.String(length=64), nullable=False),

        # money, four ways
        sa.Column('amount_inr', sa.BigInteger(), nullable=True),
        sa.Column('currency', sa.String(length=3), nullable=True),
        sa.Column('server_amount_inr', sa.BigInteger(), nullable=True),
        sa.Column('authorized_amount_inr', sa.BigInteger(), nullable=True),
        sa.Column('executed_amount_inr', sa.BigInteger(), nullable=True),
        sa.Column('amount_reconciled', sa.Boolean(), nullable=False,
                  server_default=sa.text('false')),

        sa.Column('payload_sha256', sa.String(length=64), nullable=False),
        sa.Column('binding_sha256', sa.String(length=64), nullable=False),

        # the signed artifact
        sa.Column('nonce', sa.String(length=128), nullable=False),
        sa.Column('domain', sa.String(length=128), nullable=False),
        sa.Column('key_id', sa.String(length=320), nullable=True),
        sa.Column('signature', sa.String(length=256), nullable=False),
        sa.Column('signature_verified', sa.Boolean(), nullable=False,
                  server_default=sa.text('false')),
        sa.Column('envelope', JSONType, nullable=False),
        sa.Column('response_envelope', JSONType, nullable=True),

        # time
        sa.Column('issued_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),

        # lifecycle
        sa.Column('status', A2A_STATUS, nullable=False),
        sa.Column('reason', sa.String(length=64), nullable=True),
        sa.Column('detail', sa.Text(), nullable=True),

        # what policy decided
        sa.Column('decision', sa.String(length=32), nullable=True),
        sa.Column('decision_reason', sa.String(length=64), nullable=True),
        sa.Column('policy_id', sa.String(length=128), nullable=True),
        sa.Column('policy_version', sa.String(length=32), nullable=True),
        sa.Column('authorization_request_id', sa.String(length=128), nullable=False),
        sa.Column('approval_id', sa.String(length=64), nullable=True),
        sa.Column('jit_grant_id', sa.String(length=64), nullable=True),
        sa.Column('required_approvals', sa.Integer(), nullable=True),

        # what happened
        sa.Column('execution_result', JSONType, nullable=True),
        sa.Column('result_sha256', sa.String(length=64), nullable=True),
        sa.Column('executing_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('denied_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expired_at', sa.DateTime(timezone=True), nullable=True),

        # correlation
        sa.Column('correlation_id', sa.String(length=128), nullable=True),
        # Phase 9 owns sessions. Present and NULL so one can be bound later
        # without a migration, matching approval_requests and jit_grants.
        sa.Column('session_id', sa.String(length=128), nullable=True),
        sa.Column('latency_ms', sa.Float(), nullable=True),

        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),

        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('sender_did', 'transaction_id',
                            name='uq_a2a_transaction_sender_id'),
        sa.CheckConstraint('amount_inr IS NULL OR amount_inr = abs(amount_inr)',
                           name='ck_a2a_amount_non_negative'),
        sa.CheckConstraint(
            'server_amount_inr IS NULL OR server_amount_inr = abs(server_amount_inr)',
            name='ck_a2a_server_amount_non_negative'),
        sa.CheckConstraint(
            'executed_amount_inr IS NULL OR executed_amount_inr = abs(executed_amount_inr)',
            name='ck_a2a_executed_amount_non_negative'),
        sa.CheckConstraint('(amount_inr IS NULL) = (currency IS NULL)',
                           name='ck_a2a_amount_has_currency'),
    )
    op.create_index('ix_a2a_transactions_transaction_id', 'a2a_transactions',
                    ['transaction_id'])
    op.create_index('ix_a2a_transactions_status', 'a2a_transactions', ['status'])
    op.create_index('ix_a2a_transactions_expires_at', 'a2a_transactions',
                    ['expires_at'])
    op.create_index('ix_a2a_txn_receiver_ts', 'a2a_transactions',
                    ['receiver_did', 'received_at'])
    op.create_index('ix_a2a_txn_sender_ts', 'a2a_transactions',
                    ['sender_did', 'received_at'])
    op.create_index('ix_a2a_txn_status_expiry', 'a2a_transactions',
                    ['status', 'expires_at'])
    op.create_index('ix_a2a_txn_authz_request', 'a2a_transactions',
                    ['authorization_request_id'])
    op.create_index('ix_a2a_txn_approval', 'a2a_transactions', ['approval_id'])
    op.create_index('ix_a2a_txn_correlation', 'a2a_transactions', ['correlation_id'])
    # THE REPLAY LEDGER. Partial: only a signature-verified submission
    # consumes a nonce, so failures cannot burn a legitimate sender's.
    op.create_index('uq_a2a_transaction_nonce', 'a2a_transactions',
                    ['sender_did', 'nonce'], unique=True,
                    postgresql_where=sa.text('signature_verified'))

    # --- every submission, accepted or not --------------------------------
    op.create_table(
        'a2a_transaction_attempts',
        sa.Column('id', sa.Uuid(), nullable=False),
        # `claimed_*`: on a rejected submission these are assertions that
        # failed verification, not facts. The column names say so.
        sa.Column('claimed_transaction_id', sa.String(length=128), nullable=True),
        sa.Column('claimed_sender_did', sa.String(length=255), nullable=True),
        sa.Column('claimed_receiver_did', sa.String(length=255), nullable=True),
        # The one attributable field: who actually authenticated.
        sa.Column('submitted_by', sa.String(length=255), nullable=False),
        sa.Column('payload_sha256', sa.String(length=64), nullable=True),
        sa.Column('nonce', sa.String(length=128), nullable=True),
        sa.Column('key_id', sa.String(length=320), nullable=True),
        sa.Column('signature', sa.String(length=256), nullable=True),
        sa.Column('accepted', sa.Boolean(), nullable=False),
        sa.Column('stage', sa.String(length=32), nullable=False),
        sa.Column('reason', sa.String(length=64), nullable=False),
        sa.Column('detail', sa.Text(), nullable=True),
        sa.Column('source_ip', sa.String(length=64), nullable=True),
        sa.Column('latency_ms', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_a2a_attempts_sender_ts', 'a2a_transaction_attempts',
                    ['claimed_sender_did', 'created_at'])
    op.create_index('ix_a2a_attempts_accepted_ts', 'a2a_transaction_attempts',
                    ['accepted', 'created_at'])
    op.create_index('ix_a2a_attempts_submitted_by', 'a2a_transaction_attempts',
                    ['submitted_by', 'created_at'])
    op.create_index('ix_a2a_attempts_txn', 'a2a_transaction_attempts',
                    ['claimed_transaction_id'])


def downgrade() -> None:
    # Dropped in dependency order. There is no foreign key between the two
    # tables -- deliberately: an attempt records what was CLAIMED, and tying
    # it to a transaction row would mean a rejected submission could only be
    # recorded if the thing it claimed to be existed.
    op.drop_index('ix_a2a_attempts_txn', table_name='a2a_transaction_attempts')
    op.drop_index('ix_a2a_attempts_submitted_by',
                  table_name='a2a_transaction_attempts')
    op.drop_index('ix_a2a_attempts_accepted_ts',
                  table_name='a2a_transaction_attempts')
    op.drop_index('ix_a2a_attempts_sender_ts', table_name='a2a_transaction_attempts')
    op.drop_table('a2a_transaction_attempts')

    op.drop_index('uq_a2a_transaction_nonce', table_name='a2a_transactions')
    op.drop_index('ix_a2a_txn_correlation', table_name='a2a_transactions')
    op.drop_index('ix_a2a_txn_approval', table_name='a2a_transactions')
    op.drop_index('ix_a2a_txn_authz_request', table_name='a2a_transactions')
    op.drop_index('ix_a2a_txn_status_expiry', table_name='a2a_transactions')
    op.drop_index('ix_a2a_txn_sender_ts', table_name='a2a_transactions')
    op.drop_index('ix_a2a_txn_receiver_ts', table_name='a2a_transactions')
    op.drop_index('ix_a2a_transactions_expires_at', table_name='a2a_transactions')
    op.drop_index('ix_a2a_transactions_status', table_name='a2a_transactions')
    op.drop_index('ix_a2a_transactions_transaction_id', table_name='a2a_transactions')
    op.drop_table('a2a_transactions')
