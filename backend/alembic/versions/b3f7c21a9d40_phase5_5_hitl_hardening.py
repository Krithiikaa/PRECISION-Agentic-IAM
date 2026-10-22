"""phase5.5 hitl security hardening

Three changes, each closing a gap Phase 5 left open.

`approval_requests.required_approvals` -- how many DISTINCT humans this request
needs. Set from the POLICY decision that escalated, never from a caller. It is
recorded so the queue and the audit trail can say "1 of 2"; the number that
actually gates the action is recomputed live by Rego from the amount, so
lowering this column cannot let anything through.

`approval_signoffs` -- one row per human decision. THE TWO-PERSON RULE IS THE
UNIQUE CONSTRAINT on (approval_id, approver_issuer, approver_subject), not a
comparison in Python: two requests from the same person arriving together would
both find no existing row and both proceed, and the second approval would then
be satisfied by the first person. Only one can win an INSERT. Identity is
(issuer, subject) because a subject id is only unique within its issuer.

`approval_authority_keys` -- the signing key register. Exactly one ACTIVE key
signs; RETIRED keys keep verifying the artifacts they signed while active, so
rotation does not invalidate history; REVOKED keys verify nothing, which is what
makes revocation different from rotation. PUBLIC MATERIAL ONLY -- the private
key stays in the KeyStore and is referenced by `keystore_ref`, never stored.

Backfill: existing rows get required_approvals = 1, which is exactly what they
were decided under. The approval authority's existing key is registered as
generation 1 at the next startup by `ApprovalAuthority.ensure()`, rather than
here, because only the running application knows the KeyStore reference.

Revision ID: b3f7c21a9d40
Revises: f01a7fd3e257
Create Date: 2026-08-30 21:10:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'b3f7c21a9d40'
down_revision = 'f01a7fd3e257'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- how many humans -------------------------------------------------
    op.add_column(
        'approval_requests',
        sa.Column('required_approvals', sa.Integer(), nullable=False,
                  server_default='1'),
    )
    # --- what exactly was bound ------------------------------------------
    # The binding as a document, including the material attributes (amount,
    # currency, officer of record) the digest covers. Recorded so the signer
    # binds exactly what the request bound, and so an auditor can read what a
    # person actually agreed to without reconstructing it from a resource
    # record that may since have moved -- which is the change the binding
    # exists to detect.
    #
    # Existing rows get '{}', and the service falls back to the flat columns
    # for them, which is precisely what they were bound to.
    op.add_column(
        'approval_requests',
        sa.Column('binding',
                  sa.JSON().with_variant(
                      postgresql.JSONB(astext_type=sa.Text()), 'postgresql'),
                  nullable=False, server_default='{}'),
    )

    # --- one human, one sign-off -----------------------------------------
    op.create_table(
        'approval_signoffs',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('approval_id', sa.String(length=64), nullable=False),
        sa.Column('sequence', sa.Integer(), nullable=False),
        sa.Column('approver_subject', sa.String(length=255), nullable=False),
        sa.Column('approver_issuer', sa.String(length=512), nullable=False),
        sa.Column('approver_username', sa.String(length=255), nullable=True),
        sa.Column('approver_provider', sa.String(length=64), nullable=True),
        sa.Column('approver_roles',
                  sa.JSON().with_variant(
                      postgresql.JSONB(astext_type=sa.Text()), 'postgresql'),
                  nullable=False),
        sa.Column('decision',
                  sa.Enum('APPROVED', 'REJECTED', name='approval_decision',
                          native_enum=False, length=32),
                  nullable=False),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('decision_latency_ms', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['approval_id'], ['approval_requests.approval_id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        # The two-person rule.
        sa.UniqueConstraint('approval_id', 'approver_issuer', 'approver_subject',
                            name='uq_approval_signoff_person'),
        sa.UniqueConstraint('approval_id', 'sequence',
                            name='uq_approval_signoff_sequence'),
    )
    op.create_index('ix_approval_signoffs_approval', 'approval_signoffs',
                    ['approval_id'], unique=False)

    # --- the signing key register ----------------------------------------
    op.create_table(
        'approval_authority_keys',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('did', sa.String(length=255), nullable=False),
        sa.Column('kid', sa.String(length=255), nullable=False),
        sa.Column('generation', sa.Integer(), nullable=False),
        sa.Column('algorithm', sa.String(length=32), nullable=False),
        sa.Column('public_key_multibase', sa.String(length=128), nullable=False),
        sa.Column('public_key_b64', sa.String(length=128), nullable=False),
        sa.Column('keystore_backend', sa.String(length=64), nullable=False),
        # A REFERENCE to where the private key lives. Never the key itself.
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
        sa.UniqueConstraint('did', 'generation', name='uq_authority_key_generation'),
    )
    op.create_index('ix_approval_authority_keys_kid', 'approval_authority_keys',
                    ['kid'], unique=True)
    op.create_index('ix_approval_authority_keys_did', 'approval_authority_keys',
                    ['did'], unique=False)
    op.create_index('ix_authority_keys_did_status', 'approval_authority_keys',
                    ['did', 'status'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_authority_keys_did_status', table_name='approval_authority_keys')
    op.drop_index('ix_approval_authority_keys_did', table_name='approval_authority_keys')
    op.drop_index('ix_approval_authority_keys_kid', table_name='approval_authority_keys')
    op.drop_table('approval_authority_keys')
    op.drop_index('ix_approval_signoffs_approval', table_name='approval_signoffs')
    op.drop_table('approval_signoffs')
    op.drop_column('approval_requests', 'binding')
    op.drop_column('approval_requests', 'required_approvals')
