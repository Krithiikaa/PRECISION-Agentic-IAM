"""phase10 presentation challenge ledger

One new table. Nothing existing is altered -- no ALTER TABLE appears in this
file -- so every prior phase's schema is untouched and this migration cannot
regress them.

`presentation_challenges` closes a gap this codebase has documented since
Phase 2 and that was still open at the end of Phase 9: the presentation
`challenge` was compared for equality but never recorded, so a captured
presentation could be replayed against any verifier that reused one.

    UNIQUE (challenge)
        THE CONTROL. A nonce is spendable once, and the constraint is what
        makes that true rather than a comment claiming it. Two concurrent
        presentations of the same challenge both reach the conditional
        `UPDATE ... WHERE consumed_at IS NULL`, and exactly one wins.

    consumed_at NULL = unspent
        Deliberately a nullable timestamp rather than a boolean: an auditor
        asking "when was this spent, and by whom?" gets an answer, and a
        boolean would have to be joined against the audit trail to say the
        same thing.

    domain
        The audience a challenge was issued for. `domain` is already inside
        the SIGNED presentation; recording it here means the LEDGER enforces
        the binding too, so a verifier that forgot to pass
        `expected_domain` is still protected against a challenge minted for
        somebody else.

WHAT IS NOT STORED: the presentation, any credential, any key material. A
challenge is a public single-use nonce -- worthless to whoever reads it,
which is exactly why the endpoint that hands them out can stay open.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = 'b8c2e91a4d73'
down_revision = 'a4f19c7e5b22'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'presentation_challenges',
        sa.Column('id', sa.Uuid(), nullable=False),

        # The nonce. UNIQUE: see the module docstring.
        sa.Column('challenge', sa.String(length=128), nullable=False),
        sa.Column('domain', sa.String(length=128), nullable=True),

        sa.Column('issued_at', sa.DateTime(timezone=True), nullable=False),
        # Freshness against the SERVER clock. A challenge with no expiry
        # would be a permanent one-use token.
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),

        # NULL means unspent. The atomic claim keys on exactly this.
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('consumed_by', sa.String(length=255), nullable=True),
        sa.Column('presentation_id', sa.String(length=128), nullable=True),

        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),

        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('challenge', name='uq_presentation_challenge'),
    )
    op.create_index('ix_presentation_challenges_challenge',
                    'presentation_challenges', ['challenge'])
    op.create_index('ix_presentation_challenges_domain',
                    'presentation_challenges', ['domain'])
    # Supports the sweep, which deletes spent and expired rows.
    op.create_index('ix_presentation_challenges_unspent',
                    'presentation_challenges', ['expires_at', 'consumed_at'])


def downgrade() -> None:
    op.drop_index('ix_presentation_challenges_unspent',
                  table_name='presentation_challenges')
    op.drop_index('ix_presentation_challenges_domain',
                  table_name='presentation_challenges')
    op.drop_index('ix_presentation_challenges_challenge',
                  table_name='presentation_challenges')
    op.drop_table('presentation_challenges')
