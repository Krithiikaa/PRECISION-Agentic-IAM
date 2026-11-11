"""phase8 mcp security

Two new tables. Nothing existing is altered -- no ALTER TABLE appears in this
file at all -- so every prior phase's schema is untouched and this migration
cannot regress them.

`mcp_sessions` -- one MCP session, and the agent it belongs to.

    agent_did NOT NULL
        THE BINDING, expressed as a schema constraint rather than a
        convention. An MCP session id travels in a header on every request
        and is therefore a bearer value; if a session could exist without an
        owner, presenting a stolen id would be presenting an identity. The
        column is NOT NULL so an unbound session is not representable, and
        no code path in the service updates it after creation.

`mcp_invocations` -- one tools/call, and everything that happened to it.

    UNIQUE (session_id, request_id)
        THE EXACTLY-ONCE INVARIANT. A constraint rather than a check in
        Python: concurrent submissions of one call all reach the INSERT and
        exactly one wins it. COMPOSITE rather than global because the
        JSON-RPC id is the CLIENT'S identifier and is only required to be
        unique within its own session -- a global unique would let one agent
        squat on another's id namespace, exactly as Phase 7 reasoned about
        transaction ids.

THREE ARGUMENT COLUMNS, and they are three on purpose:

    claimed_arguments     what the CLIENT sent
    authorized_arguments  what the PDP decided on
    executed_arguments    what the tool actually received

`arguments_reconciled` records whether the last two agreed. Phase 7 keeps
four amounts for the same reason: a system that retains only the final value
cannot demonstrate that the value executed was the value authorized.

WHAT IS DELIBERATELY NOT IN THIS SCHEMA: any column for an access token, a
bearer credential or a client assertion. `token_jti` is the token's
IDENTIFIER, which lets a session be correlated with and revoked alongside the
credential that opened it, and which is useless to anyone who captures it.

NO THRESHOLD, LIMIT OR RISK NUMBER APPEARS HERE. Which actions may be carried
over MCP is policy configuration (`policies/data/mcp_policy.json`), read by
Rego. The schema records what happened; it never decides what may.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = 'a4f19c7e5b22'
down_revision = 'e7d2a41c8b09'
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(JSONB(), "postgresql")

# VARCHAR + CHECK rather than a native PostgreSQL ENUM, matching every other
# table in this schema. Native enums require ALTER TYPE to extend, which is
# a fragile migration; a CHECK constraint is edited like any other.
MCP_SESSION_STATUS = sa.Enum(
    'ACTIVE', 'TERMINATED', 'EXPIRED', 'REVOKED',
    name='mcp_session_status', native_enum=False, length=32,
)
MCP_INVOCATION_STATUS = sa.Enum(
    'RECEIVED', 'PENDING_APPROVAL', 'EXECUTED', 'DENIED', 'REJECTED', 'FAILED',
    name='mcp_invocation_status', native_enum=False, length=32,
)


def upgrade() -> None:
    op.create_table(
        'mcp_sessions',
        sa.Column('id', sa.Uuid(), nullable=False),

        # The value carried in the `Mcp-Session-Id` header. UNIQUE because it
        # is the lookup key, and the transport resolves a session by it on
        # every request.
        sa.Column('session_id', sa.String(length=128), nullable=False),

        # THE BINDING. See the module docstring.
        sa.Column('agent_did', sa.String(length=255), nullable=False),

        # The revision AGREED at initialize, not the one requested. A later
        # request declaring a different one is refused rather than
        # re-negotiated.
        sa.Column('protocol_version', sa.String(length=32), nullable=False),

        sa.Column('client_name', sa.String(length=128), nullable=True),
        sa.Column('client_version', sa.String(length=64), nullable=True),
        sa.Column('client_capabilities', JSONType, nullable=False,
                  server_default=sa.text("'{}'")),

        # The token's IDENTIFIER, never the token.
        sa.Column('token_jti', sa.String(length=128), nullable=True),
        sa.Column('token_expires_at', sa.DateTime(timezone=True), nullable=True),

        sa.Column('status', MCP_SESSION_STATUS, nullable=False,
                  server_default=sa.text("'ACTIVE'")),
        # Set by notifications/initialized. Until then the handshake is
        # incomplete and the spec restricts what may be sent, so the state is
        # tracked rather than assumed.
        sa.Column('initialized', sa.Boolean(), nullable=False,
                  server_default=sa.text('false')),

        sa.Column('origin', sa.String(length=512), nullable=True),
        sa.Column('source_ip', sa.String(length=64), nullable=True),

        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('terminated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('termination_reason', sa.String(length=64), nullable=True),

        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),

        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_id', name='uq_mcp_session_id'),
    )
    op.create_index('ix_mcp_sessions_session_id', 'mcp_sessions', ['session_id'])
    op.create_index('ix_mcp_sessions_agent_did', 'mcp_sessions', ['agent_did'])
    op.create_index('ix_mcp_sessions_status', 'mcp_sessions', ['status'])
    op.create_index('ix_mcp_sessions_token_jti', 'mcp_sessions', ['token_jti'])
    op.create_index('ix_mcp_sessions_agent_status', 'mcp_sessions',
                    ['agent_did', 'status'])

    op.create_table(
        'mcp_invocations',
        sa.Column('id', sa.Uuid(), nullable=False),

        sa.Column('session_pk', sa.Uuid(), nullable=False),
        # Denormalised from the session so the ledger reads, and deduplicates,
        # without a join.
        sa.Column('session_id', sa.String(length=128), nullable=False),
        sa.Column('agent_did', sa.String(length=255), nullable=False),
        sa.Column('request_id', sa.String(length=128), nullable=False),

        # `tool_name` is what the CLIENT named; `action` and `resource_type`
        # are what the SERVER's registry declares for that tool. Separate
        # columns on purpose -- the authorization request is built from the
        # tool's declared action and resource, never from anything the client
        # said about them, and an auditor must be able to see both.
        sa.Column('tool_name', sa.String(length=128), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=True),
        sa.Column('resource_type', sa.String(length=64), nullable=True),
        sa.Column('resource_id', sa.String(length=128), nullable=True),

        # CLAIMED, and named that way: honoured only where it matches a
        # purpose attested by a credential the Phase 2 verifier accepted.
        sa.Column('claimed_purpose', sa.String(length=64), nullable=True),

        # arguments, three ways
        sa.Column('claimed_arguments', JSONType, nullable=False,
                  server_default=sa.text("'{}'")),
        sa.Column('authorized_arguments', JSONType, nullable=True),
        sa.Column('executed_arguments', JSONType, nullable=True),
        sa.Column('arguments_reconciled', sa.Boolean(), nullable=False,
                  server_default=sa.text('false')),

        sa.Column('status', MCP_INVOCATION_STATUS, nullable=False,
                  server_default=sa.text("'RECEIVED'")),
        sa.Column('reason', sa.String(length=64), nullable=True),
        sa.Column('detail', sa.Text(), nullable=True),

        # what policy decided
        sa.Column('decision', sa.String(length=32), nullable=True),
        sa.Column('decision_reason', sa.String(length=64), nullable=True),
        sa.Column('policy_id', sa.String(length=64), nullable=True),
        sa.Column('policy_version', sa.String(length=32), nullable=True),

        sa.Column('authorization_request_id', sa.String(length=128), nullable=True),
        sa.Column('approval_id', sa.String(length=128), nullable=True),
        sa.Column('jit_grant_id', sa.String(length=128), nullable=True),
        sa.Column('required_approvals', sa.Integer(), nullable=True),

        # A digest, plus the reply itself so an idempotent retry is answered
        # with the same bytes rather than a re-execution.
        sa.Column('result_sha256', sa.String(length=64), nullable=True),
        sa.Column('result', JSONType, nullable=True),

        sa.Column('protocol_version', sa.String(length=32), nullable=True),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('latency_ms', sa.Float(), nullable=True),

        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['session_pk'], ['mcp_sessions.id'],
                                ondelete='CASCADE'),
        # THE EXACTLY-ONCE INVARIANT. See the module docstring.
        sa.UniqueConstraint('session_id', 'request_id',
                            name='uq_mcp_invocation_request'),
    )
    op.create_index('ix_mcp_invocations_session_pk', 'mcp_invocations',
                    ['session_pk'])
    op.create_index('ix_mcp_invocations_session_id', 'mcp_invocations',
                    ['session_id'])
    op.create_index('ix_mcp_invocations_agent_did', 'mcp_invocations',
                    ['agent_did'])
    op.create_index('ix_mcp_invocations_tool_name', 'mcp_invocations',
                    ['tool_name'])
    op.create_index('ix_mcp_invocations_status', 'mcp_invocations', ['status'])
    op.create_index('ix_mcp_invocations_authorization_request_id',
                    'mcp_invocations', ['authorization_request_id'])
    op.create_index('ix_mcp_invocations_approval_id', 'mcp_invocations',
                    ['approval_id'])
    op.create_index('ix_mcp_invocations_jit_grant_id', 'mcp_invocations',
                    ['jit_grant_id'])
    op.create_index('ix_mcp_invocations_agent_status', 'mcp_invocations',
                    ['agent_did', 'status'])
    op.create_index('ix_mcp_invocations_tool', 'mcp_invocations',
                    ['tool_name', 'status'])


def downgrade() -> None:
    # Child first: `mcp_invocations` holds the foreign key.
    op.drop_index('ix_mcp_invocations_tool', table_name='mcp_invocations')
    op.drop_index('ix_mcp_invocations_agent_status', table_name='mcp_invocations')
    op.drop_index('ix_mcp_invocations_jit_grant_id', table_name='mcp_invocations')
    op.drop_index('ix_mcp_invocations_approval_id', table_name='mcp_invocations')
    op.drop_index('ix_mcp_invocations_authorization_request_id',
                  table_name='mcp_invocations')
    op.drop_index('ix_mcp_invocations_status', table_name='mcp_invocations')
    op.drop_index('ix_mcp_invocations_tool_name', table_name='mcp_invocations')
    op.drop_index('ix_mcp_invocations_agent_did', table_name='mcp_invocations')
    op.drop_index('ix_mcp_invocations_session_id', table_name='mcp_invocations')
    op.drop_index('ix_mcp_invocations_session_pk', table_name='mcp_invocations')
    op.drop_table('mcp_invocations')

    op.drop_index('ix_mcp_sessions_agent_status', table_name='mcp_sessions')
    op.drop_index('ix_mcp_sessions_token_jti', table_name='mcp_sessions')
    op.drop_index('ix_mcp_sessions_status', table_name='mcp_sessions')
    op.drop_index('ix_mcp_sessions_agent_did', table_name='mcp_sessions')
    op.drop_index('ix_mcp_sessions_session_id', table_name='mcp_sessions')
    op.drop_table('mcp_sessions')
