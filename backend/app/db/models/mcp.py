"""MCP session and invocation persistence (Phase 8).

WHY MCP NEEDS SERVER-SIDE STATE AT ALL, given every call is authorized afresh.

Three properties cannot be established from a request in isolation, and none
of them is an authorization decision:

    session binding     the MCP session is created by `initialize` and then
                        named by a header on every later request. The header
                        is a BEARER of the session, so the session must record
                        which agent opened it -- otherwise agent B, holding a
                        valid token of its own, could present agent A's
                        session id and be served as A. The binding is checked
                        on every request and is the reason a session id is not
                        a credential.
    exactly-once        "this tools/call has already run" is a fact about the
                        present. A client that did not see a response must be
                        able to ask again and learn the outcome without the
                        side effect happening twice.
    audit correlation   a reviewer asking "what did this agent do over MCP on
                        Tuesday?" needs the arc -- session opened, tools
                        listed, calls attempted, allowed, denied, escalated --
                        reconstructible without joining against log lines.

    mcp_sessions        one initialize: who opened it, which protocol version
                        was negotiated, and whether it is still live
    mcp_invocations     one tools/call: what was asked, what policy decided,
                        and what happened

WHAT IS NOT STORED, anywhere in this module: access tokens, bearer
credentials, client assertions, private key material, or full tool results
for a confidential resource. `token_jti` is the token's identifier, not the
token; it exists so a session can be tied to the credential that opened it
and revoked with it, and it is useless to anyone who captures it.

Tool ARGUMENTS are stored, and that is a deliberate, bounded decision: an
argument is the thing policy authorized and the thing that was executed, so
four-way reconciliation is impossible without it. The protected tools in this
system take record identifiers, not secrets. A tool whose arguments were
themselves sensitive would need a redaction policy before it were exposed
here, and `docs/PHASE_8_ARCHITECTURE.md` says so in the limitations section.

WHY INVOCATION UNIQUENESS IS COMPOSITE, exactly as Phase 7's is:
`UNIQUE (session_id, request_id)`. The JSON-RPC id is the CLIENT'S identifier
and is only required to be unique within its own session. A global unique on
`request_id` would let one agent squat on another's id namespace.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models.agent import JSONType, _enum


class MCPSessionStatus(str, enum.Enum):
    """The lifecycle of one MCP session.

    TERMINATED and EXPIRED are distinct for the reason this system keeps
    REJECTED and DENIED distinct elsewhere: a client that said goodbye and a
    session that aged out are different facts, and only one of them suggests
    a client bug. REVOKED is a third thing again -- the agent behind the
    session stopped being allowed to hold one, which is an administrative act
    on the identity and not an event in the session's own life.
    """

    ACTIVE = "ACTIVE"
    TERMINATED = "TERMINATED"   # terminal: the client sent HTTP DELETE
    EXPIRED = "EXPIRED"         # terminal: idle past the configured window
    REVOKED = "REVOKED"         # terminal: the agent was deactivated


class MCPInvocationStatus(str, enum.Enum):
    """The lifecycle of one tools/call.

    These mirror the A2A statuses deliberately. A reviewer who has learned to
    read one ledger should not have to learn a second vocabulary for the
    other, and the underlying arc really is the same: received, decided,
    possibly escalated to a human, then executed or not.
    """

    RECEIVED = "RECEIVED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    EXECUTED = "EXECUTED"       # terminal
    DENIED = "DENIED"           # terminal
    REJECTED = "REJECTED"       # terminal: refused before authorization
    FAILED = "FAILED"           # terminal: allowed, but did not complete


class MCPSession(Base, TimestampMixin):
    """One MCP session, bound to the agent that opened it.

    THE BINDING IS THE POINT. `agent_did` is written from the AUTHENTICATED
    principal at initialize time and is never updated. Every subsequent
    request carrying this session's id is checked against the principal
    authenticated on THAT request, and a mismatch is refused. A session id is
    therefore a correlation handle, never a credential: stealing one buys an
    attacker nothing without also holding a token for the same agent.
    """

    __tablename__ = "mcp_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    # The value carried in the `Mcp-Session-Id` header. The spec requires
    # visible ASCII (0x21-0x7E) and recommends a cryptographically secure
    # value; this is a token_urlsafe string, which satisfies both.
    session_id: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )

    # WHO. Not nullable: an unbound session is exactly the vulnerability this
    # table exists to prevent, so the schema refuses to represent one.
    agent_did: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # The protocol version AGREED at initialize, not the one requested. Later
    # requests carrying a different `MCP-Protocol-Version` are refused.
    protocol_version: Mapped[str] = mapped_column(String(32), nullable=False)

    client_name: Mapped[str | None] = mapped_column(String(128))
    client_version: Mapped[str | None] = mapped_column(String(64))
    client_capabilities: Mapped[dict] = mapped_column(
        JSONType, nullable=False, default=dict
    )

    # The IDENTIFIER of the access token that opened the session, never the
    # token. Lets a session be correlated with, and revoked alongside, the
    # credential that created it.
    token_jti: Mapped[str | None] = mapped_column(String(128), index=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    status: Mapped[MCPSessionStatus] = mapped_column(
        _enum(MCPSessionStatus, "mcp_session_status"),
        nullable=False,
        default=MCPSessionStatus.ACTIVE,
        index=True,
    )

    # Set by the `notifications/initialized` notification. Until then the
    # session exists but the handshake is incomplete, and the spec restricts
    # what may be sent. Tracked so that restriction is enforceable rather
    # than assumed.
    initialized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    origin: Mapped[str | None] = mapped_column(String(512))
    source_ip: Mapped[str | None] = mapped_column(String(64))

    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    terminated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    termination_reason: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        Index("ix_mcp_sessions_agent_status", "agent_did", "status"),
    )


class MCPInvocation(Base, TimestampMixin):
    """One tools/call: what was asked, what policy decided, what happened.

    WHAT THIS IS NOT: a permission. Every column below the request is a RECORD
    of a decision made elsewhere -- by Rego, by a human, by the database. The
    row confers nothing. Re-presenting the same (session, request id) re-reads
    it and is answered idempotently, never re-decided.

    THE FOUR ARGUMENT COLUMNS exist for the same reason Phase 7 carries four
    amounts: the values a client CLAIMED, the values policy AUTHORIZED and the
    values actually EXECUTED must be the same values, and a system that
    retains only one of them cannot demonstrate that they were.
    """

    __tablename__ = "mcp_invocations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    session_pk: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("mcp_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Denormalised from the session so the ledger is readable, and
    # deduplication works, without a join.
    session_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    agent_did: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # The JSON-RPC `id` of the tools/call request, as a string. Unique within
    # the session; see the module docstring for why not globally.
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)

    # The request, as received. `tool_name` is what the CLIENT named; `action`
    # and `resource_type` are what the SERVER's registry declares for that
    # tool. They are stored separately on purpose -- the client names a tool,
    # and the authorization request is built from the tool's declared action
    # and resource, never from anything the client said about them.
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[str | None] = mapped_column(String(64))
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(128))

    # The purpose the client asked for. CLAIMED, and named that way: it is
    # honoured only where it matches a purpose attested by a credential the
    # Phase 2 verifier accepted.
    claimed_purpose: Mapped[str | None] = mapped_column(String(64))

    claimed_arguments: Mapped[dict] = mapped_column(
        JSONType, nullable=False, default=dict
    )
    authorized_arguments: Mapped[dict | None] = mapped_column(JSONType)
    executed_arguments: Mapped[dict | None] = mapped_column(JSONType)
    arguments_reconciled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    status: Mapped[MCPInvocationStatus] = mapped_column(
        _enum(MCPInvocationStatus, "mcp_invocation_status"),
        nullable=False,
        default=MCPInvocationStatus.RECEIVED,
        index=True,
    )
    reason: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(Text)

    # What the PDP said. Mirrors the A2A ledger's columns so one query shape
    # answers "what did policy decide?" across both channels.
    decision: Mapped[str | None] = mapped_column(String(32))
    decision_reason: Mapped[str | None] = mapped_column(String(64))
    policy_id: Mapped[str | None] = mapped_column(String(64))
    policy_version: Mapped[str | None] = mapped_column(String(32))

    # The deterministic correlation key. Everything the PDP, PIP and audit
    # service emit about this invocation carries it.
    authorization_request_id: Mapped[str | None] = mapped_column(
        String(128), index=True
    )
    approval_id: Mapped[str | None] = mapped_column(String(128), index=True)
    jit_grant_id: Mapped[str | None] = mapped_column(String(128), index=True)
    required_approvals: Mapped[int | None] = mapped_column(Integer)

    # A digest, not the result. Enough to prove two replies were identical,
    # never enough to reconstruct a confidential record from the ledger.
    result_sha256: Mapped[str | None] = mapped_column(String(64))
    # The reply actually returned, kept so an idempotent retry can be answered
    # with the same bytes rather than a re-execution.
    result: Mapped[dict | None] = mapped_column(JSONType)

    protocol_version: Mapped[str | None] = mapped_column(String(32))
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    latency_ms: Mapped[float | None] = mapped_column(Float)

    __table_args__ = (
        # THE DEDUPLICATION CONSTRAINT. The database is the arbiter of
        # exactly-once, not application code: two concurrent workers racing
        # on the same (session, request id) cannot both win an INSERT.
        UniqueConstraint("session_id", "request_id", name="uq_mcp_invocation_request"),
        Index("ix_mcp_invocations_agent_status", "agent_did", "status"),
        Index("ix_mcp_invocations_tool", "tool_name", "status"),
    )
