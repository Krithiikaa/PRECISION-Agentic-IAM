"""MCP session lifecycle and binding (Phase 8).

A SESSION ID IS NOT A CREDENTIAL, and every design decision here follows from
that single sentence.

The Streamable HTTP transport lets a server issue an `Mcp-Session-Id` at
initialize time and requires the client to echo it on every later request.
That header is a bearer value: it travels in plaintext, it is logged by
proxies, and any client that obtains one can present it. If the session alone
determined who the caller was, stealing a session id would be stealing an
identity.

So it does not determine that. Every request to the MCP endpoint
authenticates independently -- a bearer access token, validated against
Keycloak, yielding an agent DID -- and the session is then checked to BELONG
to that DID. The two must agree. A session id is therefore a correlation
handle and a protocol requirement, and nothing an attacker can spend.

    agent A opens session S        -> mcp_sessions(S) = {agent_did: A}
    agent B presents S with B's
    valid token                    -> refused: SESSION_NOT_OWNED

That refusal is the reason this module exists.

WHAT ELSE IS ENFORCED HERE, each because the specification asks for it and
each stated as a check rather than an assumption:

    unknown / terminated session   HTTP 404, per the transport spec ("The
                                   server MAY terminate the session at any
                                   time, after which it MUST respond to
                                   requests containing that session ID with
                                   HTTP 404 Not Found").
    missing session id             HTTP 400 for anything but initialize
                                   ("Servers that require a session ID SHOULD
                                   respond to requests without an
                                   Mcp-Session-Id header (other than
                                   initialization) with HTTP 400 Bad
                                   Request").
    protocol version drift         a session negotiated one revision; a later
                                   request claiming another is refused rather
                                   than silently re-negotiated.
    idle expiry                    a session outliving the token that opened
                                   it is a row with no live authority behind
                                   it.

REVOCATION. A session does not keep an agent alive. Agent status is
re-established by the PIP on every authorization evaluation, so deactivating
an agent stops its invocations immediately even while its session row is
still ACTIVE and its access token is still unexpired. `revoke_for_agent()`
additionally closes the sessions, so the next protocol-level request fails at
the transport instead of at the policy engine -- a faster, clearer refusal,
but not the control. The control is the PIP.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.models.mcp import MCPSession, MCPSessionStatus

log = get_logger("mcp.session")


class SessionReason:
    """Why a session could not be used. Coarse, like every other reason set."""

    MISSING = "MCP_SESSION_MISSING"
    UNKNOWN = "MCP_SESSION_UNKNOWN"
    TERMINATED = "MCP_SESSION_TERMINATED"
    EXPIRED = "MCP_SESSION_EXPIRED"
    REVOKED = "MCP_SESSION_REVOKED"
    NOT_OWNED = "MCP_SESSION_NOT_OWNED"
    NOT_INITIALIZED = "MCP_SESSION_NOT_INITIALIZED"
    PROTOCOL_MISMATCH = "MCP_SESSION_PROTOCOL_MISMATCH"
    LIMIT_EXCEEDED = "MCP_SESSION_LIMIT_EXCEEDED"


@dataclass(frozen=True)
class SessionLookup:
    """The result of resolving a session id for an authenticated principal."""

    ok: bool
    session: MCPSession | None = None
    reason: str | None = None
    detail: str | None = None
    # True when the correct protocol response is 404 rather than 400. The
    # transport spec distinguishes them and a client's recovery differs: 404
    # means "start a new session with a fresh initialize", 400 means "your
    # request was wrong".
    not_found: bool = False


def new_session_id() -> str:
    """A session id that satisfies the transport spec's constraints.

    `token_urlsafe` yields only characters from [A-Za-z0-9_-], which is
    inside the required visible-ASCII range (0x21-0x7E), and 32 bytes of
    entropy is comfortably "cryptographically secure" as the spec asks.
    """
    return secrets.token_urlsafe(32)


class MCPSessionService:
    """Creates, resolves and terminates MCP sessions."""

    def __init__(self, session: AsyncSession, settings: Settings | None = None) -> None:
        self.session = session
        self.settings = settings or get_settings()

    async def create(
        self,
        *,
        agent_did: str,
        protocol_version: str,
        client_name: str | None,
        client_version: str | None,
        client_capabilities: dict,
        token_jti: str | None,
        token_expires_at: datetime | None,
        origin: str | None = None,
        source_ip: str | None = None,
        now: datetime | None = None,
    ) -> MCPSession:
        """Open a session bound to one agent.

        The binding is written here and never updated afterwards. There is
        deliberately no method on this service that changes `agent_did`.
        """
        now = now or datetime.now(timezone.utc)
        await self._prune(agent_did, now=now)

        record = MCPSession(
            session_id=new_session_id(),
            agent_did=agent_did,
            protocol_version=protocol_version,
            client_name=client_name,
            client_version=client_version,
            client_capabilities=client_capabilities or {},
            token_jti=token_jti,
            token_expires_at=token_expires_at,
            status=MCPSessionStatus.ACTIVE,
            initialized=False,
            origin=origin,
            source_ip=source_ip,
            last_activity_at=now,
        )
        self.session.add(record)
        await self.session.flush()
        log.info(
            "mcp_session_created",
            agent_did=agent_did,
            protocol_version=protocol_version,
            # The session id is hashed in the log. It is a bearer value, and
            # a log line is exactly the place one gets captured from.
            session=hashlib.sha256(record.session_id.encode()).hexdigest()[:16],
        )
        return record

    async def resolve(
        self,
        session_id: str | None,
        *,
        agent_did: str,
        protocol_version: str | None = None,
        now: datetime | None = None,
    ) -> SessionLookup:
        """Resolve a session id FOR a specific authenticated agent.

        `agent_did` is not optional, and that is the point: there is no way
        to call this function that looks a session up without also checking
        who is asking.
        """
        now = now or datetime.now(timezone.utc)

        if not session_id:
            return SessionLookup(
                ok=False, reason=SessionReason.MISSING,
                detail="this server issues a session at initialize and "
                       "requires Mcp-Session-Id on every subsequent request",
            )

        record = (
            await self.session.execute(
                select(MCPSession).where(MCPSession.session_id == session_id)
            )
        ).scalar_one_or_none()

        if record is None:
            # 404, per the transport spec: the client's correct recovery is
            # to begin a new session.
            return SessionLookup(
                ok=False, reason=SessionReason.UNKNOWN, not_found=True,
                detail="no such session; start a new one with initialize",
            )

        # THE OWNERSHIP CHECK. Deliberately placed before the status checks:
        # an attacker presenting somebody else's session id must not be able
        # to learn whether that session is live, terminated or expired. All
        # they learn is that it is not theirs.
        if record.agent_did != agent_did:
            log.warning(
                "mcp_session_ownership_violation",
                presented_by=agent_did,
                session=hashlib.sha256(session_id.encode()).hexdigest()[:16],
            )
            return SessionLookup(
                ok=False, reason=SessionReason.NOT_OWNED, not_found=True,
                detail="no such session; start a new one with initialize",
            )

        if record.status is not MCPSessionStatus.ACTIVE:
            reason = {
                MCPSessionStatus.TERMINATED: SessionReason.TERMINATED,
                MCPSessionStatus.EXPIRED: SessionReason.EXPIRED,
                MCPSessionStatus.REVOKED: SessionReason.REVOKED,
            }[record.status]
            return SessionLookup(
                ok=False, reason=reason, not_found=True,
                detail="this session is no longer usable; start a new one",
            )

        # Idle expiry, evaluated against the server clock and applied here so
        # there is no window in which an aged-out session is still honoured.
        idle_cutoff = now - timedelta(seconds=self.settings.mcp_session_idle_seconds)
        last = record.last_activity_at or record.created_at
        if last is not None and last < idle_cutoff:
            record.status = MCPSessionStatus.EXPIRED
            record.terminated_at = now
            record.termination_reason = SessionReason.EXPIRED
            await self.session.flush()
            return SessionLookup(
                ok=False, reason=SessionReason.EXPIRED, not_found=True,
                detail="this session expired; start a new one",
            )

        # A session negotiated exactly one revision. A later request claiming
        # a different one is refused rather than re-negotiated, because
        # re-negotiating mid-session would let a client downgrade after the
        # handshake it already agreed to.
        if protocol_version and protocol_version != record.protocol_version:
            return SessionLookup(
                ok=False, reason=SessionReason.PROTOCOL_MISMATCH,
                detail=f"this session negotiated {record.protocol_version}",
            )

        record.last_activity_at = now
        return SessionLookup(ok=True, session=record)

    async def mark_initialized(self, record: MCPSession) -> None:
        record.initialized = True
        await self.session.flush()

    async def terminate(
        self,
        record: MCPSession,
        *,
        reason: str = SessionReason.TERMINATED,
        now: datetime | None = None,
    ) -> None:
        now = now or datetime.now(timezone.utc)
        record.status = MCPSessionStatus.TERMINATED
        record.terminated_at = now
        record.termination_reason = reason
        await self.session.flush()

    async def revoke_for_agent(
        self, agent_did: str, *, now: datetime | None = None
    ) -> int:
        """Close every live session of one agent.

        A CONVENIENCE, NOT THE CONTROL. Revocation is already effective
        without this, because the PIP re-reads agent status inside every
        authorization evaluation and a deactivated agent is denied there.
        This exists so a revoked agent's next MCP request fails fast at the
        transport with a clear reason, instead of being carried all the way
        to a policy denial.
        """
        now = now or datetime.now(timezone.utc)
        result = await self.session.execute(
            update(MCPSession)
            .where(
                MCPSession.agent_did == agent_did,
                MCPSession.status == MCPSessionStatus.ACTIVE,
            )
            .values(
                status=MCPSessionStatus.REVOKED,
                terminated_at=now,
                termination_reason=SessionReason.REVOKED,
            )
        )
        await self.session.flush()
        return int(result.rowcount or 0)

    async def _prune(self, agent_did: str, *, now: datetime) -> None:
        """Keep one agent's live session count under the configured ceiling.

        Oldest-first, so a client that leaks sessions loses its stale ones
        rather than the one it is about to use. An unbounded count would let
        a single agent fill the table.
        """
        live = (
            await self.session.execute(
                select(MCPSession)
                .where(
                    MCPSession.agent_did == agent_did,
                    MCPSession.status == MCPSessionStatus.ACTIVE,
                )
                .order_by(MCPSession.created_at.asc())
            )
        ).scalars().all()

        excess = len(live) - self.settings.mcp_max_sessions_per_agent + 1
        for record in live[: max(0, excess)]:
            record.status = MCPSessionStatus.EXPIRED
            record.terminated_at = now
            record.termination_reason = SessionReason.LIMIT_EXCEEDED
        if excess > 0:
            await self.session.flush()
