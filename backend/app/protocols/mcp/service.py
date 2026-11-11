"""The MCP invocation ledger and the fact policy reads (Phase 8).

THIS SERVICE AUTHORIZES NOTHING. It records what arrived, lets the database
settle exactly-once, and produces a VERDICT ABOUT THE TRANSPORT that the PIP
hands to Rego as one more fact -- alongside credentials, approvals and
mandates, never instead of them.

That is the whole shape of the phase. An MCP request that is perfectly
authenticated, perfectly formed, on a perfectly bound session, is still
decided by `agentic_iam.authz` exactly as the same action would be over any
other channel. The transport contributes facts; it does not contribute
permission.

WHY A FACT AT ALL, rather than letting Rego ignore the channel.

Two questions are genuinely policy's, and both need the channel in the input
document to be answerable:

    may this action be reached over MCP at all?   Not every protected tool
        should be remotely invocable just because it exists. The eligible set
        is policy CONFIGURATION (policies/data/mcp_policy.json), changed by a
        risk owner, not a constant in Python.
    was the caller's session bound to the caller? Python already refuses an
        unbound session at the transport. Asserting it again in Rego means
        the property is reviewable in the policy set rather than emergent
        from control flow -- the same reason Phase 7 restates envelope
        validity in `a2a/transaction.rego`.

DISCOVERY IS NOT INVOCATION, and the ledger is where that stops being a
slogan. `tools/list` writes nothing here and consults no policy about
individual tools; it reports what exists. `tools/call` writes a row, asks the
PDP, and is refused by default. A client can therefore see a tool it can
never call, which is the correct and intended outcome.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.credentials.canonical import canonical_bytes
from app.core.logging import get_logger
from app.db.models.mcp import MCPInvocation, MCPInvocationStatus, MCPSession

log = get_logger("mcp.service")


class MCPReason:
    """Transport-level reasons, in the vocabulary the rest of the system uses.

    Coarse: a reason names the CLASS of failure, never which record or claim
    value was involved.
    """

    MISSING = "MCP_REQUEST_ABSENT"
    TOOL_UNKNOWN = "MCP_TOOL_UNKNOWN"
    ARGUMENTS_MALFORMED = "MCP_ARGUMENTS_MALFORMED"
    ARGUMENTS_UNKNOWN_FIELD = "MCP_ARGUMENTS_UNKNOWN_FIELD"
    ARGUMENTS_MISSING_REQUIRED = "MCP_ARGUMENTS_MISSING_REQUIRED"
    ARGUMENTS_MISMATCH = "MCP_ARGUMENTS_MISMATCH"
    REPLAY_BLOCKED = "MCP_REPLAY_BLOCKED"
    REQUEST_ID_REUSE = "MCP_REQUEST_ID_REUSE"
    NO_ENFORCEMENT_PATH = "MCP_NO_ENFORCEMENT_PATH"
    EXECUTION_FAILED = "MCP_EXECUTION_FAILED"
    # Policy refusals for a request that arrived perfectly.
    POLICY_UNCONFIGURED = "MCP_POLICY_UNCONFIGURED"
    ACTION_NOT_ELIGIBLE = "MCP_ACTION_NOT_ELIGIBLE"
    SESSION_NOT_BOUND = "MCP_SESSION_NOT_BOUND"
    # ALLOW, named distinctly so an auditor can find every action taken over
    # the MCP transport rather than through the direct API.
    INVOCATION_AUTHORIZED = "MCP_INVOCATION_AUTHORIZED"


def authorization_request_id(session_id: str, request_id: str) -> str:
    """`mcp-{digest}`. DETERMINISTIC, and that is load-bearing.

    Every event the PDP, PIP, approval service and audit trail emit about
    this invocation carries this id, so the whole arc is reconstructible
    without a join. A digest rather than the raw values because a JSON-RPC id
    is client-chosen and may be any string -- including one long enough to
    overflow the column, or one containing characters that make a log line
    ambiguous.
    """
    digest = hashlib.sha256(f"{session_id}\x1f{request_id}".encode()).hexdigest()
    return f"mcp-{digest[:32]}"


def canonical_digest(value: Any) -> str:
    """A stable digest of an argument set, for comparing two of them.

    USES THE ONE CANONICALISER, `app.credentials.canonical`, which every
    proof type in this system shares. A locally written serialisation would
    be a second set of rules about key order, number formatting and string
    escaping, and two digests computed under subtly different rules compare
    unequal for inputs that are in fact identical. Here that would turn a
    legitimate retry into a REQUEST_ID_REUSE refusal; elsewhere in this
    system the same mistake breaks a signature. This package therefore
    contains no JSON serialisation of its own, and a test asserts it.
    """
    return hashlib.sha256(canonical_bytes(value or {})).hexdigest()


@dataclass
class MCPFact:
    """What the PIP reports to policy about an MCP invocation.

    A VERDICT plus its reason -- the same shape the credential, approval,
    mandate and A2A facts use, so Rego consumes MCP the way it consumes
    everything else and never sees a token.

    NOTE WHAT IS ABSENT: the access token, its jti, any header, and the tool
    result. Policy decides on what was ASKED and on the transport's own
    verdict. Handing it a credential would be handing it something to leak.
    """

    present: bool
    valid: bool
    reason: str
    session_id: str | None = None
    request_id: str | None = None
    agent_did: str | None = None
    tool_name: str | None = None
    action: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    purpose: str | None = None
    protocol_version: str | None = None
    # The transport's own checks, each a fact rather than a decision.
    authenticated: bool = False
    session_bound: bool = False
    arguments_validated: bool = False
    # Whether this is a discovery call. Policy does not authorise discovery
    # per-tool, but it can see that the two are different kinds of request.
    discovery: bool = False
    claimed_arguments: dict[str, Any] = field(default_factory=dict)
    checks: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "valid": self.valid,
            "reason": self.reason,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "agent_did": self.agent_did,
            "tool_name": self.tool_name,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "purpose": self.purpose,
            "protocol_version": self.protocol_version,
            "authenticated": self.authenticated,
            "session_bound": self.session_bound,
            "arguments_validated": self.arguments_validated,
            "discovery": self.discovery,
            "claimed_arguments": dict(self.claimed_arguments),
            "checks": list(self.checks),
        }

    @classmethod
    def absent(cls) -> "MCPFact":
        """No MCP invocation applies to this request.

        A FACT, not an omission, and never a permissive default. Every rule
        in `mcp/invocation.rego` guards on `present == true`, so an ordinary
        Phase 1-7 authorization request is decided exactly as it was before
        Phase 8 existed.
        """
        return cls(present=False, valid=False, reason=MCPReason.MISSING)


@dataclass
class InvocationOutcome:
    """Whether this (session, request id) is new, a retry, or a conflict."""

    registered: bool
    record: MCPInvocation
    idempotent: bool = False
    conflict: bool = False
    reason: str | None = None
    detail: str | None = None


class MCPInvocationService:
    """The ledger. Records invocations and settles exactly-once."""

    def __init__(self, session: AsyncSession, settings: Settings | None = None) -> None:
        self.session = session
        self.settings = settings or get_settings()

    async def register(
        self,
        *,
        mcp_session: MCPSession,
        request_id: str,
        tool_name: str,
        action: str | None,
        resource_type: str | None,
        resource_id: str | None,
        purpose: str | None,
        arguments: dict[str, Any],
        protocol_version: str,
        now: datetime | None = None,
    ) -> InvocationOutcome:
        """Claim this (session, request id), or report what already holds it.

        THE DATABASE IS THE ARBITER, not this function. Two concurrent
        workers racing on the same id cannot both win the INSERT, because
        `uq_mcp_invocation_request` will not let them. The IntegrityError
        branch below is the loser of that race discovering it lost -- it is
        the normal path under concurrency, not an error condition.
        """
        now = now or datetime.now(timezone.utc)
        request_id = str(request_id)

        record = MCPInvocation(
            session_pk=mcp_session.id,
            session_id=mcp_session.session_id,
            agent_did=mcp_session.agent_did,
            request_id=request_id,
            tool_name=tool_name,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            claimed_purpose=purpose,
            claimed_arguments=arguments or {},
            status=MCPInvocationStatus.RECEIVED,
            protocol_version=protocol_version,
            authorization_request_id=authorization_request_id(
                mcp_session.session_id, request_id
            ),
            received_at=now,
        )

        savepoint = await self.session.begin_nested()
        try:
            self.session.add(record)
            await self.session.flush()
        except IntegrityError:
            await savepoint.rollback()
            existing = (
                await self.session.execute(
                    select(MCPInvocation).where(
                        MCPInvocation.session_id == mcp_session.session_id,
                        MCPInvocation.request_id == request_id,
                    )
                )
            ).scalar_one()

            # A REUSED ID CARRYING DIFFERENT CONTENT is an attack, not a
            # retry, and is refused as one. A client resending the identical
            # call is answered idempotently instead.
            same = (
                existing.tool_name == tool_name
                and canonical_digest(existing.claimed_arguments)
                == canonical_digest(arguments or {})
                and existing.claimed_purpose == purpose
            )
            if not same:
                log.warning(
                    "mcp_request_id_reuse",
                    agent_did=mcp_session.agent_did,
                    request_id=request_id,
                    tool=tool_name,
                )
                return InvocationOutcome(
                    registered=False, record=existing, conflict=True,
                    reason=MCPReason.REQUEST_ID_REUSE,
                    detail="this request id has already been used in this "
                           "session for a different call",
                )
            return InvocationOutcome(
                registered=False, record=existing, idempotent=True,
                reason=MCPReason.REPLAY_BLOCKED,
            )
        else:
            await savepoint.commit()

        return InvocationOutcome(registered=True, record=record)

    async def mark_decided(
        self,
        record: MCPInvocation,
        *,
        decision: str,
        reason: str | None,
        policy_id: str | None = None,
        policy_version: str | None = None,
        status: MCPInvocationStatus,
        approval_id: str | None = None,
        required_approvals: int | None = None,
        authorized_arguments: dict[str, Any] | None = None,
        jit_grant_id: str | None = None,
        now: datetime | None = None,
    ) -> None:
        now = now or datetime.now(timezone.utc)
        record.decision = decision
        record.decision_reason = reason
        record.policy_id = policy_id
        record.policy_version = policy_version
        record.status = status
        record.decided_at = now
        if approval_id is not None:
            record.approval_id = approval_id
        if required_approvals is not None:
            record.required_approvals = required_approvals
        if jit_grant_id is not None:
            record.jit_grant_id = jit_grant_id
        if authorized_arguments is not None:
            record.authorized_arguments = authorized_arguments
        await self.session.flush()

    async def mark_executed(
        self,
        record: MCPInvocation,
        *,
        result: Any,
        executed_arguments: dict[str, Any],
        latency_ms: float | None = None,
        now: datetime | None = None,
    ) -> None:
        """Record the outcome, and the FOURTH side of argument reconciliation.

        `arguments_reconciled` is computed here rather than asserted: the
        values authorized and the values executed are digested and compared,
        and a disagreement is recorded as a disagreement. Nothing sets this
        flag true by assumption.
        """
        now = now or datetime.now(timezone.utc)
        record.status = MCPInvocationStatus.EXECUTED
        record.executed_arguments = executed_arguments
        record.arguments_reconciled = (
            canonical_digest(record.authorized_arguments or {})
            == canonical_digest(executed_arguments or {})
        )
        record.result = result if isinstance(result, dict) else {"value": result}
        record.result_sha256 = canonical_digest(record.result)
        record.executed_at = now
        if latency_ms is not None:
            record.latency_ms = latency_ms
        await self.session.flush()

    async def mark_refused(
        self,
        record: MCPInvocation,
        *,
        status: MCPInvocationStatus,
        reason: str,
        detail: str | None = None,
        latency_ms: float | None = None,
        now: datetime | None = None,
    ) -> None:
        now = now or datetime.now(timezone.utc)
        record.status = status
        record.reason = reason
        record.detail = detail
        record.decided_at = record.decided_at or now
        if latency_ms is not None:
            record.latency_ms = latency_ms
        await self.session.flush()
