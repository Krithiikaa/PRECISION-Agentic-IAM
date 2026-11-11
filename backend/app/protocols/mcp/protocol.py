"""MCP method dispatch (Phase 8).

WHERE THIS SITS, and what it is forbidden from doing.

    HTTP transport        routes/mcp.py   Origin, headers, status codes
    authentication        auth.py         token -> agent DID
    session binding       session.py      session belongs to that DID
    THIS MODULE                           JSON-RPC method semantics
    authorization         AEM -> PDP -> OPA
    execution             protected tool

This module decides NOTHING about permission. For `tools/call` it assembles
a trusted invocation context -- an authenticated DID, a validated tool name,
validated arguments, an established purpose -- and hands it to
`AdapterEnforcementMiddleware.enforce()`, the SAME boundary the direct API
uses. There is deliberately no MCP-specific authorization path: a second
engine would be a second set of rules to keep in agreement, and the one that
drifted would be the one an attacker used.

THE TWO ERROR CHANNELS, and why a denial uses the second one.

MCP distinguishes protocol errors (JSON-RPC `error`: unknown tool, invalid
arguments, server fault) from tool execution errors (a normal `result`
carrying `isError: true`: "API failures, invalid input data, business logic
errors"). An authorization refusal is the second kind. The call was
well-formed and the server processed it correctly; the outcome is "no".
Reporting a policy denial as a JSON-RPC protocol error would tell a client
its request was malformed when it was not, and would make a refusal
indistinguishable from a client bug in every dashboard downstream.

The refusal carries only the system's coarse reason codes -- the same ones
every other channel emits -- which name a class of failure and never a
record, claim value or internal identifier.

DISCOVERY IS UNFILTERED, DELIBERATELY. `tools/list` returns the catalogue of
protected tools without consulting policy and without regard to the calling
agent's credentials. Two reasons, and the second is the stronger:

    1. Filtering by what the caller could invoke would put a second copy of
       "what may be called" in Python, beside the real one in Rego. The copy
       would drift.
    2. A filtered list LEAKS. If the catalogue shrinks when an agent's
       credential expires, discovery has become an oracle for which
       credentials an agent holds.

So an agent can see a tool it will never be allowed to call, and that is the
intended and correct behaviour: listing a tool confers nothing whatsoever.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.authorization.contracts import Decision
from app.core.config import Settings, get_settings
from app.credentials.canonical import CanonicalizationError, canonicalize
from app.core.logging import get_logger
from app.db.models.mcp import MCPInvocation, MCPInvocationStatus, MCPSession
from app.enforcement.aem import AdapterEnforcementMiddleware, UnknownToolError
from app.monitoring.events import Event, EventType
from app.protocols.mcp.arguments import validate_arguments
from app.protocols.mcp.auth import MCPPrincipal
from app.protocols.mcp.jsonrpc import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    JSONRPCError,
    JSONRPCMessage,
    METHOD_NOT_FOUND,
)
from app.protocols.mcp.purpose import resolve_purpose
from app.protocols.mcp.service import MCPFact, MCPInvocationService, MCPReason
from app.protocols.mcp.session import MCPSessionService

log = get_logger("mcp.protocol")

SERVER_NAME = "agentic-iam-mcp"
SERVER_VERSION = "8.0"

# Methods this server implements. Anything else gets -32601, rather than
# being silently ignored: a client must be able to tell "not supported" from
# "accepted and did nothing".
IMPLEMENTED_METHODS = frozenset({
    "initialize",
    "notifications/initialized",
    "ping",
    "tools/list",
    "tools/call",
})


@dataclass
class MCPResponse:
    """What the transport should send.

    `payload` is None for a notification, which the transport turns into
    `202 Accepted` with no body, per the Streamable HTTP spec.
    """

    payload: dict[str, Any] | None = None
    session_id: str | None = None


def _text_result(text: str, *, is_error: bool, **extra: Any) -> dict[str, Any]:
    """A tools/call result.

    `structuredContent` carries the machine-readable form and the text block
    carries the same information serialised, which is what the spec asks for
    ("a tool that returns structured content SHOULD also return the
    serialized JSON in a TextContent block").
    """
    payload: dict[str, Any] = {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }
    if extra:
        payload["structuredContent"] = extra
    return payload


class MCPServer:
    """Dispatches one MCP message against the enforcement architecture."""

    def __init__(
        self,
        *,
        aem: AdapterEnforcementMiddleware,
        sessions: MCPSessionService,
        invocations: MCPInvocationService,
        settings: Settings | None = None,
    ) -> None:
        self.aem = aem
        self.sessions = sessions
        self.invocations = invocations
        self.settings = settings or get_settings()
        # The protected tool registry, reused verbatim from Phase 4. MCP does
        # not maintain a tool list of its own: a second registry could expose
        # something the enforcement boundary does not know about.
        self.tools = aem.tools
        self.audit = aem.audit

    # --- initialize --------------------------------------------------------

    def negotiate_version(self, requested: Any) -> str:
        """Pick the protocol revision for this session.

        Per the lifecycle spec: "If the server supports the requested
        protocol version, it MUST respond with the same version. Otherwise,
        the server MUST respond with another protocol version it supports."

        So an unsupported request is NOT an error here -- it is answered with
        what this server does speak, and the client decides whether to
        continue. (The transport-level `MCP-Protocol-Version` HEADER is a
        different matter and does produce 400; see routes/mcp.py.)
        """
        supported = self.settings.mcp_protocol_versions
        if isinstance(requested, str) and requested in supported:
            return requested
        return self.settings.mcp_protocol_version

    async def handle_initialize(
        self,
        message: JSONRPCMessage,
        *,
        principal: MCPPrincipal,
        origin: str | None,
        source_ip: str | None,
    ) -> MCPResponse:
        params = message.params
        client_info = params.get("clientInfo")
        if not isinstance(client_info, dict):
            client_info = {}
        capabilities = params.get("capabilities")
        if not isinstance(capabilities, dict):
            capabilities = {}

        version = self.negotiate_version(params.get("protocolVersion"))

        record = await self.sessions.create(
            agent_did=principal.agent_did,
            protocol_version=version,
            client_name=str(client_info.get("name") or "")[:128] or None,
            client_version=str(client_info.get("version") or "")[:64] or None,
            client_capabilities=capabilities,
            token_jti=principal.token_jti,
            token_expires_at=datetime.fromtimestamp(
                principal.expires_at, tz=timezone.utc
            ),
            origin=origin,
            source_ip=source_ip,
        )

        await self.audit.record(
            Event(
                EventType.MCP_SESSION_CREATED,
                agent_did=principal.agent_did,
                session_id=record.session_id,
                metadata={
                    "protocol_version": version,
                    "client": client_info.get("name"),
                    "origin": origin,
                    "transport": "streamable-http",
                },
            )
        )

        result = {
            "protocolVersion": version,
            "capabilities": {
                # Only what is actually implemented. `listChanged` is false
                # because this server does not emit
                # notifications/tools/list_changed -- claiming the
                # sub-capability would be advertising a notification that
                # never arrives.
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "title": "Agentic IAM protected tools",
                "version": SERVER_VERSION,
            },
            "instructions": (
                "Every tool on this server is protected. A tools/call is "
                "authorized per invocation against the caller's verifiable "
                "credentials and may require human approval. Listing a tool "
                "does not grant permission to call it. Each call must state "
                f"a purpose in params._meta['{self.settings.mcp_purpose_meta_key}']; "
                "the purpose must be one the caller's credentials attest."
            ),
        }
        return MCPResponse(payload=result, session_id=record.session_id)

    # --- tools -------------------------------------------------------------

    def handle_tools_list(self, message: JSONRPCMessage) -> dict[str, Any]:
        """The catalogue. Unfiltered; see the module docstring.

        Pagination is accepted in the sense that an explicit `cursor` is
        rejected rather than ignored: this server returns the whole list in
        one page and never emits `nextCursor`, so any cursor a client sends
        is one this server did not issue.
        """
        cursor = message.params.get("cursor")
        if cursor is not None:
            raise JSONRPCError(
                INVALID_PARAMS,
                "this server returns all tools in a single page and issues "
                "no cursors",
            )

        tools = []
        for described in self.tools.describe():
            tools.append({
                "name": described["name"],
                "title": described["name"].replace("_", " ").title(),
                "description": described["description"],
                "inputSchema": described["parameters"],
                "annotations": {
                    # Descriptive only. The MCP spec warns clients to treat
                    # annotations as untrusted; nothing in this server reads
                    # them back or gives them any authorization weight.
                    "readOnlyHint": described["action"] == "read",
                },
                "_meta": {
                    "agentic-iam.precisionit.co.in/protected": True,
                    "agentic-iam.precisionit.co.in/action": described["action"],
                    "agentic-iam.precisionit.co.in/resource": described["resource"],
                    "agentic-iam.precisionit.co.in/requiredCapability":
                        described["required_capability"],
                },
            })
        return {"tools": tools}

    async def handle_tools_call(
        self,
        message: JSONRPCMessage,
        *,
        principal: MCPPrincipal,
        mcp_session: MCPSession,
    ) -> dict[str, Any]:
        """One tools/call, all the way through the enforcement architecture."""
        started = time.perf_counter()
        params = message.params
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise JSONRPCError(INVALID_PARAMS, "params.name must be a tool name")

        await self.audit.record(
            Event(
                EventType.MCP_REQUEST,
                agent_did=principal.agent_did,
                session_id=mcp_session.session_id,
                metadata={
                    "tool": name,
                    "request_id": str(message.id),
                    "protocol_version": mcp_session.protocol_version,
                    "stage": "received; nothing has been authorized yet",
                },
            )
        )

        tool = self.tools.get(name)
        if tool is None:
            # A PROTOCOL error: the spec's own example of -32602 is
            # "Unknown tool". Note this leaks only that the name is not in a
            # catalogue the caller can already list in full.
            raise JSONRPCError(INVALID_PARAMS, f"Unknown tool: {name}")

        # --- the purpose, which fails closed --------------------------------
        resolution = resolve_purpose(params, self.settings)
        if not resolution.established:
            raise JSONRPCError(
                INVALID_PARAMS, resolution.detail or "a purpose is required",
                data={"reason": resolution.reason},
            )

        # --- strict argument validation -------------------------------------
        validation = validate_arguments(tool.spec.parameters, params.get("arguments"))
        if not validation.ok:
            raise JSONRPCError(
                INVALID_PARAMS, validation.detail or "invalid arguments",
                data={"reason": validation.reason},
            )
        arguments = validation.arguments
        resource_id = arguments.get(tool.resource_id_argument)

        # --- the ledger: exactly-once is the database's to settle -----------
        outcome = await self.invocations.register(
            mcp_session=mcp_session,
            request_id=str(message.id),
            tool_name=name,
            action=tool.spec.action,
            resource_type=tool.spec.resource,
            resource_id=resource_id,
            purpose=resolution.purpose,
            arguments=arguments,
            protocol_version=mcp_session.protocol_version,
        )
        if outcome.conflict:
            raise JSONRPCError(
                INVALID_REQUEST,
                "this request id has already been used in this session",
                data={"reason": outcome.reason},
            )
        if outcome.idempotent:
            # IDEMPOTENT. The recorded outcome is returned verbatim; nothing
            # is re-decided, because credential state, policy and approvals
            # could all have moved since, and a retry must not get a
            # different answer for a call that already settled.
            return self._replay_result(outcome.record)

        record = outcome.record

        # --- THE ENFORCEMENT BOUNDARY ---------------------------------------
        # The same `enforce()` the direct API calls. Everything above this
        # line established WHO is asking and WHAT they asked for; nothing
        # above it decided whether they may.
        # The transport's verdict, as a FACT for policy. Everything in it was
        # established before this point: the token was validated, the session
        # was proven to belong to this agent, the tool exists in the registry
        # and the arguments matched its schema. Policy reads it; it does not
        # re-derive it, and it is never a substitute for the credential,
        # approval and mandate checks that run alongside.
        fact = MCPFact(
            present=True,
            valid=True,
            reason=MCPReason.INVOCATION_AUTHORIZED,
            session_id=mcp_session.session_id,
            request_id=str(message.id),
            agent_did=principal.agent_did,
            tool_name=name,
            action=tool.spec.action,
            resource_type=tool.spec.resource,
            resource_id=resource_id,
            purpose=resolution.purpose,
            protocol_version=mcp_session.protocol_version,
            authenticated=True,
            session_bound=True,
            arguments_validated=True,
            discovery=False,
            claimed_arguments=arguments,
        )

        try:
            result = await self.aem.enforce(
                subject_did=principal.agent_did,
                tool_name=name,
                arguments=arguments,
                purpose=resolution.purpose,
                request_id=record.authorization_request_id,
                mcp=fact,
                context={
                    # UNTRUSTED transport metadata, passed so a rule that
                    # legitimately wants it can see it. No rule reads an
                    # authorization input from here;
                    # `strip_decision_claims()` removes self-asserted
                    # verdicts before policy sees the context.
                    "mcp": {
                        "session_id": mcp_session.session_id,
                        "protocol_version": mcp_session.protocol_version,
                        "transport": "streamable-http",
                        "channel": "mcp",
                    },
                },
            )
        except UnknownToolError as exc:  # pragma: no cover - guarded above
            raise JSONRPCError(INVALID_PARAMS, str(exc)) from exc

        elapsed = (time.perf_counter() - started) * 1000
        decision = result.decision

        # --- escalation ------------------------------------------------------
        if decision.decision is Decision.HUMAN_APPROVAL_REQUIRED:
            approval = (decision.evaluation or {}).get("approval_request") or {}
            await self.invocations.mark_decided(
                record,
                decision=decision.decision.value,
                reason=decision.reason,
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                status=MCPInvocationStatus.PENDING_APPROVAL,
                approval_id=approval.get("approval_id"),
                required_approvals=approval.get("required_approvals"),
            )
            await self.invocations.mark_refused(
                record, status=MCPInvocationStatus.PENDING_APPROVAL,
                reason=decision.reason, latency_ms=elapsed,
                detail="awaiting human approval",
            )
            return _text_result(
                "This action requires human approval before it can proceed. "
                "Re-send the same call with a NEW request id once the "
                "required approvals are recorded.",
                is_error=True,
                reason=decision.reason,
                decision=decision.decision.value,
                approvalId=approval.get("approval_id"),
                requiredApprovals=approval.get("required_approvals"),
                signoffsRecorded=approval.get("signoffs_recorded"),
            )

        # --- denial -----------------------------------------------------------
        if decision.decision is not Decision.ALLOW:
            await self.invocations.mark_decided(
                record,
                decision=decision.decision.value,
                reason=decision.reason,
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                status=MCPInvocationStatus.DENIED,
            )
            await self.invocations.mark_refused(
                record, status=MCPInvocationStatus.DENIED,
                reason=decision.reason, detail=result.error, latency_ms=elapsed,
            )
            log.warning(
                "mcp_denied", agent_did=principal.agent_did, tool=name,
                reason=decision.reason, request_id=record.authorization_request_id,
            )
            return _text_result(
                f"Refused: {decision.reason}.",
                is_error=True,
                reason=decision.reason,
                decision=decision.decision.value,
                policy=decision.policy_ref,
            )

        # --- allowed, but the tool did not complete ---------------------------
        # A SEPARATE BRANCH FROM THE DENIAL ABOVE, and it has to be. Policy
        # said yes and the action still did not happen -- a missing record, a
        # downstream fault. Reporting that as a denial would attach the ALLOW
        # reason to a refusal, so an operator reading the trail would see
        # `VALID_CREDENTIAL_AND_POLICY_MATCH` next to a failure and conclude
        # policy had refused something it permitted. Phase 7 draws the same
        # line between DENIED and FAILED, for the same reason.
        if not result.executed:
            await self.invocations.mark_decided(
                record,
                decision=decision.decision.value,
                reason=decision.reason,
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                status=MCPInvocationStatus.FAILED,
                authorized_arguments=arguments,
            )
            await self.invocations.mark_refused(
                record, status=MCPInvocationStatus.FAILED,
                reason=MCPReason.EXECUTION_FAILED, detail=result.error,
                latency_ms=elapsed,
            )
            log.error(
                "mcp_execution_failed", agent_did=principal.agent_did, tool=name,
                request_id=record.authorization_request_id,
            )
            return _text_result(
                f"The call was authorized but did not complete: "
                f"{MCPReason.EXECUTION_FAILED}.",
                is_error=True,
                reason=MCPReason.EXECUTION_FAILED,
                decision=decision.decision.value,
                policy=decision.policy_ref,
            )

        # --- allowed and executed ---------------------------------------------
        await self.invocations.mark_decided(
            record,
            decision="ALLOW",
            reason=decision.reason,
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            status=MCPInvocationStatus.RECEIVED,
            # THE AUTHORIZED ARGUMENTS. Recorded from the validated set that
            # was actually passed to `enforce()`, so the fourth side of the
            # reconciliation below compares against what policy saw.
            authorized_arguments=arguments,
        )
        await self.invocations.mark_executed(
            record, result=result.result, executed_arguments=arguments,
            latency_ms=elapsed,
        )

        if not record.arguments_reconciled:
            # Unreachable by construction today -- the same dict is used for
            # both -- and asserted anyway, because "by construction" is a
            # property that survives exactly until someone refactors.
            log.error(
                "mcp_argument_reconciliation_failed",
                request_id=record.authorization_request_id, tool=name,
            )
            return _text_result(
                f"Refused: {MCPReason.ARGUMENTS_MISMATCH}.",
                is_error=True, reason=MCPReason.ARGUMENTS_MISMATCH,
            )

        log.info(
            "mcp_allowed", agent_did=principal.agent_did, tool=name,
            policy=decision.policy_ref, latency_ms=round(elapsed, 2),
        )
        return _text_result(
            _serialise(result.result),
            is_error=False,
            result=result.result,
            reason=decision.reason,
            policy=decision.policy_ref,
        )

    def _replay_result(self, record: MCPInvocation) -> dict[str, Any]:
        """The previously recorded outcome, returned without re-executing."""
        if record.status is MCPInvocationStatus.EXECUTED:
            stored = record.result or {}
            payload = stored.get("value", stored)
            return _text_result(
                _serialise(payload), is_error=False,
                result=payload, replayed=True,
                reason=record.decision_reason,
            )
        return _text_result(
            f"Refused: {record.reason or record.decision_reason}.",
            is_error=True, replayed=True,
            reason=record.reason or record.decision_reason,
            decision=record.decision,
        )

    # --- dispatch -----------------------------------------------------------

    async def dispatch(
        self,
        message: JSONRPCMessage,
        *,
        principal: MCPPrincipal,
        mcp_session: MCPSession,
    ) -> MCPResponse:
        """Route one post-initialize message.

        `initialize` is handled by the transport, because it is the message
        that creates the session this function requires.
        """
        method = message.method

        if method == "initialize":
            # A second initialize on an established session. Refused rather
            # than silently re-handshaking: re-negotiating mid-session would
            # let a client change the agreed protocol version after the fact.
            raise JSONRPCError(
                INVALID_REQUEST, "this session is already initialized"
            )

        if method == "notifications/initialized":
            await self.sessions.mark_initialized(mcp_session)
            return MCPResponse(payload=None)

        if method == "ping":
            # Permitted before `initialized`, per the lifecycle spec.
            return MCPResponse(payload={})

        # Everything below requires a COMPLETED handshake. The spec says a
        # client "SHOULD NOT" send other requests before the server has
        # responded to initialize; this server enforces the stronger
        # condition that the `initialized` notification has arrived, because
        # a half-open handshake is a state no caller needs.
        if not mcp_session.initialized:
            raise JSONRPCError(
                INVALID_REQUEST,
                "the initialized notification has not been received",
            )

        if method == "tools/list":
            return MCPResponse(payload=self.handle_tools_list(message))

        if method == "tools/call":
            if message.is_notification:
                # A tools/call with no id has nowhere to send a result, and a
                # side effect nobody can observe the outcome of is not one
                # this server will perform.
                raise JSONRPCError(
                    INVALID_REQUEST, "tools/call must be a request, not a notification"
                )
            return MCPResponse(
                payload=await self.handle_tools_call(
                    message, principal=principal, mcp_session=mcp_session,
                )
            )

        if method.startswith("notifications/"):
            # An unknown notification is dropped rather than refused: a
            # notification has no reply, and the spec tells receivers not to
            # send one.
            return MCPResponse(payload=None)

        raise JSONRPCError(METHOD_NOT_FOUND, f"Method not found: {method}")


def _serialise(value: Any) -> str:
    """Render a tool result as the text block MCP asks for alongside
    `structuredContent`.

    Uses the shared canonicaliser for the reason `canonical_digest` does:
    this package deliberately contains no JSON serialisation of its own, so
    there is exactly one set of rules about key order and escaping in the
    system. The canonicaliser refuses values it cannot represent
    unambiguously (floats, for one), so a result containing one falls back
    to `repr` rather than being rendered under different rules from
    everything else.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        try:
            return canonicalize(value)
        except CanonicalizationError:
            return str(value)
    return str(value)
