"""MCP Streamable HTTP transport (Phase 8), revision 2025-06-18.

    POST   /mcp                                  one JSON-RPC message
    GET    /mcp                                  405: no server-initiated stream
    DELETE /mcp                                  terminate a session
    GET    /.well-known/oauth-protected-resource RFC 9728 metadata

WHAT THIS FILE OWNS: the HTTP layer and nothing above it. Origin validation,
header checks, status codes, content types, session headers, and turning a
dispatcher result into a response. Every authorization question belongs to
the AEM/PDP/OPA chain that `protocol.py` calls into.

THE ORDER OF CHECKS IS DELIBERATE, and it is the security-relevant part of
this module:

    1. Origin            DNS-rebinding defence. Before authentication,
                         because a rebinding attack rides a browser that
                         already holds credentials -- checking the token
                         first would authenticate the victim and then ask
                         whether the page was allowed to make the call.
    2. Accept            a transport requirement, cheap, no state touched.
    3. Authorization     401 + WWW-Authenticate with resource_metadata.
    4. MCP-Protocol-Version   400 on an unsupported value, per the spec.
    5. parse             JSON-RPC shape; batches refused.
    6. session           resolved FOR the authenticated agent; 404 if it is
                         not theirs, 400 if absent on a non-initialize call.
    7. dispatch          protocol semantics, then the enforcement boundary.

WHY NO SSE STREAM. The transport spec permits a server to answer a POSTed
request with either `application/json` or `text/event-stream`, and to offer
a GET stream or refuse it with 405. This server returns JSON and refuses the
GET. That is a conformant choice, not an omission: nothing here streams
partial results, and this server never initiates a request to a client, so
an SSE stream would be a connection that exists only to stay empty. Declared
as an intentionally unsupported OPTIONAL feature in the conformance matrix,
not quietly skipped.

WHY `/mcp` IS NOT UNDER `/api/v1`. The MCP endpoint's URL is its OAuth
resource identifier: it is the `resource` a client sends under RFC 8707 and
the audience a token is bound to. It is part of the security contract, so it
is a fixed, documented path rather than one that moves with API versioning.

NOTHING SENSITIVE IS LOGGED HERE: not the Authorization header, not the
token, not a session id in the clear, not tool arguments.
"""
from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.api.deps import KeyStoreDep, SessionDep, SettingsDep
from app.core.logging import get_logger
from app.enforcement.aem import AdapterEnforcementMiddleware
from app.monitoring.events import Event, EventType
from app.protocols.mcp.auth import (
    MCPAuthenticationError,
    MCPAuthReason,
    MCPTokenValidator,
    bearer_token,
    protected_resource_metadata,
    www_authenticate_header,
)
from app.protocols.mcp.jsonrpc import (
    INTERNAL_ERROR,
    INVALID_REQUEST,
    JSONRPCError,
    error as jsonrpc_error,
    parse_message,
    success,
)
from app.protocols.mcp.protocol import MCPServer
from app.protocols.mcp.service import MCPInvocationService
from app.protocols.mcp.session import MCPSessionService, SessionReason

log = get_logger("api.mcp")

router = APIRouter(tags=["mcp"])

SESSION_HEADER = "Mcp-Session-Id"
PROTOCOL_HEADER = "MCP-Protocol-Version"

# A single shared validator so the JWKS cache is actually a cache. It holds
# no per-request state.
_validator = MCPTokenValidator()


def _hashed(value: str | None) -> str | None:
    """A session id as it may appear in a log line: hashed, never in clear."""
    if not value:
        return None
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _origin_allowed(origin: str | None, settings) -> bool:
    """Origin validation, per the transport spec's security warning.

    "Servers MUST validate the Origin header on all incoming connections to
    prevent DNS rebinding attacks."

    A REQUEST WITH NO ORIGIN IS ALLOWED, and that is correct rather than a
    hole. `Origin` is set by browsers; a service-to-service client does not
    send one, and this endpoint's clients are agents. The attack being
    defended against is a web page in a victim's browser reaching a local
    server -- and a browser ALWAYS sends `Origin` on such a request. So the
    rule is: no Origin means not-a-browser and is allowed; an Origin present
    must be on the allow-list, which is empty by default.
    """
    if origin is None:
        return True
    return origin in settings.mcp_origins


def _unauthorized(reason: str, detail: str, settings) -> Response:
    """401 with the RFC 9728 challenge.

    The body is a JSON-RPC error so a client that only speaks JSON-RPC still
    gets something it can parse, and the header is what an OAuth-aware client
    reads to find the authorization server.
    """
    return JSONResponse(
        status_code=401,
        content=jsonrpc_error(None, INVALID_REQUEST, detail, data={"reason": reason}),
        headers={
            "WWW-Authenticate": www_authenticate_header(
                settings, error="invalid_token", description=detail,
            )
        },
    )


@router.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(settings: SettingsDep) -> JSONResponse:
    """RFC 9728 Protected Resource Metadata.

    Required by MCP 2025-06-18: "MCP servers MUST implement OAuth 2.0
    Protected Resource Metadata". Unauthenticated on purpose -- its entire
    job is to tell a client without a token where to get one.
    """
    return JSONResponse(content=protected_resource_metadata(settings))


@router.get("/mcp")
async def mcp_get() -> Response:
    """No server-initiated SSE stream is offered.

    The transport spec provides for exactly this answer: the server "MUST
    either return Content-Type: text/event-stream in response to this HTTP
    GET, or else return HTTP 405 Method Not Allowed, indicating that the
    server does not offer an SSE stream at this endpoint."
    """
    return JSONResponse(
        status_code=405,
        content=jsonrpc_error(
            None, INVALID_REQUEST,
            "this server does not offer a server-initiated SSE stream",
        ),
        headers={"Allow": "POST, DELETE"},
    )


@router.delete("/mcp")
async def mcp_delete(
    request: Request, session: SessionDep, settings: SettingsDep,
) -> Response:
    """Terminate a session, per the transport spec's DELETE semantics."""
    if not _origin_allowed(request.headers.get("origin"), settings):
        return JSONResponse(
            status_code=403,
            content=jsonrpc_error(None, INVALID_REQUEST, "origin not allowed"),
        )

    token = bearer_token(request.headers)
    if token is None:
        return _unauthorized(
            MCPAuthReason.MISSING, "a bearer token is required", settings,
        )
    try:
        principal = _validator.validate(token)
    except MCPAuthenticationError as exc:
        return _unauthorized(exc.reason, exc.detail, settings)

    session_id = request.headers.get(SESSION_HEADER)
    sessions = MCPSessionService(session, settings)
    lookup = await sessions.resolve(session_id, agent_did=principal.agent_did)
    if not lookup.ok:
        # 404 for "not yours / gone", 400 for "you did not send one".
        status = 404 if lookup.not_found else 400
        return JSONResponse(
            status_code=status,
            content=jsonrpc_error(
                None, INVALID_REQUEST, lookup.detail or "no such session",
                data={"reason": lookup.reason},
            ),
        )

    await sessions.terminate(lookup.session)
    audit = AdapterEnforcementMiddleware(session, settings=settings).audit
    await audit.record(
        Event(
            EventType.MCP_SESSION_TERMINATED,
            agent_did=principal.agent_did,
            session_id=lookup.session.session_id,
            metadata={"reason": SessionReason.TERMINATED, "by": "client DELETE"},
        )
    )
    await session.commit()
    return Response(status_code=204)


@router.post("/mcp")
async def mcp_post(
    request: Request,
    session: SessionDep,
    keystore: KeyStoreDep,
    settings: SettingsDep,
) -> Response:
    """The MCP endpoint. One JSON-RPC message per request."""
    aem = AdapterEnforcementMiddleware(session, keystore, settings)
    audit = aem.audit
    origin = request.headers.get("origin")
    source_ip = request.client.host if request.client else None

    # --- 1. ORIGIN -------------------------------------------------------
    if not _origin_allowed(origin, settings):
        await audit.record(
            Event(
                EventType.MCP_ORIGIN_REJECTED,
                metadata={"origin": origin, "source_ip": source_ip},
            )
        )
        await session.commit()
        log.warning("mcp_origin_rejected", origin=origin)
        return JSONResponse(
            status_code=403,
            content=jsonrpc_error(
                None, INVALID_REQUEST, "origin not allowed",
                data={"reason": "MCP_ORIGIN_NOT_ALLOWED"},
            ),
        )

    # --- 2. ACCEPT -------------------------------------------------------
    # "The client MUST include an Accept header, listing both
    # application/json and text/event-stream as supported content types."
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" not in accept or "text/event-stream" not in accept:
        return JSONResponse(
            status_code=400,
            content=jsonrpc_error(
                None, INVALID_REQUEST,
                "Accept must list both application/json and text/event-stream",
            ),
        )

    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" not in content_type:
        return JSONResponse(
            status_code=415,
            content=jsonrpc_error(
                None, INVALID_REQUEST, "Content-Type must be application/json",
            ),
        )

    # --- 3. AUTHENTICATION ----------------------------------------------
    token = bearer_token(request.headers)
    if token is None:
        await audit.record(
            Event(
                EventType.MCP_AUTHENTICATION_FAILED,
                metadata={"reason": MCPAuthReason.MISSING, "source_ip": source_ip},
            )
        )
        await session.commit()
        return _unauthorized(
            MCPAuthReason.MISSING, "a bearer token is required", settings,
        )
    try:
        principal = _validator.validate(token)
    except MCPAuthenticationError as exc:
        await audit.record(
            Event(
                EventType.MCP_AUTHENTICATION_FAILED,
                metadata={"reason": exc.reason, "source_ip": source_ip},
            )
        )
        await session.commit()
        log.warning("mcp_authentication_failed", reason=exc.reason)
        return _unauthorized(exc.reason, exc.detail, settings)

    await audit.record(
        Event(
            EventType.MCP_AUTHENTICATED,
            agent_did=principal.agent_did,
            metadata={
                "audience": principal.audience,
                "token_jti": principal.token_jti,
                "source_ip": source_ip,
            },
        )
    )

    # --- 4. PROTOCOL VERSION HEADER --------------------------------------
    # "If the server receives a request with an invalid or unsupported
    # MCP-Protocol-Version, it MUST respond with 400 Bad Request." And:
    # absent means assume 2025-03-26, for backwards compatibility -- which
    # this server does not implement, so an absent header on a non-initialize
    # request is treated as the unsupported version it stands for.
    declared = request.headers.get(PROTOCOL_HEADER)
    if declared is not None and declared not in settings.mcp_protocol_versions:
        return JSONResponse(
            status_code=400,
            content=jsonrpc_error(
                None, INVALID_REQUEST,
                f"unsupported {PROTOCOL_HEADER}: {declared}",
                data={"supported": settings.mcp_protocol_versions},
            ),
        )

    # --- 5. PARSE --------------------------------------------------------
    body = await request.body()
    try:
        message = parse_message(body)
    except JSONRPCError as exc:
        await audit.record(
            Event(
                EventType.MCP_PROTOCOL_ERROR,
                agent_did=principal.agent_did,
                metadata={"code": exc.code, "message": exc.message},
            )
        )
        await session.commit()
        return JSONResponse(
            status_code=400,
            content=jsonrpc_error(None, exc.code, exc.message, exc.data),
        )

    sessions = MCPSessionService(session, settings)
    invocations = MCPInvocationService(session, settings)
    server = MCPServer(
        aem=aem, sessions=sessions, invocations=invocations, settings=settings,
    )

    # --- 6a. INITIALIZE: the one message that needs no session -----------
    if message.method == "initialize":
        if message.is_notification:
            return JSONResponse(
                status_code=400,
                content=jsonrpc_error(
                    None, INVALID_REQUEST,
                    "initialize must be a request, not a notification",
                ),
            )
        # AN INITIALIZE CARRYING A SESSION ID IS A CLIENT ERROR, and refusing
        # it here rather than minting a second session is deliberate. The
        # transport spec's recovery path is explicit that a new session
        # begins "by sending a new InitializeRequest WITHOUT a session ID
        # attached", so a request that has one is contradicting itself.
        #
        # Allowing it would also let a client re-handshake an established
        # session and change the agreed protocol version after the fact,
        # while leaving the previous session row live and bound.
        if request.headers.get(SESSION_HEADER):
            return JSONResponse(
                status_code=400,
                content=jsonrpc_error(
                    message.id, INVALID_REQUEST,
                    "initialize must not carry a session id; a new session "
                    "begins without one",
                ),
            )
        result = await server.handle_initialize(
            message, principal=principal, origin=origin, source_ip=source_ip,
        )
        await session.commit()
        return JSONResponse(
            content=success(message.id, result.payload or {}),
            headers={SESSION_HEADER: result.session_id or ""},
        )

    # --- 6b. SESSION ------------------------------------------------------
    lookup = await sessions.resolve(
        request.headers.get(SESSION_HEADER),
        agent_did=principal.agent_did,
        protocol_version=declared,
    )
    if not lookup.ok:
        if lookup.reason == SessionReason.NOT_OWNED:
            await audit.record(
                Event(
                    EventType.MCP_SESSION_BINDING_VIOLATION,
                    agent_did=principal.agent_did,
                    metadata={
                        "presented_session": _hashed(
                            request.headers.get(SESSION_HEADER)
                        ),
                        "source_ip": source_ip,
                    },
                )
            )
        await session.commit()
        status = 404 if lookup.not_found else 400
        return JSONResponse(
            status_code=status,
            content=jsonrpc_error(
                message.id, INVALID_REQUEST,
                lookup.detail or "session unusable",
                data={"reason": lookup.reason},
            ),
        )

    # --- 7. DISPATCH ------------------------------------------------------
    try:
        response = await server.dispatch(
            message, principal=principal, mcp_session=lookup.session,
        )
    except JSONRPCError as exc:
        await audit.record(
            Event(
                EventType.MCP_PROTOCOL_ERROR,
                agent_did=principal.agent_did,
                session_id=lookup.session.session_id,
                metadata={"code": exc.code, "message": exc.message,
                          "method": message.method},
            )
        )
        await session.commit()
        if message.is_notification:
            # A notification gets no JSON-RPC reply. The spec's answer for a
            # notification the server cannot accept is an HTTP error status.
            return JSONResponse(
                status_code=400,
                content=jsonrpc_error(None, exc.code, exc.message, exc.data),
            )
        return JSONResponse(
            content=jsonrpc_error(message.id, exc.code, exc.message, exc.data)
        )
    except Exception as exc:  # noqa: BLE001 - never leak an internal failure
        log.error(
            "mcp_internal_error", method=message.method,
            error=f"{type(exc).__name__}", agent_did=principal.agent_did,
        )
        await session.rollback()
        # The exception's text is deliberately NOT returned: it may name
        # internal records, SQL or paths.
        return JSONResponse(
            status_code=500,
            content=jsonrpc_error(message.id, INTERNAL_ERROR, "Internal error"),
        )

    await session.commit()

    # "If the input is a JSON-RPC response or notification: ... the server
    # MUST return HTTP status code 202 Accepted with no body."
    if response.payload is None:
        return Response(status_code=202)

    return JSONResponse(content=success(message.id, response.payload))
