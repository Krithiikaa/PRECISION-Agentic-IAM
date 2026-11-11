"""MCP protocol adapter (Phase 8), revision 2025-06-18.

Implemented directly on the existing FastAPI stack with ZERO new runtime
dependencies. The official `mcp` SDK is deliberately not used: it requires
`pydantic>=2.12` while this project pins 2.10.4, and upgrading the model
layer of a security system to gain a transport helper is the wrong trade.

The modules are split by concern, and the split is load-bearing -- each one
is forbidden from doing the next one's job:

    jsonrpc    JSON-RPC 2.0 shape only. Classifies; never dispatches.
    auth       OAuth 2.1 resource-server token validation -> agent DID.
    session    session creation and the agent-ownership binding.
    purpose    reads the requested purpose; never decides if it is allowed.
    arguments  strict schema validation against the tool's declared schema.
    service    the invocation ledger and the fact policy reads.
    protocol   MCP method semantics, then straight to the AEM.

WHAT IS NOT HERE: an authorization engine. Every `tools/call` goes through
`AdapterEnforcementMiddleware.enforce()` -- the same boundary the direct API
uses -- and is decided by the same Rego. See docs/PHASE_8_ARCHITECTURE.md
for the conformance matrix and the threat model.
"""
from app.protocols.mcp.auth import (
    MCPAuthenticationError,
    MCPAuthReason,
    MCPPrincipal,
    MCPTokenValidator,
)
from app.protocols.mcp.service import MCPFact, MCPInvocationService, MCPReason
from app.protocols.mcp.session import MCPSessionService, SessionReason

__all__ = [
    "MCPAuthReason",
    "MCPAuthenticationError",
    "MCPFact",
    "MCPInvocationService",
    "MCPPrincipal",
    "MCPReason",
    "MCPSessionService",
    "MCPTokenValidator",
    "SessionReason",
]
