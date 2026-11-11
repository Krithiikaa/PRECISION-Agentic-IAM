"""JSON-RPC 2.0 message parsing and validation for the MCP endpoint.

THIS MODULE DECIDES NOTHING ABOUT AUTHORIZATION. It answers one question --
"is this a well-formed JSON-RPC 2.0 message, and which kind?" -- and refuses
anything it cannot classify. Keeping it separate from `protocol.py` is not
tidiness: a parser that also dispatches is a parser whose failure modes are
hard to enumerate, and every MCP exploit that matters starts with a message
the server classified wrongly.

WHY HAND-WRITTEN rather than an SDK's parser: Phase 8 is implemented with
zero new runtime dependencies (the `mcp` SDK requires `pydantic>=2.12` and
this project pins 2.10.4). The spec's wire format is small and fully
specified, so it is implemented here directly and asserted by tests written
against the published requirements rather than against this code.

THE BATCHING RULE IS LOAD-BEARING. Revision 2025-03-26 permitted JSON-RPC
batches; revision 2025-06-18 REMOVED them. A server that quietly accepts a
batch is speaking the older protocol while advertising the newer one, and a
batch is a convenient way to smuggle a second call past a reviewer who read
only the first. An array is refused here, by shape, before anything else
looks at it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# --- Standard JSON-RPC 2.0 error codes -------------------------------------
# Spelled out rather than imported from anywhere, because these numbers are
# part of the wire contract and a test should be able to assert them against
# the specification without following an import.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

JSONRPC_VERSION = "2.0"


class JSONRPCError(Exception):
    """A protocol-level failure, carrying the code that must go on the wire.

    Distinct from a tool execution failure, which is NOT an error response at
    all -- it is a successful JSON-RPC result carrying `isError: true`. The
    specification draws that line and so does this implementation: conflating
    them would let a denied authorization look like a malformed request, and
    an operator would not be able to tell a policy refusal from a client bug.
    """

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def to_error_object(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return error


@dataclass(frozen=True)
class JSONRPCMessage:
    """One parsed, classified JSON-RPC message.

    `is_request` and `is_notification` are mutually exclusive and exhaustive
    for anything this parser returns: a message that is neither was refused.
    """

    method: str
    params: dict[str, Any] = field(default_factory=dict)
    id: str | int | None = None
    # True when the message carried an `id` member, which is what separates a
    # request from a notification. Tracked explicitly rather than inferred
    # from `id is not None`, because `id` may legitimately be the integer 0
    # and `0 is not None` is True only by luck of Python's truthiness rules
    # not being involved here -- being explicit removes the question.
    has_id: bool = False

    @property
    def is_request(self) -> bool:
        return self.has_id

    @property
    def is_notification(self) -> bool:
        return not self.has_id


def parse_message(raw: bytes | str) -> JSONRPCMessage:
    """Parse and classify one JSON-RPC message, or raise JSONRPCError.

    Every refusal below is a specification requirement, not a house style:

    * invalid JSON                -> -32700, per JSON-RPC 2.0.
    * an array (batch)            -> -32600. Removed in MCP 2025-06-18.
    * a non-object                -> -32600.
    * `jsonrpc` != "2.0"          -> -32600.
    * a missing or non-string
      `method`                    -> -32600.
    * `id` present but null       -> -32600. Base JSON-RPC allows a null id;
                                     MCP explicitly does NOT ("Unlike base
                                     JSON-RPC, the ID MUST NOT be null").
    * `id` of any type other than
      string or integer           -> -32600. A float id round-trips badly and
                                     booleans are integers in Python, which
                                     is exactly the kind of coincidence that
                                     turns into a correlation bug.
    * `params` present but not an
      object                      -> -32600. MCP never uses positional
                                     params, so a JSON-RPC array here is
                                     well-formed JSON-RPC and still not a
                                     message this server can act on.
    """
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise JSONRPCError(PARSE_ERROR, "Parse error") from exc

    if isinstance(payload, list):
        raise JSONRPCError(
            INVALID_REQUEST,
            "JSON-RPC batching is not supported in MCP revision 2025-06-18",
        )
    if not isinstance(payload, dict):
        raise JSONRPCError(INVALID_REQUEST, "Invalid Request")

    if payload.get("jsonrpc") != JSONRPC_VERSION:
        raise JSONRPCError(INVALID_REQUEST, "Invalid Request: jsonrpc must be '2.0'")

    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise JSONRPCError(INVALID_REQUEST, "Invalid Request: method must be a string")

    has_id = "id" in payload
    message_id = payload.get("id")
    if has_id:
        if message_id is None:
            raise JSONRPCError(INVALID_REQUEST, "Invalid Request: id MUST NOT be null")
        # `isinstance(True, int)` is True in Python. A boolean id would be
        # accepted by a naive check and then compared unequal to the integer
        # the client believes it sent.
        if isinstance(message_id, bool) or not isinstance(message_id, (str, int)):
            raise JSONRPCError(
                INVALID_REQUEST, "Invalid Request: id must be a string or integer"
            )

    params = payload.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise JSONRPCError(INVALID_REQUEST, "Invalid Request: params must be an object")

    return JSONRPCMessage(
        method=method, params=params, id=message_id, has_id=has_id,
    )


def success(message_id: str | int | None, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": message_id, "result": result}


def error(
    message_id: str | int | None, code: int, message: str, data: Any = None
) -> dict[str, Any]:
    """An error response.

    `id` is included even when it is None. The specification requires an error
    response to carry the id of the request it answers, and for a message so
    malformed that no id could be read, a null id is the defined way to say
    "this reply belongs to a request I could not identify".
    """
    payload: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        payload["data"] = data
    return {"jsonrpc": JSONRPC_VERSION, "id": message_id, "error": payload}
