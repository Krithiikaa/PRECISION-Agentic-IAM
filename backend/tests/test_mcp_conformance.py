"""MCP protocol conformance (Phase 8), revision 2025-06-18.

EVERY TEST HERE IS WRITTEN AGAINST THE PUBLISHED SPECIFICATION, not against
this implementation. Each one quotes the requirement it asserts, so a
reviewer can check the test against the spec without reading the server, and
so a test that drifts from the spec is visible as a wrong quotation rather
than a passing assertion.

That distinction matters more than usual here: Phase 8 hand-wrote the
protocol rather than taking the SDK, so these tests ARE the conformance
evidence. A suite written against the implementation would prove only that
the implementation does what it does.

The matrix these map to is in docs/PHASE_8_ARCHITECTURE.md.
"""
from __future__ import annotations

import json

import pytest

from app.protocols.mcp.jsonrpc import (
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    JSONRPCError,
    parse_message,
)

pytestmark = pytest.mark.integration


class TestJSONRPCMessageValidation:
    """Base protocol: "All messages ... MUST follow the JSON-RPC 2.0 spec"."""

    def test_a_well_formed_request_parses(self):
        message = parse_message(
            b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
        )
        assert message.is_request
        assert message.method == "tools/list"
        assert message.id == 1

    def test_a_notification_has_no_id(self):
        """"Notifications MUST NOT include an ID"."""
        message = parse_message(
            b'{"jsonrpc":"2.0","method":"notifications/initialized"}'
        )
        assert message.is_notification
        assert not message.is_request

    def test_invalid_json_is_a_parse_error(self):
        with pytest.raises(JSONRPCError) as exc:
            parse_message(b"{not json")
        assert exc.value.code == PARSE_ERROR

    def test_a_null_id_is_refused(self):
        """"Unlike base JSON-RPC, the ID MUST NOT be null"."""
        with pytest.raises(JSONRPCError) as exc:
            parse_message(b'{"jsonrpc":"2.0","id":null,"method":"ping"}')
        assert exc.value.code == INVALID_REQUEST

    def test_a_boolean_id_is_refused(self):
        """"Requests MUST include a string or integer ID".

        `isinstance(True, int)` is True in Python, so a naive check accepts a
        boolean and then compares it unequal to whatever the client thinks it
        sent. Asserted because the language makes it easy to get wrong.
        """
        with pytest.raises(JSONRPCError) as exc:
            parse_message(b'{"jsonrpc":"2.0","id":true,"method":"ping"}')
        assert exc.value.code == INVALID_REQUEST

    def test_a_float_id_is_refused(self):
        with pytest.raises(JSONRPCError):
            parse_message(b'{"jsonrpc":"2.0","id":1.5,"method":"ping"}')

    def test_the_wrong_jsonrpc_version_is_refused(self):
        with pytest.raises(JSONRPCError) as exc:
            parse_message(b'{"jsonrpc":"1.0","id":1,"method":"ping"}')
        assert exc.value.code == INVALID_REQUEST

    def test_a_missing_method_is_refused(self):
        with pytest.raises(JSONRPCError):
            parse_message(b'{"jsonrpc":"2.0","id":1}')

    def test_non_object_params_are_refused(self):
        """MCP never uses positional params."""
        with pytest.raises(JSONRPCError):
            parse_message(b'{"jsonrpc":"2.0","id":1,"method":"ping","params":[1]}')

    def test_a_batch_is_refused(self):
        """Revision 2025-06-18: "Remove support for JSON-RPC batching".

        THE MOST IMPORTANT TEST IN THIS CLASS. A server that accepts a batch
        is speaking 2025-03-26 while advertising 2025-06-18, and a batch is a
        convenient way to smuggle a second call past review of the first.
        """
        with pytest.raises(JSONRPCError) as exc:
            parse_message(
                b'[{"jsonrpc":"2.0","id":1,"method":"ping"},'
                b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}]'
            )
        assert exc.value.code == INVALID_REQUEST
        assert "batch" in exc.value.message.lower()


class TestInitialization:
    """Lifecycle: "The initialization phase MUST be the first interaction"."""

    async def test_initialize_returns_version_capabilities_and_server_info(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        response = await mcp_client.post(
            "/mcp",
            headers=mcp_headers(mcp_token(risk_agent.did)),
            json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "1.0"},
                },
            },
        )
        assert response.status_code == 200
        result = response.json()["result"]
        assert result["protocolVersion"] == "2025-06-18"
        assert "capabilities" in result
        assert result["serverInfo"]["name"]
        assert result["serverInfo"]["version"]

    async def test_initialize_issues_a_session_id_header(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        """"A server ... MAY assign a session ID at initialization time, by
        including it in an Mcp-Session-Id header"."""
        response = await mcp_client.post(
            "/mcp",
            headers=mcp_headers(mcp_token(risk_agent.did)),
            json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "pytest", "version": "1"}},
            },
        )
        session_id = response.headers.get("Mcp-Session-Id")
        assert session_id
        # "The session ID MUST only contain visible ASCII characters
        # (ranging from 0x21 to 0x7E)."
        assert all(0x21 <= ord(ch) <= 0x7E for ch in session_id)

    async def test_an_unsupported_requested_version_is_answered_with_a_supported_one(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        """"Otherwise, the server MUST respond with another protocol version
        it supports."

        NOT an error. A client asking for a revision this server does not
        speak gets told what it does speak and decides for itself.
        """
        response = await mcp_client.post(
            "/mcp",
            headers=mcp_headers(mcp_token(risk_agent.did)),
            json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "1999-01-01", "capabilities": {},
                           "clientInfo": {"name": "pytest", "version": "1"}},
            },
        )
        assert response.status_code == 200
        assert response.json()["result"]["protocolVersion"] == "2025-06-18"

    async def test_the_initialized_notification_is_accepted_with_202(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        """"If the input is a JSON-RPC response or notification ... the server
        MUST return HTTP status code 202 Accepted with no body"."""
        token = mcp_token(risk_agent.did)
        init = await mcp_client.post(
            "/mcp", headers=mcp_headers(token),
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "pytest", "version": "1"}}},
        )
        session_id = init.headers["Mcp-Session-Id"]
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert response.status_code == 202
        assert not response.content

    async def test_a_second_initialize_on_a_live_session_is_refused(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        """Re-negotiating mid-session would let a client change the agreed
        revision after the handshake. Not a spec clause -- a strengthening,
        recorded as such in the conformance matrix."""
        session_id, token = mcp_initialized
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 9, "method": "initialize",
                  "params": {"protocolVersion": "2025-06-18"}},
        )
        assert "error" in response.json()

    async def test_tools_list_before_initialized_notification_is_refused(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        """The handshake is not complete until `notifications/initialized`."""
        token = mcp_token(risk_agent.did)
        init = await mcp_client.post(
            "/mcp", headers=mcp_headers(token),
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "pytest", "version": "1"}}},
        )
        session_id = init.headers["Mcp-Session-Id"]
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        assert "error" in response.json()

    async def test_ping_is_allowed_before_the_handshake_completes(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        """"The client SHOULD NOT send requests other than pings before ..."."""
        token = mcp_token(risk_agent.did)
        init = await mcp_client.post(
            "/mcp", headers=mcp_headers(token),
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "pytest", "version": "1"}}},
        )
        session_id = init.headers["Mcp-Session-Id"]
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
        )
        assert response.json()["result"] == {}


class TestStreamableHTTPTransport:
    """Transport requirements for POST, GET and DELETE on the MCP endpoint."""

    async def test_accept_must_list_both_content_types(
        self, mcp_client, mcp_token, risk_agent
    ):
        """"The client MUST include an Accept header, listing both
        application/json and text/event-stream"."""
        response = await mcp_client.post(
            "/mcp",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {mcp_token(risk_agent.did)}",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 400

    async def test_a_non_json_content_type_is_refused(
        self, mcp_client, mcp_token, risk_agent
    ):
        response = await mcp_client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "text/plain",
                "Authorization": f"Bearer {mcp_token(risk_agent.did)}",
            },
            content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
        )
        assert response.status_code == 415

    async def test_get_returns_405_when_no_sse_stream_is_offered(self, mcp_client):
        """"...or else return HTTP 405 Method Not Allowed, indicating that the
        server does not offer an SSE stream at this endpoint"."""
        response = await mcp_client.get(
            "/mcp", headers={"Accept": "text/event-stream"}
        )
        assert response.status_code == 405

    async def test_a_request_gets_an_application_json_response(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        """"the server MUST either return Content-Type: text/event-stream ...
        or application/json, to return one JSON object"."""
        session_id, token = mcp_initialized
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        )
        assert response.headers["content-type"].startswith("application/json")

    async def test_an_unsupported_protocol_version_header_is_400(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        """"If the server receives a request with an invalid or unsupported
        MCP-Protocol-Version, it MUST respond with 400 Bad Request"."""
        session_id, token = mcp_initialized
        response = await mcp_client.post(
            "/mcp",
            headers=mcp_headers(
                token, session_id, **{"MCP-Protocol-Version": "1999-01-01"}
            ),
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        )
        assert response.status_code == 400

    async def test_the_negotiated_protocol_version_header_is_accepted(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        session_id, token = mcp_initialized
        response = await mcp_client.post(
            "/mcp",
            headers=mcp_headers(
                token, session_id, **{"MCP-Protocol-Version": "2025-06-18"}
            ),
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        )
        assert response.status_code == 200

    async def test_a_missing_session_id_is_400(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        """"Servers that require a session ID SHOULD respond to requests
        without an Mcp-Session-Id header (other than initialization) with
        HTTP 400 Bad Request"."""
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(mcp_token(risk_agent.did)),
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        )
        assert response.status_code == 400

    async def test_an_unknown_session_id_is_404(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        """"The server MAY terminate the session at any time, after which it
        MUST respond to requests containing that session ID with HTTP 404"."""
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(mcp_token(risk_agent.did), "no-such-session"),
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        )
        assert response.status_code == 404

    async def test_delete_terminates_the_session(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        """"Clients ... SHOULD send an HTTP DELETE to the MCP endpoint with
        the Mcp-Session-Id header, to explicitly terminate the session"."""
        session_id, token = mcp_initialized
        deleted = await mcp_client.delete(
            "/mcp", headers=mcp_headers(token, session_id)
        )
        assert deleted.status_code == 204

        # And the terminated session is then 404, per the same clause.
        after = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
        )
        assert after.status_code == 404

    async def test_an_unparseable_body_is_a_jsonrpc_parse_error(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(mcp_token(risk_agent.did)),
            content=b"{ not json",
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == PARSE_ERROR

    async def test_a_batch_is_refused_over_http(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(mcp_token(risk_agent.did)),
            content=json.dumps([
                {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            ]).encode(),
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == INVALID_REQUEST


class TestOriginValidation:
    """"Servers MUST validate the Origin header on all incoming connections
    to prevent DNS rebinding attacks"."""

    async def test_a_browser_origin_is_rejected_by_default(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        response = await mcp_client.post(
            "/mcp",
            headers=mcp_headers(
                mcp_token(risk_agent.did), **{"Origin": "http://evil.example"}
            ),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 403

    async def test_origin_is_checked_before_authentication(
        self, mcp_client, mcp_headers
    ):
        """A rebinding attack rides a browser that ALREADY holds credentials.

        Checking the token first would authenticate the victim and only then
        ask whether the page was allowed to make the call. So a bad Origin
        must lose even with no token at all -- 403, not 401.
        """
        response = await mcp_client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "Origin": "http://evil.example",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 403

    async def test_a_request_with_no_origin_is_allowed(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        """`Origin` is set by browsers. A service-to-service agent sends none,
        and the rebinding attack being defended against always carries one."""
        session_id, token = mcp_initialized
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 5, "method": "ping"},
        )
        assert response.status_code == 200


class TestMethodDispatch:
    async def test_an_unknown_method_is_method_not_found(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        session_id, token = mcp_initialized
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 7, "method": "resources/list"},
        )
        assert response.json()["error"]["code"] == METHOD_NOT_FOUND

    async def test_an_unknown_notification_is_accepted_silently(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        """"The receiver MUST NOT send a response" to a notification."""
        session_id, token = mcp_initialized
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "method": "notifications/cancelled"},
        )
        assert response.status_code == 202

    async def test_the_response_id_matches_the_request_id(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        """"Responses MUST include the same ID as the request"."""
        session_id, token = mcp_initialized
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": "abc-123", "method": "tools/list"},
        )
        assert response.json()["id"] == "abc-123"


class TestToolsList:
    async def test_tools_list_returns_name_description_and_input_schema(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        session_id, token = mcp_initialized
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        )
        tools = response.json()["result"]["tools"]
        assert tools
        for tool in tools:
            assert tool["name"]
            assert tool["description"]
            assert tool["inputSchema"]["type"] == "object"

    async def test_no_next_cursor_is_emitted(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        """This server returns one page, so it must not advertise another."""
        session_id, token = mcp_initialized
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        )
        assert "nextCursor" not in response.json()["result"]

    async def test_a_cursor_this_server_never_issued_is_refused(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        session_id, token = mcp_initialized
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list",
                  "params": {"cursor": "fabricated"}},
        )
        assert "error" in response.json()


class TestProtectedResourceMetadata:
    """"MCP servers MUST implement OAuth 2.0 Protected Resource Metadata"."""

    async def test_the_well_known_document_is_served(self, mcp_client):
        response = await mcp_client.get("/.well-known/oauth-protected-resource")
        assert response.status_code == 200
        body = response.json()
        # "...MUST include the authorization_servers field containing at
        # least one authorization server."
        assert body["authorization_servers"]
        assert body["resource"]

    async def test_the_metadata_document_needs_no_token(self, mcp_client):
        """Its entire job is to tell a client without a token where to get
        one, so requiring a token would make it useless."""
        response = await mcp_client.get("/.well-known/oauth-protected-resource")
        assert response.status_code == 200

    async def test_a_401_carries_www_authenticate_with_resource_metadata(
        self, mcp_client, mcp_headers
    ):
        """RFC 9728 s5.1, made mandatory by MCP: "MCP servers MUST use the
        HTTP header WWW-Authenticate when returning a 401 Unauthorized to
        indicate the location of the resource server metadata URL"."""
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 401
        challenge = response.headers["WWW-Authenticate"]
        assert challenge.startswith("Bearer")
        assert "resource_metadata=" in challenge
