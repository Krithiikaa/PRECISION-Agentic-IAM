"""MCP transport security (Phase 8): authentication, binding, replay.

WHAT THIS FILE IS FOR. Every test here attacks the transport rather than the
policy engine: forged and borrowed tokens, somebody else's session, a replayed
call, an argument the schema never declared. The authorization chain is
exercised in test_mcp_authorization.py.

THE INVARIANT RUNNING THROUGH ALL OF IT:

    AUTHENTICATION IS NOT AUTHORIZATION, AND A SESSION IS NOT AN IDENTITY.

A valid token proves control of a Keycloak client. It does not prove the
agent is registered, is ACTIVE, holds any credential, or may do anything at
all -- and a session id, which travels in a header on every request, proves
nothing by itself.
"""
from __future__ import annotations

import time

import pytest

from app.db.models.mcp import MCPInvocation, MCPSession, MCPSessionStatus

pytestmark = pytest.mark.integration


class TestTokenValidation:
    """The server is an OAuth 2.1 Resource Server. Every check is real."""

    async def test_no_token_is_401(self, mcp_client, mcp_headers):
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 401

    async def test_a_garbage_token_is_401(self, mcp_client, mcp_headers):
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers("not-a-jwt"),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 401

    async def test_an_expired_token_is_401(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        now = int(time.time())
        token = mcp_token(risk_agent.did, iat=now - 7200, exp=now - 3600)
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 401

    async def test_a_token_for_another_audience_is_401(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        """THE CROSS-SERVICE REUSE TEST, and the spec is emphatic about it:
        "MCP servers MUST only accept tokens specifically intended for
        themselves and MUST reject tokens that do not include them in the
        audience claim".

        `agentic-iam-api` is the HUMAN console's audience. A token minted for
        a loan officer's browser session must not open an agent's MCP
        session, which is exactly what one shared audience would allow.
        """
        token = mcp_token(risk_agent.did, aud="agentic-iam-api")
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 401

    async def test_a_token_from_another_issuer_is_401(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        token = mcp_token(risk_agent.did, iss="http://evil.example/realms/x")
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 401

    async def test_an_unsigned_token_is_401(self, mcp_client, mcp_headers):
        """ALGORITHM CONFUSION, closed. `alg: none` is the oldest JWT attack
        there is, and an allow-list rather than a deny-list is what stops it.
        """
        import jwt as pyjwt

        from app.core.config import get_settings

        settings = get_settings()
        now = int(time.time())
        token = pyjwt.encode(
            {
                "iss": settings.keycloak_issuer, "aud": settings.mcp_audience,
                "azp": "did:poc:agent:risk-001", "iat": now, "exp": now + 900,
            },
            key="", algorithm="none",
        )
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 401

    async def test_a_token_with_no_azp_is_401(
        self, mcp_client, mcp_headers, mcp_token
    ):
        token = mcp_token(None)
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 401

    async def test_a_token_whose_azp_is_not_a_did_is_401(
        self, mcp_client, mcp_headers, mcp_token
    ):
        """The console client's token is valid, correctly audienced, and
        still not an agent identity."""
        token = mcp_token("agentic-iam-console")
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 401

    async def test_a_token_in_the_query_string_is_not_accepted(
        self, mcp_client, mcp_headers, mcp_token, risk_agent
    ):
        """"Access tokens MUST NOT be included in the URI query string".

        There is deliberately no fallback that reads one, so presenting it
        that way is the same as presenting nothing.
        """
        token = mcp_token(risk_agent.did)
        response = await mcp_client.post(
            f"/mcp?access_token={token}", headers=mcp_headers(),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 401

    async def test_identity_binds_on_azp_and_not_on_sub(
        self, mcp_client, mcp_headers, mcp_token, risk_agent, session
    ):
        """THE IDENTITY CONFUSION TEST.

        `sub` is a Keycloak service-account UUID and `azp` is the client,
        whose id IS the agent DID. A server that bound on `sub` would
        authenticate fine and attribute the session to the wrong principal.
        Giving the two different values is the only way to tell which one the
        server used.
        """
        token = mcp_token(risk_agent.did, sub="00000000-dead-beef-0000-000000000000")
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token),
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "pytest", "version": "1"}}},
        )
        session_id = response.headers["Mcp-Session-Id"]

        from sqlalchemy import select
        record = (await session.execute(
            select(MCPSession).where(MCPSession.session_id == session_id)
        )).scalar_one()
        assert record.agent_did == risk_agent.did
        assert record.agent_did != "00000000-dead-beef-0000-000000000000"

    async def test_an_identity_provider_outage_fails_closed(
        self, mcp_app, mcp_client, mcp_headers, mcp_token, risk_agent, monkeypatch
    ):
        """Not being able to reach the JWKS is a reason to REFUSE, never
        permission to skip the check."""
        from app.api.routes import mcp as mcp_routes
        from app.protocols.mcp.auth import MCPAuthenticationError, MCPAuthReason

        def unreachable(token):
            raise MCPAuthenticationError(
                MCPAuthReason.KEYS_UNAVAILABLE, "jwks unreachable"
            )

        monkeypatch.setattr(mcp_routes._validator, "_signing_key", unreachable)
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(mcp_token(risk_agent.did)),
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code == 401


class TestSessionBinding:
    """A session id is a correlation handle, never a credential."""

    async def test_another_agents_session_cannot_be_used(
        self, mcp_client, mcp_headers, mcp_token, mcp_initialized, payments_agent
    ):
        """THE CENTRAL SESSION TEST.

        Agent B holds a perfectly valid token of its own and presents agent
        A's session id. Both halves are individually legitimate; the
        combination is not.
        """
        session_id, _ = mcp_initialized
        other_token = mcp_token(payments_agent.did)
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(other_token, session_id),
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        )
        assert response.status_code == 404

    async def test_a_borrowed_session_is_indistinguishable_from_an_unknown_one(
        self, mcp_client, mcp_headers, mcp_token, mcp_initialized, payments_agent
    ):
        """The ownership check runs BEFORE the status checks, so an attacker
        presenting somebody else's id cannot learn whether that session is
        live, terminated or expired. Both answers must look identical."""
        session_id, _ = mcp_initialized
        token = mcp_token(payments_agent.did)

        borrowed = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        )
        unknown = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, "totally-made-up"),
            json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
        )
        assert borrowed.status_code == unknown.status_code == 404
        assert borrowed.json()["error"]["message"] == \
            unknown.json()["error"]["message"]

    async def test_a_terminated_session_cannot_be_reused(
        self, mcp_client, mcp_headers, mcp_initialized
    ):
        session_id, token = mcp_initialized
        await mcp_client.delete("/mcp", headers=mcp_headers(token, session_id))
        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 5, "method": "tools/list"},
        )
        assert response.status_code == 404

    async def test_an_idle_session_expires(
        self, mcp_client, mcp_headers, mcp_initialized, session
    ):
        """A session outliving the token that created it is a row with no
        live authority behind it."""
        from datetime import datetime, timedelta, timezone

        from sqlalchemy import select

        session_id, token = mcp_initialized
        record = (await session.execute(
            select(MCPSession).where(MCPSession.session_id == session_id)
        )).scalar_one()
        record.last_activity_at = datetime.now(timezone.utc) - timedelta(hours=4)
        await session.flush()

        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 6, "method": "tools/list"},
        )
        assert response.status_code == 404

    async def test_revoking_an_agent_closes_its_sessions(
        self, mcp_client, mcp_headers, mcp_initialized, session, risk_agent
    ):
        """A CONVENIENCE, NOT THE CONTROL -- revocation is already effective
        through the PIP on every evaluation. This makes the refusal fast and
        legible at the transport instead of at the policy engine."""
        from sqlalchemy import select

        from app.protocols.mcp.session import MCPSessionService

        session_id, token = mcp_initialized
        closed = await MCPSessionService(session).revoke_for_agent(risk_agent.did)
        assert closed >= 1

        record = (await session.execute(
            select(MCPSession).where(MCPSession.session_id == session_id)
        )).scalar_one()
        assert record.status is MCPSessionStatus.REVOKED

        response = await mcp_client.post(
            "/mcp", headers=mcp_headers(token, session_id),
            json={"jsonrpc": "2.0", "id": 7, "method": "tools/list"},
        )
        assert response.status_code == 404


class TestArgumentValidation:
    """Strict, allow-list validation against the tool's declared schema."""

    async def test_an_undeclared_argument_is_refused(
        self, mcp_client, mcp_headers, mcp_initialized, mcp_call, mcp_policy_loaded
    ):
        """Rejected rather than dropped. A validator that silently discards
        unknown fields invites a caller to smuggle one past review in the
        hope that some layer downstream reads it."""
        session_id, token = mcp_initialized
        response = await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": "customer-007", "admin_override": True},
        )
        assert response.json()["error"]["code"] == -32602

    async def test_a_missing_required_argument_is_refused(
        self, mcp_client, mcp_headers, mcp_initialized, mcp_call, mcp_policy_loaded
    ):
        session_id, token = mcp_initialized
        response = await mcp_call(
            session_id, token, tool="get_credit_profile", arguments={},
        )
        assert response.json()["error"]["code"] == -32602

    async def test_a_wrongly_typed_argument_is_refused(
        self, mcp_client, mcp_headers, mcp_initialized, mcp_call, mcp_policy_loaded
    ):
        session_id, token = mcp_initialized
        response = await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": 12345},
        )
        assert response.json()["error"]["code"] == -32602

    async def test_an_unknown_tool_is_a_protocol_error(
        self, mcp_client, mcp_headers, mcp_initialized, mcp_call, mcp_policy_loaded
    ):
        """The spec's own example of -32602 is "Unknown tool"."""
        session_id, token = mcp_initialized
        response = await mcp_call(
            session_id, token, tool="rm_minus_rf", arguments={},
        )
        assert response.json()["error"]["code"] == -32602

    async def test_a_tool_not_in_the_registry_cannot_be_reached_by_renaming(
        self, mcp_client, mcp_headers, mcp_initialized, mcp_call, mcp_policy_loaded
    ):
        """The registry is the only source of tools. There is no second list
        the MCP layer maintains that could drift from it."""
        session_id, token = mcp_initialized
        response = await mcp_call(
            session_id, token, tool="get_credit_profile ", arguments={},
        )
        assert "error" in response.json()


class TestPurposeIsRequired:
    async def test_a_call_with_no_purpose_is_refused(
        self, mcp_client, mcp_headers, mcp_initialized, mcp_call, mcp_policy_loaded
    ):
        """FAILS CLOSED. There is no default purpose, and none is inferred
        from the tool: deriving purpose from the action would collapse the
        two concepts Phase 4 deliberately separated."""
        session_id, token = mcp_initialized
        response = await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose=None,
        )
        error = response.json()["error"]
        assert error["code"] == -32602
        assert error["data"]["reason"] == "MCP_PURPOSE_MISSING"

    async def test_a_malformed_purpose_is_refused(
        self, mcp_client, mcp_headers, mcp_initialized, mcp_call, mcp_policy_loaded
    ):
        session_id, token = mcp_initialized
        response = await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="Not A Token!",
        )
        assert response.json()["error"]["data"]["reason"] == "MCP_PURPOSE_MALFORMED"


class TestReplayAndIdempotency:
    async def test_the_same_call_twice_executes_once(
        self, mcp_client, mcp_headers, mcp_initialized, mcp_call, session,
        issued_credential, mcp_policy_loaded, policies_loaded,
    ):
        """A client that did not see a response must be able to ask again and
        learn the outcome, WITHOUT the side effect happening twice."""
        from sqlalchemy import func, select

        session_id, token = mcp_initialized
        first = await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": "customer-007"}, request_id="rpc-1",
        )
        second = await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": "customer-007"}, request_id="rpc-1",
        )
        assert first.status_code == second.status_code == 200

        count = (await session.execute(
            select(func.count()).select_from(MCPInvocation).where(
                MCPInvocation.session_id == session_id,
                MCPInvocation.request_id == "rpc-1",
            )
        )).scalar_one()
        assert count == 1

    async def test_a_reused_request_id_with_different_content_is_refused(
        self, mcp_client, mcp_headers, mcp_initialized, mcp_call,
        issued_credential, mcp_policy_loaded, policies_loaded,
    ):
        """An attack, not a retry, and refused as one: a client resending the
        identical call is answered idempotently, a client reusing an id to
        carry something else is not."""
        session_id, token = mcp_initialized
        await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": "customer-007"}, request_id="rpc-2",
        )
        response = await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": "customer-042"}, request_id="rpc-2",
        )
        body = response.json()
        assert "error" in body
        assert body["error"]["data"]["reason"] == "MCP_REQUEST_ID_REUSE"

    async def test_the_same_request_id_in_a_different_session_is_fine(
        self, mcp_client, mcp_headers, mcp_token, mcp_call, risk_agent,
        issued_credential, mcp_policy_loaded, policies_loaded,
    ):
        """Uniqueness is COMPOSITE. The JSON-RPC id is the client's own
        identifier, unique only within its session -- a global unique would
        let one agent squat on another's id namespace."""
        async def open_session():
            token = mcp_token(risk_agent.did)
            init = await mcp_client.post(
                "/mcp", headers=mcp_headers(token),
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2025-06-18",
                                 "capabilities": {},
                                 "clientInfo": {"name": "p", "version": "1"}}},
            )
            sid = init.headers["Mcp-Session-Id"]
            await mcp_client.post(
                "/mcp", headers=mcp_headers(token, sid),
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
            return sid, token

        s1, t1 = await open_session()
        s2, t2 = await open_session()
        first = await mcp_call(
            s1, t1, tool="get_credit_profile",
            arguments={"customer_id": "customer-007"}, request_id="shared-id",
        )
        second = await mcp_call(
            s2, t2, tool="get_credit_profile",
            arguments={"customer_id": "customer-007"}, request_id="shared-id",
        )
        assert "error" not in first.json()
        assert "error" not in second.json()
