"""Exactly-once MCP invocation under genuine concurrency (Phase 8).

REAL CONCURRENT TASKS ON REAL CONNECTIONS. A test that awaits one coroutine
at a time is not testing a race, and a "race" whose tasks share one session
cannot even see each other's uncommitted rows -- which would prove nothing.
Every test here commits, so the contention is real. Same construction as
test_a2a_concurrency.py, for the same reason.

THE ASSERTION THAT MATTERS IS ALWAYS THE RECORD, never a response. A test
that only checked responses could not tell one execution from two that both
reported success.

The mechanism under test is `UNIQUE (session_id, request_id)`. It is the
database that settles this, not application code: twenty workers all reach
the INSERT and exactly one wins it.
"""
from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.authorization.pdp import PolicyDecisionPoint
from app.core.config import get_settings
from app.db.models.hitl import ApprovalRequest
from app.db.models.mcp import MCPInvocation, MCPInvocationStatus, MCPSession
from app.enforcement.aem import AdapterEnforcementMiddleware
from app.protocols.mcp.jsonrpc import JSONRPCError, JSONRPCMessage
from app.protocols.mcp.protocol import MCPServer
from app.protocols.mcp.service import MCPInvocationService
from app.protocols.mcp.session import MCPSessionService

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]


def _message(request_id: str, tool: str, arguments: dict, purpose: str):
    return JSONRPCMessage(
        method="tools/call",
        id=request_id,
        has_id=True,
        params={
            "name": tool,
            "arguments": arguments,
            "_meta": {get_settings().mcp_purpose_meta_key: purpose},
        },
    )


async def _principal(agent_did: str):
    from app.protocols.mcp.auth import MCPPrincipal

    return MCPPrincipal(
        agent_did=agent_did, token_jti="concurrency-test",
        issuer=get_settings().keycloak_issuer,
        audience=get_settings().mcp_audience,
        expires_at=2 ** 31 - 1, issued_at=0,
    )


class TestConcurrentDuplicateInvocation:
    async def test_twenty_concurrent_identical_calls_record_one_invocation(
        self, engine, session, keystore, risk_agent, issued_credential,
        mcp_policy_loaded, opa_client,
    ):
        """THE CENTRAL EXACTLY-ONCE PROPERTY FOR MCP.

        Twenty callers present the SAME (session, request id) at the same
        instant. One wins the INSERT and runs the call; nineteen discover
        they lost and are answered from the recorded outcome.
        """
        sessions = MCPSessionService(session, get_settings())
        record = await sessions.create(
            agent_did=risk_agent.did, protocol_version="2025-06-18",
            client_name="pytest", client_version="1",
            client_capabilities={}, token_jti="t", token_expires_at=None,
        )
        await sessions.mark_initialized(record)
        session_id = record.session_id
        await session.commit()

        maker = async_sessionmaker(bind=engine, expire_on_commit=False)
        principal = await _principal(risk_agent.did)

        async def invoke(_n: int):
            async with maker() as s:
                aem = AdapterEnforcementMiddleware(
                    s, keystore, get_settings(),
                    pdp=PolicyDecisionPoint(
                        s, keystore, get_settings(), opa=opa_client
                    ),
                )
                server = MCPServer(
                    aem=aem,
                    sessions=MCPSessionService(s, get_settings()),
                    invocations=MCPInvocationService(s, get_settings()),
                )
                live = (await s.execute(
                    select(MCPSession).where(MCPSession.session_id == session_id)
                )).scalar_one()
                try:
                    result = await server.handle_tools_call(
                        _message("race-1", "get_credit_profile",
                                 {"customer_id": "customer-007"},
                                 "loan_assessment"),
                        principal=principal, mcp_session=live,
                    )
                    await s.commit()
                    return result
                except JSONRPCError as exc:
                    await s.rollback()
                    return {"protocol_error": exc.code}

        results = await asyncio.gather(
            *(invoke(n) for n in range(20)), return_exceptions=True
        )
        assert len(results) == 20

        # ONE ledger row. The database admitted exactly one processing path.
        count = (await session.execute(
            select(func.count()).select_from(MCPInvocation).where(
                MCPInvocation.session_id == session_id,
                MCPInvocation.request_id == "race-1",
            )
        )).scalar_one()
        assert count == 1, f"{count} invocation rows for one request id"

        row = (await session.execute(
            select(MCPInvocation).where(
                MCPInvocation.session_id == session_id,
                MCPInvocation.request_id == "race-1",
            )
        )).scalar_one()
        assert row.status is MCPInvocationStatus.EXECUTED

    async def test_concurrent_escalation_opens_exactly_one_approval(
        self, engine, session, keystore, risk_agent, loan_credential,
        mcp_policy_loaded, opa_client, approval_authority,
    ):
        """A REAL SIDE EFFECT, not just a ledger row.

        Opening an approval request is a state change a human will act on.
        Ten concurrent submissions of one escalating call must produce ONE
        request, not ten -- otherwise a dual-control queue could be flooded
        into meaninglessness by a retry loop.
        """
        sessions = MCPSessionService(session, get_settings())
        record = await sessions.create(
            agent_did=risk_agent.did, protocol_version="2025-06-18",
            client_name="pytest", client_version="1",
            client_capabilities={}, token_jti="t", token_expires_at=None,
        )
        await sessions.mark_initialized(record)
        session_id = record.session_id
        await session.commit()

        before = (await session.execute(
            select(func.count()).select_from(ApprovalRequest)
        )).scalar_one()

        maker = async_sessionmaker(bind=engine, expire_on_commit=False)
        principal = await _principal(risk_agent.did)

        async def invoke(_n: int):
            async with maker() as s:
                aem = AdapterEnforcementMiddleware(
                    s, keystore, get_settings(),
                    pdp=PolicyDecisionPoint(
                        s, keystore, get_settings(), opa=opa_client
                    ),
                )
                server = MCPServer(
                    aem=aem,
                    sessions=MCPSessionService(s, get_settings()),
                    invocations=MCPInvocationService(s, get_settings()),
                )
                live = (await s.execute(
                    select(MCPSession).where(MCPSession.session_id == session_id)
                )).scalar_one()
                try:
                    out = await server.handle_tools_call(
                        _message("race-escalate", "approve_loan_application",
                                 {"application_id": "loan-9001"},
                                 "loan_decision"),
                        principal=principal, mcp_session=live,
                    )
                    await s.commit()
                    return out
                except JSONRPCError as exc:
                    await s.rollback()
                    return {"protocol_error": exc.code}

        await asyncio.gather(*(invoke(n) for n in range(10)),
                             return_exceptions=True)

        rows = (await session.execute(
            select(func.count()).select_from(MCPInvocation).where(
                MCPInvocation.session_id == session_id,
                MCPInvocation.request_id == "race-escalate",
            )
        )).scalar_one()
        assert rows == 1

        after = (await session.execute(
            select(func.count()).select_from(ApprovalRequest)
        )).scalar_one()
        assert after - before == 1, (
            f"{after - before} approval requests opened by one escalating call"
        )

    async def test_two_different_request_ids_both_proceed(
        self, engine, session, keystore, risk_agent, issued_credential,
        mcp_policy_loaded, opa_client,
    ):
        """The control is deduplication, NOT serialisation. Two genuinely
        different calls in one session must both be processed -- a mechanism
        that blocked the second would be a correctness bug dressed as a
        safety property."""
        sessions = MCPSessionService(session, get_settings())
        record = await sessions.create(
            agent_did=risk_agent.did, protocol_version="2025-06-18",
            client_name="pytest", client_version="1",
            client_capabilities={}, token_jti="t", token_expires_at=None,
        )
        await sessions.mark_initialized(record)
        session_id = record.session_id
        await session.commit()

        maker = async_sessionmaker(bind=engine, expire_on_commit=False)
        principal = await _principal(risk_agent.did)

        async def invoke(request_id: str):
            async with maker() as s:
                aem = AdapterEnforcementMiddleware(
                    s, keystore, get_settings(),
                    pdp=PolicyDecisionPoint(
                        s, keystore, get_settings(), opa=opa_client
                    ),
                )
                server = MCPServer(
                    aem=aem,
                    sessions=MCPSessionService(s, get_settings()),
                    invocations=MCPInvocationService(s, get_settings()),
                )
                live = (await s.execute(
                    select(MCPSession).where(MCPSession.session_id == session_id)
                )).scalar_one()
                out = await server.handle_tools_call(
                    _message(request_id, "get_credit_profile",
                             {"customer_id": "customer-007"}, "loan_assessment"),
                    principal=principal, mcp_session=live,
                )
                await s.commit()
                return out

        await asyncio.gather(invoke("distinct-a"), invoke("distinct-b"))

        executed = (await session.execute(
            select(func.count()).select_from(MCPInvocation).where(
                MCPInvocation.session_id == session_id,
                MCPInvocation.status == MCPInvocationStatus.EXECUTED,
            )
        )).scalar_one()
        assert executed == 2
