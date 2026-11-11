"""MCP against the rest of the system (Phase 8): JIT, audit, regression.

PHASE 8 ADDED NO JIT CODE AND NO HITL CODE. A mandate offered over MCP is
handled by the machinery Phase 6 already built, and an escalation by what
Phase 5/5.5 built. These tests exist to prove that reusing them really is
reuse -- that the transport did not quietly acquire a second copy of either.

The audit tests check the property the whole phase is auditable by: one
deterministic `request_id` threads the ledger row, the PDP's own events and
the approval, so "what did this agent do over MCP?" is answerable from the
trail without reconstructing it from log lines.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.db.models.mcp import MCPInvocation

pytestmark = pytest.mark.integration


def _result(response):
    body = response.json()
    assert "error" not in body, body
    return body["result"]


class TestJITOverMCP:
    async def test_a_mandate_is_not_required_and_its_absence_denies_nothing(
        self, mcp_initialized, mcp_call, issued_credential, mcp_policy_loaded,
        policies_loaded,
    ):
        """`JITFact.absent()` is a FACT, not a permissive default and not a
        blocker: a request with no mandate is decided exactly as it would
        have been before Phase 6 existed."""
        session_id, token = mcp_initialized
        response = await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": "customer-007"},
        )
        assert _result(response)["isError"] is False

    async def test_a_mandate_cannot_be_issued_for_something_mcp_may_not_carry(
        self, aem, risk_agent, payment_credential, jit_policy_loaded,
        mcp_policy_loaded, policies_loaded,
    ):
        """A MANDATE CANNOT OUTFLANK CHANNEL ELIGIBILITY.

        Issuance runs the full PDP evaluation first, so a mandate can only
        ever be issued for something the agent could do at that instant.
        `execute_payment` is not reachable here, so no mandate exists to
        carry it -- the eligibility rule and the mandate rule agree, and
        neither depends on the other to hold.
        """
        from app.authorization.contracts import Reason

        result = await aem.issue_jit_grant(
            subject_did=risk_agent.did, action="execute_payment",
            resource_type="payment_instructions", resource_ids=["pay-3310"],
            purpose="payment_settlement", ttl_seconds=300, max_uses=3,
        )
        assert result.issued is False
        assert result.reason == Reason.JIT_SCOPE_EXCEEDS_DECISION


class TestAuditCorrelation:
    async def test_one_request_id_threads_the_ledger_and_the_decision(
        self, mcp_initialized, mcp_call, issued_credential, session,
        mcp_policy_loaded, policies_loaded,
    ):
        """The deterministic `mcp-{digest}` id is what makes the arc
        reconstructible. If the ledger and the decision rows carried
        different ids, an auditor could not join them."""
        from app.db.models.authorization import AuthorizationDecisionRecord

        session_id, token = mcp_initialized
        await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": "customer-007"}, request_id="audit-1",
        )
        record = (await session.execute(
            select(MCPInvocation).where(MCPInvocation.request_id == "audit-1")
        )).scalar_one()
        assert record.authorization_request_id.startswith("mcp-")

        decision = (await session.execute(
            select(AuthorizationDecisionRecord).where(
                AuthorizationDecisionRecord.request_id
                == record.authorization_request_id
            )
        )).scalars().all()
        assert decision, "the PDP's decision row does not share the request id"

    async def test_the_audit_trail_names_the_channel(
        self, mcp_initialized, mcp_call, issued_credential, session,
        mcp_policy_loaded, policies_loaded,
    ):
        """An auditor must be able to find every action taken over MCP.

        The channel lives in the TRAIL, never in the grant: the ALLOW reason
        is the action's own policy reason, because `mcp/invocation.rego`
        contributes no allow.
        """
        from app.db.models.audit import AuditEvent

        session_id, token = mcp_initialized
        await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": "customer-007"}, request_id="audit-2",
        )
        events = (await session.execute(
            select(AuditEvent).where(AuditEvent.session_id == session_id)
        )).scalars().all()
        types = {e.event_type for e in events}
        assert "MCP_REQUEST" in types
        assert "MCP_SESSION_CREATED" in types

    async def test_no_token_or_secret_reaches_the_ledger(
        self, mcp_initialized, mcp_call, issued_credential, session,
        mcp_policy_loaded, policies_loaded,
    ):
        """"Do not log private keys, bearer credentials, access tokens,
        sensitive tool arguments, or full confidential resource contents."

        The ledger stores the token's `jti` on the SESSION and nothing
        token-shaped anywhere. Asserted rather than assumed, because the
        easiest way to break it is to add a debugging column and forget.
        """
        from app.db.models.mcp import MCPSession

        session_id, token = mcp_initialized
        await mcp_call(
            session_id, token, tool="get_credit_profile",
            arguments={"customer_id": "customer-007"}, request_id="audit-3",
        )
        row = (await session.execute(
            select(MCPSession).where(MCPSession.session_id == session_id)
        )).scalar_one()

        # The access token is a long JWT. Nothing stored may contain it.
        serialised = " ".join(
            str(getattr(row, c.name)) for c in row.__table__.columns
        )
        assert token not in serialised
        assert "eyJ" not in serialised, "something JWT-shaped is stored"

        invocation = (await session.execute(
            select(MCPInvocation).where(MCPInvocation.request_id == "audit-3")
        )).scalar_one()
        inv_serialised = " ".join(
            str(getattr(invocation, c.name)) for c in invocation.__table__.columns
        )
        assert token not in inv_serialised
        assert "eyJ" not in inv_serialised


class TestPreviousPhasesAreUnaffected:
    async def test_the_direct_api_path_still_works_unchanged(
        self, aem, risk_agent, issued_credential, policies_loaded,
    ):
        """PHASE 8 THREADED AN OPTIONAL `mcp` PARAMETER THROUGH enforce(),
        pdp.decide() AND pip.collect(). All three default to absent, so a
        caller that never heard of MCP must behave exactly as before."""
        result = await aem.enforce(
            subject_did=risk_agent.did,
            tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"},
            purpose="loan_assessment",
        )
        assert result.executed is True
        assert result.decision.decision.value == "ALLOW"

    async def test_an_ordinary_request_reports_mcp_as_absent(
        self, pdp, authz_request, risk_agent, issued_credential, policies_loaded,
    ):
        """`MCPFact.absent()` must be present-and-false, not missing. A rule
        guarding on `present == true` needs the key to exist."""
        decision = await pdp.decide(authz_request(risk_agent.did))
        fact = (decision.evaluation or {}).get("pip", {}).get("mcp")
        assert fact is not None
        assert fact["present"] is False

    async def test_the_a2a_channel_is_untouched_by_phase_8(
        self, submit_a2a, a2a_envelope, issued_credential,
    ):
        """Phase 7's path must not have moved. `enforce_a2a` was not edited
        by Phase 8 and does not pass an MCP fact, so an A2A transaction
        reports MCP absent and is decided exactly as it was."""
        result = await submit_a2a(
            a2a_envelope(resource_id="pay-3310", amount_inr=50_000)
        )
        assert result.accepted is True
        pip = (result.decision.evaluation or {}).get("pip", {})
        assert pip["mcp"]["present"] is False
        assert pip["a2a"]["present"] is True
