"""The AEM enforcement boundary.

The property under test is not "authorization exists" but "authorization is
actually enforced":

    Agent -> direct tool call -> protected resource      MUST BE IMPOSSIBLE
    Agent -> AEM -> PDP -> ALLOW -> tool                 the only path
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.authorization.contracts import Decision, Reason
from app.credentials.status import CredentialStatusService
from app.db.models.audit import AuditEvent
from app.enforcement.tools import (
    EnforcementBypassError,
    GrantAlreadyUsedError,
    build_default_registry,
    mint_grant,
)
from app.enforcement.aem import UnknownToolError

pytestmark = pytest.mark.integration


class TestEnforcementAllows:
    async def test_authorized_tool_call_returns_real_data(
        self, aem, issued_credential, risk_agent
    ):
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
        )
        assert result.executed is True
        assert result.decision.decision is Decision.ALLOW
        assert result.result["customer_id"] == "customer-007"
        assert result.result["credit_score"] == 742

    async def test_the_allow_is_attributable_to_a_policy(
        self, aem, issued_credential, risk_agent
    ):
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
        )
        assert result.decision.policy_ref == "loan-credit-read:v1"
        assert result.grant["policy"] == "loan-credit-read:v1"

    async def test_enforcement_latency_is_measured(
        self, aem, issued_credential, risk_agent
    ):
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
        )
        assert result.enforcement_ms > 0
        assert result.enforcement_ms >= result.decision.total_latency_ms


class TestEnforcementBlocks:
    async def test_same_agent_same_credential_different_resource_is_blocked(
        self, aem, issued_credential, risk_agent
    ):
        """THE Phase 4 demonstration.

        Identical agent, identical identity, identical valid credential. Only
        the resource differs, and the tool is never called.
        """
        allowed = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
        )
        blocked = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_payroll_record",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
        )
        assert allowed.executed is True
        assert blocked.executed is False
        assert blocked.decision.decision is Decision.DENY
        assert blocked.decision.reason == Reason.RESOURCE_NOT_ALLOWED
        # No payroll data leaked in the denial.
        assert blocked.result is None
        assert "annual_salary_gbp" not in str(blocked.to_dict())

    async def test_revoked_credential_blocks_the_tool(
        self, session, aem, issued_credential, risk_agent
    ):
        await CredentialStatusService(session).revoke(
            issued_credential.credential_id, "COMPROMISED"
        )
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
        )
        assert result.executed is False
        assert result.decision.reason == Reason.CREDENTIAL_REVOKED
        assert result.result is None

    async def test_no_credential_blocks_the_tool(self, aem, risk_agent):
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
        )
        assert result.executed is False
        assert result.decision.reason == Reason.MISSING_CAPABILITY

    async def test_wrong_purpose_blocks_the_tool(
        self, aem, issued_credential, risk_agent
    ):
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="marketing_analytics",
        )
        assert result.executed is False
        assert result.decision.reason == Reason.PURPOSE_NOT_ALLOWED

    async def test_unknown_tool_is_an_error_not_a_fallback(self, aem, risk_agent):
        with pytest.raises(UnknownToolError):
            await aem.enforce(
                subject_did=risk_agent.did, tool_name="get_everything",
                arguments={}, purpose="loan_assessment",
            )


class TestHumanApprovalRequiredBlocks:
    async def test_the_tool_is_not_executed(self, aem, issued_credential, risk_agent):
        """Phase 4 has no approval flow, so the operation simply stops."""
        registry = build_default_registry()
        tool = registry.get("get_credit_profile")
        # Re-declare the same tool with a sensitive action to exercise the path.
        from dataclasses import replace

        tool.spec = replace(tool.spec, action="approve_loan")
        aem.tools = registry

        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
        )
        assert result.executed is False
        assert result.decision.decision is Decision.HUMAN_APPROVAL_REQUIRED
        assert result.decision.reason == Reason.SENSITIVE_ACTION_REQUIRES_HUMAN
        assert result.result is None


class TestDirectAccessIsImpossible:
    """The security property that separates 'authorization exists' from
    'authorization is enforced'."""

    async def test_calling_a_protected_tool_directly_raises(self):
        tool = build_default_registry().get("get_credit_profile")
        with pytest.raises(EnforcementBypassError) as exc:
            await tool(customer_id="customer-007")
        assert "protected tool" in str(exc.value)
        assert "AEM" in str(exc.value)

    async def test_a_forged_grant_is_rejected(self):
        """Constructing the grant type directly does not produce authority."""
        from app.enforcement.tools import EnforcementGrant

        forged = EnforcementGrant(
            request_id="authz-forged", tool_name="get_credit_profile",
            subject_did="did:poc:agent:risk-001", resource_type="credit_records",
            resource_id="customer-007", policy_ref="loan-credit-read:v1",
        )
        assert forged.authentic is False
        tool = build_default_registry().get("get_credit_profile")
        with pytest.raises(EnforcementBypassError) as exc:
            await tool(_grant=forged, customer_id="customer-007")
        assert "not issued by the AEM" in str(exc.value)

    async def test_a_grant_is_single_use(self):
        tool = build_default_registry().get("get_credit_profile")
        grant = mint_grant(
            request_id="authz-1", tool_name="get_credit_profile",
            subject_did="did:poc:agent:risk-001", resource_type="credit_records",
            resource_id="customer-007", policy_ref="loan-credit-read:v1",
        )
        first = await tool(_grant=grant, customer_id="customer-007")
        assert first["customer_id"] == "customer-007"
        with pytest.raises(GrantAlreadyUsedError):
            await tool(_grant=grant, customer_id="customer-007")

    async def test_a_grant_cannot_be_redirected_to_another_resource(self):
        """A decision about customer-007 does not authorise customer-042."""
        tool = build_default_registry().get("get_credit_profile")
        grant = mint_grant(
            request_id="authz-1", tool_name="get_credit_profile",
            subject_did="did:poc:agent:risk-001", resource_type="credit_records",
            resource_id="customer-007", policy_ref="loan-credit-read:v1",
        )
        with pytest.raises(EnforcementBypassError) as exc:
            await tool(_grant=grant, customer_id="customer-042")
        assert "authorises resource" in str(exc.value)

    async def test_a_grant_cannot_be_redirected_to_another_tool(self):
        payroll = build_default_registry().get("get_payroll_record")
        grant = mint_grant(
            request_id="authz-1", tool_name="get_credit_profile",
            subject_did="did:poc:agent:risk-001", resource_type="credit_records",
            resource_id="customer-007", policy_ref="loan-credit-read:v1",
        )
        with pytest.raises(EnforcementBypassError) as exc:
            await payroll(_grant=grant, customer_id="customer-007")
        assert "authorises 'get_credit_profile'" in str(exc.value)

    async def test_protected_tools_are_not_in_any_agent_tool_registry(self):
        """An agent's LLM cannot even see a protected tool, let alone select it."""
        from app.agents.runtime import ToolRegistry

        agent_tools = ToolRegistry()
        assert len(agent_tools) == 0
        for name in build_default_registry().names():
            assert agent_tools.get(name) is None
        assert "no tools are currently available" in agent_tools.describe()


class TestEnforcementIsAudited:
    async def test_an_allowed_call_produces_a_correlated_trail(
        self, session, aem, issued_credential, risk_agent
    ):
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
        )
        request_id = result.decision.request_id
        rows = (await session.execute(
            select(AuditEvent).where(AuditEvent.request_id == request_id)
        )).scalars().all()
        types = [r.event_type for r in rows]
        for expected in ("AEM_INTERCEPT", "AUTHORIZATION_REQUESTED",
                         "PIP_CONTEXT_COLLECTED", "OPA_DECISION", "PDP_EVALUATION",
                         "POLICY_ALLOW", "AEM_ALLOWED", "TOOL_EXECUTED"):
            assert expected in types, f"{expected} missing from {types}"

    async def test_a_blocked_call_records_the_denial_and_no_execution(
        self, session, aem, issued_credential, risk_agent
    ):
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_payroll_record",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
        )
        rows = (await session.execute(
            select(AuditEvent).where(AuditEvent.request_id == result.decision.request_id)
        )).scalars().all()
        types = [r.event_type for r in rows]
        assert "POLICY_DENY" in types
        assert "AEM_BLOCKED" in types
        assert "TOOL_EXECUTED" not in types

    async def test_a_bypass_attempt_can_be_recorded(self, session, aem, risk_agent):
        tool = build_default_registry().get("get_credit_profile")
        try:
            await tool(customer_id="customer-007")
        except EnforcementBypassError as exc:
            await aem.record_bypass_attempt(
                subject_did=risk_agent.did, tool_name="get_credit_profile",
                detail=str(exc),
            )
        rows = (await session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "AEM_BYPASS_ATTEMPT")
        )).scalars().all()
        assert len(rows) == 1
        assert rows[0].decision == "BLOCKED"


class TestAEMContainsNoPolicy:
    async def test_the_aem_does_not_second_guess_the_pdp(
        self, session, keystore, issued_credential, risk_agent
    ):
        """If the PDP says DENY, the AEM blocks -- whatever the credential says.

        Proven by substituting a PDP that always denies. The AEM has no
        independent notion of what should be allowed, so it must block a call
        that policy would otherwise permit.
        """
        from app.authorization.contracts import AuthorizationDecision
        from app.core.config import get_settings
        from app.enforcement.aem import AdapterEnforcementMiddleware

        class _AlwaysDeny:
            async def decide(self, request, record=True):
                return AuthorizationDecision.denied(
                    request.request_id, Reason.INVALID_CONTEXT, request=request,
                )

        aem = AdapterEnforcementMiddleware(
            session, keystore, get_settings(), pdp=_AlwaysDeny(),
        )
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
        )
        assert result.executed is False
        assert result.result is None
