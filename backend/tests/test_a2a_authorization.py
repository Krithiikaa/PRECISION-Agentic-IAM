"""A2A authorization: the signature is an input, and nothing more.

THE PROPERTY UNDER TEST:

    Every A2A transaction reaches the PDP, and every ordinary rule still
    runs -- against the SENDER.

A perfectly signed envelope from an agent whose credential was revoked a
second ago is refused, and it is refused by the SAME rule that refuses an
ordinary request. Phase 7 added no exemption.
"""
from __future__ import annotations

import pytest

from app.authorization.contracts import Reason
from app.enforcement.resources import payment_execution_count
from app.protocols.a2a.envelope import A2AReason

pytestmark = pytest.mark.asyncio


class TestTheSignatureIsNotAuthorization:
    async def test_a_valid_signature_alone_does_not_allow(
        self, submit_a2a, a2a_envelope, session, payment_credential
    ):
        """THE test that proves a signature is not authorization.

        The envelope is untouched: correctly signed, fresh, addressed to the
        right receiver, reconciled. The credential it rested on is revoked,
        and the transaction is refused anyway -- by the SAME Phase 4 rule
        that refuses an ordinary request. Phase 7 added no exemption.
        """
        from app.credentials.status import CredentialStatusService

        envelope = a2a_envelope(resource_id="pay-3310")
        await CredentialStatusService(session).revoke(
            payment_credential.credential_id, reason="compromised")

        result = await submit_a2a(envelope)
        assert result.executed is False
        assert result.decision.decision.value == "DENY"
        assert result.decision.reason == Reason.CREDENTIAL_REVOKED
        assert payment_execution_count("pay-3310") == 0
        # And the ENVELOPE is still a perfectly good signed document -- it is
        # the LIVE evaluation that refused, not the artifact.
        assert result.decision.evaluation["pip"]["a2a"]["valid"] is True

    async def test_a_suspended_sender_is_refused_before_the_pdp(
        self, submit_a2a, a2a_envelope, risk_agent, session
    ):
        """"Suspend the agent" is the first move in an incident, and it has
        to mean something on its own."""
        from app.db.models.agent import AgentStatus

        envelope = a2a_envelope(resource_id="pay-3310")
        risk_agent.status = AgentStatus.SUSPENDED
        await session.flush()

        result = await submit_a2a(envelope)
        assert result.accepted is False
        assert result.reason == A2AReason.SENDER_NOT_ELIGIBLE
        assert result.decision is None
        assert payment_execution_count("pay-3310") == 0

    async def test_the_pdp_is_asked_on_every_transaction(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope())
        assert result.decision is not None
        stages = [s["name"] for s in result.decision.to_dict()["stages"]]
        assert "pip" in stages and "opa" in stages

    async def test_the_subject_of_the_decision_is_the_SENDER(
        self, submit_a2a, a2a_envelope, risk_agent
    ):
        """A2A authorizes the sender. The receiver's authority is never
        borrowed -- that is the confused-deputy mitigation."""
        result = await submit_a2a(a2a_envelope())
        assert result.decision.subject_did == risk_agent.did

    async def test_the_action_and_resource_come_from_the_signed_envelope(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope())
        assert result.decision.action == "execute_payment"
        assert result.decision.resource_type == "payment_instructions"
        assert result.decision.resource_id == "pay-3310"


class TestTheSenderNeedsItsOwnAuthority:
    async def test_a_sender_with_no_payment_credential_is_denied(
        self, a2a_aem, a2a_envelope, fraud_agent, payments_agent,
        a2a_policy_loaded,
    ):
        """fraud-001 holds no credential naming payment_instructions."""
        envelope = a2a_envelope(sender=fraud_agent.did,
                                signing_agent=fraud_agent,
                                sender_kid=fraud_agent.active_key.kid)
        result = await a2a_aem.enforce_a2a(envelope=envelope,
                                           submitted_by=payments_agent.did)
        assert result.executed is False
        assert result.decision.decision.value == "DENY"
        assert payment_execution_count("pay-3310") == 0

    async def test_a_sender_cannot_borrow_the_receivers_authority(
        self, a2a_aem, a2a_envelope, fraud_agent, payments_agent,
        payment_credential, a2a_policy_loaded, session, credential_issuer,
        issuer_did, payment_claims,
    ):
        """THE CONFUSED DEPUTY.

        payments-001 is the agent that CAN execute payments. fraud-001
        instructs it to. The decision is about fraud-001, and fraud-001
        holds nothing naming payment_instructions -- so the receiver's
        capability does not rub off on the sender.
        """
        from app.credentials.issuer import IssueRequest

        # Give the RECEIVER a payment credential. It changes nothing.
        await credential_issuer.issue(IssueRequest(
            issuer_did=issuer_did, subject_did=payments_agent.did,
            credential_type="AgentCapabilityCredential",
            claims=payment_claims, ttl_seconds=3600))
        await session.flush()

        envelope = a2a_envelope(sender=fraud_agent.did,
                                signing_agent=fraud_agent,
                                sender_kid=fraud_agent.active_key.kid)
        result = await a2a_aem.enforce_a2a(envelope=envelope,
                                           submitted_by=payments_agent.did)
        assert result.executed is False
        assert payment_execution_count("pay-3310") == 0

    async def test_a_purpose_the_credential_was_not_issued_for_is_denied(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(purpose="loan_assessment"))
        assert result.executed is False
        assert result.decision.decision.value == "DENY"

    async def test_a_resource_type_the_credential_does_not_name_is_denied(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(
            action="read", resource_type="payroll_records",
            resource_id="customer-007", amount_inr=None, currency=None))
        assert result.executed is False
        assert result.decision.reason in {
            Reason.RESOURCE_NOT_ALLOWED, "A2A_ACTION_NOT_ELIGIBLE",
        }


class TestActionEligibility:
    async def test_an_action_not_on_the_allow_list_is_denied(
        self, submit_a2a, a2a_envelope
    ):
        """An ALLOW-LIST, never a deny-list: an action nobody has analysed
        for agent-to-agent instruction is not eligible."""
        result = await submit_a2a(a2a_envelope(
            action="read", resource_type="credit_records",
            resource_id="customer-007", purpose="loan_assessment",
            amount_inr=None, currency=None))
        assert result.executed is False
        assert result.decision.reason == "A2A_ACTION_NOT_ELIGIBLE"

    async def test_approve_loan_cannot_be_instructed_over_a2a(
        self, submit_a2a, a2a_envelope, loan_credential
    ):
        """The Phase 5.5 dual-control boundary is on a DIFFERENT resource
        with a different approval flow. Letting an A2A instruction reach it
        would drive that flow through a channel nobody analysed for it.
        """
        result = await submit_a2a(a2a_envelope(
            action="approve_loan", resource_type="loan_applications",
            resource_id="loan-7842", purpose="loan_decision",
            amount_inr=None, currency=None))
        assert result.executed is False
        assert result.decision.reason == "A2A_ACTION_NOT_ELIGIBLE"

    async def test_the_eligible_pair_is_the_one_that_works(
        self, submit_a2a, a2a_envelope
    ):
        assert (await submit_a2a(a2a_envelope())).executed is True


class TestFailClosed:
    async def test_an_unreachable_policy_engine_denies(
        self, a2a_aem, a2a_envelope, payments_agent, payment_credential,
        a2a_policy_loaded, monkeypatch,
    ):
        """There is no permissive fallback. An OPA outage is a denial."""
        from app.authorization.opa import OPAUnavailableError

        async def unreachable(*args, **kwargs):
            raise OPAUnavailableError("OPA is down")

        monkeypatch.setattr(a2a_aem.pdp.opa, "evaluate", unreachable)
        result = await a2a_aem.enforce_a2a(envelope=a2a_envelope(),
                                           submitted_by=payments_agent.did)
        assert result.executed is False
        assert result.decision.reason == Reason.AUTHORIZATION_UNAVAILABLE
        assert payment_execution_count("pay-3310") == 0

    async def test_a_malformed_policy_verdict_denies(
        self, a2a_aem, a2a_envelope, payments_agent, payment_credential,
        a2a_policy_loaded, monkeypatch,
    ):
        """A policy cannot invent a verdict."""
        from app.authorization.opa import OPAResult

        async def nonsense(*args, **kwargs):
            return OPAResult(document={"decision": "MAYBE"}, latency_ms=1.0)

        monkeypatch.setattr(a2a_aem.pdp.opa, "evaluate", nonsense)
        result = await a2a_aem.enforce_a2a(envelope=a2a_envelope(),
                                           submitted_by=payments_agent.did)
        assert result.executed is False
        assert result.decision.reason == Reason.AUTHORIZATION_UNAVAILABLE

    async def test_removing_the_a2a_policy_module_denies(
        self, submit_a2a, a2a_envelope, opa_client
    ):
        """Removing a module must fail CLOSED, not fail to compile.

        There is no other allow rule in the set for this action, so the
        transaction falls to the combining algorithm's default deny.
        """
        from app.authorization.pap import PolicyAdministrationPoint
        from app.core.config import get_settings

        pap = PolicyAdministrationPoint(None, get_settings())
        definition = next(d for d in pap.read_definitions()
                          if d.policy_id == "a2a-transaction")
        await opa_client.delete_policy(definition.module_id)
        try:
            result = await submit_a2a(a2a_envelope())
            assert result.executed is False
            assert result.decision.reason == Reason.NO_MATCHING_POLICY
        finally:
            await opa_client.put_policy(definition.module_id, definition.source)

        assert (await submit_a2a(a2a_envelope())).executed is True


class TestSelfAssertedContextIsStripped:
    async def test_a_sender_cannot_assert_its_own_verdict(
        self, a2a_aem, a2a_envelope, payments_agent, payment_credential,
        a2a_policy_loaded,
    ):
        """The envelope has no field for a verdict, and the context the AEM
        builds carries only transport metadata. A sender has nowhere to put
        `{"allow": true}` -- which is stronger than stripping it."""
        result = await a2a_aem.enforce_a2a(
            envelope=a2a_envelope(resource_id="pay-3311", amount_inr=500_000),
            submitted_by=payments_agent.did)
        # Rs 5,00,000 escalates however the sender describes itself.
        assert result.status == "PENDING_APPROVAL"

    async def test_the_context_carries_no_amount(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope())
        context = result.decision.to_dict()["evaluation"]["pip"]
        # The amount policy decided on is the SERVER's, in pip.resource.
        assert context["resource"]["attributes"]["amount_inr"] == 50_000


class TestNoEnforcementPath:
    async def test_the_tool_is_derived_from_the_signed_action(
        self, submit_a2a, a2a_envelope, session
    ):
        """An envelope cannot be executed through a tool it was not signed
        for, because no caller names the tool."""
        from sqlalchemy import select

        from app.db.models.audit import AuditEvent

        await submit_a2a(a2a_envelope())
        events = (await session.execute(
            select(AuditEvent).where(
                AuditEvent.event_type == "TOOL_EXECUTED"))).scalars().all()
        assert events
        assert events[0].event_metadata["tool"] == "execute_payment_instruction"

    async def test_the_registry_maps_one_pair_to_one_tool(self):
        from app.enforcement.tools import build_default_registry

        registry = build_default_registry()
        tool = registry.for_action("execute_payment", "payment_instructions")
        assert tool.spec.name == "execute_payment_instruction"
        assert registry.for_action("execute_payment", "credit_records") is None
        assert registry.for_action("nonsense", "payment_instructions") is None
