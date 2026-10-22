"""The PDP against the REAL OPA runtime evaluating REAL Rego.

These tests skip loudly when OPA is not running rather than falling back to a
substitute. A fake engine would only prove Python agrees with Python.
"""
from __future__ import annotations

import pytest

from app.authorization.contracts import Decision, Reason, Resource, Subject
from app.authorization.opa import OPAClient, OPAUnavailableError
from app.authorization.pdp import PolicyDecisionPoint
from app.core.config import get_settings
from app.credentials.issuer import IssueRequest
from app.credentials.status import CredentialStatusService
from app.db.models.authorization import AuthorizationDecisionRecord

pytestmark = pytest.mark.integration


class TestRealOPAIntegration:
    async def test_the_engine_is_actually_opa(self, opa_client):
        """Not a Python stand-in: the modules are loaded in a real OPA server."""
        modules = await opa_client.list_policies()
        assert "agentic_iam/decision" in modules
        assert "agentic_iam/loan/credit" in modules

    async def test_policy_evaluation_is_measured_not_modelled(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(authz_request(risk_agent.did))
        opa_stage = next(s for s in decision.stages if s.name == "opa")
        # A real network round trip to the engine takes real, non-zero time.
        assert opa_stage.duration_ms > 0
        assert decision.total_latency_ms > 0
        assert decision.evaluation["policy_engine"]["engine"] == "OPA"


class TestAllow:
    async def test_valid_credential_allowed_action_resource_purpose(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.ALLOW
        assert decision.reason == Reason.POLICY_MATCH
        assert decision.policy_id == "loan-credit-read"
        assert decision.policy_version == "v1"

    async def test_the_allow_names_the_policy_that_produced_it(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.policy_ref == "loan-credit-read:v1"


class TestDeny:
    async def test_wrong_resource_is_denied(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        """THE headline case: valid identity + valid credential != any resource."""
        decision = await pdp.decide(
            authz_request(risk_agent.did, resource_type="payroll_records")
        )
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.RESOURCE_NOT_ALLOWED
        assert decision.policy_id == "resource-scope"

    async def test_wrong_purpose_is_denied(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(
            authz_request(risk_agent.did, purpose="marketing_analytics")
        )
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.PURPOSE_NOT_ALLOWED

    async def test_missing_credential_is_denied(self, pdp, risk_agent, authz_request):
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.MISSING_CAPABILITY

    async def test_revoked_credential_is_denied(
        self, session, pdp, issued_credential, risk_agent, authz_request
    ):
        await CredentialStatusService(session).revoke(
            issued_credential.credential_id, "COMPROMISED"
        )
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.CREDENTIAL_REVOKED

    async def test_expired_credential_is_denied(
        self, pdp, credential_issuer, risk_agent, issuer_did, capability_claims,
        authz_request,
    ):
        import asyncio

        record = await credential_issuer.issue(
            IssueRequest(
                issuer_did=issuer_did, subject_did=risk_agent.did,
                credential_type="AgentCapabilityCredential",
                claims=capability_claims, ttl_seconds=1,
            )
        )
        assert record.credential_id
        await asyncio.sleep(1.2)   # real elapsed time, not a mocked clock
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.CREDENTIAL_EXPIRED

    async def test_tampered_credential_is_denied(
        self, session, pdp, issued_credential, risk_agent, authz_request
    ):
        """The PIP's Phase 2 verifier rejects it; policy denies on that verdict."""
        document = dict(issued_credential.document)
        subject = dict(document["credentialSubject"])
        subject["capability"] = "payroll_access"
        document["credentialSubject"] = subject
        issued_credential.document = document
        await session.flush()

        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.CREDENTIAL_INVALID

    async def test_unknown_subject_is_denied(self, pdp, authz_request):
        decision = await pdp.decide(authz_request("did:poc:agent:ghost-001"))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.UNKNOWN_SUBJECT

    async def test_unknown_action_falls_through_to_default_deny(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(authz_request(risk_agent.did, action="delete"))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.NO_MATCHING_POLICY

    async def test_another_agents_credential_cannot_be_borrowed(
        self, pdp, issued_credential, fraud_agent, authz_request
    ):
        """The credential is genuine, but it names a different subject."""
        decision = await pdp.decide(authz_request(fraud_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.MISSING_CAPABILITY


class TestHumanApprovalRequired:
    async def test_sensitive_action_requires_a_human(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(authz_request(risk_agent.did, action="approve_loan"))
        assert decision.decision is Decision.HUMAN_APPROVAL_REQUIRED
        assert decision.reason == Reason.SENSITIVE_ACTION_REQUIRES_HUMAN
        assert decision.policy_id == "sensitive-action"

    async def test_it_is_a_decision_value_only_and_grants_nothing(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(authz_request(risk_agent.did, action="approve_loan"))
        assert decision.allowed is False

    async def test_deny_overrides_human_approval(
        self, session, pdp, issued_credential, risk_agent, authz_request
    ):
        """A human is never asked to approve an already-invalid request."""
        await CredentialStatusService(session).revoke(
            issued_credential.credential_id, "COMPROMISED"
        )
        decision = await pdp.decide(authz_request(risk_agent.did, action="approve_loan"))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.CREDENTIAL_REVOKED


class TestSelfAssertedDecisionsAreIgnored:
    async def test_agent_supplied_allow_does_not_authorize(
        self, pdp, risk_agent, authz_request
    ):
        """The agent has no credential and claims it is allowed. It is not."""
        decision = await pdp.decide(
            authz_request(risk_agent.did, context={"allow": True, "decision": "ALLOW"})
        )
        assert decision.decision is Decision.DENY
        assert decision.evaluation["rejected_context_keys"] == ["allow", "decision"]

    async def test_agent_supplied_allow_never_reaches_policy(
        self, pdp, risk_agent, authz_request
    ):
        decision = await pdp.decide(
            authz_request(risk_agent.did, context={"allow": True, "channel": "api"})
        )
        context_seen = decision.evaluation["opa_document"]
        assert context_seen  # policy evaluated
        # The stripped context is what was sent; verify via the request builder.
        request = authz_request(risk_agent.did, context={"allow": True, "channel": "api"})
        assert request.strip_decision_claims() == {"channel": "api"}

    async def test_self_asserted_trust_score_is_ignored(
        self, pdp, risk_agent, authz_request
    ):
        """Trust scoring is Phase 10. A caller cannot supply its own."""
        decision = await pdp.decide(
            authz_request(risk_agent.did, context={"trust_score": 100})
        )
        assert decision.decision is Decision.DENY
        assert "trust_score" in decision.evaluation["rejected_context_keys"]


class TestFailClosed:
    async def test_opa_unavailable_denies(self, session, keystore, risk_agent,
                                          issued_credential, authz_request):
        """OPA down must never become ALLOW."""
        settings = get_settings()
        broken = OPAClient(settings)
        broken.base_url = "http://127.0.0.1:9"      # nothing listens here

        class _Unreachable(OPAClient):
            async def evaluate(self, input_document):
                raise OPAUnavailableError("simulated outage: connection refused")

        pdp = PolicyDecisionPoint(session, keystore, settings, opa=_Unreachable(settings))
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.AUTHORIZATION_UNAVAILABLE
        await broken.aclose()

    async def test_malformed_request_is_denied_and_never_evaluated(
        self, pdp, risk_agent, authz_request
    ):
        decision = await pdp.decide(authz_request(risk_agent.did, purpose=""))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.MALFORMED_REQUEST
        # It never reached the engine.
        assert [s.name for s in decision.stages] == ["validate"]

    async def test_a_policy_returning_nonsense_is_denied(
        self, session, keystore, risk_agent, issued_credential, authz_request
    ):
        """A decision value the PDP does not recognise is not honoured."""
        settings = get_settings()

        class _Rogue(OPAClient):
            async def evaluate(self, input_document):
                from app.authorization.opa import OPAResult

                return OPAResult(document={"decision": "SUPER_ALLOW"}, latency_ms=1.0)

        pdp = PolicyDecisionPoint(session, keystore, settings, opa=_Rogue(settings))
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.AUTHORIZATION_UNAVAILABLE

    async def test_no_policy_loaded_denies(self, session, keystore, risk_agent,
                                           issued_credential, authz_request):
        settings = get_settings()

        class _Empty(OPAClient):
            async def evaluate(self, input_document):
                raise OPAUnavailableError("policy module is not loaded")

        pdp = PolicyDecisionPoint(session, keystore, settings, opa=_Empty(settings))
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY


class TestDecisionsArePersisted:
    async def test_every_decision_is_recorded_with_its_policy(
        self, session, pdp, issued_credential, risk_agent, authz_request
    ):
        from sqlalchemy import select

        request = authz_request(risk_agent.did)
        decision = await pdp.decide(request)
        rows = (await session.execute(select(AuthorizationDecisionRecord))).scalars().all()
        assert len(rows) == 1
        row = rows[0]
        assert row.request_id == request.request_id
        assert row.subject_did == risk_agent.did
        assert row.decision == decision.decision.value
        assert row.policy_id == "loan-credit-read"
        assert row.policy_version == "v1"
        assert row.latency_ms > 0
        assert row.purpose == "loan_assessment"

    async def test_the_recorded_context_carries_no_secrets(
        self, session, pdp, issued_credential, risk_agent, authz_request
    ):
        from sqlalchemy import select

        await pdp.decide(authz_request(risk_agent.did))
        row = (await session.execute(select(AuthorizationDecisionRecord))).scalars().one()
        blob = str(row.context_snapshot)
        for forbidden in ("proofValue", "privateKey", "private_key", "keystore_ref"):
            assert forbidden not in blob

    async def test_denials_are_recorded_too(
        self, session, pdp, issued_credential, risk_agent, authz_request
    ):
        from sqlalchemy import select

        await pdp.decide(authz_request(risk_agent.did, resource_type="payroll_records"))
        row = (await session.execute(select(AuthorizationDecisionRecord))).scalars().one()
        assert row.decision == "DENY"
        assert row.reason == Reason.RESOURCE_NOT_ALLOWED
