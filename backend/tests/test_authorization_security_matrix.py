"""The Phase 4 security matrix, as one auditable file.

Each test maps to a numbered requirement so the matrix can be read as a
checklist rather than inferred from scattered assertions.

The organising claim under all of it:

    IDENTITY        != AUTHORIZATION
    DISCOVERY       != AUTHORIZATION
    AUTHENTICATION  != AUTHORIZATION
    LLM DECISION    != SECURITY DECISION

    PDP DECISION + AEM ENFORCEMENT = AUTHORIZED ACTION
"""
from __future__ import annotations

import asyncio

import pytest

from app.authorization.contracts import (
    AuthorizationDecision,
    Decision,
    Reason,
    Resource,
    Subject,
)
from app.authorization.opa import OPAClient, OPAUnavailableError
from app.authorization.pdp import PolicyDecisionPoint
from app.core.config import get_settings
from app.credentials.issuer import IssueRequest
from app.credentials.status import CredentialStatusService
from app.enforcement.tools import EnforcementBypassError, build_default_registry

pytestmark = pytest.mark.integration


class TestSecurityMatrix:
    # 1
    async def test_01_valid_identity_valid_credential_allowed_action_allows(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.ALLOW

    # 2
    async def test_02_valid_identity_wrong_resource_denies(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(
            authz_request(risk_agent.did, resource_type="payroll_records")
        )
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.RESOURCE_NOT_ALLOWED

    # 3
    async def test_03_missing_capability_denies(self, pdp, risk_agent, authz_request):
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.MISSING_CAPABILITY

    # 4
    async def test_04_expired_credential_denies(
        self, pdp, credential_issuer, risk_agent, issuer_did, capability_claims,
        authz_request,
    ):
        await credential_issuer.issue(
            IssueRequest(
                issuer_did=issuer_did, subject_did=risk_agent.did,
                credential_type="AgentCapabilityCredential",
                claims=capability_claims, ttl_seconds=1,
            )
        )
        await asyncio.sleep(1.2)
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.CREDENTIAL_EXPIRED

    # 5
    async def test_05_revoked_credential_denies(
        self, session, pdp, issued_credential, risk_agent, authz_request
    ):
        await CredentialStatusService(session).revoke(
            issued_credential.credential_id, "COMPROMISED"
        )
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.CREDENTIAL_REVOKED

    # 6
    async def test_06_invalid_credential_denies(
        self, session, pdp, issued_credential, risk_agent, authz_request
    ):
        document = dict(issued_credential.document)
        subject = dict(document["credentialSubject"])
        subject["allowedResources"] = ["credit_records", "payroll_records"]
        document["credentialSubject"] = subject
        issued_credential.document = document
        await session.flush()

        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.CREDENTIAL_INVALID

    # 7
    async def test_07_wrong_purpose_denies(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(
            authz_request(risk_agent.did, purpose="marketing_analytics")
        )
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.PURPOSE_NOT_ALLOWED

    # 8 -- audience binding (the Phase 2 S-2 protection, preserved)
    async def test_08_wrong_domain_is_rejected_by_the_presentation_verifier(
        self, session, keystore, issuers, issued_credential, risk_agent
    ):
        """Phase 4 did not silently remove the Phase 2 audience protection."""
        from app.credentials.presenter import (
            CredentialPresenter,
            PresentationReason,
            PresentationVerifier,
        )

        presenter = CredentialPresenter(session, keystore)
        verifier = PresentationVerifier(session, keystore)
        document = await presenter.present(
            holder_did=risk_agent.did, challenge="n1", domain="loan-service",
        )
        good = await verifier.verify(document, expected_challenge="n1",
                                     expected_domain="loan-service")
        assert good.valid is True

        relayed = await verifier.verify(document, expected_challenge="n1",
                                        expected_domain="payments-service")
        assert relayed.valid is False
        assert relayed.reason == PresentationReason.DOMAIN_MISMATCH

    # 9
    async def test_09_unknown_context_fails_safely(self, pdp, authz_request):
        """An unresolvable subject and no context at all still denies."""
        decision = await pdp.decide(authz_request("did:poc:agent:ghost-001"))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.UNKNOWN_SUBJECT

    # 10
    async def test_10_human_required_action_returns_that_decision(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(authz_request(risk_agent.did, action="approve_loan"))
        assert decision.decision is Decision.HUMAN_APPROVAL_REQUIRED
        assert decision.allowed is False

    # 11
    async def test_11_direct_protected_resource_access_is_blocked(self):
        tool = build_default_registry().get("get_credit_profile")
        with pytest.raises(EnforcementBypassError):
            await tool(customer_id="customer-007")

    # 12
    async def test_12_manipulated_authorization_input_denies(
        self, pdp, risk_agent, authz_request
    ):
        """The agent asserts it is allowed and supplies its own trust score."""
        decision = await pdp.decide(authz_request(
            risk_agent.did,
            context={"allow": True, "decision": "ALLOW", "trust_score": 100,
                     "policy_id": "loan-credit-read"},
        ))
        assert decision.decision is Decision.DENY
        assert set(decision.evaluation["rejected_context_keys"]) == {
            "allow", "decision", "trust_score", "policy_id",
        }

    # 13
    async def test_13_policy_unavailable_fails_closed(
        self, session, keystore, issued_credential, risk_agent, authz_request
    ):
        class _NoPolicy(OPAClient):
            async def evaluate(self, input_document):
                raise OPAUnavailableError("the policy module is not loaded")

        pdp = PolicyDecisionPoint(session, keystore, get_settings(),
                                  opa=_NoPolicy(get_settings()))
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.AUTHORIZATION_UNAVAILABLE

    # 14
    async def test_14_opa_unavailable_fails_closed(
        self, session, keystore, issued_credential, risk_agent, authz_request
    ):
        """A real connection to a port where nothing listens."""
        settings = get_settings()
        pdp = PolicyDecisionPoint(session, keystore, settings)
        pdp.opa.base_url = "http://127.0.0.1:9"
        pdp.opa.settings = type(settings).model_construct(
            **{**settings.model_dump(), "opa_url": "http://127.0.0.1:9"}
        )
        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.AUTHORIZATION_UNAVAILABLE

    # 15
    async def test_15_malformed_request_is_rejected(
        self, pdp, issued_credential, risk_agent, authz_request
    ):
        decision = await pdp.decide(authz_request(risk_agent.did, action="DROP TABLE"))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.MALFORMED_REQUEST
        assert [s.name for s in decision.stages] == ["validate"]


class TestNoErrorPathEverAllows:
    async def test_the_denied_constructor_can_only_produce_deny(self):
        for reason in (Reason.AUTHORIZATION_UNAVAILABLE, Reason.MALFORMED_REQUEST,
                       Reason.NO_MATCHING_POLICY, Reason.UNKNOWN_SUBJECT,
                       Reason.INVALID_CONTEXT):
            decision = AuthorizationDecision.denied("authz-x", reason)
            assert decision.decision is Decision.DENY
            assert decision.allowed is False

    async def test_fail_closed_cannot_be_configured_off(self):
        """A setting that could turn an outage into an ALLOW must not exist."""
        from pydantic import ValidationError

        from app.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(authorization_fail_closed=False)


class TestPhaseBoundariesHold:
    async def test_ans_discovery_grants_no_access(
        self, discovery, registered_risk_agent, issued_credential, pdp, authz_request
    ):
        """DISCOVERY != AUTHORIZATION.

        The agent is discoverable for the capability AND holds a valid
        credential, yet payroll access is still refused. Being findable is not
        being permitted.
        """
        from app.ans.discovery import DiscoveryQuery

        outcome = await discovery.discover(DiscoveryQuery(capability="credit_analysis"))
        assert outcome.selected is not None
        assert outcome.selected.agent.did == registered_risk_agent.did

        decision = await pdp.decide(
            authz_request(registered_risk_agent.did, resource_type="payroll_records")
        )
        assert decision.decision is Decision.DENY

    async def test_no_authorization_logic_leaked_into_ans(self):
        """Phase 3 must not have grown a policy engine."""
        import pathlib

        ans_dir = pathlib.Path(__file__).resolve().parents[1] / "app" / "ans"
        for path in ans_dir.glob("*.py"):
            source = path.read_text()
            for forbidden in ("PolicyDecisionPoint", "authorization.pdp",
                              "OPAClient", "EnforcementGrant"):
                assert forbidden not in source, f"{forbidden} found in {path.name}"

    async def test_coordinator_has_no_authorization_logic(self):
        """The coordinator routes; it does not decide permission."""
        import pathlib

        path = (pathlib.Path(__file__).resolve().parents[1]
                / "app" / "agents" / "coordinator.py")
        source = path.read_text()
        for forbidden in ("PolicyDecisionPoint", "OPAClient", "EnforcementGrant"):
            assert forbidden not in source

    async def test_the_credential_model_was_never_redesigned_for_approvals(self):
        """PHASE 5 UPDATE, and what this test now guarantees.

        It used to assert that HITL did not exist -- no Keycloak, no OIDC, no
        approval artifact. Phase 5 built all three, so asserting their absence
        would now be asserting the feature is missing.

        What it checks INSTEAD is the constraint that still holds and still
        matters: `AgentCapabilityCredential` was never redesigned into a
        `HumanApprovalCredential`. A human approval is a SEPARATE artifact type
        with its own proof purpose, its own signing authority and its own
        lifecycle. Folding approvals into the credential model would have
        conflated "the issuer says this agent has a capability" with "a person
        agreed to this one action" -- two facts with different issuers,
        different lifetimes and different meanings.
        """
        import pathlib

        app_dir = pathlib.Path(__file__).resolve().parents[1] / "app"
        for path in app_dir.rglob("*.py"):
            source = path.read_text()
            assert "HumanApprovalCredential" not in source, (
                f"HumanApprovalCredential found in {path}: an approval is not "
                f"a credential and must not be modelled as one"
            )

    async def test_an_approval_is_a_distinct_artifact_type(self):
        """The approval type and proof purpose are their own, not a credential's."""
        from app.credentials.vc import (
            CREDENTIAL_PROOF_PURPOSE,
            PRESENTATION_PROOF_PURPOSE,
        )
        from app.hitl.artifact import APPROVAL_PROOF_PURPOSE, ARTIFACT_TYPE

        assert ARTIFACT_TYPE == "HumanApprovalArtifact"
        assert APPROVAL_PROOF_PURPOSE not in {
            CREDENTIAL_PROOF_PURPOSE, PRESENTATION_PROOF_PURPOSE,
        }
