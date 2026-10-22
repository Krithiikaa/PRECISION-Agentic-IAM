"""The Policy Information Point.

Two properties matter here and are tested directly:

  1. The PIP consumes the PHASE 2 VERIFIER. It does not re-implement signature,
     expiry or revocation checking, so there is exactly one implementation of
     credential validity in the system.

  2. The PIP invents nothing. An unavailable attribute is null and named as
     unavailable -- never defaulted, and never defaulted to something trusted.
"""
from __future__ import annotations

import pytest

from app.authorization.contracts import Resource, Subject
from app.authorization.pip import PolicyInformationPoint
from app.core.config import get_settings
from app.credentials.status import CredentialStatusService

pytestmark = pytest.mark.integration


@pytest.fixture
def pip(session, keystore, issuers):
    return PolicyInformationPoint(session, keystore, get_settings())


class TestSubjectResolution:
    async def test_a_registered_agent_resolves(self, pip, risk_agent, authz_request):
        context = await pip.collect(authz_request(risk_agent.did))
        assert context.subject_resolved is True
        assert context.subject["did"] == risk_agent.did
        assert context.subject["status"] == "ACTIVE"

    async def test_an_unknown_did_does_not_resolve(self, pip, authz_request):
        context = await pip.collect(authz_request("did:poc:agent:ghost-001"))
        assert context.subject_resolved is False
        assert context.subject["status"] is None

    async def test_declared_capabilities_are_labelled_as_declarations(
        self, pip, risk_agent, authz_request
    ):
        """What an agent says about itself is not evidence."""
        context = await pip.collect(authz_request(risk_agent.did))
        assert "declared_capabilities" in context.subject
        assert "credit_analysis" in context.subject["declared_capabilities"]
        # An agent with no credential has NO attested capability, whatever it declares.
        assert context.verified_capabilities == []


class TestCredentialFactsComeFromPhase2:
    async def test_a_valid_credential_is_reported_valid(
        self, pip, issued_credential, risk_agent, authz_request
    ):
        context = await pip.collect(authz_request(risk_agent.did))
        assert len(context.credentials) == 1
        fact = context.credentials[0]
        assert fact.valid is True
        assert fact.reason == "CREDENTIAL_VALID"
        assert fact.claims["capability"] == "credit_analysis"
        assert context.verified_capabilities == ["credit_analysis"]

    async def test_revocation_is_seen_immediately(
        self, session, pip, issued_credential, risk_agent, authz_request
    ):
        await CredentialStatusService(session).revoke(
            issued_credential.credential_id, "COMPROMISED"
        )
        context = await pip.collect(authz_request(risk_agent.did))
        assert context.credentials[0].valid is False
        assert context.credentials[0].reason == "CREDENTIAL_REVOKED"
        # A revoked credential attests nothing.
        assert context.verified_capabilities == []

    async def test_tampering_is_seen_by_the_phase_2_verifier(
        self, session, pip, issued_credential, risk_agent, authz_request
    ):
        document = dict(issued_credential.document)
        subject = dict(document["credentialSubject"])
        subject["capability"] = "payroll_access"
        document["credentialSubject"] = subject
        issued_credential.document = document
        await session.flush()

        context = await pip.collect(authz_request(risk_agent.did))
        assert context.credentials[0].valid is False
        assert context.credentials[0].reason == "SIGNATURE_INVALID"

    async def test_a_credential_for_another_subject_is_not_counted(
        self, pip, issued_credential, fraud_agent, authz_request
    ):
        """expected_subject binding: credentials are not transferable."""
        context = await pip.collect(authz_request(fraud_agent.did))
        assert context.credentials == []
        assert context.verified_capabilities == []

    async def test_offered_credential_ids_narrow_but_do_not_vouch(
        self, pip, issued_credential, risk_agent, authz_request
    ):
        request = authz_request(risk_agent.did)
        request.credentials = [issued_credential.credential_id]
        context = await pip.collect(request)
        assert len(context.credentials) == 1
        # Still verified, not taken on trust.
        assert context.credentials[0].reason == "CREDENTIAL_VALID"

    async def test_offering_an_unrelated_id_yields_nothing(
        self, pip, issued_credential, risk_agent, authz_request
    ):
        request = authz_request(risk_agent.did)
        request.credentials = ["urn:uuid:00000000-0000-0000-0000-000000000000"]
        context = await pip.collect(request)
        assert context.credentials == []


class TestNothingIsInvented:
    async def test_trust_score_is_null_not_a_number(
        self, pip, issued_credential, risk_agent, authz_request
    ):
        """Phase 10 owns trust. A default here would authorise on a number
        nobody computed."""
        context = await pip.collect(authz_request(risk_agent.did))
        assert context.trust_score is None
        assert "trust_score" in context.unavailable
        assert "Phase 10" in context.unavailable["trust_score"]

    async def test_session_is_null_and_named(
        self, pip, issued_credential, risk_agent, authz_request
    ):
        context = await pip.collect(authz_request(risk_agent.did))
        assert context.session is None
        assert "session" in context.unavailable

    async def test_approval_is_a_verdict_not_a_default(
        self, pip, issued_credential, risk_agent, authz_request
    ):
        """PHASE 5 UPDATE.

        `approval` used to be NULL and listed as unavailable, because no
        approval mechanism existed. It is now a real fact, established the same
        way credential validity is: the approval service verifies the artifact
        and the PIP reports the VERDICT.

        The discipline is unchanged. "No approval applies to this request" is
        reported as `present: false` with a named reason -- a fact -- and is
        never defaulted to something permissive.
        """
        context = await pip.collect(authz_request(risk_agent.did))
        assert context.approval["present"] is False
        assert context.approval["valid"] is False
        assert context.approval["reason"] == "APPROVAL_MISSING"
        # No longer claimed as unimplemented, because it is implemented.
        assert "approval" not in context.unavailable

    async def test_unavailable_attributes_are_serialised_for_policy(
        self, pip, issued_credential, risk_agent, authz_request
    ):
        body = (await pip.collect(authz_request(risk_agent.did))).to_dict()
        assert body["trust_score"] is None
        assert body["session"] is None
        assert set(body["unavailable"]) >= {"trust_score", "session"}
        # Phase 5: approval is serialised as a VERDICT for policy, never null.
        assert body["approval"]["present"] is False


class TestContextShape:
    async def test_resource_and_environment_are_present(
        self, pip, risk_agent, authz_request
    ):
        from app.authorization.contracts import AuthorizationRequest

        request = AuthorizationRequest(
            subject=Subject(did=risk_agent.did), action="read",
            resource=Resource(type="credit_records", id="customer-007",
                              classification="CONFIDENTIAL"),
            purpose="loan_assessment",
        )
        context = await pip.collect(request)
        assert context.resource["type"] == "credit_records"
        assert context.resource["classification"] == "CONFIDENTIAL"
        assert "time" in context.environment

    async def test_collection_is_timed(self, pip, risk_agent, authz_request):
        context = await pip.collect(authz_request(risk_agent.did))
        assert context.collection_ms > 0
