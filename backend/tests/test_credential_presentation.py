"""Presentations: the holder proving it controls the credential's subject DID."""
from __future__ import annotations

import base64
import copy

import pytest

from app.core.errors import IdentityError, NotFoundError
from app.credentials.issuer import IssueRequest
from app.credentials.presenter import (
    CredentialPresenter,
    PresentationReason,
    PresentationVerifier,
)
from app.credentials.verifier import Reason
from app.credentials.status import CredentialStatusService
from app.identity.multibase import encode_ed25519_public_key

pytestmark = pytest.mark.integration


@pytest.fixture
def presenter(session, keystore, issuers):
    return CredentialPresenter(session, keystore)


@pytest.fixture
def presentation_verifier(session, keystore, issuers):
    return PresentationVerifier(session, keystore)


def checks(report) -> dict[str, bool]:
    return {c.name: c.passed for c in report.checks}


class TestBuildingPresentations:
    async def test_presentation_is_signed_by_the_holder_not_the_issuer(
        self, presenter, issued_credential, risk_agent, issuers
    ):
        document = await presenter.present(holder_did=risk_agent.did)

        assert document["holder"] == risk_agent.did
        assert document["type"] == ["VerifiablePresentation"]
        assert len(document["verifiableCredential"]) == 1

        holder_proof = document["proof"]
        assert holder_proof["proofPurpose"] == "authentication"
        assert holder_proof["verificationMethod"] == risk_agent.active_key.kid

        # Two distinct proofs by two distinct keys.
        issuer = await issuers.require("did:poc:organization:bank-demo")
        issuer_proof = document["verifiableCredential"][0]["proof"]
        assert issuer_proof["verificationMethod"] == issuer.kid
        assert issuer_proof["proofValue"] != holder_proof["proofValue"]
        assert len(base64.b64decode(holder_proof["proofValue"])) == 64

    async def test_challenge_and_domain_are_bound_into_the_proof(
        self, presenter, issued_credential, risk_agent
    ):
        document = await presenter.present(
            holder_did=risk_agent.did, challenge="nonce-abc", domain="loan-service"
        )
        assert document["proof"]["challenge"] == "nonce-abc"
        assert document["proof"]["domain"] == "loan-service"

    async def test_presenting_with_nothing_to_present_fails(self, presenter, risk_agent):
        with pytest.raises(NotFoundError, match="holds no credentials"):
            await presenter.present(holder_did=risk_agent.did)

    async def test_registry_refuses_to_present_for_an_agent_held_key(
        self, presenter, registry, agent_spec, credential_issuer, issuer_did, capability_claims
    ):
        """The IAM API has no private key for a self-custodying agent."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        public_raw = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        agent = await registry.create_agent(
            agent_spec("selfheld-001",
                       public_key_multibase=encode_ed25519_public_key(public_raw))
        )
        await credential_issuer.issue(
            IssueRequest(issuer_did, agent.did, "AgentCapabilityCredential", capability_claims)
        )
        with pytest.raises(IdentityError, match="holds its own key"):
            await presenter.present(holder_did=agent.did)

    async def test_presentation_is_recorded(self, presenter, session, issued_credential,
                                            risk_agent):
        from app.db.repositories.credentials import CredentialRepository

        document = await presenter.present(holder_did=risk_agent.did)
        records = await CredentialRepository(session).list_presentations(
            holder_did=risk_agent.did
        )
        assert [r.presentation_id for r in records] == [document["id"]]
        assert records[0].credential_ids == [issued_credential.credential_id]


class TestVerifyingPresentations:
    async def test_valid_presentation(self, presenter, presentation_verifier,
                                      issued_credential, risk_agent):
        document = await presenter.present(holder_did=risk_agent.did, challenge="nonce-1")
        report = await presentation_verifier.verify(document, expected_challenge="nonce-1")

        assert report.valid
        assert report.reason == PresentationReason.VALID
        assert all(checks(report).values())
        assert [c.valid for c in report.credentials] == [True]

    async def test_tampered_holder_proof_is_rejected(self, presenter, presentation_verifier,
                                                     issued_credential, risk_agent):
        document = await presenter.present(holder_did=risk_agent.did)
        raw = bytearray(base64.b64decode(document["proof"]["proofValue"]))
        raw[0] ^= 0x01
        document["proof"]["proofValue"] = base64.b64encode(raw).decode()

        report = await presentation_verifier.verify(document)
        assert not report.valid
        assert report.reason == PresentationReason.HOLDER_PROOF_INVALID

    async def test_stolen_credential_cannot_be_presented_by_another_agent(
        self, presenter, presentation_verifier, issued_credential, risk_agent, fraud_agent,
        credential_issuer, issuer_did
    ):
        """The core reason holder proof exists.

        The fraud agent copies the risk agent's credential -- credentials are
        meant to be shown, so copies are expected -- and presents it under its
        own, genuine holder proof. The subject binding catches it.
        """
        await credential_issuer.issue(
            IssueRequest(issuer_did, fraud_agent.did, "AgentRoleCredential",
                         {"role": "fraud_analyst", "department": "financial_crime"})
        )
        stolen = copy.deepcopy(issued_credential.document)
        document = await presenter.present(holder_did=fraud_agent.did)
        document["verifiableCredential"] = [stolen]

        report = await presentation_verifier.verify(document)
        assert not report.valid
        # The holder proof no longer covers the swapped payload.
        assert report.reason == PresentationReason.HOLDER_PROOF_INVALID

    async def test_subject_mismatch_when_the_holder_proof_is_genuine(
        self, session, keystore, presentation_verifier, issued_credential, risk_agent,
        fraud_agent
    ):
        """Fraud agent legitimately signs a presentation of a credential about the risk agent."""
        from app.credentials.presentation import attach_proof, build_unsigned_presentation
        from app.identity.signer import Signer

        unsigned = build_unsigned_presentation(
            holder_did=fraud_agent.did,
            holder_kid=fraud_agent.active_key.kid,
            credentials=[issued_credential.document],
        )
        signature = Signer(keystore).sign(fraud_agent.active_key.kid, unsigned.payload)
        document = attach_proof(unsigned, signature.signature_b64)

        report = await presentation_verifier.verify(document)
        assert not report.valid
        assert checks(report)["holder_proof"] is True     # they really are the fraud agent
        assert report.reason == PresentationReason.CREDENTIAL_INVALID
        assert report.credentials[0].reason == Reason.SUBJECT_MISMATCH

    async def test_challenge_mismatch_is_rejected(self, presenter, presentation_verifier,
                                                  issued_credential, risk_agent):
        document = await presenter.present(holder_did=risk_agent.did, challenge="nonce-1")
        report = await presentation_verifier.verify(document, expected_challenge="nonce-2")
        assert not report.valid
        assert report.reason == PresentationReason.CHALLENGE_MISMATCH

    async def test_revoked_credential_fails_inside_a_valid_presentation(
        self, session, presenter, presentation_verifier, issued_credential, risk_agent
    ):
        document = await presenter.present(holder_did=risk_agent.did)
        await CredentialStatusService(session).revoke(
            issued_credential.credential_id, "COMPROMISED"
        )

        report = await presentation_verifier.verify(document)
        assert not report.valid
        assert checks(report)["holder_proof"] is True
        assert report.reason == PresentationReason.CREDENTIAL_INVALID
        assert report.credentials[0].reason == Reason.REVOKED

    async def test_unknown_holder_is_rejected(self, presenter, presentation_verifier,
                                              issued_credential, risk_agent):
        document = await presenter.present(holder_did=risk_agent.did)
        document["holder"] = "did:poc:agent:ghost-001"
        report = await presentation_verifier.verify(document)
        assert not report.valid
        assert report.reason == PresentationReason.HOLDER_UNKNOWN

    async def test_malformed_presentation_is_rejected(self, presentation_verifier):
        report = await presentation_verifier.verify({"type": ["Nonsense"]})
        assert not report.valid
        assert report.reason == PresentationReason.MALFORMED

    async def test_required_claims_apply_to_presented_credentials(
        self, presenter, presentation_verifier, issued_credential, risk_agent
    ):
        document = await presenter.present(holder_did=risk_agent.did)
        ok = await presentation_verifier.verify(
            document, required_claims={"capability": "credit_analysis"}
        )
        assert ok.valid
        bad = await presentation_verifier.verify(
            document, required_claims={"capability": "payroll_access"}
        )
        assert not bad.valid
        assert bad.credentials[0].reason == Reason.MISSING_CLAIM


class TestAudienceBinding:
    """S-2: SIGNED DOMAIN + EXPECTED VERIFIER DOMAIN = AUDIENCE BINDING.

    `domain` was already created, signed, stored and transmitted; what was
    missing was the verifier comparing it against its own context, so a
    presentation minted for one service verified cleanly at another.
    """

    async def test_matching_domain_verifies(
        self, presenter, presentation_verifier, issued_credential, risk_agent
    ):
        document = await presenter.present(
            holder_did=risk_agent.did, challenge="n1", domain="loan-service"
        )
        report = await presentation_verifier.verify(
            document, expected_challenge="n1", expected_domain="loan-service"
        )
        assert report.valid
        assert checks(report)["domain"] is True

    async def test_presentation_for_another_audience_is_rejected(
        self, presenter, presentation_verifier, issued_credential, risk_agent
    ):
        """The relay this fix exists to stop."""
        document = await presenter.present(
            holder_did=risk_agent.did, challenge="n1", domain="loan-service"
        )
        report = await presentation_verifier.verify(
            document, expected_challenge="n1", expected_domain="payments-service"
        )
        assert not report.valid
        assert report.reason == PresentationReason.DOMAIN_MISMATCH
        assert checks(report)["domain"] is False
        # The holder proof itself is genuine -- it was simply made for someone else.
        assert checks(report)["holder_proof"] is True

    async def test_missing_domain_fails_when_an_audience_is_required(
        self, presenter, presentation_verifier, issued_credential, risk_agent
    ):
        document = await presenter.present(holder_did=risk_agent.did, challenge="n1")
        assert "domain" not in document["proof"]
        report = await presentation_verifier.verify(
            document, expected_challenge="n1", expected_domain="loan-service"
        )
        assert not report.valid
        assert report.reason == PresentationReason.DOMAIN_MISMATCH
        assert "carries no domain" in (
            next(c.detail for c in report.checks if c.name == "domain")
        )

    async def test_tampering_with_the_domain_breaks_the_holder_proof(
        self, presenter, presentation_verifier, issued_credential, risk_agent
    ):
        """The domain is signature-covered, so it cannot be rewritten in transit.

        An attacker who captures a presentation for `loan-service` cannot
        re-address it: editing `domain` invalidates the holder proof, which is
        checked before the audience comparison is ever reached.
        """
        document = await presenter.present(
            holder_did=risk_agent.did, challenge="n1", domain="loan-service"
        )
        document["proof"]["domain"] = "payments-service"
        report = await presentation_verifier.verify(
            document, expected_challenge="n1", expected_domain="payments-service"
        )
        assert not report.valid
        assert report.reason == PresentationReason.HOLDER_PROOF_INVALID
        assert checks(report)["holder_proof"] is False

    async def test_no_expected_domain_preserves_existing_behaviour(
        self, presenter, presentation_verifier, issued_credential, risk_agent
    ):
        """Documented compatibility behaviour: a verifier that declares no
        audience does not get to demand one. Existing callers are unaffected."""
        document = await presenter.present(
            holder_did=risk_agent.did, challenge="n1", domain="loan-service"
        )
        report = await presentation_verifier.verify(document, expected_challenge="n1")
        assert report.valid
        assert checks(report)["domain"] is True
        # The declared audience is still reported, not silently discarded.
        assert "loan-service" in (
            next(c.detail for c in report.checks if c.name == "domain")
        )

    async def test_an_existing_domainless_presentation_still_verifies(
        self, presenter, presentation_verifier, issued_credential, risk_agent
    ):
        """Backwards compatibility for presentations minted before this change."""
        document = await presenter.present(holder_did=risk_agent.did)
        report = await presentation_verifier.verify(document)
        assert report.valid
        assert all(checks(report).values())


class TestVerificationEventCorrelation:
    """S-3: credential -> presentation -> verification event -> presentation_id."""

    async def test_verification_inside_a_presentation_records_its_id(
        self, session, presenter, presentation_verifier, issued_credential, risk_agent
    ):
        from sqlalchemy import select
        from app.db.models.credential import CredentialVerificationEvent

        document = await presenter.present(holder_did=risk_agent.did)
        report = await presentation_verifier.verify(document)
        assert report.valid

        rows = (
            await session.execute(select(CredentialVerificationEvent))
        ).scalars().all()
        assert rows
        assert all(r.presentation_id == document["id"] for r in rows)
        # The real id from the flow, not a fabricated one.
        assert document["id"].startswith("urn:uuid:")
        assert all(r.credential_id == issued_credential.credential_id for r in rows)

    async def test_standalone_verification_leaves_presentation_id_null(
        self, session, verifier, issued_credential
    ):
        """NULL is preserved where the event genuinely had no presentation."""
        from sqlalchemy import select
        from app.db.models.credential import CredentialVerificationEvent

        await verifier.verify(issued_credential.document)
        rows = (
            await session.execute(select(CredentialVerificationEvent))
        ).scalars().all()
        assert rows
        assert all(r.presentation_id is None for r in rows)
