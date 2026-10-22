"""Credential issuance: structure, binding, timestamps, signature."""
from __future__ import annotations

import base64
from datetime import timedelta

import pytest

from app.core.errors import ConflictError, IdentityError, NotFoundError
from app.credentials.canonical import canonical_bytes
from app.credentials.issuer import IssueRequest
from app.credentials.vc import PROOF_TYPE, signing_payload
from app.db.models.credential import CredentialStatusValue
from app.identity.signer import verify_signature

pytestmark = pytest.mark.integration


class TestIssuerIdentities:
    async def test_issuers_have_their_own_keys(self, issuers, keystore):
        registry = await issuers.list_issuers()
        assert {i.slug for i in registry} == {"bank-demo", "compliance-authority"}
        for issuer in registry:
            assert issuer.algorithm == "Ed25519"
            assert issuer.public_key_multibase.startswith("z6Mk")
            assert keystore.exists(issuer.kid)

    async def test_issuer_key_is_not_any_agents_key(self, issuers, risk_agent):
        """The separation the whole trust model rests on."""
        bank = await issuers.require("did:poc:organization:bank-demo")
        assert bank.public_key_multibase != risk_agent.active_key.public_key_multibase
        assert bank.kid != risk_agent.active_key.kid

    async def test_issuers_differ_from_each_other(self, issuers):
        bank = await issuers.require("did:poc:organization:bank-demo")
        compliance = await issuers.require("did:poc:organization:compliance-authority")
        assert bank.public_key_multibase != compliance.public_key_multibase

    async def test_bootstrap_is_idempotent(self, issuers):
        first = [i.did for i in await issuers.ensure_configured_issuers()]
        second = [i.did for i in await issuers.ensure_configured_issuers()]
        assert first == second
        assert len(await issuers.list_issuers()) == 2

    async def test_issuer_did_document_publishes_the_public_key(self, issuers):
        bank = await issuers.require("did:poc:organization:bank-demo")
        document = bank.did_document
        assert document["id"] == bank.did
        assert document["assertionMethod"] == [bank.kid]
        assert (
            document["verificationMethod"][0]["publicKeyMultibase"]
            == bank.public_key_multibase
        )


class TestIssuance:
    async def test_credential_has_every_required_element(self, issued_credential, risk_agent):
        document = issued_credential.document
        assert document["id"].startswith("urn:uuid:")
        assert document["type"] == ["VerifiableCredential", "AgentCapabilityCredential"]
        assert document["issuer"] == "did:poc:organization:bank-demo"
        assert document["credentialSubject"]["id"] == risk_agent.did
        assert document["issuanceDate"] and document["expirationDate"]
        assert document["credentialStatus"]["id"].endswith("/status")
        assert document["proof"]["type"] == PROOF_TYPE
        assert document["proof"]["proofPurpose"] == "assertionMethod"

    async def test_subject_is_the_phase_one_did(self, issued_credential, risk_agent):
        """No second identifier is minted for the agent."""
        assert issued_credential.subject_did == risk_agent.did
        assert issued_credential.document["credentialSubject"]["id"] == "did:poc:agent:risk-001"

    async def test_claims_are_normalised_to_the_data_model_spelling(self, issued_credential):
        subject = issued_credential.document["credentialSubject"]
        assert subject["allowedActions"] == ["READ_CREDIT_PROFILE"]
        assert subject["allowedResources"] == ["credit_records"]
        assert "allowed_actions" not in subject

    async def test_expiry_follows_the_requested_ttl(self, credential_issuer, risk_agent,
                                                    issuer_did, capability_claims):
        record = await credential_issuer.issue(
            IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                         capability_claims, ttl_seconds=60)
        )
        assert record.expires_at - record.issued_at == timedelta(seconds=60)

    async def test_signature_is_a_real_ed25519_signature_by_the_issuer(
        self, issued_credential, issuers
    ):
        issuer = await issuers.require(issued_credential.issuer_did)
        proof = issued_credential.document["proof"]
        assert len(base64.b64decode(proof["proofValue"])) == 64

        options = {k: v for k, v in proof.items() if k != "proofValue"}
        payload = canonical_bytes(signing_payload(issued_credential.document, options))
        assert verify_signature(issuer.public_key_multibase, payload, proof["proofValue"]).valid

    async def test_status_starts_active(self, issued_credential):
        assert issued_credential.status_record.status == CredentialStatusValue.ACTIVE

    async def test_two_credentials_get_distinct_ids(self, credential_issuer, risk_agent,
                                                    issuer_did, capability_claims):
        first = await credential_issuer.issue(
            IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                         capability_claims)
        )
        second = await credential_issuer.issue(
            IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                         capability_claims)
        )
        assert first.credential_id != second.credential_id
        assert first.proof["proofValue"] != second.proof["proofValue"]


class TestIssuanceRefusals:
    async def test_unknown_issuer_cannot_issue(self, credential_issuer, risk_agent,
                                               capability_claims):
        with pytest.raises(NotFoundError, match="Unknown issuer"):
            await credential_issuer.issue(
                IssueRequest("did:poc:organization:rogue", risk_agent.did,
                             "AgentCapabilityCredential", capability_claims)
            )

    async def test_subject_must_be_a_registered_agent(self, credential_issuer, issuer_did,
                                                      capability_claims):
        with pytest.raises(NotFoundError, match="not a registered agent"):
            await credential_issuer.issue(
                IssueRequest(issuer_did, "did:poc:agent:ghost-001",
                             "AgentCapabilityCredential", capability_claims)
            )

    async def test_missing_required_claim_is_refused_at_issuance(
        self, credential_issuer, risk_agent, issuer_did
    ):
        with pytest.raises(IdentityError, match="requires claims"):
            await credential_issuer.issue(
                IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                             {"capability": "credit_analysis"})
            )

    async def test_reserved_claim_key_is_refused(self, credential_issuer, risk_agent,
                                                 issuer_did, capability_claims):
        with pytest.raises(IdentityError, match="reserved"):
            await credential_issuer.issue(
                IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                             {**capability_claims, "id": "did:poc:agent:someone-else"})
            )

    async def test_duplicate_credential_id_is_refused(self, credential_issuer, risk_agent,
                                                      issuer_did, capability_claims):
        first = await credential_issuer.issue(
            IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                         capability_claims)
        )
        with pytest.raises(ConflictError):
            await credential_issuer.issue(
                IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                             capability_claims, credential_id=first.credential_id)
            )

    async def test_absurd_ttl_is_refused(self, credential_issuer, risk_agent, issuer_did,
                                         capability_claims):
        with pytest.raises(IdentityError, match="expires_in_seconds"):
            await credential_issuer.issue(
                IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                             capability_claims, ttl_seconds=10**9)
            )


class TestOtherCredentialTypes:
    async def test_compliance_credential(self, credential_issuer, risk_agent,
                                         compliance_issuer_did):
        record = await credential_issuer.issue(
            IssueRequest(compliance_issuer_did, risk_agent.did, "ComplianceCredential",
                         {"framework": "SOX", "status": "COMPLIANT",
                          "scope": "financial_data_processing"})
        )
        assert record.document["type"][1] == "ComplianceCredential"
        assert record.claims["framework"] == "SOX"
        assert record.issuer_did == compliance_issuer_did

    async def test_role_credential(self, credential_issuer, risk_agent, issuer_did):
        record = await credential_issuer.issue(
            IssueRequest(issuer_did, risk_agent.did, "AgentRoleCredential",
                         {"role": "risk_analyst", "department": "credit_risk"})
        )
        assert record.claims == {"role": "risk_analyst", "department": "credit_risk"}
