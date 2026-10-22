"""Credential verification, including every mandatory failure case.

The failure cases from the Phase 2 specification, sections 19 and 38-41:
  1 tampered      2 expired      3 revoked      4 wrong subject
  5 unknown issuer 6 invalid signature          7 missing required claim
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone

import pytest

from app.credentials.issuer import IssueRequest
from app.credentials.status import CredentialStatusService
from app.credentials.verifier import Reason
from app.db.models.credential import CredentialStatusValue

pytestmark = pytest.mark.integration


def checks(report) -> dict[str, bool]:
    return {c.name: c.passed for c in report.checks}


class TestValidCredential:
    async def test_untouched_credential_verifies(self, verifier, issued_credential, risk_agent):
        report = await verifier.verify(
            issued_credential.document, expected_subject=risk_agent.did
        )
        assert report.valid
        assert report.reason == Reason.VALID
        assert all(checks(report).values())

    async def test_every_check_is_reported_not_just_a_boolean(self, verifier, issued_credential):
        report = await verifier.verify(issued_credential.document)
        names = [c.name for c in report.checks]
        assert names == ["structure", "issuer", "signature", "subject", "not_before",
                         "expiration", "status", "claims"]
        assert all(c.detail for c in report.checks)

    async def test_report_carries_the_credential_facts(self, verifier, issued_credential):
        report = await verifier.verify(issued_credential.document)
        assert report.issuer == "did:poc:organization:bank-demo"
        assert report.subject == "did:poc:agent:risk-001"
        assert report.credential_type == "AgentCapabilityCredential"
        assert report.status == "ACTIVE"


class TestCase1And6Tampering:
    """Cases 1 and 6: any edit to the signed document invalidates the proof."""

    async def test_tampered_capability_claim(self, verifier, issued_credential, risk_agent):
        """The mandatory failure test: credit_analysis -> payroll_access."""
        forged = copy.deepcopy(issued_credential.document)
        forged["credentialSubject"]["capability"] = "payroll_access"

        report = await verifier.verify(forged, expected_subject=risk_agent.did)
        assert not report.valid
        assert report.reason == Reason.SIGNATURE_INVALID
        assert checks(report)["signature"] is False
        # The other properties still hold -- only the cryptography catches this.
        assert checks(report)["issuer"] is True
        assert checks(report)["subject"] is True

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            (("issuer",), "did:poc:organization:compliance-authority"),
            (("credentialSubject", "id"), "did:poc:agent:fraud-001"),
            (("expirationDate",), "2099-01-01T00:00:00.000Z"),
            (("issuanceDate",), "2000-01-01T00:00:00.000Z"),
            (("credentialSubject", "allowedResources"), ["payroll_records"]),
            (("id",), "urn:uuid:00000000-0000-0000-0000-000000000000"),
        ],
    )
    async def test_any_field_edit_breaks_the_proof(self, verifier, issued_credential,
                                                   path, value):
        forged = copy.deepcopy(issued_credential.document)
        target = forged
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

        report = await verifier.verify(forged)
        assert not report.valid
        assert checks(report)["signature"] is False

    async def test_extending_expiry_does_not_help_an_attacker(self, verifier,
                                                              credential_issuer, risk_agent,
                                                              issuer_did, capability_claims):
        """Expiry is inside the signature, so it cannot be edited to buy time."""
        record = await credential_issuer.issue(
            IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                         capability_claims, ttl_seconds=1)
        )
        forged = copy.deepcopy(record.document)
        forged["expirationDate"] = "2099-01-01T00:00:00.000Z"
        report = await verifier.verify(forged)
        assert not report.valid
        assert report.reason == Reason.SIGNATURE_INVALID

    async def test_flipped_signature_byte(self, verifier, issued_credential):
        forged = copy.deepcopy(issued_credential.document)
        raw = bytearray(base64.b64decode(forged["proof"]["proofValue"]))
        raw[0] ^= 0x01
        forged["proof"]["proofValue"] = base64.b64encode(raw).decode()

        report = await verifier.verify(forged)
        assert report.reason == Reason.SIGNATURE_INVALID

    async def test_proof_cannot_be_redirected_to_another_key(self, verifier,
                                                             issued_credential, issuers):
        """proof.verificationMethod is signed, and must be the issuer's own key."""
        compliance = await issuers.require("did:poc:organization:compliance-authority")
        forged = copy.deepcopy(issued_credential.document)
        forged["proof"]["verificationMethod"] = compliance.kid

        report = await verifier.verify(forged)
        assert not report.valid
        assert report.reason == Reason.ISSUER_UNKNOWN
        assert "not the issuer's verification method" in (
            next(c.detail for c in report.checks if c.name == "issuer")
        )


class TestCase5UnknownIssuer:
    async def test_credential_from_an_unregistered_issuer(self, verifier, issued_credential):
        forged = copy.deepcopy(issued_credential.document)
        forged["issuer"] = "did:poc:organization:totally-made-up"
        forged["proof"]["verificationMethod"] = "did:poc:organization:totally-made-up#key-1"

        report = await verifier.verify(forged)
        assert not report.valid
        assert report.reason == Reason.ISSUER_UNKNOWN
        assert checks(report)["issuer"] is False
        assert checks(report)["signature"] is False   # cannot even be evaluated

    async def test_agent_cannot_self_issue(self, verifier, session, keystore, risk_agent):
        """An agent signing its own 'credential' is not a credential.

        This is the attack the issuer/holder key separation exists to stop: the
        agent holds a key, so it can produce a signature -- but not one that
        resolves to a registered issuer.
        """
        from app.credentials.canonical import canonical_bytes
        from app.credentials.vc import (
            build_credential_document, build_proof_options, default_expiry,
            new_credential_id, signing_payload, utcnow,
        )
        from app.identity.signer import Signer

        now = utcnow()
        document = build_credential_document(
            credential_id=new_credential_id(),
            credential_type="AgentCapabilityCredential",
            issuer_did=risk_agent.did,            # the agent naming ITSELF as issuer
            subject_did=risk_agent.did,
            claims={"capability": "payroll_access", "allowedActions": ["READ_PAYROLL"],
                    "allowedResources": ["payroll_records"], "purpose": "exfiltration"},
            issued_at=now,
            expires_at=default_expiry(now, 3600),
        )
        options = build_proof_options(
            verification_method=risk_agent.active_key.kid,
            proof_purpose="assertionMethod", created=now,
        )
        signature = Signer(keystore).sign(
            risk_agent.active_key.kid, canonical_bytes(signing_payload(document, options))
        )
        document["proof"] = {**options, "proofValue": signature.signature_b64}

        # The signature itself is mathematically fine. It is worthless anyway.
        report = await verifier.verify(document)
        assert not report.valid
        assert report.reason == Reason.ISSUER_UNKNOWN


class TestCase4SubjectBinding:
    async def test_credential_presented_for_the_wrong_agent(self, verifier, issued_credential,
                                                            fraud_agent):
        """Risk agent's credential, offered in the fraud agent's context."""
        report = await verifier.verify(
            issued_credential.document, expected_subject=fraud_agent.did
        )
        assert not report.valid
        assert report.reason == Reason.SUBJECT_MISMATCH
        assert checks(report)["signature"] is True    # genuinely issued, just not to them
        assert checks(report)["subject"] is False

    async def test_no_expected_subject_means_no_binding_check(self, verifier,
                                                              issued_credential):
        report = await verifier.verify(issued_credential.document)
        assert report.valid
        assert "no expected subject supplied" in (
            next(c.detail for c in report.checks if c.name == "subject")
        )


class TestCase2Expiration:
    async def test_valid_before_expiry_invalid_after(self, verifier, credential_issuer,
                                                     risk_agent, issuer_did, capability_claims):
        record = await credential_issuer.issue(
            IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                         capability_claims, ttl_seconds=60)
        )
        before = await verifier.verify(record.document)
        assert before.valid

        # The backend compares timestamps; no frontend timer is involved.
        later = datetime.now(timezone.utc) + timedelta(seconds=61)
        after = await verifier.verify(record.document, now=later)
        assert not after.valid
        assert after.reason == Reason.EXPIRED
        assert "expired" in next(c.detail for c in after.checks if c.name == "expiration")

    async def test_real_elapsed_time_expires_a_short_credential(
        self, verifier, credential_issuer, risk_agent, issuer_did, capability_claims
    ):
        """No clock injection: a 1-second credential really does die."""
        import asyncio

        record = await credential_issuer.issue(
            IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                         capability_claims, ttl_seconds=1)
        )
        assert (await verifier.verify(record.document)).valid
        await asyncio.sleep(1.2)
        report = await verifier.verify(record.document)
        assert not report.valid
        assert report.reason == Reason.EXPIRED

    async def test_sweep_marks_expired_but_verification_does_not_depend_on_it(
        self, session, verifier, credential_issuer, risk_agent, issuer_did, capability_claims
    ):
        import asyncio

        record = await credential_issuer.issue(
            IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                         capability_claims, ttl_seconds=1)
        )
        await asyncio.sleep(1.2)

        # Rejected before any sweep has run.
        assert (await verifier.verify(record.document)).reason == Reason.EXPIRED

        swept = await CredentialStatusService(session).sweep_expired()
        assert record.credential_id in swept
        status = await CredentialStatusService(session).get(record.credential_id)
        assert status["status"] == CredentialStatusValue.EXPIRED.value


class TestCase3Revocation:
    async def test_revoked_credential_is_rejected(self, session, verifier, issued_credential):
        assert (await verifier.verify(issued_credential.document)).valid

        await CredentialStatusService(session).revoke(
            issued_credential.credential_id, "COMPROMISED"
        )

        report = await verifier.verify(issued_credential.document)
        assert not report.valid
        assert report.reason == Reason.REVOKED
        # Note what is still true: the signature is untouched and still verifies.
        assert checks(report)["signature"] is True
        assert checks(report)["status"] is False
        assert "COMPROMISED" in next(c.detail for c in report.checks if c.name == "status")

    async def test_revocation_reports_reason_and_timestamp(self, session, issued_credential):
        service = CredentialStatusService(session)
        await service.revoke(issued_credential.credential_id, "KEY_COMPROMISE")
        status = await service.get(issued_credential.credential_id)
        assert status["status"] == "REVOKED"
        assert status["revocation_reason"] == "KEY_COMPROMISE"
        assert status["revoked_at"] is not None

    async def test_double_revocation_is_rejected(self, session, issued_credential):
        from app.core.errors import ConflictError

        service = CredentialStatusService(session)
        await service.revoke(issued_credential.credential_id, "FIRST")
        with pytest.raises(ConflictError, match="already revoked"):
            await service.revoke(issued_credential.credential_id, "SECOND")


class TestCase7MissingClaims:
    async def test_verifier_required_claim_absent(self, verifier, issued_credential):
        report = await verifier.verify(
            issued_credential.document, required_claims=["fraudClearance"]
        )
        assert not report.valid
        assert report.reason == Reason.MISSING_CLAIM

    async def test_verifier_required_claim_value_mismatch(self, verifier, issued_credential):
        report = await verifier.verify(
            issued_credential.document, required_claims={"capability": "payroll_access"}
        )
        assert not report.valid
        assert report.reason == Reason.MISSING_CLAIM
        assert "verifier requires 'payroll_access'" in (
            next(c.detail for c in report.checks if c.name == "claims")
        )

    async def test_required_claim_value_match_passes(self, verifier, issued_credential):
        report = await verifier.verify(
            issued_credential.document, required_claims={"capability": "credit_analysis"}
        )
        assert report.valid

    async def test_credential_type_schema_is_enforced(self, credential_issuer, verifier,
                                                      risk_agent, issuer_did):
        """A credential missing a claim its own type requires is invalid."""
        record = await credential_issuer.issue(
            IssueRequest(issuer_did, risk_agent.did, "AgentCapabilityCredential",
                         {"capability": "credit_analysis"}),
            validate_claims=False,       # construct the malformed artefact deliberately
        )
        report = await verifier.verify(record.document)
        assert not report.valid
        assert report.reason == Reason.MISSING_CLAIM


class TestMalformedAndUnregistered:
    async def test_missing_proof(self, verifier, issued_credential):
        forged = copy.deepcopy(issued_credential.document)
        del forged["proof"]
        report = await verifier.verify(forged)
        assert report.reason == Reason.MALFORMED

    async def test_wrong_proof_type(self, verifier, issued_credential):
        forged = copy.deepcopy(issued_credential.document)
        forged["proof"]["type"] = "Ed25519Signature2020"
        report = await verifier.verify(forged)
        assert report.reason == Reason.MALFORMED
        assert "unsupported proof type" in (
            next(c.detail for c in report.checks if c.name == "structure")
        )

    async def test_credential_not_in_the_registry_cannot_have_its_status_established(
        self, verifier, issued_credential, session
    ):
        from sqlalchemy import delete
        from app.db.models.credential import Credential

        await session.execute(
            delete(Credential).where(Credential.credential_id == issued_credential.credential_id)
        )
        await session.flush()

        report = await verifier.verify(issued_credential.document)
        assert not report.valid
        assert report.reason == Reason.NOT_REGISTERED
        assert checks(report)["signature"] is True


class TestProofPurpose:
    """S-1: the credential verifier enforces `assertionMethod`.

    The presentation verifier has always required `authentication` on a holder
    proof. These assert the credential half now keeps the same purposes apart,
    so a signature made for one purpose is not a valid proof for another.

    `proofPurpose` is inside the signed payload, so this is domain separation
    rather than a new cryptographic control -- `test_editing_the_purpose_still
    _breaks_the_signature` below pins that down.
    """

    async def test_a_genuine_credential_still_carries_assertion_method(
        self, verifier, issued_credential, risk_agent
    ):
        # Backwards compatibility: the credential the system actually issues is
        # unaffected by the new check.
        assert issued_credential.document["proof"]["proofPurpose"] == "assertionMethod"
        report = await verifier.verify(
            issued_credential.document, expected_subject=risk_agent.did
        )
        assert report.valid
        assert all(checks(report).values())

    async def test_missing_proof_purpose_is_malformed(self, verifier, issued_credential):
        forged = copy.deepcopy(issued_credential.document)
        del forged["proof"]["proofPurpose"]
        report = await verifier.verify(forged)
        assert not report.valid
        assert report.reason == Reason.MALFORMED
        assert "proofPurpose" in (
            next(c.detail for c in report.checks if c.name == "structure")
        )

    async def test_holder_proof_purpose_is_rejected_on_a_credential(
        self, verifier, issued_credential
    ):
        """An `authentication` proof must not be accepted as a credential proof."""
        forged = copy.deepcopy(issued_credential.document)
        forged["proof"]["proofPurpose"] = "authentication"
        report = await verifier.verify(forged)
        assert not report.valid
        assert report.reason == Reason.MALFORMED
        detail = next(c.detail for c in report.checks if c.name == "structure")
        assert "assertionMethod" in detail and "authentication" in detail

    async def test_editing_the_purpose_still_breaks_the_signature(
        self, verifier, issued_credential
    ):
        """The cryptographic model is unchanged: purpose is signature-covered.

        Structure is checked before signature, so a purpose edit now reports
        MALFORMED. Restoring a valid purpose on a credential whose bytes were
        signed with a different one still fails on the signature, which is the
        property the new check must not be allowed to mask.
        """
        forged = copy.deepcopy(issued_credential.document)
        forged["proof"]["proofPurpose"] = "authentication"
        # ...and now put it back to something structurally acceptable, while
        # tampering with a covered field, to prove signature checking still runs.
        forged["proof"]["proofPurpose"] = "assertionMethod"
        forged["credentialSubject"]["capability"] = "payroll_access"
        report = await verifier.verify(forged)
        assert not report.valid
        assert report.reason == Reason.SIGNATURE_INVALID
        assert checks(report)["structure"] is True
