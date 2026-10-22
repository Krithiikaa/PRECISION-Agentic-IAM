"""The agent-side credential wallet and holder proof.

The IAM API is stubbed with an httpx MockTransport so the wallet's own logic is
under test. The cryptography is not stubbed: the presentation is signed with a
real Ed25519 key and verified with the real verifier.
"""
from __future__ import annotations

import json

import httpx
import pytest

from app.agents.wallet import CredentialWallet, HeldCredential
from app.credentials.issuer import IssueRequest
from app.credentials.presenter import PresentationVerifier
from app.identity.signer import Signer

pytestmark = pytest.mark.integration


def _wallet_for(agent, keystore, entries):
    """A wallet whose IAM client returns `entries` from the credentials endpoint."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/credentials"):
            return httpx.Response(200, json=entries)
        return httpx.Response(404)

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://iam.test"
    )
    return CredentialWallet(
        iam=client,
        holder_did=agent.did,
        holder_kid=agent.active_key.kid,
        signer=Signer(keystore),
    )


def _entry(record, status="ACTIVE", seconds_remaining=3600):
    return {
        "credential_id": record.credential_id,
        "credential_type": record.credential_type,
        "issuer": record.issuer_did,
        "status": status,
        "issued_at": record.issued_at.isoformat(),
        "expires_at": record.expires_at.isoformat(),
        "seconds_remaining": seconds_remaining,
        "credential": record.document,
    }


class TestWalletContents:
    async def test_refresh_loads_held_credentials(self, issued_credential, risk_agent,
                                                  keystore):
        wallet = _wallet_for(risk_agent, keystore, [_entry(issued_credential)])
        held = await wallet.refresh()

        assert [c.credential_id for c in held] == [issued_credential.credential_id]
        assert held[0].capability == "credit_analysis"
        assert held[0].usable

    async def test_attested_capabilities_come_from_credentials_not_declarations(
        self, issued_credential, risk_agent, keystore
    ):
        wallet = _wallet_for(risk_agent, keystore, [_entry(issued_credential)])
        await wallet.refresh()
        assert wallet.attested_capabilities() == ["credit_analysis"]

    async def test_revoked_and_expired_credentials_are_not_usable(
        self, issued_credential, risk_agent, keystore
    ):
        wallet = _wallet_for(risk_agent, keystore, [
            _entry(issued_credential, status="REVOKED"),
        ])
        await wallet.refresh()
        assert wallet.attested_capabilities() == []
        assert wallet.select(capability="credit_analysis") == []

        wallet = _wallet_for(risk_agent, keystore, [
            _entry(issued_credential, seconds_remaining=0),
        ])
        await wallet.refresh()
        assert wallet.attested_capabilities() == []

    async def test_refresh_failure_is_reported_not_hidden(self, risk_agent, keystore):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("IAM is down")

        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://iam.test"
        )
        wallet = CredentialWallet(
            iam=client, holder_did=risk_agent.did,
            holder_kid=risk_agent.active_key.kid, signer=Signer(keystore),
        )
        assert await wallet.refresh() == []
        assert "ConnectError" in wallet.last_error

    async def test_select_filters_by_type_and_capability(
        self, credential_issuer, issued_credential, risk_agent, keystore, issuer_did
    ):
        role = await credential_issuer.issue(
            IssueRequest(issuer_did, risk_agent.did, "AgentRoleCredential",
                         {"role": "risk_analyst", "department": "credit_risk"})
        )
        wallet = _wallet_for(risk_agent, keystore,
                             [_entry(issued_credential), _entry(role)])
        await wallet.refresh()

        assert len(wallet.select()) == 2
        assert [c.credential_type for c in wallet.select(
            credential_type="AgentRoleCredential")] == ["AgentRoleCredential"]
        assert [c.capability for c in wallet.select(
            capability="credit_analysis")] == ["credit_analysis"]
        assert wallet.select(capability="payroll_access") == []


class TestHolderProof:
    async def test_wallet_signs_a_verifiable_presentation(
        self, session, keystore, issued_credential, risk_agent, issuers
    ):
        wallet = _wallet_for(risk_agent, keystore, [_entry(issued_credential)])
        await wallet.refresh()
        document = wallet.present(
            wallet.select(capability="credit_analysis"), challenge="nonce-9"
        )

        assert document["holder"] == risk_agent.did
        assert document["proof"]["verificationMethod"] == risk_agent.active_key.kid
        assert document["proof"]["challenge"] == "nonce-9"

        report = await PresentationVerifier(session, keystore).verify(
            document, expected_challenge="nonce-9"
        )
        assert report.valid

    async def test_presenting_nothing_is_an_error_not_an_empty_presentation(
        self, risk_agent, keystore
    ):
        wallet = _wallet_for(risk_agent, keystore, [])
        await wallet.refresh()
        with pytest.raises(ValueError, match="no matching credential"):
            wallet.present(wallet.select(capability="credit_analysis"))
