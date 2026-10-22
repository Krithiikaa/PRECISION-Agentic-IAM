"""HTTP surface of the credential plane, plus audit integration."""
from __future__ import annotations

import copy

import pytest

pytestmark = pytest.mark.integration

BANK = "did:poc:organization:bank-demo"
CLAIMS = {
    "capability": "credit_analysis",
    "allowed_actions": ["READ_CREDIT_PROFILE"],
    "allowed_resources": ["credit_records"],
    "purpose": "loan_assessment",
}


@pytest.fixture
async def agent(client, admin_post):
    response = await admin_post("/api/v1/agents", {
        "slug": "risk-001", "name": "Credit Risk Analysis Agent", "agent_type": "RISK",
        "capabilities": ["credit_analysis"], "endpoint": "http://localhost:9003",
    })
    assert response.status_code == 201
    return response.json()


@pytest.fixture
async def credential(client, agent, issuers, admin_post):
    response = await admin_post("/api/v1/credentials/issue", {
        "issuer": BANK, "subject": agent["did"],
        "credential_type": "AgentCapabilityCredential",
        "claims": CLAIMS, "expires_in_seconds": 3600,
    })
    assert response.status_code == 201
    return response.json()


class TestIssuerEndpoints:
    async def test_issuers_are_listed_without_private_keys(self, client, issuers):
        body = (await client.get("/api/v1/credentials/issuers")).json()
        assert {i["did"] for i in body} == {BANK, "did:poc:organization:compliance-authority"}
        import json
        assert "private" not in json.dumps(body).lower()

    async def test_issuer_did_document(self, client, issuers):
        document = (
            await client.get(f"/api/v1/credentials/issuers/{BANK}/did-document")
        ).json()
        assert document["id"] == BANK
        assert document["verificationMethod"][0]["publicKeyMultibase"].startswith("z6Mk")


class TestIssueAndVerify:
    async def test_issue_returns_the_signed_credential(self, credential):
        document = credential["credential"]
        assert document["proof"]["proofValue"]
        assert credential["summary"]["status"] == "ACTIVE"
        assert credential["summary"]["seconds_remaining"] > 3500

    async def test_verify_reports_every_check(self, client, credential, agent):
        report = (await client.post("/api/v1/credentials/verify", json={
            "credential": credential["credential"], "expected_subject": agent["did"],
        })).json()
        assert report["valid"] is True
        assert report["reason"] == "CREDENTIAL_VALID"
        assert set(report["checks"]) == {
            "structure", "issuer", "signature", "subject",
            "not_before", "expiration", "status", "claims",
        }
        assert all(c["detail"] for c in report["check_details"])

    async def test_tampering_is_rejected_over_http(self, client, credential, agent):
        forged = copy.deepcopy(credential["credential"])
        forged["credentialSubject"]["capability"] = "payroll_access"
        response = await client.post("/api/v1/credentials/verify", json={
            "credential": forged, "expected_subject": agent["did"],
        })
        assert response.status_code == 200          # a verdict, not an error
        assert response.json()["reason"] == "SIGNATURE_INVALID"

    async def test_issue_refuses_an_unknown_issuer(self, client, agent, issuers, admin_post):
        response = await admin_post("/api/v1/credentials/issue", {
            "issuer": "did:poc:organization:rogue", "subject": agent["did"],
            "credential_type": "AgentCapabilityCredential", "claims": CLAIMS,
        })
        assert response.status_code == 404


class TestStatusAndRevocation:
    async def test_status_endpoint(self, client, credential):
        cid = credential["credential_id"]
        status = (await client.get(f"/api/v1/credentials/{cid}/status")).json()
        assert status["status"] == "ACTIVE"
        assert status["seconds_remaining"] > 0

    async def test_revoke_then_verify_fails(self, client, credential, admin_post):
        cid = credential["credential_id"]
        revoked = (await admin_post(f"/api/v1/credentials/{cid}/revoke", {"reason": "COMPROMISED"})).json()
        assert revoked["status"] == "REVOKED"
        assert revoked["revocation_reason"] == "COMPROMISED"

        report = (await client.post("/api/v1/credentials/verify",
                                    json={"credential": credential["credential"]})).json()
        assert report["valid"] is False
        assert report["reason"] == "CREDENTIAL_REVOKED"

    async def test_double_revoke_conflicts(self, client, credential, admin_post):
        cid = credential["credential_id"]
        await admin_post(f"/api/v1/credentials/{cid}/revoke", {"reason": "A"})
        response = await admin_post(f"/api/v1/credentials/{cid}/revoke", {"reason": "B"})
        assert response.status_code == 409


class TestRegistryEndpoints:
    async def test_list_and_fetch(self, client, credential, agent):
        listing = (await client.get(f"/api/v1/credentials?subject={agent['did']}")).json()
        assert [c["credential_id"] for c in listing] == [credential["credential_id"]]

        fetched = (
            await client.get(f"/api/v1/credentials/{credential['credential_id']}")
        ).json()
        assert fetched["credential"]["proof"]["proofValue"] == (
            credential["credential"]["proof"]["proofValue"]
        )

    async def test_agent_detail_exposes_the_credential_inventory(self, client, credential,
                                                                 agent):
        detail = (await client.get(f"/api/v1/agents/{agent['id']}")).json()
        inventory = detail["credentials"]
        assert len(inventory) == 1
        assert inventory[0]["credential_type"] == "AgentCapabilityCredential"
        assert inventory[0]["status"] == "ACTIVE"
        import json
        assert "private" not in json.dumps(detail).lower()

    async def test_agent_credentials_endpoint_can_include_documents(self, client, credential,
                                                                    agent):
        entries = (
            await client.get(f"/api/v1/agents/did/{agent['did']}/credentials",
                             params={"include_document": "true"})
        ).json()
        assert entries[0]["credential"]["id"] == credential["credential_id"]

    async def test_verification_history_is_queryable(self, client, credential):
        cid = credential["credential_id"]
        await client.post("/api/v1/credentials/verify",
                          json={"credential": credential["credential"]})
        history = (await client.get(f"/api/v1/credentials/{cid}/verifications")).json()
        assert history[0]["valid"] is True
        assert history[0]["checks"]["signature"] is True


class TestPresentationEndpoints:
    async def test_present_and_verify_presentation(self, client, credential, agent, admin_post):
        challenge = (await client.get("/api/v1/credentials/challenge")).json()["challenge"]
        presented = (await admin_post("/api/v1/credentials/present", {
            "holder": agent["did"], "challenge": challenge, "domain": "loan-service",
        })).json()

        report = (await client.post("/api/v1/credentials/verify-presentation", json={
            "presentation": presented["presentation"], "expected_challenge": challenge,
        })).json()
        assert report["valid"] is True
        assert report["checks"]["holder_proof"] is True
        assert report["credentials"][0]["valid"] is True

    async def test_challenge_endpoint_is_honest_about_replay(self, client):
        body = (await client.get("/api/v1/credentials/challenge")).json()
        assert body["single_use_enforced"] is False

    async def test_expected_domain_is_enforced_over_http(self, client, credential, agent, admin_post):
        """S-2 wiring: the route must actually pass the audience to the verifier."""
        challenge = (await client.get("/api/v1/credentials/challenge")).json()["challenge"]
        presented = (await admin_post("/api/v1/credentials/present", {
            "holder": agent["did"], "challenge": challenge, "domain": "loan-service",
        })).json()
        vp = presented["presentation"]

        matched = (await client.post("/api/v1/credentials/verify-presentation", json={
            "presentation": vp, "expected_challenge": challenge,
            "expected_domain": "loan-service",
        })).json()
        assert matched["valid"] is True
        assert matched["checks"]["domain"] is True

        relayed = (await client.post("/api/v1/credentials/verify-presentation", json={
            "presentation": vp, "expected_challenge": challenge,
            "expected_domain": "payments-service",
        })).json()
        assert relayed["valid"] is False
        assert relayed["reason"] == "DOMAIN_MISMATCH"
        assert relayed["checks"]["domain"] is False


class TestAuditIntegration:
    async def test_credential_events_reach_the_audit_trail(self, client, credential, agent, admin_post):
        cid = credential["credential_id"]
        await client.post("/api/v1/credentials/verify",
                          json={"credential": credential["credential"]})
        forged = copy.deepcopy(credential["credential"])
        forged["credentialSubject"]["capability"] = "payroll_access"
        await client.post("/api/v1/credentials/verify", json={"credential": forged})
        await admin_post(f"/api/v1/credentials/{cid}/revoke", {"reason": "DEMO"})

        events = (await client.get(f"/api/v1/audit?agent_did={agent['did']}&limit=100")).json()
        recorded = {e["event_type"] for e in events}
        assert {
            "CREDENTIAL_ISSUED", "CREDENTIAL_STORED", "CREDENTIAL_VERIFICATION_STARTED",
            "CREDENTIAL_VERIFIED", "CREDENTIAL_SIGNATURE_INVALID", "CREDENTIAL_REVOKED",
        } <= recorded

    async def test_failed_verification_records_the_failing_check(self, client, credential):
        forged = copy.deepcopy(credential["credential"])
        forged["credentialSubject"]["capability"] = "payroll_access"
        await client.post("/api/v1/credentials/verify", json={"credential": forged})

        events = (await client.get("/api/v1/audit?event_type=CREDENTIAL_SIGNATURE_INVALID")).json()
        assert events[0]["decision"] == "INVALID"
        assert events[0]["metadata"]["failed_check"] == "signature"
