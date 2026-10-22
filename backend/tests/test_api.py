"""HTTP surface of the identity plane."""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.integration

MESSAGE = "I am the Risk Analysis Agent"
TAMPERED = "I am the Payroll Agent"


def _payload(slug="risk-001", **overrides):
    body = {
        "slug": slug,
        "name": "Credit Risk Analysis Agent",
        "agent_type": "RISK",
        "purpose": "Analyse the financial risk of a loan application.",
        "capabilities": ["credit_analysis", "risk_analysis"],
        "endpoint": "http://localhost:9003",
    }
    body.update(overrides)
    return body


class TestAgentEndpoints:
    async def test_create_returns_identity_without_key_material(self, client, admin_post):
        response = await admin_post("/api/v1/agents", _payload())
        assert response.status_code == 201
        body = response.json()

        assert body["did"] == "did:poc:agent:risk-001"
        assert body["status"] == "ACTIVE"
        assert body["active_key"]["algorithm"] == "Ed25519"
        assert body["active_key"]["public_key_multibase"].startswith("z6Mk")

        # No private key can appear: no field carries one, at any depth.
        serialised = json.dumps(body).lower()
        assert "private" not in serialised
        assert "secret" not in serialised

    async def test_duplicate_slug_conflicts(self, client, admin_post):
        await admin_post("/api/v1/agents", _payload())
        response = await admin_post("/api/v1/agents", _payload())
        assert response.status_code == 409
        assert response.json()["error"] == "CONFLICT"

    async def test_invalid_slug_is_rejected_by_validation(self, client, admin_post):
        assert (await admin_post("/api/v1/agents", _payload("Risk_001"))).status_code == 422

    async def test_list_and_filter_by_capability(self, client, admin_post):
        await admin_post("/api/v1/agents", _payload())
        await admin_post(
            "/api/v1/agents",
            _payload("fraud-001", name="Fraud Detection Agent", agent_type="FRAUD",
                     capabilities=["fraud_detection"]),
        )
        assert len((await client.get("/api/v1/agents")).json()) == 2
        filtered = (await client.get("/api/v1/agents?capability=fraud_detection")).json()
        assert [a["did"] for a in filtered] == ["did:poc:agent:fraud-001"]

    async def test_resolve_by_did_and_fetch_did_document(self, client, admin_post):
        created = (await admin_post("/api/v1/agents", _payload())).json()
        did = created["did"]

        assert (await client.get(f"/api/v1/agents/did/{did}")).json()["id"] == created["id"]

        document = (await client.get(f"/api/v1/agents/did/{did}/did-document")).json()
        assert document["id"] == did
        assert document["verificationMethod"][0]["publicKeyMultibase"] == (
            created["active_key"]["public_key_multibase"]
        )
        assert document["service"][0]["serviceEndpoint"] == "http://localhost:9003"

    async def test_unknown_did_is_404(self, client):
        response = await client.get("/api/v1/agents/did/did:poc:agent:ghost-001")
        assert response.status_code == 404
        assert response.json()["error"] == "NOT_FOUND"


class TestIdentityLab:
    async def test_sign_verify_and_tamper(self, client, cp_post, control_plane,
                                          identity_admin_did, opa_ready, admin_post):
        """The exact Identity Lab flow, over HTTP.

        PHASE 4.5: signing as a custodied identity is an administrative
        operation now (S-6) -- it produces a signature over ARBITRARY bytes
        with an agent's key, which is a forgery oracle for every DID proof in
        the system if left open. VERIFYING stays unauthenticated: it needs only
        a public key and is exactly what a third party must be able to do alone.
        """
        created = (await admin_post("/api/v1/agents", _payload())).json()

        signed = (
            await cp_post(f"/api/v1/agents/{created['id']}/sign", identity_admin_did,
                          {"message": MESSAGE})
        ).json()
        assert signed["algorithm"] == "Ed25519"

        good = (
            await client.post(
                "/api/v1/identity/verify",
                json={"did": created["did"], "message": MESSAGE, "signature": signed["signature"]},
            )
        ).json()
        assert good["valid"] is True

        bad = (
            await client.post(
                "/api/v1/identity/verify",
                json={"did": created["did"], "message": TAMPERED,
                      "signature": signed["signature"]},
            )
        ).json()
        assert bad["valid"] is False
        assert bad["reason"].startswith("SIGNATURE_MISMATCH")

    async def test_verification_failure_is_200_not_an_error(self, client, admin_post):
        created = (await admin_post("/api/v1/agents", _payload())).json()
        response = await client.post(
            "/api/v1/identity/verify",
            json={"did": created["did"], "message": MESSAGE, "signature": "AAAA"},
        )
        assert response.status_code == 200
        assert response.json()["valid"] is False


class TestLifecycleEndpoints:
    async def test_terminate_blocks_further_signing(self, client, cp_post,
                                                    control_plane,
                                                    identity_admin_did, opa_ready, admin_post):
        """Even an AUTHORIZED administrator cannot sign for a terminated agent.

        The control-plane guard answers "may this principal ask?"; the identity
        authority still answers "does this identity exist and may it sign?".
        Both have to say yes, and the second one refuses here.
        """
        created = (await admin_post("/api/v1/agents", _payload())).json()
        response = await admin_post(
            f"/api/v1/agents/{created['id']}/status",
            {"status": "TERMINATED", "reason": "COMPROMISED"},
        )
        assert response.json()["status"] == "TERMINATED"

        blocked = await cp_post(
            f"/api/v1/agents/{created['id']}/sign", identity_admin_did,
            {"message": MESSAGE},
        )
        assert blocked.status_code == 400
        assert blocked.json()["error"] == "IDENTITY_ERROR"


class TestAuditTrail:
    async def test_lifecycle_events_are_recorded(self, client, cp_post, control_plane,
                                                 identity_admin_did, opa_ready, admin_post):
        created = (await admin_post("/api/v1/agents", _payload())).json()
        await cp_post(f"/api/v1/agents/{created['id']}/sign", identity_admin_did,
                      {"message": MESSAGE})

        events = (await client.get(f"/api/v1/audit?agent_did={created['did']}")).json()
        recorded = {e["event_type"] for e in events}
        assert {
            "AGENT_CREATED", "DID_ASSIGNED", "KEY_GENERATED",
            "DID_DOCUMENT_PUBLISHED", "AGENT_ACTIVATED", "SIGNATURE_CREATED",
        } <= recorded

    async def test_invalid_signature_is_audited_as_such(self, client, cp_post,
                                                        control_plane,
                                                        identity_admin_did, opa_ready, admin_post):
        created = (await admin_post("/api/v1/agents", _payload())).json()
        signed = (
            await cp_post(f"/api/v1/agents/{created['id']}/sign", identity_admin_did,
                          {"message": MESSAGE})
        ).json()
        await client.post(
            "/api/v1/identity/verify",
            json={"did": created["did"], "message": TAMPERED, "signature": signed["signature"]},
        )
        events = (await client.get("/api/v1/audit?event_type=SIGNATURE_INVALID")).json()
        assert len(events) == 1
        assert events[0]["decision"] == "INVALID"

    async def test_agent_process_events_are_ingested(self, client, agent_post,
                                                     admin_post, opa_ready):
        """An agent writes its OWN activity, and the event is ATTRIBUTABLE.

        PHASE 5: ingest used to be unauthenticated, and this test used to
        assert that the event was flagged as an unauthenticated claim. It is no
        longer a claim -- the agent proves control of the DID it writes under,
        exactly as it does for a heartbeat -- so the assertion is now that the
        trail records who wrote the entry.
        """
        created = (await admin_post("/api/v1/agents", _payload())).json()
        response = await agent_post(
            "/api/v1/audit/events", created["did"],
            {"event_type": "AGENT_TASK_COMPLETED", "agent_did": created["did"],
             "task_id": "t-1"},
        )
        assert response.status_code == 202
        events = (await client.get("/api/v1/audit?event_type=AGENT_TASK_COMPLETED")).json()
        assert events[0]["metadata"]["task_id"] == "t-1"
        assert events[0]["metadata"]["ingested_by"] == created["did"]
        assert events[0]["metadata"]["ingested_by_type"] == "agent"

    async def test_unauthenticated_audit_ingest_is_refused(self, client, opa_ready):
        """Audit forgery, refused.

        An open ingest endpoint lets an attacker write a record of events that
        never happened, or drown the real ones. Reading stays open; the trail
        is meant to be inspectable.
        """
        response = await client.post(
            "/api/v1/audit/events",
            json={"event_type": "AGENT_TASK_COMPLETED",
                  "agent_did": "did:poc:agent:risk-001", "task_id": "forged"},
        )
        assert response.status_code == 401
        assert (await client.get(
            "/api/v1/audit?event_type=AGENT_TASK_COMPLETED")).json() == []

    async def test_an_agent_cannot_write_history_for_another_agent(
        self, client, agent_post, admin_post, opa_ready
    ):
        """Bound to self, exactly like a heartbeat."""
        created = (await admin_post("/api/v1/agents", _payload())).json()
        response = await agent_post(
            "/api/v1/audit/events", created["did"],
            {"event_type": "AGENT_TASK_COMPLETED",
             "agent_did": "did:poc:agent:someone-else", "task_id": "t-2"},
        )
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "PRINCIPAL_IS_NOT_THE_SUBJECT"
