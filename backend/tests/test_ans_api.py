"""HTTP surface of the ANS service.

PHASE 4.5: heartbeat and deregistration are signed control-plane requests. The
`ans_post` fixture (in conftest.py) signs as the agent itself -- the same proof a running
agent produces. The refusal cases live in
test_control_plane_security_matrix.py.
"""
from __future__ import annotations

import base64

import pytest

pytestmark = pytest.mark.integration


class TestRegistrationEndpoint:
    async def test_valid_registration_is_201(self, ans_client, sign_registration,
                                             risk_agent):
        payload, signature = sign_registration(risk_agent)
        response = await ans_client.post("/api/v1/ans/register",
                                         json={**payload.to_dict(), "signature": signature})
        assert response.status_code == 201
        assert response.json()["accepted"] is True

    async def test_spoofed_registration_is_403_with_the_failing_check(
        self, ans_client, sign_registration, risk_agent
    ):
        payload, _ = sign_registration(risk_agent, endpoint="http://attacker:9999")
        response = await ans_client.post(
            "/api/v1/ans/register",
            json={**payload.to_dict(),
                  "signature": base64.b64encode(b"\x00" * 64).decode()},
        )
        assert response.status_code == 403
        body = response.json()
        assert body["reason"] == "INVALID_REGISTRATION_PROOF"
        failed = [c["name"] for c in body["checks"] if not c["passed"]]
        assert failed == ["registration_proof"]


class TestDiscoveryEndpoint:
    async def test_discover_returns_ranked_results(self, ans_client,
                                                   registered_risk_agent):
        response = await ans_client.post("/api/v1/ans/discover",
                                         json={"capability": "credit_analysis"})
        assert response.status_code == 200
        body = response.json()
        assert body["matched_count"] == 1
        assert body["selected"]["did"] == registered_risk_agent.did
        assert body["ans_latency_ms"] > 0

    async def test_no_match_is_explicit(self, ans_client, registered_risk_agent):
        body = (await ans_client.post("/api/v1/ans/discover",
                                      json={"capability": "payroll_access"})).json()
        assert body["results"] == []
        assert body["selected"] is None
        assert body["reason"] == "NO_MATCHING_AGENT"

    async def test_discovery_request_is_retrievable(self, ans_client,
                                                    registered_risk_agent):
        body = (await ans_client.post("/api/v1/ans/discover",
                                      json={"capability": "credit_analysis"})).json()
        stored = (await ans_client.get(
            f"/api/v1/ans/discovery/{body['request_id']}")).json()
        assert stored["request_id"] == body["request_id"]
        assert stored["results"][0]["matched"] is True


class TestRegistryEndpoints:
    async def test_agents_and_capabilities(self, ans_client, registered_risk_agent):
        agents = (await ans_client.get("/api/v1/ans/agents")).json()
        assert [a["did"] for a in agents] == [registered_risk_agent.did]

        catalogue = (await ans_client.get("/api/v1/ans/capabilities")).json()
        assert "credit_analysis" in [c["capability"] for c in catalogue]

    async def test_resolve(self, ans_client, registered_risk_agent):
        resolved = (await ans_client.get(
            f"/api/v1/ans/resolve/{registered_risk_agent.did}")).json()
        assert resolved["endpoint"] == "http://localhost:9003"
        assert resolved["did_document"]["id"] == registered_risk_agent.did

    async def test_resolve_unknown_is_404(self, ans_client):
        response = await ans_client.get("/api/v1/ans/resolve/did:poc:agent:ghost-999")
        assert response.status_code == 404

    async def test_heartbeat_and_unregister(self, ans_post, opa_ready,
                                            registered_risk_agent):
        did = registered_risk_agent.did
        beat = await ans_post("/api/v1/ans/heartbeat", did,
                              {"did": did, "active_tasks": 2})
        assert beat.json()["status"] == "ACTIVE"

        off = await ans_post(f"/api/v1/ans/unregister/{did}", did,
                             {"reason": "SIGTERM"})
        assert off.json()["status"] == "OFFLINE"

    async def test_heartbeat_cannot_move_the_endpoint(self, ans_post, opa_ready,
                                                      registered_risk_agent):
        """Authenticating as yourself does not let you redirect your own traffic.

        Moving an endpoint requires a fresh signed REGISTRATION. A heartbeat
        proof authenticates liveness, and liveness only -- otherwise a stolen
        agent key could quietly reroute the network without ever re-registering.
        """
        did = registered_risk_agent.did
        response = await ans_post(
            "/api/v1/ans/heartbeat", did,
            {"did": did, "endpoint": "http://attacker.invalid:9999"})
        assert response.status_code == 400
        assert response.json()["error"] == "IDENTITY_ERROR"
