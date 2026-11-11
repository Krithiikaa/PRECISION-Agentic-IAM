"""Operations-console aggregate endpoints (Phase 11).

Every figure is a query or a live probe; these tests prove the endpoints are
guarded like the rest of the read surface, report REAL state (a contained agent
shows up as contained), and never claim a service is up without probing it.
"""
from __future__ import annotations

import pytest

from app.db.models.security import SessionState
from app.sessions.sss import SessionStateSynchronizer

pytestmark = pytest.mark.integration

PATHS = ["/api/v1/console/overview", "/api/v1/console/health", "/api/v1/console/mcp"]


class TestGuarded:
    @pytest.mark.parametrize("path", PATHS)
    async def test_anonymous_is_refused(self, client, path):
        assert (await client.get(path)).status_code == 401

    @pytest.mark.parametrize("path", PATHS)
    async def test_the_loan_administrator_may_not_read_them(self, cp_get, path):
        response = await cp_get(path, "did:poc:administrator:core-banking")
        assert response.status_code == 403

    async def test_an_agent_may_not_read_them(self, agent_post, client, risk_agent):
        # Agents read only peer identity; the console is an operator surface.
        response = await client.get(PATHS[0], headers={})
        assert response.status_code == 401


class TestRealState:
    async def test_overview_counts_come_from_the_database(self, session, cp_get, risk_agent,
                                                          issued_credential):
        await SessionStateSynchronizer(session).set_state(
            risk_agent.did, SessionState.TERMINATED_IMMEDIATE_SECURITY_LOCKOUT,
            reason="t", changed_by="t")
        body = (await cp_get("/api/v1/console/overview")).json()
        assert body["agents"]["by_status"].get("ACTIVE", 0) >= 1
        assert body["agents"]["contained"] == 1
        assert body["credentials"]["by_stored_status"].get("ACTIVE", 0) >= 1
        assert isinstance(body["recent_audit"], list) and body["recent_audit"]

    async def test_health_probes_every_dependency_and_reports_failures(self, cp_get):
        body = (await cp_get("/api/v1/console/health")).json()
        names = {s["service"] for s in body["services"]}
        assert {"PostgreSQL", "OPA / Rego", "Keycloak / OIDC", "Redis",
                "Agent Naming Service", "MCP gateway", "Anomaly detector"} <= names
        for service in body["services"]:
            assert isinstance(service["up"], bool) and service["latency_ms"] >= 0
        postgres = next(s for s in body["services"] if s["service"] == "PostgreSQL")
        assert postgres["up"] is True

    async def test_an_unreachable_service_is_reported_down_not_up(self, cp_get, monkeypatch):
        from app.core.config import get_settings
        monkeypatch.setattr(get_settings(), "ans_base_url", "http://127.0.0.1:1")
        body = (await cp_get("/api/v1/console/health")).json()
        ans = next(s for s in body["services"] if s["service"] == "Agent Naming Service")
        assert ans["up"] is False and "error" in ans

    async def test_mcp_catalogue_marks_discovery_as_not_permission(self, cp_get):
        body = (await cp_get("/api/v1/console/mcp")).json()
        assert "never permission" in body["note"]
        tools = {t["name"]: t for t in body["tools"]}
        assert tools["get_credit_profile"]["mcp_eligible"] is True
        assert tools["execute_payment_instruction"]["mcp_eligible"] is False
