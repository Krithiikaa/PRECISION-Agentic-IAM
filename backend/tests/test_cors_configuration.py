"""Phase 12: browser origins are configuration, validated, and the same everywhere.

Before: the IAM API read CORS_ALLOWED_ORIGINS, but the ANS and all nine agent
processes hard-coded two localhost origins with `allow_methods=["*"]` and
`allow_headers=["*"]`. Changing the console's origin for a deployment left
ten services answering the old one.

CORS is not authorization. These tests assert only what CORS is for: which
browser origins may READ a response.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from app.core.config import Settings, get_settings

ALLOWED = "http://localhost:5173"
EVIL = "https://evil.example"


def preflight_headers(origin):
    return {"Origin": origin, "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type"}


async def _preflight(app, origin, path="/health"):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.options(path, headers=preflight_headers(origin))


def _apps(settings):
    """Every browser-reachable service, built with the given settings."""
    import app.agents.service as agent_service
    import app.ans.service as ans_service
    import app.main as main
    from app.agents.service import AgentServiceConfig

    originals = (agent_service.get_settings, ans_service.get_settings, main.get_settings)
    agent_service.get_settings = ans_service.get_settings = main.get_settings = lambda: settings
    try:
        return {
            "iam-api": main.create_app(),
            "ans": ans_service.create_ans_app(),
            "agent risk-001": agent_service.create_agent_service(
                AgentServiceConfig(slug="risk-001")),
            "agent coordinator-001": agent_service.create_agent_service(
                AgentServiceConfig(slug="coordinator-001")),
        }
    finally:
        agent_service.get_settings, ans_service.get_settings, main.get_settings = originals


class TestEveryServiceUsesTheConfiguredAllowList:
    @pytest.mark.parametrize("name", ["iam-api", "ans", "agent risk-001",
                                      "agent coordinator-001"])
    async def test_an_allowed_origin_is_answered(self, name):
        app = _apps(get_settings())[name]
        response = await _preflight(app, ALLOWED)
        assert response.status_code == 200, (name, response.text)
        assert response.headers["access-control-allow-origin"] == ALLOWED
        assert response.headers.get("access-control-allow-credentials") == "true"

    @pytest.mark.parametrize("name", ["iam-api", "ans", "agent risk-001",
                                      "agent coordinator-001"])
    async def test_an_unlisted_origin_is_refused(self, name):
        app = _apps(get_settings())[name]
        response = await _preflight(app, EVIL)
        assert response.status_code == 400, name
        assert "access-control-allow-origin" not in response.headers

    async def test_changing_the_configuration_changes_every_service(self):
        custom = get_settings().model_copy(update={
            "cors_allowed_origins": "https://ops.bank.example"})
        for name, app in _apps(custom).items():
            ok = await _preflight(app, "https://ops.bank.example")
            old = await _preflight(app, ALLOWED)
            assert ok.headers.get("access-control-allow-origin") == \
                "https://ops.bank.example", name
            assert "access-control-allow-origin" not in old.headers, name

    async def test_agents_no_longer_allow_every_header(self):
        app = _apps(get_settings())["agent risk-001"]
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            response = await c.options("/health", headers={
                "Origin": ALLOWED, "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "x-forwarded-for-spoof"})
        assert response.status_code == 400


class TestConfigurationIsValidatedAtStartup:
    @pytest.mark.parametrize("bad", [
        "http://localhost:5173/",            # trailing path
        "http://localhost:5173/console",
        "https://*.example.com",             # wildcard fragment
        "localhost:5173",                    # no scheme
        "ftp://console.example.com",
        "https://console.example.com?x=1",
    ])
    def test_a_malformed_origin_refuses_to_start(self, bad):
        with pytest.raises(ValidationError, match="not an exact origin"):
            Settings(cors_allowed_origins=bad)

    def test_a_wildcard_with_credentials_is_refused_in_every_environment(self):
        with pytest.raises(ValidationError, match="cannot be"):
            Settings(env="development", cors_allowed_origins="*",
                     cors_allow_credentials=True)

    def test_a_wildcard_is_refused_in_production_even_without_credentials(self):
        from tests.test_production_configuration import production
        with pytest.raises(ValidationError, match="cannot contain"):
            production(cors_allowed_origins="*", cors_allow_credentials=False)

    def test_production_accepts_an_explicit_https_allow_list(self):
        from tests.test_production_configuration import production
        settings = production(cors_allowed_origins="https://console.bank.example,"
                                                    "https://ops.bank.example")
        assert settings.cors_middleware_options()["allow_origins"] == [
            "https://console.bank.example", "https://ops.bank.example"]

    def test_development_defaults_are_the_local_console_only(self):
        assert Settings(env="development").cors_origins == [
            "http://localhost:5173", "http://localhost:3000"]
