"""CORS configuration (Phase 10).

WHAT CORS IS, AND WHAT IT IS NOT. It restricts which BROWSER ORIGINS may
READ a response. It does nothing whatsoever about a direct HTTP call — curl
ignores it, and so does every script. That is why every sensitive route in
this service is independently guarded (`test_route_security_inventory.py`)
and why nothing here is relied on as an access control.

Narrowing it still matters: it reduces what a hostile page can do with a
signed-in operator's session. No more than that, and this file does not
claim more.

WHAT PHASE 10 CHANGED. `main.py` hardcoded two localhost origins with
`allow_methods=["*"]` and `allow_headers=["*"]`. That failed SAFE — a real
console simply would not load — but it could not be deployed, and the
wildcards were wider than anything needed.
"""
from __future__ import annotations

import base64
import os

import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings

pytestmark = pytest.mark.integration

REAL_KEY = base64.b64encode(os.urandom(32)).decode()

PRODUCTION = {
    "env": "production",
    "keystore_master_key": REAL_KEY,
    "opa_url": "https://opa.internal",
    "keycloak_base_url": "https://sso.example.com",
    "keycloak_issuer": "https://sso.example.com/realms/agentic-iam",
    "mcp_resource_uri": "https://api.example.com/mcp",
    "api_public_url": "https://api.example.com",
    "ratelimit_enabled": True,
    "ratelimit_redis_policy": "fail_closed",
}


def production(**overrides) -> Settings:
    return Settings(**{**PRODUCTION, "cors_allowed_origins":
                       "https://console.example.com", **overrides})


class TestOriginsAreConfiguration:
    def test_origins_come_from_the_environment(self):
        settings = Settings(cors_allowed_origins="https://a.example,https://b.example")
        assert settings.cors_origins == ["https://a.example", "https://b.example"]

    def test_whitespace_and_empty_entries_are_tolerated(self):
        """An operator editing a comma-separated list will leave a trailing
        comma eventually. Producing an empty-string origin from that would
        silently match nothing and be very hard to see."""
        settings = Settings(cors_allowed_origins=" https://a.example , , ")
        assert settings.cors_origins == ["https://a.example"]

    def test_methods_and_headers_are_configurable_and_not_wildcards(self):
        settings = get_settings()
        assert "*" not in settings.cors_methods
        assert "*" not in settings.cors_headers

    def test_the_mcp_headers_are_allowed(self):
        """An MCP browser client sends `Mcp-Session-Id` and
        `MCP-Protocol-Version`. Omitting them would make the endpoint
        unusable from a browser for a reason nobody would look for in a
        CORS list."""
        headers = [h.lower() for h in get_settings().cors_headers]
        assert "mcp-session-id" in headers
        assert "mcp-protocol-version" in headers


class TestProductionRefusesUnsafeCORS:
    def test_a_wildcard_with_credentials_is_refused(self):
        """Browsers reject `Access-Control-Allow-Origin: *` together with
        credentials anyway. Configuring it means somebody believes it works,
        and the usual next step is to "fix" it by turning off something that
        matters."""
        with pytest.raises(ValidationError, match="CORS_ALLOWED_ORIGINS"):
            production(cors_allowed_origins="*", cors_allow_credentials=True)

    def test_a_plaintext_origin_is_refused_in_production(self):
        """An http origin means the console's bearer token travels in
        clear."""
        with pytest.raises(ValidationError, match="CORS_ALLOWED_ORIGINS"):
            production(cors_allowed_origins="http://console.example.com")

    def test_an_https_origin_is_accepted(self):
        assert production().cors_origins == ["https://console.example.com"]

    def test_several_https_origins_are_accepted(self):
        settings = production(
            cors_allowed_origins="https://a.example,https://b.example")
        assert len(settings.cors_origins) == 2

    def test_development_still_allows_localhost(self):
        """The whole POC runs on localhost. A guard that broke development
        would be removed within the day, which is not a guard."""
        settings = Settings(env="development")
        assert any(o.startswith("http://localhost") for o in settings.cors_origins)


class TestTheBrowserContract:
    async def test_an_allowed_origin_is_echoed(self, client):
        response = await client.get(
            "/health", headers={"Origin": "http://localhost:5173"})
        assert response.headers.get("access-control-allow-origin") == \
            "http://localhost:5173"

    async def test_an_unapproved_origin_is_not_echoed(self, client):
        """Starlette answers the request but omits the header, so the
        BROWSER refuses to hand the body to the page. The server does not
        403 — which is precisely why CORS is not an access control and the
        route guards exist independently."""
        response = await client.get(
            "/health", headers={"Origin": "https://evil.example"})
        assert response.headers.get("access-control-allow-origin") != \
            "https://evil.example"

    async def test_a_preflight_from_an_allowed_origin_succeeds(self, client):
        response = await client.options(
            "/api/v1/audit",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )
        assert response.status_code in (200, 204)
        assert response.headers.get("access-control-allow-origin") == \
            "http://localhost:5173"

    async def test_a_preflight_from_an_unapproved_origin_is_not_approved(
        self, client
    ):
        response = await client.options(
            "/api/v1/audit",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.headers.get("access-control-allow-origin") != \
            "https://evil.example"

    async def test_a_preflight_for_an_undeclared_method_is_not_approved(
        self, client
    ):
        response = await client.options(
            "/api/v1/audit",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "TRACE",
            },
        )
        allowed = response.headers.get("access-control-allow-methods", "")
        assert "TRACE" not in allowed


class TestCORSIsNotAuthorization:
    async def test_a_guarded_route_still_refuses_an_allowed_origin(self, client):
        """THE POINT OF THIS WHOLE FILE.

        A request from a permitted origin, with no credentials, must still
        be refused by the route guard. If CORS were doing the authorizing,
        this would return data.
        """
        response = await client.get(
            "/api/v1/audit", headers={"Origin": "http://localhost:5173"})
        assert response.status_code in (401, 403)

    async def test_an_origin_header_is_not_required_either(self, client):
        """A non-browser caller sends no Origin at all. It must be judged on
        its credentials, not on the absence of a header."""
        assert (await client.get("/api/v1/audit")).status_code in (401, 403)
