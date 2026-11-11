"""Production configuration refuses insecure settings (Phase 9).

WHAT THESE TESTS ARE FOR. Every other security control in this system is
exercised by sending it a request. A configuration guard is not: it fires
once, at process start, on a machine nobody is looking at, and the failure
mode of a BROKEN guard is that production comes up quietly with development
settings. So the guards are tested the only way they can be -- by building
Settings with the dangerous value and asserting the process would refuse to
start.

THE SHAPE OF EVERY GUARD HERE IS THE SAME, and it is deliberate: refuse to
start, with no opt-out flag. A switch that turns a security requirement into
a no-op is a bypass with a configuration file in front of it, so the
codebase does not offer one. These tests assert that absence as much as they
assert the refusal.
"""
from __future__ import annotations

import base64
import os

import pytest
from pydantic import ValidationError

from app.core.config import DEV_MASTER_KEY, Settings

# A syntactically valid master key that is not the development one. Random
# per run so it cannot accidentally become a fixture anybody depends on, and
# it never reaches a keystore.
REAL_KEY = base64.b64encode(os.urandom(32)).decode()

SECURE = {
    "opa_url": "https://opa.internal",
    "keycloak_base_url": "https://sso.example.com",
    "keycloak_issuer": "https://sso.example.com/realms/agentic-iam",
    "mcp_resource_uri": "https://api.example.com/mcp",
    "api_public_url": "https://api.example.com",
    # Phase 10 added two more production requirements. Spelled out here so a
    # test that breaks ONE of them is testing that one, rather than tripping
    # over an unrelated default it never meant to exercise.
    # The suite sets RATELIMIT_ENABLED=false in the environment so thousands
    # of machine-speed requests do not trip the limiter. Production refuses
    # that, correctly -- so these tests override it back on. The fact that
    # this override is NEEDED is itself the guard working.
    "ratelimit_enabled": True,
    "ratelimit_redis_policy": "fail_closed",
    "cors_allowed_origins": "https://console.example.com",
}


def production(**overrides) -> Settings:
    """Settings as production would load them, with everything secure
    unless a test deliberately breaks one field.

    The defaults are merged into a single dict rather than passed as
    keywords alongside `**overrides`: passing both is a TypeError the moment
    a test wants to override one of them, which is exactly what a test of
    `keystore_master_key` wants to do.
    """
    settings = {
        "env": "production",
        "keystore_master_key": REAL_KEY,
        **SECURE,
        **overrides,
    }
    return Settings(**settings)


class TestTheDevelopmentMasterKeyCannotReachProduction:
    def test_production_refuses_the_development_master_key(self):
        with pytest.raises(ValidationError, match="KEYSTORE_MASTER_KEY"):
            Settings(env="production", keystore_master_key=DEV_MASTER_KEY, **SECURE)

    def test_development_still_accepts_it(self):
        """The whole POC runs on it. A guard that broke development would be
        removed within the day, which is not a guard."""
        assert Settings(env="development").keystore_master_key == DEV_MASTER_KEY


class TestProductionRequiresTLS:
    """Each of these URLs carries something forgeable over plaintext."""

    @pytest.mark.parametrize(
        "field,insecure",
        [
            # An ALLOW is a plain JSON body. Rewrite it and you decide
            # authorization.
            ("opa_url", "http://opa.internal"),
            # Substitute the JWKS and you mint tokens this service accepts;
            # the signature check then passes honestly against your key.
            ("keycloak_base_url", "http://sso.example.com"),
            ("keycloak_issuer", "http://sso.example.com/realms/agentic-iam"),
            # Agents present bearer tokens here.
            ("mcp_resource_uri", "http://api.example.com/mcp"),
            # The protected-resource metadata URL derives from it.
            ("api_public_url", "http://api.example.com"),
        ],
    )
    def test_a_plaintext_url_refuses_to_start_in_production(self, field, insecure):
        with pytest.raises(ValidationError) as exc:
            production(**{field: insecure})
        assert field.upper() in str(exc.value)

    def test_all_https_starts(self):
        settings = production()
        assert settings.env == "production"
        assert settings.opa_url.startswith("https://")

    def test_the_error_names_every_offending_field_at_once(self):
        """An operator fixing one URL only to be refused for the next one is
        an operator who stops reading the message. All of them, in one go."""
        with pytest.raises(ValidationError) as exc:
            production(
                opa_url="http://opa.internal",
                keycloak_issuer="http://sso.example.com/realms/agentic-iam",
            )
        message = str(exc.value)
        assert "OPA_URL" in message
        assert "KEYCLOAK_ISSUER" in message

    def test_development_is_unaffected(self):
        """Plaintext localhost everywhere is exactly how this POC runs."""
        settings = Settings(env="development")
        assert settings.opa_url.startswith("http://")
        assert settings.keycloak_issuer.startswith("http://")

    def test_test_environment_is_unaffected(self):
        assert Settings(env="test").env == "test"

    def test_https_is_matched_case_insensitively(self):
        """A URL is not insecure because somebody typed the scheme in caps."""
        assert production(opa_url="HTTPS://opa.internal").env == "production"


class TestTheRefusalDoesNotLeak:
    """A validation error becomes a log line, a container event and often a
    screenshot in a ticket. It must not spill what it is complaining about."""

    def test_credentials_embedded_in_a_url_are_redacted(self):
        """`http://user:password@host` is a legal URL. Echoing it verbatim
        would leak a credential while complaining about security."""
        with pytest.raises(ValidationError) as exc:
            production(opa_url="http://admin:SuperSecret123@opa.internal")
        message = str(exc.value)
        assert "SuperSecret123" not in message
        assert "admin:" not in message

    def test_but_the_operator_can_still_tell_which_url_is_wrong(self):
        """Redaction that hides the problem is not redaction, it is a
        different bug. The field and the host must survive."""
        with pytest.raises(ValidationError) as exc:
            production(opa_url="http://admin:SuperSecret123@opa.internal")
        message = str(exc.value)
        assert "OPA_URL" in message
        assert "opa.internal" in message

    def test_a_url_without_credentials_is_shown_in_full(self):
        with pytest.raises(ValidationError) as exc:
            production(opa_url="http://opa.internal:8181")
        assert "opa.internal:8181" in str(exc.value)

    def test_a_real_master_key_is_never_echoed_in_an_error(self):
        """PYDANTIC ECHOES THE REJECTED INPUT in a field validator's error
        (`input_value=...`). That is worth knowing about and worth pinning,
        because it means any future validator added to `keystore_master_key`
        WOULD print a real key into the logs.

        Today it cannot happen, and this test is why: the only check on that
        field rejects the development placeholder, and a real key passes it.
        So the value echoed is never a secret. If someone later adds a
        length or entropy check to this field, this test fails and tells
        them to raise it from a model validator instead.
        """
        real = base64.b64encode(os.urandom(32)).decode()
        # A real key passes the field validator, so nothing echoes it...
        assert production(keystore_master_key=real).env == "production"

        # ...and the model-level TLS refusal does not dump the model either.
        with pytest.raises(ValidationError) as exc:
            production(keystore_master_key=real, opa_url="http://opa.internal")
        assert real not in str(exc.value)

    def test_only_the_documented_placeholder_can_appear(self):
        """The dev-key refusal DOES echo the value it rejected. Accepted,
        and asserted so it stays accepted for the right reason: that value
        is the readable placeholder `dev-only-master-key-32-bytes-long!!`,
        documented in .env.example as not-a-credential."""
        with pytest.raises(ValidationError) as exc:
            Settings(env="production", keystore_master_key=DEV_MASTER_KEY,
                     **SECURE)
        decoded = base64.b64decode(DEV_MASTER_KEY).decode()
        assert "dev-only" in decoded, (
            "the development key is no longer a readable placeholder, so the "
            "refusal above is now echoing something that looks like a secret"
        )


class TestSecurityRequirementsHaveNoOffSwitch:
    """Asserting an ABSENCE: there is no configuration that disables these.

    This is the test most likely to be deleted by someone adding a flag "just
    for local debugging", so it states why it exists.
    """

    @pytest.mark.parametrize(
        "field",
        [
            "authorization_fail_closed",
            "control_plane_authentication_required",
            "hitl_enabled",
            "a2a_verification_required",
            "mcp_authentication_required",
        ],
    )
    def test_it_cannot_be_turned_off(self, field):
        with pytest.raises(ValidationError):
            Settings(**{field: False})

    @pytest.mark.parametrize(
        "field",
        [
            "authorization_fail_closed",
            "control_plane_authentication_required",
            "hitl_enabled",
            "a2a_verification_required",
            "mcp_authentication_required",
        ],
    )
    def test_and_it_defaults_to_on(self, field):
        assert getattr(Settings(), field) is True


class TestAudienceSeparation:
    """The MCP resource server and the human API must not share an audience.

    If they ever did, a token minted for a loan officer's browser session
    would open an agent's MCP session and vice versa -- the cross-service
    reuse the MCP authorization spec forbids. It is a one-line mistake to
    make in a config file, so it is asserted here.
    """

    def test_the_two_audiences_differ_by_default(self):
        settings = Settings()
        assert settings.oidc_audience != settings.mcp_audience

    def test_they_still_differ_in_production(self):
        settings = production()
        assert settings.oidc_audience != settings.mcp_audience
