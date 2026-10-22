"""Human identity: OIDC token validation against a REAL Keycloak.

Not "login works". The tests that matter are the ones where a token is
*almost* right:

    signed by the wrong key          a forgery
    issued by the wrong realm        a valid token about a different system
    issued for a different audience  a valid token meant for someone else
    expired                          a valid token that stopped being true
    `alg: none` / HS256 confusion    the two classic JWT forgeries
    no roles                         authenticated, and permitted nothing

WHERE THE TOKENS COME FROM. Positive cases use GENUINE tokens from the running
Keycloak, obtained by direct grant -- RS256, signed by a key this repository
does not hold. Negative cases are real JWTs signed with a throwaway RSA key, so
the validator is exercised rather than mocked: a test that hand-built a claims
dict would prove nothing about the code that actually parses one.
"""
from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import Settings, get_settings
from app.humans.oidc import OIDCReason, OIDCValidator, TokenInvalid, bearer_token

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def forge_key():
    """A throwaway RSA key. Real cryptography, wrong signer."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def forge(forge_key):
    """Mint a REAL RS256 JWT with a key Keycloak does not know."""
    settings = get_settings()

    def make(**overrides):
        now = int(time.time())
        claims = {
            "iss": settings.keycloak_issuer,
            "aud": settings.oidc_audience,
            "sub": "forged-subject",
            "iat": now,
            "exp": now + 300,
            "preferred_username": "mallory",
            "realm_access": {"roles": ["LOAN_OFFICER"]},
        }
        claims.update(overrides)
        for key, value in list(claims.items()):
            if value is None:
                del claims[key]
        return jwt.encode(claims, forge_key, algorithm="RS256",
                          headers={"kid": "forged-key-id"})

    return make


@pytest.fixture
def trusting_validator(forge_key, monkeypatch):
    """A validator that TRUSTS the throwaway key.

    This isolates the CLAIM checks from the signature check. Without it, every
    negative case would fail at the signature and `exp`, `iss` and `aud`
    validation would never be reached -- so the tests would pass while proving
    nothing about them.

    The signature is still genuinely verified; only the key is substituted.
    """
    validator = OIDCValidator(get_settings())
    monkeypatch.setattr(validator, "_signing_key",
                        lambda token: forge_key.public_key())
    return validator


class TestRealTokens:
    def test_a_genuine_keycloak_token_authenticates(self, loan_officer_token):
        identity = OIDCValidator(get_settings()).validate(loan_officer_token)
        assert identity.username == "loan.officer"
        assert identity.roles == ("LOAN_OFFICER",)
        assert identity.issuer == get_settings().keycloak_issuer
        assert identity.provider == "keycloak-oidc"

    def test_roles_come_from_the_token_not_from_us(self, iam_admin_token,
                                                   auditor_token):
        """Keycloak is authoritative. Different people, different roles."""
        validator = OIDCValidator(get_settings())
        assert validator.validate(iam_admin_token).roles == ("IAM_ADMIN",)
        assert validator.validate(auditor_token).roles == ("AUDITOR",)

    def test_an_authenticated_human_may_hold_no_roles(self, no_roles_token):
        """Authenticated is not authorized. This is a real, tested state."""
        identity = OIDCValidator(get_settings()).validate(no_roles_token)
        assert identity.username == "no.roles"
        assert identity.roles == ()

    def test_the_principal_is_a_urn_not_a_did(self, loan_officer_token):
        """A human holds no key and is not a DID subject.

        Minting a DID for a person would imply they can sign -- and the whole
        trust model of the approval artifact rests on the fact that they cannot.
        """
        identity = OIDCValidator(get_settings()).validate(loan_officer_token)
        assert identity.principal_urn.startswith("urn:iam:human:")
        assert not identity.principal_urn.startswith("did:")

    def test_the_token_itself_is_never_returned(self, loan_officer_token):
        """Nothing downstream can accidentally log or store the credential."""
        identity = OIDCValidator(get_settings()).validate(loan_officer_token)
        serialised = str(identity.to_dict())
        assert loan_officer_token not in serialised


class TestForgeriesAreRefused:
    def test_a_token_signed_by_the_wrong_key_is_refused(self, forge, keycloak_ready):
        """A perfectly well-formed token, signed by somebody else."""
        with pytest.raises(TokenInvalid) as exc:
            OIDCValidator(get_settings()).validate(forge())
        assert exc.value.reason == OIDCReason.SIGNATURE_INVALID

    def test_alg_none_is_refused(self, keycloak_ready):
        """The classic JWT forgery: declare there is no signature."""
        import base64
        import json

        def segment(payload):
            return base64.urlsafe_b64encode(
                json.dumps(payload).encode()).rstrip(b"=").decode()

        settings = get_settings()
        token = (f'{segment({"alg": "none", "typ": "JWT"})}.'
                 f'{segment({"sub": "x", "iss": settings.keycloak_issuer, "aud": settings.oidc_audience, "exp": 9999999999, "iat": 1})}.')
        with pytest.raises(TokenInvalid) as exc:
            OIDCValidator(settings).validate(token)
        assert exc.value.reason == OIDCReason.ALGORITHM_NOT_ALLOWED

    def test_hs256_key_confusion_is_refused(self, keycloak_ready):
        """The other classic: sign with HMAC, hoping the RSA public key is used
        as the shared secret."""
        settings = get_settings()
        token = jwt.encode(
            {"sub": "x", "iss": settings.keycloak_issuer,
             "aud": settings.oidc_audience,
             "exp": int(time.time()) + 300, "iat": int(time.time())},
            "the-rsa-public-key-as-a-secret", algorithm="HS256",
        )
        with pytest.raises(TokenInvalid) as exc:
            OIDCValidator(settings).validate(token)
        assert exc.value.reason == OIDCReason.ALGORITHM_NOT_ALLOWED

    def test_the_algorithm_list_is_an_allowlist(self):
        assert get_settings().oidc_algorithms == ["RS256"]

    @pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b", "a.b.c.d"])
    def test_malformed_tokens_are_refused(self, token, keycloak_ready):
        with pytest.raises(TokenInvalid) as exc:
            OIDCValidator(get_settings()).validate(token)
        assert exc.value.reason in {OIDCReason.TOKEN_MALFORMED,
                                    OIDCReason.SIGNATURE_INVALID}


class TestClaimValidation:
    """Each claim check, isolated behind a genuinely verified signature."""

    def test_an_expired_token_is_refused(self, trusting_validator, forge):
        now = int(time.time())
        with pytest.raises(TokenInvalid) as exc:
            trusting_validator.validate(forge(exp=now - 3600, iat=now - 7200))
        assert exc.value.reason == OIDCReason.EXPIRED

    def test_a_token_from_the_wrong_issuer_is_refused(self, trusting_validator, forge):
        """A valid token about a DIFFERENT system."""
        with pytest.raises(TokenInvalid) as exc:
            trusting_validator.validate(
                forge(iss="http://localhost:8080/realms/some-other-realm"))
        assert exc.value.reason == OIDCReason.ISSUER_INVALID

    def test_a_token_for_the_wrong_audience_is_refused(self, trusting_validator, forge):
        """A valid token meant for somebody else.

        Without this check, an access token minted for ANY other client in the
        realm would be accepted here.
        """
        with pytest.raises(TokenInvalid) as exc:
            trusting_validator.validate(forge(aud="some-other-service"))
        assert exc.value.reason == OIDCReason.AUDIENCE_INVALID

    def test_a_token_with_no_subject_is_refused(self, trusting_validator, forge):
        with pytest.raises(TokenInvalid) as exc:
            trusting_validator.validate(forge(sub=None))
        assert exc.value.reason == OIDCReason.TOKEN_MALFORMED

    def test_a_post_dated_token_is_refused(self, trusting_validator, forge):
        now = int(time.time())
        with pytest.raises(TokenInvalid) as exc:
            trusting_validator.validate(forge(nbf=now + 3600, iat=now + 3600,
                                              exp=now + 7200))
        assert exc.value.reason == OIDCReason.NOT_YET_VALID

    def test_a_token_whose_expiry_is_missing_is_refused(self, trusting_validator, forge):
        with pytest.raises(TokenInvalid) as exc:
            trusting_validator.validate(forge(exp=None))
        assert exc.value.reason == OIDCReason.TOKEN_MALFORMED

    def test_clock_skew_is_bounded_and_small(self):
        """Generous enough for drift, tight enough to be meaningful."""
        assert 0 < get_settings().oidc_clock_skew_seconds <= 60


class TestProviderAvailability:
    async def test_provider_health_is_reported_honestly(self, keycloak_ready):
        health = await OIDCValidator(get_settings()).provider_health()
        assert health["available"] is True
        assert health["issuer_matches_configuration"] is True

    async def test_an_unreachable_provider_is_reported_not_assumed(self):
        settings = Settings.model_construct(
            **{**get_settings().model_dump(), "keycloak_base_url": "http://127.0.0.1:9"}
        )
        health = await OIDCValidator(settings).provider_health()
        assert health["available"] is False

    def test_an_unreachable_provider_refuses_the_token(self, loan_officer_token):
        """FAIL CLOSED. An identity provider outage is an authentication
        failure, never a reason to accept an unverified token."""
        settings = Settings.model_construct(
            **{**get_settings().model_dump(), "keycloak_base_url": "http://127.0.0.1:9"}
        )
        with pytest.raises(TokenInvalid) as exc:
            OIDCValidator(settings).validate(loan_officer_token)
        assert exc.value.reason in {OIDCReason.PROVIDER_UNAVAILABLE,
                                    OIDCReason.SIGNATURE_INVALID}


class TestBearerExtraction:
    @pytest.mark.parametrize("header,expected", [
        ("Bearer abc", "abc"),
        ("bearer abc", "abc"),
        ("  Bearer   abc  ", "abc"),
        ("Basic abc", None),
        ("abc", None),
        ("Bearer", None),
        ("Bearer ", None),
        ("", None),
    ])
    def test_bearer_parsing(self, header, expected):
        assert bearer_token({"Authorization": header}) == expected

    def test_header_name_is_case_insensitive(self):
        assert bearer_token({"authorization": "Bearer abc"}) == "abc"
