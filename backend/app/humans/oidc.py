"""OIDC token validation against a REAL Keycloak.

This module answers exactly one question: **who is this human?** It does not
decide what they may do -- that is the PDP -- and it does not record that they
approved anything -- that is the HITL service. Keeping those apart is the whole
point of Phase 5, and an OIDC token is the thing most likely to be mistaken for
an approval, so the boundary is stated here as well as documented.

    An OIDC token says WHO SOMEONE IS.
    It does not say WHAT THEY AGREED TO.

WHAT IS VERIFIED, and why each one matters:

  signature   RS256 against Keycloak's published JWKS. The token is never
              decoded-and-trusted first; every claim below is read only from a
              payload whose signature already verified.
  algorithm   An ALLOWLIST. `alg: none` and an HS256 token signed with the
              RSA public key as an HMAC secret are the two classic JWT
              forgeries, and both are refused because they are not on the list.
  issuer      Exact match. A token from another realm -- or another Keycloak
              entirely -- is a valid token that says nothing about this system.
  audience    Must contain our audience. Without this, an access token minted
              for any other client in the realm would be accepted here.
  expiry      `exp`, against the SERVER clock, with a small configured skew.
  not-before  `nbf`/`iat` sanity, so a post-dated token is not accepted early.

The JWKS is fetched live and cached by `kid`. An unknown `kid` forces a
refresh, so a Keycloak key rotation does not need a restart. A JWKS fetch
failure is an authentication FAILURE -- never a bypass, and never a fallback to
an unverified decode.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

log = get_logger("humans.oidc")


class OIDCReason:
    """Why a token was accepted or refused.

    Coarse on purpose. A caller learns that its token was refused and which
    CLASS of check failed; it does not learn which key, which claim value, or
    what the server expected instead.
    """

    VALID = "HUMAN_TOKEN_VALID"

    TOKEN_MISSING = "HUMAN_TOKEN_MISSING"
    TOKEN_MALFORMED = "HUMAN_TOKEN_MALFORMED"
    ALGORITHM_NOT_ALLOWED = "HUMAN_TOKEN_ALGORITHM_NOT_ALLOWED"
    SIGNATURE_INVALID = "HUMAN_TOKEN_SIGNATURE_INVALID"
    ISSUER_INVALID = "HUMAN_TOKEN_ISSUER_INVALID"
    AUDIENCE_INVALID = "HUMAN_TOKEN_AUDIENCE_INVALID"
    EXPIRED = "HUMAN_TOKEN_EXPIRED"
    NOT_YET_VALID = "HUMAN_TOKEN_NOT_YET_VALID"
    SUBJECT_MISSING = "HUMAN_TOKEN_SUBJECT_MISSING"
    PROVIDER_UNAVAILABLE = "IDENTITY_PROVIDER_UNAVAILABLE"


class TokenInvalid(Exception):
    """Validation failed. Carries the reason class, never the detail of a key."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class HumanIdentity:
    """An AUTHENTICATED human. Never constructed from an unverified token."""

    subject: str
    issuer: str
    username: str | None
    display_name: str | None
    email: str | None
    roles: tuple[str, ...]
    client_id: str | None
    expires_at: int
    issued_at: int
    token_id: str | None
    provider: str = "keycloak-oidc"

    @property
    def principal_urn(self) -> str:
        """A stable identifier for audit and policy.

        Deliberately a `urn:`, not a DID. A human in this system holds no key
        and is not a DID subject; minting one would suggest they could sign,
        and the whole trust model of the approval artifact rests on the fact
        that they cannot.
        """
        return f"urn:iam:human:{self.subject}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "username": self.username,
            "display_name": self.display_name,
            "roles": sorted(self.roles),
            "provider": self.provider,
            "principal": self.principal_urn,
        }


def bearer_token(headers: dict[str, str]) -> str | None:
    """Extract a bearer token, case-insensitively. Returns None if absent."""
    lookup = {k.lower(): v for k, v in headers.items()}
    raw = (lookup.get("authorization") or "").strip()
    if not raw:
        return None
    scheme, _, token = raw.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


class OIDCValidator:
    """Validates access tokens issued by the configured Keycloak realm."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._jwk_client: PyJWKClient | None = None
        self._jwk_client_at: float = 0.0

    # --- key material -----------------------------------------------------
    def _client(self, *, refresh: bool = False) -> PyJWKClient:
        """A JWKS client, rebuilt when the cache ages out or a kid is unknown."""
        age = time.monotonic() - self._jwk_client_at
        if self._jwk_client is None or refresh or age > self.settings.oidc_jwks_cache_seconds:
            self._jwk_client = PyJWKClient(
                self.settings.oidc_jwks_url,
                cache_keys=True,
                timeout=self.settings.oidc_http_timeout_seconds,
            )
            self._jwk_client_at = time.monotonic()
        return self._jwk_client

    def _signing_key(self, token: str):
        try:
            return self._client().get_signing_key_from_jwt(token).key
        except PyJWKClientError as exc:
            # An unknown `kid` is the normal shape of a key rotation. Refresh
            # once and try again before concluding the token is bad.
            try:
                return self._client(refresh=True).get_signing_key_from_jwt(token).key
            except PyJWKClientError as retry:
                raise TokenInvalid(OIDCReason.SIGNATURE_INVALID,
                                   f"no usable signing key: {retry}") from exc
        except (httpx.HTTPError, OSError, ValueError) as exc:
            # The identity provider is unreachable. That is an outage of
            # authentication, not permission to skip it.
            raise TokenInvalid(
                OIDCReason.PROVIDER_UNAVAILABLE,
                f"cannot reach the identity provider's JWKS: {type(exc).__name__}",
            ) from exc

    # --- validation --------------------------------------------------------
    def validate(self, token: str) -> HumanIdentity:
        """Validate and return the authenticated human. Raises `TokenInvalid`."""
        if not token or token.count(".") != 2:
            raise TokenInvalid(OIDCReason.TOKEN_MALFORMED, "not a compact JWS")

        # Read the header ONLY to select a key and check the algorithm. Nothing
        # from an unverified token influences anything else.
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenInvalid(OIDCReason.TOKEN_MALFORMED, str(exc)) from exc

        algorithm = header.get("alg")
        if algorithm not in self.settings.oidc_algorithms:
            # Covers `none` and the HS256-with-the-public-key confusion attack.
            raise TokenInvalid(
                OIDCReason.ALGORITHM_NOT_ALLOWED,
                f"algorithm {algorithm!r} is not accepted",
            )

        key = self._signing_key(token)
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=self.settings.oidc_algorithms,
                issuer=self.settings.keycloak_issuer,
                audience=self.settings.oidc_audience,
                leeway=self.settings.oidc_clock_skew_seconds,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenInvalid(OIDCReason.EXPIRED, "the token has expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise TokenInvalid(OIDCReason.NOT_YET_VALID, "the token is not yet valid") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenInvalid(OIDCReason.ISSUER_INVALID,
                               "the token was issued by another authority") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenInvalid(OIDCReason.AUDIENCE_INVALID,
                               "the token was not issued for this application") from exc
        except jwt.InvalidSignatureError as exc:
            raise TokenInvalid(OIDCReason.SIGNATURE_INVALID,
                               "the signature does not verify") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise TokenInvalid(OIDCReason.TOKEN_MALFORMED, str(exc)) from exc
        except jwt.PyJWTError as exc:
            # Catch-all so a NEW failure mode from the library denies rather
            # than falling through as success.
            raise TokenInvalid(OIDCReason.SIGNATURE_INVALID,
                               f"{type(exc).__name__}") from exc

        subject = claims.get("sub")
        if not subject:
            raise TokenInvalid(OIDCReason.SUBJECT_MISSING, "no subject claim")

        return HumanIdentity(
            subject=subject,
            issuer=claims["iss"],
            username=claims.get("preferred_username"),
            display_name=claims.get("name") or claims.get("preferred_username"),
            email=claims.get("email"),
            # Realm roles, as Keycloak issued them for THIS token. Read fresh
            # every request: a role removed in Keycloak stops applying at once,
            # because nothing here consults a stored copy.
            roles=tuple(sorted((claims.get("realm_access") or {}).get("roles") or [])),
            client_id=claims.get("azp"),
            expires_at=int(claims["exp"]),
            issued_at=int(claims["iat"]),
            token_id=claims.get("jti"),
        )

    async def provider_health(self) -> dict[str, Any]:
        """Is the identity provider reachable? Reported, never assumed."""
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.oidc_http_timeout_seconds
            ) as client:
                response = await client.get(self.settings.oidc_discovery_url)
            body = response.json() if response.status_code == 200 else {}
            return {
                "available": response.status_code == 200,
                "url": self.settings.oidc_discovery_url,
                "issuer": body.get("issuer"),
                "issuer_matches_configuration":
                    body.get("issuer") == self.settings.keycloak_issuer,
                "detail": f"HTTP {response.status_code}",
            }
        except (httpx.HTTPError, ValueError) as exc:
            return {
                "available": False,
                "url": self.settings.oidc_discovery_url,
                "issuer": None,
                "issuer_matches_configuration": False,
                "detail": f"{type(exc).__name__}: {exc}",
            }
