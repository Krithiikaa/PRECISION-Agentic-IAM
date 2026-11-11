"""MCP transport authentication: OAuth 2.1 Resource Server (Phase 8).

THIS MODULE ESTABLISHES WHO IS CALLING. It decides nothing about what they
may do. The separation is the same one Phase 4.5 draws between
CONTROL_PLANE_AUTHENTICATED and CONTROL_PLANE_AUTHORIZED: "we could not tell
who you are" and "we know exactly who you are and you may not do that" are
different incidents, and an operator must be able to tell them apart at a
glance.

THE IDENTITY MAPPING, and why it needs no second credential root.

Keycloak's `agentic-iam` realm advertises `private_key_jwt` client
authentication with `EdDSA` among its supported client-assertion algorithms.
That is the whole hinge of this phase: an agent already holds an Ed25519 key
from Phase 1, so it can authenticate to the token endpoint by signing a
client assertion with THAT key. No second secret is provisioned, nothing new
is stored, and the KeyStore's private material never leaves the KeyStore.

Each agent is registered as a confidential Keycloak client whose `clientId`
IS the agent's DID. The access token then carries:

    azp   the agent DID, verbatim            <- the identity binding
    sub   the service-account UUID           <- NOT the agent
    aud   the MCP resource server audience   <- must be us
    iss   the realm issuer                   <- must be our realm

BIND ON `azp`, NEVER ON `sub`. This is the single most dangerous confusion
available here. `sub` is a Keycloak-internal service-account UUID; it is
stable and unique and completely unrelated to the agent's DID. A server that
bound identity to `sub` would authenticate successfully and then attribute
the call to nobody, or -- worse, after a Keycloak re-provision -- to the
wrong agent. `azp` is the client that the token was issued to, and the client
is the DID.

A VALID TOKEN IS NOT A VALID AGENT, and this module does not pretend
otherwise. Keycloak knows nothing about agent lifecycle: a token minted at
09:00 stays cryptographically valid until it expires even if the agent was
revoked at 09:01. Token validation therefore establishes a CLAIM to a DID;
whether that DID is an agent in good standing is re-established from this
system's own records on every single invocation, by the PIP, inside the
authorization evaluation. See `AGENT STATUS IS NOT CHECKED HERE` below.

NOTHING IN THIS MODULE IS LOGGED THAT COULD BE REPLAYED. Not the token, not
the assertion, not the Authorization header. `jti` is recorded because it
identifies a token without being one.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

log = get_logger("mcp.auth")


class MCPAuthReason:
    """Why authentication failed.

    Coarse on purpose, exactly as `app.controlplane.proof` is: a reason names
    the CLASS of failure and never which record, claim value or internal
    identifier was involved. An attacker probing the endpoint learns that
    their token was unacceptable, not which check rejected which field.

    These map to HTTP status codes in `routes/mcp.py`, per the MCP
    authorization specification: 401 for "authorization required or token
    invalid", 403 for "invalid scopes or insufficient permissions".
    """

    MISSING = "MCP_TOKEN_MISSING"
    MALFORMED = "MCP_TOKEN_MALFORMED"
    SIGNATURE_INVALID = "MCP_TOKEN_SIGNATURE_INVALID"
    EXPIRED = "MCP_TOKEN_EXPIRED"
    ISSUER_MISMATCH = "MCP_TOKEN_ISSUER_MISMATCH"
    AUDIENCE_MISMATCH = "MCP_TOKEN_AUDIENCE_MISMATCH"
    ALGORITHM_NOT_ALLOWED = "MCP_TOKEN_ALGORITHM_NOT_ALLOWED"
    SUBJECT_MISSING = "MCP_TOKEN_SUBJECT_MISSING"
    SUBJECT_NOT_A_DID = "MCP_TOKEN_SUBJECT_NOT_A_DID"
    KEYS_UNAVAILABLE = "MCP_IDENTITY_PROVIDER_UNAVAILABLE"


class MCPAuthenticationError(Exception):
    """Authentication failed. Carries a coarse reason and a safe detail."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class MCPPrincipal:
    """An authenticated MCP caller.

    `agent_did` is the identity this system will use everywhere downstream.
    It came from `azp`, and it is a CLAIM TO BE an agent -- the PIP decides
    whether it is a registered, ACTIVE one.
    """

    agent_did: str
    token_jti: str | None
    issuer: str
    audience: str
    expires_at: int
    issued_at: int
    scopes: tuple[str, ...] = ()
    # The service-account subject. Retained for audit correlation with
    # Keycloak's own logs and NEVER used as an identity in this system.
    service_account_sub: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_did": self.agent_did,
            "token_jti": self.token_jti,
            "issuer": self.issuer,
            "audience": self.audience,
            "expires_at": self.expires_at,
            "scopes": list(self.scopes),
            "service_account_sub": self.service_account_sub,
        }


def bearer_token(headers: Any) -> str | None:
    """Extract a bearer token from the Authorization header.

    THE QUERY STRING IS NOT CONSULTED, and that is a specification
    requirement, not a preference: "Access tokens MUST NOT be included in the
    URI query string". Query strings land in access logs, proxy logs and
    browser history. There is deliberately no fallback here to read one.
    """
    raw = None
    for key in ("authorization", "Authorization"):
        try:
            raw = headers.get(key)
        except AttributeError:  # pragma: no cover - defensive
            raw = None
        if raw:
            break
    if not raw or not isinstance(raw, str):
        return None
    parts = raw.split(None, 1)
    # The scheme is case-insensitive per RFC 7235.
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


class MCPTokenValidator:
    """Validates access tokens presented to the MCP resource server.

    WHY NOT REUSE `app.humans.oidc.OIDCValidator` VERBATIM: because it
    validates tokens for a DIFFERENT audience, and that difference is a
    security boundary rather than a configuration detail. The human API's
    audience is `agentic-iam-api`; the MCP resource server's is its own. If
    one validator accepted both, a token minted for a human console session
    would be accepted at the MCP endpoint and vice versa -- which is exactly
    the cross-service token reuse the MCP specification forbids ("MCP servers
    MUST only accept tokens specifically intended for themselves").

    The JWKS handling mirrors the Phase 5 validator deliberately: fetched
    live, cached by `kid`, refreshed on an unknown `kid` so a Keycloak key
    rotation does not need a restart, and a fetch failure is an AUTHENTICATION
    FAILURE rather than permission to skip the check.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._jwk_client: PyJWKClient | None = None
        self._fetched_at = 0.0

    def _client(self, *, refresh: bool = False) -> PyJWKClient:
        age = time.monotonic() - self._fetched_at
        if (
            self._jwk_client is None
            or refresh
            or age > self.settings.oidc_jwks_cache_seconds
        ):
            self._jwk_client = PyJWKClient(
                self.settings.oidc_jwks_url, cache_keys=False,
            )
            self._fetched_at = time.monotonic()
        return self._jwk_client

    def _signing_key(self, token: str):
        try:
            return self._client().get_signing_key_from_jwt(token).key
        except Exception:  # noqa: BLE001 - any JWKS failure is an auth failure
            # An unknown kid may simply mean Keycloak rotated. Refresh once.
            try:
                return self._client(refresh=True).get_signing_key_from_jwt(token).key
            except Exception as exc:  # noqa: BLE001
                # FAIL CLOSED. Not being able to reach the identity provider
                # is a reason to refuse authentication, never permission to
                # skip it.
                raise MCPAuthenticationError(
                    MCPAuthReason.KEYS_UNAVAILABLE,
                    f"cannot reach the identity provider's JWKS: "
                    f"{type(exc).__name__}",
                ) from exc

    def validate(self, token: str) -> MCPPrincipal:
        """Validate one access token and return the principal it names.

        The order matters only in that every check runs before anything
        downstream sees the token; none of them is skippable and none has a
        permissive default.
        """
        if not token:
            raise MCPAuthenticationError(
                MCPAuthReason.MISSING, "no bearer token was presented"
            )

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise MCPAuthenticationError(
                MCPAuthReason.MALFORMED, "the token is not a well-formed JWT"
            ) from exc

        algorithm = header.get("alg")
        # ALGORITHM CONFUSION, closed explicitly. Without this a token signed
        # with `none`, or symmetrically signed with a public key as the HMAC
        # secret, reaches the verifier. The allow-list is checked against the
        # header BEFORE the key is fetched.
        if algorithm not in self.settings.mcp_token_algorithms:
            raise MCPAuthenticationError(
                MCPAuthReason.ALGORITHM_NOT_ALLOWED,
                f"token algorithm {algorithm!r} is not accepted",
            )

        key = self._signing_key(token)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=self.settings.mcp_token_algorithms,
                issuer=self.settings.keycloak_issuer,
                audience=self.settings.mcp_audience,
                options={
                    "require": ["exp", "iat", "iss", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise MCPAuthenticationError(
                MCPAuthReason.EXPIRED, "the token has expired"
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise MCPAuthenticationError(
                MCPAuthReason.ISSUER_MISMATCH,
                "the token was issued by another authority",
            ) from exc
        except jwt.InvalidAudienceError as exc:
            # THE CROSS-SERVICE REUSE CHECK. A token minted for the human API,
            # or for any other service in the realm, dies here.
            raise MCPAuthenticationError(
                MCPAuthReason.AUDIENCE_MISMATCH,
                "the token was not issued for this resource server",
            ) from exc
        except jwt.InvalidSignatureError as exc:
            raise MCPAuthenticationError(
                MCPAuthReason.SIGNATURE_INVALID, "the token signature is invalid"
            ) from exc
        except jwt.MissingRequiredClaimError as exc:
            raise MCPAuthenticationError(
                MCPAuthReason.MALFORMED, "the token is missing a required claim"
            ) from exc
        except jwt.PyJWTError as exc:
            raise MCPAuthenticationError(
                MCPAuthReason.SIGNATURE_INVALID, "the token could not be validated"
            ) from exc

        # --- THE IDENTITY BINDING ----------------------------------------
        # `azp` ("authorized party") is the client the token was issued to,
        # and each agent's Keycloak client id IS its DID. See the module
        # docstring for why `sub` is deliberately not used.
        agent_did = claims.get("azp")
        if not agent_did or not isinstance(agent_did, str):
            raise MCPAuthenticationError(
                MCPAuthReason.SUBJECT_MISSING,
                "the token does not name an authorized party",
            )
        if not agent_did.startswith("did:"):
            # A token from a client that is not an agent -- the console, say.
            # Valid, correctly audienced, and still not an agent identity.
            raise MCPAuthenticationError(
                MCPAuthReason.SUBJECT_NOT_A_DID,
                "the authorized party is not an agent identity",
            )

        scope_claim = claims.get("scope") or ""
        scopes = tuple(s for s in scope_claim.split() if s) \
            if isinstance(scope_claim, str) else ()

        # AGENT STATUS IS NOT CHECKED HERE, and the omission is deliberate
        # rather than forgotten. This module's job ends at "the bearer of
        # this token controls the Keycloak client named by this DID".
        # Whether that DID is a registered agent, and whether it is ACTIVE,
        # is established by the PIP from this system's own records during
        # every authorization evaluation -- which is the only place it can be
        # established freshly enough to make revocation effective within a
        # token's lifetime.
        log.info(
            "mcp_authenticated",
            agent_did=agent_did,
            jti=claims.get("jti"),
            audience=self.settings.mcp_audience,
        )
        return MCPPrincipal(
            agent_did=agent_did,
            token_jti=claims.get("jti"),
            issuer=claims["iss"],
            audience=self.settings.mcp_audience,
            expires_at=int(claims["exp"]),
            issued_at=int(claims["iat"]),
            scopes=scopes,
            service_account_sub=claims.get("sub"),
        )


def protected_resource_metadata(settings: Settings | None = None) -> dict[str, Any]:
    """The RFC 9728 Protected Resource Metadata document.

    MCP 2025-06-18 requires an MCP server to publish this ("MCP servers MUST
    implement OAuth 2.0 Protected Resource Metadata") and requires
    `authorization_servers` to name at least one authorization server, so a
    client that receives a 401 can discover where to get a token.
    """
    settings = settings or get_settings()
    return {
        "resource": settings.mcp_resource_uri,
        "authorization_servers": [settings.keycloak_issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": list(settings.mcp_scopes_supported),
        "resource_documentation": f"{settings.mcp_resource_uri}/docs",
    }


def www_authenticate_header(
    settings: Settings | None = None, *, error: str | None = None,
    description: str | None = None,
) -> str:
    """The `WWW-Authenticate` challenge for a 401.

    RFC 9728 section 5.1 requires the challenge to carry `resource_metadata`
    so an unauthenticated client can find the metadata document without
    guessing. MCP makes parsing this header mandatory for clients, which only
    works if servers actually emit it.
    """
    settings = settings or get_settings()
    parts = [f'Bearer realm="{settings.mcp_resource_name}"']
    if error:
        parts.append(f'error="{error}"')
    if description:
        # Quoted-string: a stray quote would break the header. The reasons
        # this is called with are fixed constants, but sanitising is cheap.
        safe = description.replace('"', "'")
        parts.append(f'error_description="{safe}"')
    parts.append(f'resource_metadata="{settings.mcp_resource_metadata_url}"')
    return ", ".join(parts)
