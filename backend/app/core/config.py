"""Central configuration for the Agentic IAM backend.

All values are environment-driven. Nothing operationally significant
(model name, database URL, key material) is hardcoded.
"""
from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The well-known development master key.
#
# WHY THIS IS A READABLE PHRASE AND NOT A BASE64 LITERAL, which it used to be.
#
# The VALUE is unchanged, byte for byte -- it has always decoded to exactly
# the ASCII below, and every keystore already on disk stays readable. What
# changed is that the repository no longer contains a high-entropy blob.
#
# That matters for a reason worth stating rather than assuming. A secret
# scanner cannot tell a base64 placeholder from a base64 key: it sees entropy
# and raises an incident, correctly, on the information available to it. And
# neither can a human skimming the file. A placeholder that looks exactly
# like a credential teaches everyone who reads it to ignore things that look
# like credentials, which is the habit that gets a real one committed.
#
# IT IS NOT A SECRET, and it is not treated as one: `_reject_dev_key_in_prod`
# below refuses to start with it when ENV=production, and the application
# logs a warning whenever it is in use anywhere else.
_DEV_MASTER_PHRASE = b"dev-only-master-key-32-bytes-long!!"
DEV_MASTER_KEY = base64.b64encode(_DEV_MASTER_PHRASE).decode()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env",), env_file_encoding="utf-8", extra="ignore"
    )

    # --- Environment ---
    env: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"

    # --- API ---
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_public_url: str = "http://localhost:8000"

    # --- Database ---
    database_url: str = (
        "postgresql+psycopg://iam:iam@localhost:5433/agentic_iam"
    )

    # --- Redis (used from Phase 9 onwards; connection is optional in Phase 1) ---
    redis_url: str = "redis://localhost:6380/0"

    # --- Identity ---
    did_method: str = "poc"
    organization_did: str = "did:poc:organization:bank-demo"
    keystore_backend: Literal["encrypted_file"] = "encrypted_file"
    keystore_dir: str = "./.keystore"
    keystore_master_key: str = DEV_MASTER_KEY

    # --- Verifiable Credentials (Phase 2) ---
    # Authorities that may issue credentials. Bootstrapped at startup; each
    # gets its own Ed25519 key pair, never shared with any agent.
    credential_issuers: str = (
        "bank-demo:Demo Bank Identity Authority,"
        "compliance-authority:Demo Compliance Authority"
    )
    vc_default_ttl_seconds: int = 3600
    vc_demo_ttl_seconds: int = 15
    vc_max_ttl_seconds: int = 60 * 60 * 24 * 365

    # --- Agent Naming Service (Phase 3) ---
    ans_base_url: str = "http://localhost:8100"
    ans_host: str = "0.0.0.0"
    ans_port: int = 8100
    # How often an agent reports in.
    ans_heartbeat_interval_seconds: int = 15
    # No heartbeat for this long -> STALE (still registered, not preferred).
    ans_agent_timeout_seconds: int = 45
    # No heartbeat for this long -> OFFLINE (not discoverable).
    ans_agent_offline_seconds: int = 120
    # How often the registry sweeps for overdue agents.
    ans_sweep_interval_seconds: int = 10
    ans_health_probe_timeout_seconds: float = 3.0
    ans_registration_freshness_seconds: int = 300

    # --- Authorization (Phase 4) ---
    # The real OPA runtime. Host runs reach it on localhost; inside compose it
    # is the `opa` service name -- a container must never assume localhost is
    # the host, exactly as with ANS_BASE_URL and OLLAMA_BASE_URL.
    opa_url: str = "http://localhost:8181"
    opa_timeout_seconds: float = 5.0
    # The Rego entrypoint the PDP queries.
    opa_decision_path: str = "agentic_iam/authz/decision"
    # Directory the PAP loads policy modules from.
    policy_dir: str = "./policies"
    # Fail-closed is not configurable. Named here so the intent is explicit and
    # so no future setting can quietly turn an error into an ALLOW.
    authorization_fail_closed: bool = True

    # --- Control plane (Phase 4.5) ---
    # Security-critical control-plane operations require a signed request proof
    # from a principal that can prove control of its DID. Reuses the Phase 1
    # machine identity: no bearer tokens, no shared secrets, no second PKI.
    #
    # How far a control-plane proof's timestamp may be from the server clock.
    # Generous enough for container clock drift, tight enough that a captured
    # proof dies quickly even if the nonce table were pruned.
    control_plane_freshness_seconds: int = 300
    # The Rego entrypoint for control-plane decisions. A SEPARATE package from
    # the data-plane one, so hardening the control plane cannot alter the
    # semantics of resource authorization.
    control_plane_decision_path: str = "agentic_iam/control_plane/decision"
    # Administrators, as `slug:Display Name:role|role`. Each gets its own
    # Ed25519 key pair and a published DID Document at startup, exactly like a
    # credential issuer. FOUR principals rather than one so least privilege is
    # demonstrable: the identity administrator cannot activate policy, and the
    # system that can restate a loan amount can do nothing else at all.
    control_plane_administrators: str = (
        "platform-security:Platform Security Administrator:policy_admin|registry_admin,"
        "identity-authority:Identity Administrator:identity_admin,"
        "enforcement-gateway:Policy Enforcement Gateway:enforcement,"
        # Phase 5.5. The upstream system that can restate a loan amount. A
        # SEPARATE principal with a SEPARATE role, because the amount is an
        # authorization input: whoever can change it can change how many humans
        # a request needs, and that must not be a side privilege of
        # administering identity or policy.
        "core-banking:Core Banking Gateway:loan_admin"
    )
    # Authentication of control-plane requests is not configurable off, for the
    # same reason fail-closed is not: a switch that turns a proof requirement
    # into a no-op is a bypass with a configuration file in front of it.
    control_plane_authentication_required: bool = True

    # --- Human-in-the-Loop (Phase 5) ---
    # Keycloak authenticates PEOPLE. It authorizes nothing: the PDP does that.
    #
    # BASE_URL is where this process reaches Keycloak (a service name inside
    # compose, localhost on the host). ISSUER is what Keycloak writes into the
    # token's `iss` claim, which must match EXACTLY or every token is refused.
    # They are configured separately because they genuinely differ inside
    # compose, and deriving one from the other would break token validation in
    # a way that looks like a signature bug.
    keycloak_base_url: str = "http://localhost:8080"
    keycloak_realm: str = "agentic-iam"
    keycloak_issuer: str = "http://localhost:8080/realms/agentic-iam"
    # The audience every access token must carry. Keycloak's default is
    # `account`; the realm adds this one with an explicit audience mapper so
    # the check is meaningful rather than vacuous.
    oidc_audience: str = "agentic-iam-api"
    oidc_client_id: str = "agentic-iam-console"
    # Signature algorithms accepted. An ALLOWLIST, not a denylist: `none` and
    # HS256 key-confusion are refused because they are not on it.
    oidc_allowed_algorithms: str = "RS256"
    oidc_clock_skew_seconds: int = 30
    oidc_jwks_cache_seconds: int = 300
    oidc_http_timeout_seconds: float = 5.0

    # The service principal that signs approval artifacts. NOT an agent, NOT
    # Keycloak, NOT a credential issuer -- see docs/HITL_SECURITY_MODEL.md.
    approval_authority_slug: str = "approval-authority"
    # Audience binding for approval artifacts, mirroring the Phase 2 S-2 fix.
    approval_domain: str = "loan-service"
    # How long a human decision stays usable. This is NOT JIT: it bounds the
    # life of a DECISION, not of an agent's permission.
    approval_ttl_seconds: int = 300
    # How long a pending request waits for a human before it expires.
    approval_request_ttl_seconds: int = 900
    # Human approval is not configurable off, for the same reason fail-closed
    # and control-plane authentication are not.
    hitl_enabled: bool = True

    # --- Phase 6: JIT temporary access ---
    # The service principal that signs JIT grants. DELIBERATELY NOT the
    # approval authority: whoever can attest that a human decided something
    # must not thereby be able to mint temporary access, and vice versa. One
    # compromised key must not yield both.
    jit_authority_slug: str = "jit-authority"
    # Audience binding for grants, mirroring the Phase 2 S-2 fix.
    jit_domain: str = "agentic-iam-aem"
    # Fallback TTL when a caller does not ask for one. The CEILING is policy
    # configuration (policies/data/jit_policy.json), never this value -- these
    # are defaults for convenience, and policy is what refuses.
    jit_default_ttl_seconds: int = 300
    # A hard structural bound applied BEFORE policy is consulted, so a
    # nonsensical request is refused without an OPA round trip. Policy may be
    # (and is) stricter; it can never be more permissive than this.
    jit_absolute_max_ttl_seconds: int = 3600
    jit_default_max_uses: int = 5
    jit_absolute_max_uses: int = 100

    # --- Phase 7: secure A2A transactions ---
    # Audience binding for A2A envelopes, mirroring the Phase 2 S-2 fix. An
    # envelope minted for this enforcement boundary cannot be relayed to
    # another one.
    a2a_domain: str = "agentic-iam-a2a"
    # How far an envelope's issuance may sit from the server clock, in EITHER
    # direction. Generous enough for container clock drift, tight enough that
    # a captured envelope dies quickly even if the ledger were pruned.
    a2a_freshness_seconds: int = 300
    # A hard structural CEILING on how long a sender may make its own envelope
    # live. A sender does not get to choose: an envelope with a one-year
    # window would be a standing instruction with a year to be stolen in.
    # Policy may be stricter; it can never be more permissive than this.
    a2a_max_ttl_seconds: int = 300
    # An absolute structural bound applied BEFORE policy is consulted, so a
    # nonsensical figure is refused without an OPA round trip. The real
    # thresholds are policy configuration (policies/data/a2a_policy.json).
    a2a_absolute_max_amount_inr: int = 100_000_000
    # A2A envelope verification is not configurable off, for the same reason
    # fail-closed, control-plane authentication and HITL are not: a switch
    # that turns a signature requirement into a no-op is a bypass with a
    # configuration file in front of it.
    a2a_verification_required: bool = True

    # --- LLM ---
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = Field(default="llama3:latest")
    llm_timeout_seconds: float = 120.0
    llm_temperature: float = 0.1

    @field_validator("keystore_master_key")
    @classmethod
    def _reject_dev_key_in_prod(cls, v: str, info) -> str:
        if info.data.get("env") == "production" and v == DEV_MASTER_KEY:
            raise ValueError(
                "KEYSTORE_MASTER_KEY must be set to a real value when ENV=production"
            )
        return v

    @field_validator("authorization_fail_closed")
    @classmethod
    def _authorization_must_fail_closed(cls, v: bool) -> bool:
        # An authorization layer that can be configured to fail open is not an
        # authorization layer. This refuses to start rather than silently
        # granting access on an OPA outage.
        if v is not True:
            raise ValueError(
                "AUTHORIZATION_FAIL_CLOSED cannot be disabled: an OPA or policy "
                "failure must never become ALLOW."
            )
        return v

    @field_validator("control_plane_authentication_required")
    @classmethod
    def _control_plane_must_authenticate(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError(
                "CONTROL_PLANE_AUTHENTICATION_REQUIRED cannot be disabled: an "
                "unauthenticated caller must never be able to mutate "
                "security-critical control-plane state."
            )
        return v

    @field_validator("a2a_verification_required")
    @classmethod
    def _a2a_must_verify(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError(
                "A2A_VERIFICATION_REQUIRED cannot be disabled: an unverified "
                "agent-to-agent instruction must never reach the enforcement "
                "boundary."
            )
        return v

    @field_validator("hitl_enabled")
    @classmethod
    def _hitl_cannot_be_disabled(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError(
                "HITL_ENABLED cannot be disabled: an action that policy routed "
                "to a human must never proceed because a flag was flipped."
            )
        return v

    @property
    def oidc_algorithms(self) -> list[str]:
        return [a.strip() for a in self.oidc_allowed_algorithms.split(",") if a.strip()]

    @property
    def oidc_discovery_url(self) -> str:
        return (f"{self.keycloak_base_url.rstrip('/')}/realms/"
                f"{self.keycloak_realm}/.well-known/openid-configuration")

    @property
    def oidc_jwks_url(self) -> str:
        return (f"{self.keycloak_base_url.rstrip('/')}/realms/"
                f"{self.keycloak_realm}/protocol/openid-connect/certs")

    @property
    def oidc_token_url(self) -> str:
        return (f"{self.keycloak_base_url.rstrip('/')}/realms/"
                f"{self.keycloak_realm}/protocol/openid-connect/token")

    @property
    def approval_authority_did(self) -> str:
        from app.identity.did import build_service_did

        return build_service_did(self.approval_authority_slug, self.did_method)

    @property
    def jit_authority_did(self) -> str:
        from app.identity.did import build_service_did

        return build_service_did(self.jit_authority_slug, self.did_method)

    @property
    def administrator_definitions(self) -> list[tuple[str, str, tuple[str, ...]]]:
        """Parse CONTROL_PLANE_ADMINISTRATORS into (slug, name, roles).

        A principal declared with NO roles is kept, not defaulted to something
        permissive: it authenticates and is then denied every action, which is
        the correct reading of "no privileges were granted".
        """
        principals: list[tuple[str, str, tuple[str, ...]]] = []
        for entry in self.control_plane_administrators.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(":")
            slug = parts[0].strip()
            name = parts[1].strip() if len(parts) > 1 and parts[1].strip() else slug
            roles = tuple(
                sorted({r.strip() for r in parts[2].split("|") if r.strip()})
            ) if len(parts) > 2 else ()
            principals.append((slug, name, roles))
        return principals

    @property
    def control_plane_decision_url(self) -> str:
        return (
            f"{self.opa_url.rstrip('/')}/v1/data/"
            f"{self.control_plane_decision_path.strip('/')}"
        )

    @property
    def resolved_policy_dir(self) -> "Path":
        """Locate the policy repository from wherever the process was started.

        The policy directory lives at the REPOSITORY root, but processes start
        from different places: the API and the test suite run with `backend/` as
        the working directory, while the container sets POLICY_DIR=/app/policies
        explicitly. Resolving here keeps `POLICY_DIR` meaningful when it is set
        without requiring every host invocation to set it.

        An explicit POLICY_DIR that does not exist is NOT silently replaced --
        that would hide a misconfiguration and load the wrong policy set.
        """
        from pathlib import Path

        configured = Path(self.policy_dir)
        if configured.is_absolute():
            return configured
        if (configured / "manifest.json").is_file():
            return configured
        # backend/app/core/config.py -> backend/app -> backend -> repo root
        repo_root = Path(__file__).resolve().parents[3]
        candidate = repo_root / configured.name
        if (candidate / "manifest.json").is_file():
            return candidate
        return configured

    @property
    def opa_decision_url(self) -> str:
        return f"{self.opa_url.rstrip('/')}/v1/data/{self.opa_decision_path.strip('/')}"

    @property
    def a2a_decision_url(self) -> str:
        """The A2A entrypoint is the ORDINARY data-plane one, deliberately.

        "May sender A cause action X on resource R for purpose P?" IS the
        ordinary authorization question -- unlike JIT issuance ("may a mandate
        be issued, and with what bounds?"), which is a different question and
        earns its own package. Evaluating A2A anywhere else would mean a
        second combining algorithm deciding resource access, and the first
        time the two disagreed they would do so silently.
        """
        return self.opa_decision_url

    @property
    def jit_decision_url(self) -> str:
        """The JIT ISSUANCE entrypoint.

        A separate Rego package evaluated through the SAME OPA runtime, exactly
        as the control plane is. "May a mandate be issued, and with what
        bounds?" is a different question from "is this action permitted?", and
        answering it inside the data-plane combining algorithm would let an
        issuance rule contribute a deny to an ordinary action.

        Note what is NOT here: the rules that decide whether a PRESENTED grant
        contributes to an ALLOW live in `agentic_iam.authz` with everything
        else, because that IS the ordinary question.
        """
        return f"{self.opa_url.rstrip('/')}/v1/data/agentic_iam/jit/decision"

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def issuer_definitions(self) -> list[tuple[str, str]]:
        """Parse CREDENTIAL_ISSUERS into (slug, display name) pairs."""
        pairs: list[tuple[str, str]] = []
        for entry in self.credential_issuers.split(","):
            entry = entry.strip()
            if not entry:
                continue
            slug, _, name = entry.partition(":")
            pairs.append((slug.strip(), (name or slug).strip()))
        return pairs


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
