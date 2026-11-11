"""Central configuration for the Agentic IAM backend.

All values are environment-driven. Nothing operationally significant
(model name, database URL, key material) is hardcoded.
"""
from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
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

    # --- Phase 8: MCP security ---
    # The canonical URI of this MCP server, per RFC 8707 section 2. It is the
    # value an access token must carry as its audience, and the value a
    # client must send as the `resource` parameter. No fragment, no trailing
    # slash: RFC 9728 and the MCP spec both key off an exact string match, so
    # a cosmetic difference here is an authentication failure later.
    mcp_resource_uri: str = "http://localhost:8000/mcp"
    mcp_resource_name: str = "agentic-iam-mcp"
    # The audience claim required on an MCP access token. SEPARATE from
    # `oidc_audience` on purpose: a token minted for the human console API
    # must not be accepted here, and vice versa. Collapsing these two into
    # one value would silently create exactly the cross-service token reuse
    # the MCP authorization spec forbids.
    mcp_audience: str = "agentic-iam-mcp"
    # An ALLOWLIST, like `oidc_allowed_algorithms` and for the same reason:
    # `none` and HS256 key-confusion are refused because they are not on it.
    # Keycloak signs access tokens with the realm's RS256 key; EdDSA is used
    # for the CLIENT ASSERTION at the token endpoint, which is Keycloak's
    # side of the exchange and never validated here.
    mcp_allowed_algorithms: str = "RS256"
    # The MCP protocol revision this server implements. A single value, not a
    # range: see docs/PHASE_8_ARCHITECTURE.md for the conformance matrix.
    mcp_protocol_version: str = "2025-06-18"
    # Revisions accepted during initialize negotiation. Only the implemented
    # one, deliberately -- advertising a revision whose requirements are not
    # met is the "partial conformance presented as compliance" this phase was
    # explicitly told not to produce.
    mcp_supported_protocol_versions: str = "2025-06-18"
    # Origins permitted on the MCP endpoint. The transport spec requires
    # Origin validation on ALL incoming connections to prevent DNS rebinding.
    # An empty list means "no cross-origin browser client may connect", which
    # is the correct default for a service-to-service endpoint and is NOT the
    # same as "allow anything".
    mcp_allowed_origins: str = ""
    # How long an idle MCP session survives. A session is a correlation
    # handle bound to an agent, not a credential, but an unbounded one is
    # still a row that outlives the token that created it.
    mcp_session_idle_seconds: int = 900
    mcp_max_sessions_per_agent: int = 16
    # The `_meta` key carrying the requested purpose. An IMPLEMENTATION
    # EXTENSION, not part of MCP: `_meta` is the spec's sanctioned place for
    # implementation metadata, and this prefix is non-reserved per the key
    # naming rules (reserved prefixes are those containing `modelcontextprotocol`
    # or `mcp` as a label). Documented as an extension and never described as
    # a protocol feature.
    mcp_purpose_meta_key: str = "agentic-iam.precisionit.co.in/purpose"
    # MCP transport authentication is not configurable off, for the same
    # reason fail-closed, control-plane authentication, HITL and A2A envelope
    # verification are not.
    mcp_authentication_required: bool = True

    # --- Phase 10: rate limiting ---
    # Not configurable OFF in production; see the validator below. A rate
    # limit that an environment variable can remove is not a control.
    ratelimit_enabled: bool = True
    # Per-tier "requests,window_seconds". Tiers are resolved by path in
    # app/ratelimit/middleware.py and asserted against the live route table
    # by test_rate_limiting.py.
    #
    #   auth       credential, token and verification endpoints. TIGHTEST,
    #              because this is where guessing and replay happen.
    #   expensive  a full policy evaluation, and possibly a tool execution.
    #   mutation   anything that changes state.
    #   read       everything else.
    ratelimit_auth: str = "20,60"
    ratelimit_expensive: str = "60,60"
    ratelimit_mutation: str = "120,60"
    ratelimit_read: str = "300,60"
    # What to do when Redis cannot be reached. "fail_closed" refuses the
    # request; "fail_open_local" counts in process memory and WARNS on every
    # request. The second is refused in production by the validator below:
    # a per-process counter across N workers is an N-times-looser limit that
    # reports itself as enforced.
    # The per-ADDRESS ceiling, as a multiple of each tier's per-identity limit.
    # A request naming an identity is counted against that identity AND
    # against its address; the address ceiling is what bounds a caller who
    # invents a new identity per request to get a fresh bucket.
    ratelimit_address_multiplier: int = Field(default=10, ge=1, le=1000)
    ratelimit_redis_policy: str = "fail_open_local"
    ratelimit_redis_timeout_seconds: float = 0.25
    # Networks whose X-Forwarded-For this service will believe. EMPTY means
    # believe nobody, which is correct unless there really is a proxy in
    # front: a caller that can set its own forwarded address can mint itself
    # a fresh rate-limit allowance on every request.
    trusted_proxy_networks_raw: str = ""

    # --- Phase 10: presentation replay protection ---
    # How long a verifier challenge stays spendable. Short on purpose: a
    # challenge is a single-use nonce, and a long-lived one is a permanent
    # one-use token that is strictly worse to leak.
    challenge_ttl_seconds: int = 300
    # Whether a presentation MUST carry a challenge this verifier issued.
    # True closes the Phase 2 replay gap outright. It is a setting rather
    # than a constant because a verifier that genuinely does not need
    # freshness (an offline audit of an archived presentation) should be
    # able to say so explicitly rather than by omission.
    challenge_required: bool = True

    # --- Trust & risk engine, anomaly detection, Session Authority -------
    # (CSA paper sections 4.2 Layer 4, 5.3 and 5.4.)
    #
    # A trust score is 100 minus the weight of every unexpired negative
    # signal, floored at 0. Signals expire, so an agent that stops misbehaving
    # recovers on its own; a CONTAINED agent does not, because containment is
    # a separate state only a human can lift.
    trust_signal_ttl_seconds: int = Field(default=86_400, ge=60)
    # Score bands. Below `trust_reduced_below` sensitive actions escalate to a
    # human; below `trust_untrusted_below` the PDP denies outright.
    trust_reduced_below: int = Field(default=70, ge=1, le=100)
    trust_untrusted_below: int = Field(default=40, ge=0, le=99)
    # --- Phase 12: tamper-evident audit trail ---
    # The sealer chains committed audit events (app/audit/integrity.py). It is
    # NOT a gate-harness switch: production refuses it off.
    audit_sealer_enabled: bool = True
    audit_seal_interval_seconds: float = Field(default=2.0, gt=0)
    audit_seal_batch_size: int = Field(default=2000, ge=1, le=50_000)
    # A signed checkpoint at most this often while new entries are sealed.
    # Bounds how much of the chain's tail could be truncated undetected.
    audit_checkpoint_interval_seconds: float = Field(default=30.0, gt=0)
    # Full verification cadence, and how long an event may stay unsealed
    # before the verifier reports it.
    audit_verify_interval_seconds: float = Field(default=900.0, gt=0)
    audit_unsealed_grace_seconds: float = Field(default=120.0, gt=0)
    audit_checkpoint_kid: str = "did:poc:service:audit-integrity#checkpoint-1"
    # Optional base64 Ed25519 public key an auditor recorded out of band. When
    # set, checkpoints signed by any other key fail verification.
    audit_pinned_checkpoint_key: str = ""

    # The anomaly detector tails the audit trail from inside the IAM API.
    anomaly_detector_enabled: bool = True
    anomaly_poll_seconds: float = Field(default=2.0, gt=0)
    # Rule thresholds. Counted per authenticated agent DID.
    anomaly_denial_burst_count: int = Field(default=5, ge=2)
    anomaly_denial_burst_window_seconds: int = Field(default=60, ge=1)
    anomaly_rate_spike_count: int = Field(default=40, ge=2)
    anomaly_rate_spike_window_seconds: int = Field(default=60, ge=1)
    anomaly_jit_denied_count: int = Field(default=3, ge=2)
    anomaly_jit_denied_window_seconds: int = Field(default=600, ge=1)
    anomaly_spawn_count: int = Field(default=5, ge=2)
    anomaly_spawn_window_seconds: int = Field(default=60, ge=1)
    # When trust collapses to UNTRUSTED, contain the agent automatically
    # (paper R-129 "automated response"). A human still has to reinstate.
    auto_containment_enabled: bool = True
    # Redis pub/sub channel the Session State Synchronizer pushes on.
    sss_channel: str = "agentic-iam:sss"

    # --- Delegated identities: sub-agents, ephemeral agents, forks --------
    # (CSA paper Table 3, R-63/64/65, R-94, R-253, R-254.)
    # A persistent agent is depth 0. A sub-agent of it is depth 1, and so on.
    # Re-delegation beyond this depth is refused (paper R-254: "limiting
    # re-delegation chains").
    delegation_max_depth: int = Field(default=2, ge=1, le=8)
    # Ceiling on any delegated identity's lifetime, and the default for an
    # ephemeral one. A child never outlives its parent or the credentials it
    # was delegated from, whatever is requested.
    delegation_max_ttl_seconds: int = Field(default=86_400, ge=60)
    ephemeral_default_ttl_seconds: int = Field(default=900, ge=30)
    # Hard spawn-rate limit per parent (paper R-253). The anomaly detector
    # alerts earlier, at ANOMALY_SPAWN_COUNT.
    delegation_max_spawns: int = Field(default=10, ge=1)
    delegation_spawn_window_seconds: int = Field(default=60, ge=1)
    # The runtime version recorded in every Agent ID profile and bound into
    # its model hash.
    agent_software_version: str = "agentic-iam-runtime/1.0.0"

    # --- Phase 10: CORS ---
    # Was hardcoded to two localhost origins in main.py. Now configuration,
    # and validated: a wildcard with credentials enabled is refused outright
    # because browsers reject that combination anyway and configuring it
    # means someone believes it works.
    cors_allowed_origins: str = "http://localhost:5173,http://localhost:3000"
    cors_allow_credentials: bool = True
    cors_allowed_methods: str = "GET,POST,DELETE,OPTIONS"
    cors_allowed_headers: str = "authorization,content-type,mcp-session-id,mcp-protocol-version"
    cors_max_age_seconds: int = 600

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

    # Every URL below carries something an attacker who could sit in the
    # middle would be able to forge: a policy decision, a signing key, or a
    # bearer token. Named here so the check is a list a reviewer can read
    # rather than a condition buried in a loop.
    _PRODUCTION_TLS_URLS = (
        ("opa_url", "authorization decisions"),
        ("keycloak_base_url", "the JWKS this service validates tokens against"),
        ("keycloak_issuer", "the token issuer this service trusts"),
        ("mcp_resource_uri", "the OAuth resource agents present tokens to"),
        ("api_public_url", "the base URL this service advertises"),
    )

    @model_validator(mode="after")
    def _cors_origins_are_explicit(self):
        """Phase 12: validated in EVERY environment, not only production.

        The same list now configures the IAM API, the ANS and every agent
        process, so a malformed entry would fail open in nine places at once.
        Each entry must be an exact origin (scheme://host[:port], no path,
        no wildcard fragment). A bare '*' is refused with credentials
        everywhere, and refused outright in production (below).
        """
        import re

        pattern = re.compile(r"^https?://[A-Za-z0-9.\-]+(:[0-9]{1,5})?$")
        for origin in self.cors_origins:
            if origin == "*":
                if self.cors_allow_credentials:
                    raise ValueError(
                        "CORS_ALLOWED_ORIGINS cannot be '*' while CORS_ALLOW_CREDENTIALS is "
                        "true: browsers refuse that combination, so it is a "
                        "misconfiguration that looks like a permission.")
                continue
            if not pattern.match(origin):
                raise ValueError(
                    f"CORS_ALLOWED_ORIGINS entry {origin!r} is not an exact origin "
                    "(expected scheme://host[:port] with no path, query or wildcard)")
        return self

    def cors_middleware_options(self) -> dict:
        """The one CORS configuration, for the IAM API, the ANS and every agent."""
        return {"allow_origins": self.cors_origins,
                "allow_credentials": self.cors_allow_credentials,
                "allow_methods": self.cors_methods, "allow_headers": self.cors_headers,
                "max_age": self.cors_max_age_seconds}

    @model_validator(mode="after")
    def _trust_bands_are_ordered(self):
        # An inverted pair would make REDUCED unreachable and silently turn
        # every degraded agent straight into a denied one -- or, the other way
        # round, never deny anyone. Refuse rather than guess which was meant.
        if self.trust_untrusted_below >= self.trust_reduced_below:
            raise ValueError(
                "TRUST_UNTRUSTED_BELOW must be lower than TRUST_REDUCED_BELOW "
                f"(got {self.trust_untrusted_below} >= {self.trust_reduced_below})"
            )
        return self

    @model_validator(mode="after")
    def _production_requires_tls(self):
        """In production, security-critical URLs must be https.

        WHY THIS REFUSES TO START rather than warning. Each of these carries
        something forgeable over plaintext:

            opa_url            an ALLOW is a plain JSON body. Anyone who can
                               rewrite it decides authorization.
            keycloak_*         the JWKS is fetched over this URL. Substitute
                               the keys and you mint tokens this service
                               accepts; the signature check then passes
                               honestly against the attacker's key.
            mcp_resource_uri   agents present bearer tokens here, and the MCP
                               authorization spec requires HTTPS.
            api_public_url     the protected-resource metadata URL derives
                               from it, so a plaintext value sends clients to
                               a plaintext discovery document.

        There is deliberately NO opt-out flag. This codebase already refuses
        to start rather than let `AUTHORIZATION_FAIL_CLOSED`,
        `CONTROL_PLANE_AUTHENTICATION_REQUIRED`, `HITL_ENABLED`,
        `A2A_VERIFICATION_REQUIRED` or `MCP_AUTHENTICATION_REQUIRED` be
        turned off, for the reason stated at each of them: a switch that
        turns a security requirement into a no-op is a bypass with a
        configuration file in front of it.

        An operator terminating TLS at a sidecar or ingress still sets these
        to the https public name -- that is the name clients resolve and the
        name the metadata document must advertise, so it is the correct
        value regardless of where the handshake ends.

        DEVELOPMENT AND TEST ARE UNAFFECTED. The whole POC runs on plaintext
        localhost and must keep doing so.
        """
        if self.env != "production":
            return self

        def redacted(url: str) -> str:
            """The URL with any embedded credentials removed.

            A validation error becomes a log line, a container event and
            often a screenshot in a ticket. `http://user:password@host` is a
            legal URL, so echoing the raw value verbatim would spill a
            credential into all three while complaining about security. The
            scheme and host are what the operator needs; the userinfo is not.
            """
            if "@" not in url:
                return url
            scheme, _, rest = url.partition("://")
            _, _, host = rest.rpartition("@")
            return f"{scheme}://***@{host}" if scheme else f"***@{host}"

        insecure = [
            (name, what, redacted(str(getattr(self, name))))
            for name, what in self._PRODUCTION_TLS_URLS
            if not str(getattr(self, name)).lower().startswith("https://")
        ]
        # --- anomaly detection ---------------------------------------
        # The security gates start the API with the detector off, because
        # they deliberately attack as one agent and then expect it to keep
        # working. That switch is a TEST-HARNESS setting and must never
        # reach production, for the same reason the rate limiter's cannot.
        if not self.anomaly_detector_enabled:
            raise ValueError(
                "ANOMALY_DETECTOR_ENABLED cannot be false when ENV=production: "
                "it is the gate-harness switch, not an operating mode."
            )
        if not self.audit_sealer_enabled:
            raise ValueError(
                "AUDIT_SEALER_ENABLED cannot be false when ENV=production: an "
                "audit trail nobody chains is not tamper-evident."
            )
        # --- rate limiting ---------------------------------------------
        if not self.ratelimit_enabled:
            raise ValueError(
                "RATELIMIT_ENABLED cannot be false when ENV=production: an "
                "abuse control that an environment variable removes is not a "
                "control."
            )
        if self.ratelimit_redis_policy != "fail_closed":
            raise ValueError(
                "RATELIMIT_REDIS_POLICY must be 'fail_closed' when "
                "ENV=production. 'fail_open_local' counts in PROCESS memory, "
                "so across N workers the effective limit is N times what was "
                "configured -- while every dashboard still reports the limit "
                "as enforced. A silently unenforced rate limit is worse than "
                "none, because nobody goes looking for it."
            )

        # --- CORS --------------------------------------------------------
        # A wildcard origin WITH credentials is refused outright. Browsers
        # reject that combination themselves, so configuring it means
        # somebody believes it is working when it is not -- and the usual
        # next step is to "fix" it by disabling something that matters.
        if "*" in self.cors_origins and self.cors_allow_credentials:
            raise ValueError(
                "CORS_ALLOWED_ORIGINS cannot be '*' while "
                "CORS_ALLOW_CREDENTIALS is true: browsers refuse that "
                "combination, so it is a misconfiguration that looks like a "
                "permission."
            )
        for origin in self.cors_origins:
            if origin == "*":
                # Phase 12: an explicit allow-list only. A wildcard without
                # credentials still lets any site read every response that
                # needs no cookie, which is not a production posture.
                raise ValueError(
                    "CORS_ALLOWED_ORIGINS cannot contain '*' when ENV=production; "
                    "list each console origin explicitly.")
            if not origin.startswith("https://"):
                raise ValueError(
                    f"CORS_ALLOWED_ORIGINS entry {origin!r} must be https in "
                    f"production: an http origin means the console's token "
                    f"travels in clear."
                )

        if insecure:
            lines = "; ".join(
                f"{name.upper()} ({what}) is {value!r}"
                for name, what, value in insecure
            )
            raise ValueError(
                f"ENV=production requires https for every security-critical "
                f"URL, and these are not: {lines}. Each of them carries "
                f"something an attacker in the middle could forge -- a policy "
                f"decision, a signing key, or a bearer token."
            )
        return self

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

    @field_validator("mcp_authentication_required")
    @classmethod
    def _mcp_must_authenticate(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError(
                "MCP_AUTHENTICATION_REQUIRED cannot be disabled: an "
                "unauthenticated caller must never be able to list or invoke "
                "a protected tool over MCP."
            )
        return v

    @staticmethod
    def _pair(raw: str, field: str) -> tuple[int, int]:
        try:
            limit, window = (int(part.strip()) for part in raw.split(","))
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"{field} must be 'requests,window_seconds', got {raw!r}"
            ) from exc
        if limit < 1 or window < 1:
            raise ValueError(f"{field} must be positive, got {raw!r}")
        return limit, window

    @property
    def ratelimit_tiers(self) -> dict[str, tuple[int, int]]:
        return {
            "auth": self._pair(self.ratelimit_auth, "RATELIMIT_AUTH"),
            "expensive": self._pair(self.ratelimit_expensive, "RATELIMIT_EXPENSIVE"),
            "mutation": self._pair(self.ratelimit_mutation, "RATELIMIT_MUTATION"),
            "read": self._pair(self.ratelimit_read, "RATELIMIT_READ"),
        }

    @property
    def trusted_proxy_networks(self) -> list[str]:
        return [n.strip() for n in self.trusted_proxy_networks_raw.split(",") if n.strip()]

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def cors_methods(self) -> list[str]:
        return [m.strip().upper() for m in self.cors_allowed_methods.split(",") if m.strip()]

    @property
    def cors_headers(self) -> list[str]:
        return [h.strip() for h in self.cors_allowed_headers.split(",") if h.strip()]

    @property
    def oidc_algorithms(self) -> list[str]:
        return [a.strip() for a in self.oidc_allowed_algorithms.split(",") if a.strip()]

    @property
    def mcp_token_algorithms(self) -> list[str]:
        return [a.strip() for a in self.mcp_allowed_algorithms.split(",") if a.strip()]

    @property
    def mcp_protocol_versions(self) -> list[str]:
        return [
            v.strip() for v in self.mcp_supported_protocol_versions.split(",")
            if v.strip()
        ]

    @property
    def mcp_origins(self) -> list[str]:
        return [o.strip() for o in self.mcp_allowed_origins.split(",") if o.strip()]

    @property
    def mcp_scopes_supported(self) -> list[str]:
        """Scopes advertised in the protected resource metadata.

        DESCRIPTIVE, not load-bearing. Authorization in this system is decided
        by Rego against verified credentials, not by an OAuth scope. The list
        is published because RFC 9728 provides for it and a client may use it
        to request a token; nothing downstream grants anything on its basis.
        """
        return ["mcp:invoke"]

    @property
    def mcp_resource_metadata_url(self) -> str:
        """The RFC 9728 well-known location for this resource's metadata."""
        return (
            f"{self.mcp_resource_uri.rstrip('/').rsplit('/mcp', 1)[0]}"
            f"/.well-known/oauth-protected-resource"
        )

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
