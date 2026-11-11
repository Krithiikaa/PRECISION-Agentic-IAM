# Production Deployment

**Read this before deploying. The system refuses to start with several
development defaults, and those refusals are deliberate — they are the
cheapest point at which a misconfiguration can be caught.**

Operational procedures (backup, restore, key rotation, compromise response)
are in [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md).

---

## 1. What the application refuses to start with

`ENV=production` turns on checks that have no override flag. There is no
opt-out for any of them, for the reason stated at each one in
`backend/app/core/config.py`: a switch that turns a security requirement
into a no-op is a bypass with a configuration file in front of it.

| Refusal | Why |
|---|---|
| `KEYSTORE_MASTER_KEY` is the development default | the keystore would be decryptable by anyone who read the source |
| `OPA_URL`, `KEYCLOAK_BASE_URL`, `KEYCLOAK_ISSUER`, `MCP_RESOURCE_URI`, `API_PUBLIC_URL` not `https://` | each carries something an attacker in the middle can forge — a policy decision, a signing key, a bearer token. Substituting the JWKS is the worst: tokens then verify *honestly* against the attacker's key |
| `RATELIMIT_ENABLED=false` | an abuse control an environment variable removes is not a control |
| `RATELIMIT_REDIS_POLICY` ≠ `fail_closed` | `fail_open_local` counts in **process** memory: across N workers the effective limit is N× what was configured, while every dashboard still reports it as enforced |
| `CORS_ALLOWED_ORIGINS` is `*` with credentials | browsers reject that combination anyway, so configuring it means somebody believes it works |
| a CORS origin is `http://` | the console's bearer token would travel in clear |
| `AUTHORIZATION_FAIL_CLOSED`, `CONTROL_PLANE_AUTHENTICATION_REQUIRED`, `HITL_ENABLED`, `A2A_VERIFICATION_REQUIRED`, `MCP_AUTHENTICATION_REQUIRED` set false | each disables a control the architecture depends on |

Covered by `tests/test_production_configuration.py` (29 tests) and
`tests/test_cors_configuration.py`.

---

## 2. Operator-provided configuration

**No secret or certificate is in this repository, and none is generated for
you.** Every value below is yours to supply.

```bash
ENV=production

# Generate once, store in a secrets manager, never in the repo:
#   python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
KEYSTORE_MASTER_KEY=

DATABASE_URL=postgresql+psycopg://USER:PASS@HOST:5432/DB?sslmode=verify-full
REDIS_URL=redis://:PASSWORD@HOST:6379/0

# All https, all exact. KEYCLOAK_ISSUER must match the token `iss` claim
# EXACTLY or every token is refused with what looks like a signature error.
API_PUBLIC_URL=https://api.example.com
OPA_URL=https://opa.internal:8181
KEYCLOAK_BASE_URL=https://sso.example.com
KEYCLOAK_ISSUER=https://sso.example.com/realms/agentic-iam
MCP_RESOURCE_URI=https://api.example.com/mcp

# Keep these two DIFFERENT. One shared audience would let a token minted for
# a loan officer's browser session open an agent's MCP session.
OIDC_AUDIENCE=agentic-iam-api
MCP_AUDIENCE=agentic-iam-mcp

RATELIMIT_ENABLED=true
RATELIMIT_REDIS_POLICY=fail_closed
# Your ingress CIDR. EMPTY means believe nobody's X-Forwarded-For, which is
# correct without a proxy -- but behind one it makes the limiter key on the
# proxy's address and treat the whole internet as a single caller.
TRUSTED_PROXY_NETWORKS=10.0.0.0/8

CORS_ALLOWED_ORIGINS=https://console.example.com

# Keycloak's own database and TLS material.
KC_HOSTNAME=https://sso.example.com
KC_DB_URL=jdbc:postgresql://HOST:5432/keycloak
KC_DB_USERNAME=
KC_DB_PASSWORD=
KC_CERT_DIR=/path/to/certs
KC_CERT_FILE=/certs/tls.crt
KC_CERT_KEY_FILE=/certs/tls.key
POSTGRES_CERT_DIR=/path/to/pg-certs
```

---

## 3. TLS

**Not provided by this repository.** `ENV=production` forces every
security-critical URL to https, which means the service will refuse to start
until something in front of it actually serves https. That refusal is the
feature: it is better than starting and quietly serving bearer tokens in
clear.

What an operator must provide:

1. **A TLS-terminating reverse proxy** in front of the API and Keycloak.
   `docker-compose.prod.yml` publishes no ports — nothing is reachable
   except through the proxy.
2. **Trusted certificates.** `KC_HTTPS_CERTIFICATE_FILE` and
   `KC_HTTPS_CERTIFICATE_KEY_FILE` for Keycloak; PostgreSQL `ssl=on` with
   `ssl_cert_file`/`ssl_key_file`.
3. **Verified database TLS:** `?sslmode=verify-full` in `DATABASE_URL`.
   `require` encrypts but does not authenticate the server, which leaves the
   MITM this is meant to stop.
4. **No verification bypass.** There is no `verify=False` anywhere in this
   codebase and none should be added. The JWKS fetch in
   `app/humans/oidc.py` and `app/protocols/mcp/auth.py` uses the default
   trust store, and a fetch failure is an **authentication failure**, never
   permission to skip the check.

### Browser origins (Phase 12)

`CORS_ALLOWED_ORIGINS` is the single allow-list for the IAM API, the ANS and
every agent process. In production list each console origin explicitly
(`https://console.bank.example`); `*` and malformed entries refuse to start.
An unlisted origin receives no CORS headers, so browsers withhold the
response. CORS is not authorization: every route is still guarded.

### mTLS and certificates — BLOCKED_EXTERNAL

**Integration procedure** once certificates exist: (1) issue a server
certificate per service from the organisation's PKI; (2) terminate TLS at the
proxy for browsers and Keycloak; (3) for service-to-service mTLS place a
sidecar or mesh (e.g. Envoy) in front of OPA, PostgreSQL and Redis requiring
client certificates; (4) set `DATABASE_URL ...?sslmode=verify-full` and the
https URLs `ENV=production` already demands.
**Evidence required:** `openssl s_client -connect <host>:443 -verify_return_error`
succeeds for each endpoint; a connection to OPA/PostgreSQL *without* a client
certificate is refused; `GET /ready` reports every dependency healthy over TLS.
Until that evidence exists the status is **BLOCKED_EXTERNAL**.

### HSM / KMS — BLOCKED_EXTERNAL

All signing goes through the `KeyStore` interface (`app/identity/keys.py`:
`generate_key`, `get_public_key`, `sign`, `exists`, `delete`) and private keys
never leave it. **Integration procedure:** implement a `KeyStore` backed by
the provider's sign API (PKCS#11 or cloud KMS, Ed25519 keys, non-exportable),
select it in `build_keystore()`, and move `KEYSTORE_MASTER_KEY` (also the
audit-MAC root) into the KMS. **Evidence required:** key attributes show
non-exportable; `tests/test_identity_crypto.py`, the rotation tests and
`tests/test_audit_integrity.py` pass against the HSM-backed store; an audit
of the KMS shows signing calls from the IAM API identity only. No HSM is
simulated here.

### Internal trust model

Within the compose network, `iam-api` → `opa`, `postgres`, `redis` and
`keycloak` are **not** individually authenticated beyond their own
credentials. The model is a trusted network segment.

**This is an accepted risk and it is stated rather than hidden.** Anyone who
can reach OPA directly can return `ALLOW`. `docker-compose.prod.yml`
publishes no ports for those services precisely because the segment boundary
*is* the control. A deployment that needs defence in depth here should add
mTLS between services; this repository does not implement it.

---

## 4. Keycloak

`docker-compose.yml` runs `start-dev`, which disables hostname checking,
serves plain HTTP and uses an ephemeral in-memory database that loses every
user on restart. `docker-compose.prod.yml` replaces it with `start
--optimized` against a real PostgreSQL.

| Setting | Value | Why |
|---|---|---|
| `KC_DB` | `postgres` | a realm that vanishes on restart takes every human identity with it |
| `KC_HOSTNAME` | your https URL | written into the token `iss`, which this service compares exactly |
| `KC_HOSTNAME_STRICT` | `true` | otherwise Keycloak accepts the Host header, and a wrong one mints tokens with a wrong issuer |
| `KC_PROXY_HEADERS` | `xforwarded` | behind a TLS proxy; without it redirect URLs carry the wrong scheme and login never completes |
| `KC_HTTP_ENABLED` | `false` | no plaintext listener at all |

### Demo credentials must not reach production

`keycloak/realm-agentic-iam.json` contains **demo users with known
passwords** (`loan.officer`, `iam.admin`, `auditor`, `payment.officer`,
`no.roles`). They exist so the gates can run.

**Before deploying:** remove the `users` array from the realm file, or
import the realm and then delete those accounts. Also delete the bootstrap
admin once a real administrator exists — leaving it is leaving a
known-username account on an internet-facing SSO.

**This is not enforced by code.** It is an operator step, and it is the
single most likely thing on this page to be forgotten.

### What to verify after import

- The `mcp-invoke` client scope exists with its audience mapper, or MCP
  tokens arrive without `agentic-iam-mcp` and every call fails
  authentication. `scripts/provision_mcp_clients.py` creates it if absent.
- Each agent has a confidential client whose `clientId` is its DID, with
  `client-jwt` authentication and `EdDSA`.
- Token lifespan is short. The default 900s bounds how long a revoked
  agent's token stays cryptographically valid — revocation is already
  effective immediately through the PIP, but a shorter token narrows the
  window in which a stolen one is useful.

---

## 5. Redis

**Required in production**, and this is a change from Phase 9, where Redis
was recorded as "an unused but mandatory startup dependency".

Phase 10 made it the shared counter behind rate limiting. With
`RATELIMIT_REDIS_POLICY=fail_closed`, an unreachable Redis means the API
refuses rate-limited requests with 503 rather than serving an unenforced
limit.

- Set `REDIS_PASSWORD` and include it in `REDIS_URL`.
- Do not publish its port.
- Treat it as a security-critical dependency: its outage is an API outage,
  by design.

---

## 6. Deployment verification

Run these after deploying. Each has a defined correct answer.

```bash
# 1. Liveness. Public by design.
curl -fsS https://api.example.com/health
curl -fsS https://api.example.com/ready

# 2. Sensitive reads refuse anonymity. MUST be 401 or 403 -- a 200 here
#    means the Phase 10 read guards are not in effect.
for p in audit agents credentials hitl/approvals hitl/humans loans policies; do
  printf '%-20s %s\n' "$p" \
    "$(curl -s -o /dev/null -w '%{http_code}' https://api.example.com/api/v1/$p)"
done

# 3. OAuth metadata is reachable without a token (RFC 9728 requires it).
curl -fsS https://api.example.com/.well-known/oauth-protected-resource

# 4. An unauthenticated MCP call is 401 WITH a WWW-Authenticate challenge.
curl -si -X POST https://api.example.com/mcp \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' | grep -i www-authenticate

# 5. Rate limiting is live: headers present, and a burst is refused.
curl -si https://api.example.com/health | grep -i ratelimit

# 6. Internal services are NOT reachable from outside.
#    Each MUST fail to connect.
curl -m 3 https://api.example.com:8181/v1/policies   # OPA
curl -m 3 https://api.example.com:5432               # PostgreSQL
curl -m 3 https://api.example.com:6379               # Redis
```

**If step 2 returns 200 for anything, stop and investigate before going
live.** That is the Phase 9 HIGH finding re-opening.

---

## 7. What is still not production-ready

Stated plainly. None of these is fixed by configuration.

| Gap | Status |
|---|---|
| TLS termination | **operator-provided**; not in this repo |
| Independent security review | **NOT PERFORMED.** Nothing in this repository substitutes for one |
| Disaster-recovery rehearsal | **NOT PERFORMED** |
| RPO / RTO | **NOT ESTABLISHED** |
| Load, capacity and failover behaviour | **UNMEASURED** |
| Service-to-service mTLS | **not implemented**; trusted-segment model (§3) |
| Log aggregation, metrics, alerting | **not implemented** |
| Demo users removed from the realm | **operator step**, not enforced by code |
| MCP interoperability with a third-party client | **UNVERIFIED** (see PHASE_8_ARCHITECTURE.md) |
| Legal non-repudiation | **not provided.** Signatures establish that a key signed a payload; binding a key to a legal person needs a trust framework this POC does not implement |
| Tool arguments stored unredacted | safe for the current tool set; a tool taking a secret would need a redaction policy first |

**Verdict on deployment readiness: the application's own configuration
surface is ready and self-enforcing. The surrounding infrastructure — TLS,
secrets, backups, monitoring and an independent review — is not, and this
repository cannot make it so.**
