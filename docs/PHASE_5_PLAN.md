# Phase 5 — Human-in-the-Loop Authorization: plan

Phase 4 introduced `HUMAN_APPROVAL_REQUIRED` as a **decision value with nothing
behind it**. Phase 4.5 made the control plane accountable to a proven principal.
Phase 5 makes the human real: a person authenticates against a real identity
provider, sees exactly what they are approving, and their decision becomes a
cryptographically bound artifact that the **PDP re-evaluates** before anything
is enforced.

    AGENT -> AEM -> PDP -> OPA -> HUMAN_APPROVAL_REQUIRED
                                        |
                                        v
                          HITL service -> Keycloak -> human
                                        |
                                        v
                              approval artifact (signed)
                                        |
                                        v
                              PDP AGAIN -> OPA -> ALLOW / DENY
                                        |
                                        v
                                  AEM -> protected tool

The human never touches the resource. The approval is evidence; the PDP remains
the authority.

---

## 1. Baseline (recorded before any code changed)

    $ .venv/bin/python -m pytest
    440 passed in 120.65s

| | |
|---|---|
| Collected | 440 |
| Passed | 440 |
| Failed | 0 |
| Skipped | 0 |

An initial run reported `99 passed, 341 skipped`. That was an environment
artifact, not a regression: the PostgreSQL container was not running, and the
integration tests skip loudly rather than pretending to pass. The figure above
is from a run with the full infrastructure up (PostgreSQL 16, Redis 7, OPA
healthy), and it matches the expected Phase 4.5 baseline exactly.

---

## 2. Keycloak — verified before anything was designed around it

`quay.io/keycloak/keycloak:26.0`, started with `start-dev --import-realm`, realm
versioned at `keycloak/realm-agentic-iam.json`.

| | |
|---|---|
| Realm | `agentic-iam` |
| Issuer | `http://localhost:8080/realms/agentic-iam` |
| JWKS | `.../protocol/openid-connect/certs` |
| Client | `agentic-iam-console` — public, Authorization Code + **PKCE (S256)** |
| Audience | `agentic-iam-api`, added by an explicit audience protocol mapper |
| Realm roles | `IAM_ADMIN`, `LOAN_OFFICER`, `AUDITOR` |
| Redirect URIs | `http://localhost:5173/*`, `:3000/*`, `:8000/*` |
| Port | published on **127.0.0.1:8080** only, as with OPA |

A real token was obtained and inspected before any code was written:

    alg RS256   iss http://localhost:8080/realms/agentic-iam
    aud agentic-iam-api    azp agentic-iam-console
    sub 1f2514af-…         preferred_username loan.officer
    realm_access.roles [LOAN_OFFICER]     lifetime 900s

The audience mapper matters: Keycloak's default access-token audience is
`account`, which would make a correct `aud` check impossible to satisfy. Rather
than skip the check, the realm is configured to say who the token is *for*.

**Demo humans** (synthetic; passwords are in the realm file because this is a
POC and they are worthless outside it):

| Username | Role | May |
|---|---|---|
| `loan.officer` | `LOAN_OFFICER` | approve loan decisions — **nothing in IAM** |
| `iam.admin` | `IAM_ADMIN` | manage agents and credentials — **cannot approve loans** |
| `auditor` | `AUDITOR` | read the audit trail — approves nothing |
| `no.roles` | *(none)* | authenticate, and be refused everything |

`no.roles` exists so "authenticated but unauthorized" is a tested state rather
than an assumed one.

---

## 3. The four things that must stay separate (§21, §59)

| | Answers | Established by | Proof |
|---|---|---|---|
| Agent credential | "the issuer says this agent has capability X" | Phase 2 verifier | VC, `assertionMethod` |
| Human identity | "Keycloak says this is Priya Raman" | OIDC token validation | RS256 JWT via JWKS |
| Human approval | "Priya approved THIS action" | HITL service | Ed25519 artifact, `humanApproval` |
| Authorization | "this action may proceed" | PDP | OPA/Rego decision |
| Enforcement | "the tool may run" | AEM | single-use `EnforcementGrant` |

**An OIDC token is not an approval.** It says who someone is, not what they
agreed to. Nothing in this phase accepts an ID or access token where an approval
artifact is required, and a test asserts each token type is rejected in the
others' place (§42).

---

## 4. Human identity model (§3)

`human_principals` stores the **minimum** needed for authorization and audit:

    subject (Keycloak `sub`) + issuer     unique together
    provider                              "keycloak-oidc"
    username / display name / email       for the approval UI and audit
    last_seen_roles                       AUDIT ONLY, never authorization
    status                                ACTIVE | SUSPENDED (local stand-down)
    first_seen_at / last_seen_at

Keycloak stays authoritative for identity and roles. The row is created or
refreshed on each successful authentication.

**Roles used for authorization come from the validated token on every request**,
never from this table. If an operator removes `LOAN_OFFICER` in Keycloak, the
next token lacks it, and the change takes effect immediately. Storing roles as
`last_seen_roles` and authorizing from them would have created a second,
stale copy of Keycloak's decisions.

`status` is the one thing that is ours: a locally suspended principal
authenticates (its token is genuinely valid) and is then refused everything —
"we do not know you" and "we know you and you may not" stay distinguishable.

No password, no token, no refresh token and no client secret is ever stored.

---

## 5. OIDC (§5)

**Browser:** Authorization Code + PKCE (S256) directly against Keycloak. The
console is a public client; the backend holds no client secret and mints no
session cookie. There is deliberately no server-side human session — inventing
one would collide with the Session Authority that Phase 9 owns.

**Backend:** every request carries `Authorization: Bearer <access token>` and is
validated on **every call**:

| Check | How |
|---|---|
| signature | RS256 against Keycloak's **JWKS**, fetched live and cached by `kid` |
| algorithm | allowlist `{RS256}`; `alg: none` and HS256 key-confusion refused |
| issuer | exact match against configured `KEYCLOAK_ISSUER` |
| audience | must contain `agentic-iam-api` |
| expiry | `exp`, server clock, small leeway |
| not-before / issued-at | `nbf`/`iat` sanity |
| token type | `typ`/`azp` recorded; an ID token is not accepted as an access token |

Decoded claims are never trusted before the signature verifies. The JWKS cache
refreshes on an unknown `kid` so a Keycloak key rotation does not require a
restart, and a fetch failure is an authentication **failure**, not a bypass.

**Tests** obtain real tokens from Keycloak via the direct-grant flow — genuine
RS256 tokens from the real issuer, not fixtures. Negative cases (wrong issuer,
wrong audience, bad signature, expired, `alg: none`) are constructed as real
JWTs signed with a real throwaway key, so the validator is exercised rather than
mocked.

## 6. SAML (§6)

**OIDC is implemented. SAML federation is documented, not faked.**

    Enterprise IdP --SAML--> Keycloak --OIDC--> this application

Keycloak is the SAML Service Provider; the application never parses a SAML
assertion and never sees one. Adding a real enterprise IdP means configuring an
Identity Provider in the realm — **no application code changes**, because the
application already consumes only the OIDC token Keycloak issues afterwards.
That is the honest boundary, and `docs/HITL_SECURITY_MODEL.md` records exactly
what would need configuring. Standing up a second real IdP to demonstrate it is
not something this 6 GiB host can host alongside Keycloak, Ollama, OPA and
PostgreSQL, and a stubbed SAML endpoint would be a lie.

---

## 7. The approval artifact, and who signs it (§10, §11)

**Not the agent.** The agent must not be able to manufacture its own approval,
so its key is never involved.

**Not Keycloak.** Keycloak signs *identity* tokens. It has no idea what a loan
is, and claiming it signs approvals would be false.

The **approval authority** — a distinct service principal with its own Ed25519
key, a DID and a published DID Document, in the same KeyStore as everything
else:

    did:poc:service:approval-authority

Trust model, stated plainly: the artifact is the approval authority attesting
*"I authenticated this human against Keycloak, showed them this exact action,
and they decided X."* It is attributable to the human **through** the service.
The human holds no key; a POC that claimed otherwise would be inventing a second
PKI, which §10 forbids.

Key separation is a real property: no agent, no issuer and no control-plane
administrator holds this key, and a test asserts it.

Format — the project's existing shape, not a new one: canonical JSON (RFC 8785
style) + `PocEd25519Signature2026` + a proof purpose of **`humanApproval`**,
which is its own domain separator alongside `assertionMethod`,
`authentication`, `ansRegistration` and `controlPlaneRequest`. A signature made
for any of those can never verify as an approval, and vice versa.

## 8. Binding (§9) — the core security requirement

The artifact does not say *"a human approved this agent"*. It says:

> human `sub` at issuer `iss` approved agent `did` performing `action` on
> `resource_type`/`resource_id` for `purpose`, under authorization request
> `request_id`, valid until `expires_at`, once.

Bound fields: `approval_id`, `request_id`, `agent_did`, `action`,
`resource_type`, `resource_id`, `purpose`, `approver`, `decision`, `issued_at`,
`expires_at`, `nonce`, `domain`, and a `binding_sha256` over the canonical
tuple of the request-defining fields.

At re-evaluation the PDP recomputes `binding_sha256` **from the live
authorization request** and compares. Changing the resource, the action, the
agent or the request id after approval produces a mismatch, not an allow.

## 9. Lifecycle (§12, §13, §14)

    PENDING ──approve──> APPROVED ──consume──> CONSUMED
       │                    │
       ├──reject──> REJECTED└──expire──> EXPIRED
       ├──expire──> EXPIRED
       └──cancel──> CANCELLED

Terminal states are terminal. `CONSUMED -> APPROVED` and `REJECTED -> CONSUMED`
are refused by an explicit transition table, not by convention.

**Expiry** is server-side, from `expires_at` written at request time; a client
clock is never consulted and expiry is never silently extended.

**Consumption** happens at AEM enforcement, once, and is a single conditional
`UPDATE ... WHERE approval_id = ? AND status = 'APPROVED'`. The winner is
decided by the database, so two concurrent requests presenting the same approval
cannot both succeed (§49). A `/authorize` call evaluates but does **not**
consume — asking is not acting.

## 10. PDP re-evaluation (§19, §20)

There is no path from "human approved" to ALLOW that skips policy.

The PIP verifies the artifact — signature, issuer, expiry, state, binding — and
reports a **verdict**, exactly as it already does for credentials. Rego decides
what the verdict means:

    policies/security/human_approval.rego
        approval_present · approval_valid · approval_not_expired
        approval_not_consumed · bound_to_{request,agent,action,resource,purpose}

    policies/security/sensitive.rego      (modified)
        sensitive action + no valid approval -> HUMAN_APPROVAL_REQUIRED

    policies/loan/approval.rego
        approve_loan on loan_applications + valid bound approval
        + valid capability credential                          -> ALLOW

No approval logic in Python decides anything; Python only establishes facts.

## 11. S-7 closure (§22–§26, §46)

The mutations that were open become control-plane operations, using the
**Phase 4.5 guard unchanged** — extended with one new principal type:

| Operation | Route | Required |
|---|---|---|
| `agent_create` | `POST /api/v1/agents` | human `IAM_ADMIN` or machine `identity_admin` |
| `agent_status_change` | `POST /api/v1/agents/{id}/status` | " |
| `credential_issue` | `POST /api/v1/credentials/issue` | " |
| `credential_revoke` | `POST /api/v1/credentials/{id}/revoke` | " |
| `credential_present` | `POST /api/v1/credentials/present` | " |
| `audit_ingest` | `POST /api/v1/audit/events` | agent (self) or `identity_admin` |

The control-plane authenticator gains a second credential type: an OIDC bearer
token yields a `human` principal carrying the token's realm roles. A DID proof
still yields an `agent` or `administrator`. Rego then decides, in the same
package, with `principal.type` distinguishing them.

`LOAN_OFFICER` is refused every one of these, and `IAM_ADMIN` is refused loan
approval (§28, §29, §45). Human roles and agent capabilities never meet.

## 12. Demonstration (§33) and the loan resource

A `loan_applications` resource type with synthetic application **#7842** for
**₹25,00,000**, and a protected tool `approve_loan_application`
(action `approve_loan`). Reached only through the AEM, and only with a valid,
bound, unconsumed approval.

## 13. Deployment note

The HITL service is a **module and router inside the IAM API**, not a separate
process. The architecture diagram shows it as its own box because it is its own
trust boundary — its own signing key, its own state machine — but running it as
an eighth process on a 6 GiB host that also runs Keycloak, OPA, PostgreSQL,
Redis, seven agents and Ollama would buy separation the POC cannot demonstrate.
The boundary that matters is the key, and that is real.

## 14. Out of scope, deliberately

No JIT, A2A, MCP security, Session Authority, SSS, anomaly detection, trust
engine or kill switch. Approval expiry is **not** JIT: it bounds how long a
human decision stays usable, not how long an agent holds permission (§53). The
approval carries `request_id` and a `session_id` column that stays NULL, so
Phase 9 can bind sessions later without a schema change (§54).


---

## 15. Outcome

Everything planned above was implemented and verified against the running
system. Final state:

| | |
|---|---|
| Tests | 567 collected, 567 passing, 0 failures, 0 skips |
| Baseline | 440 (Phase 4.5) |
| Added | 127 |
| Phase 1 gate | 12/12 |
| Phase 2 gate | 30/30 |
| Phase 3 gate | 40/40 |
| Phase 4 gate | 31/31 |
| Phase 4.5 gate | 46/46 |
| Phase 5 gate | 67/67 |

S-7 is closed. Design details are in
[HITL_SECURITY_MODEL.md](HITL_SECURITY_MODEL.md); the component map and known
gaps are in [PHASE_5_ARCHITECTURE.md](PHASE_5_ARCHITECTURE.md).

One deviation from the plan, worth naming: agents no longer self-register their
identities. Closing S-7 made that impossible in principle -- an agent minting
its own identity is exactly the hole -- so provisioning became an authorized
administrative step (`scripts/provision_agents.py`), and an unprovisioned agent
now refuses to start rather than serving unregistered.
