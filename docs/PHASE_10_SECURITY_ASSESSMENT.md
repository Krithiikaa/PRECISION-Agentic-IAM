# Phase 10 — Final Security Assessment

**Scope:** the nine findings Phase 9 left open, plus whatever Phase 10's own
work uncovered.

**Verdict up front.** The Phase 9 HIGH finding is **closed and verified on a
running system**. Three of the four Phase 9 MEDIUM/operational findings are
closed; the rest are either closed by configuration the operator must supply
or explicitly accepted and documented. **No independent security review has
been performed, and nothing in this repository substitutes for one.**

---

## 1. Phase 9 findings, re-assessed

| # | Phase 9 finding | Severity | Status now |
|---|---|---|---|
| 1 | Unauthenticated read APIs | HIGH | **FIXED** — §2 |
| 2 | No API rate limiting | MEDIUM | **FIXED** — §3 |
| 3 | Hardcoded CORS | MEDIUM | **FIXED** — §4 |
| 4 | Replayable presentations | MEDIUM | **FIXED** — §5 |
| 5 | Redis unused but mandatory | LOW | **RESOLVED** — it is now the rate-limit backend and genuinely required (§6) |
| 6 | TLS not configured | Operational | **REQUIRES OPERATOR CONFIGURATION** — enforced by a startup refusal (§7) |
| 7 | Keycloak in development mode | Operational | **REQUIRES OPERATOR CONFIGURATION** — production overlay provided (§7) |
| 8 | Backup / key rotation undocumented | Operational | **DOCUMENTED** — OPERATIONS_RUNBOOK.md (§8) |
| 9 | No independent security review | Operational | **UNRESOLVED. Still not performed.** |

---

## 2. HIGH — unauthenticated read APIs · **FIXED**

**Was:** ten read endpoints served an anonymous caller the audit trail, the
credential inventory, the agent registry, the approval queue, human
identities, loan records and the decision history.

**Affected:** `app/api/routes/{agents,credentials,audit,authorization,hitl,jit,loans,a2a,events}.py`

**Risk:** complete disclosure of who did what, which agents hold which
credentials, which approvals are pending, and applicant names with amounts.

**Fix.** 26 routes now carry the existing `ControlPlaneGuard`. No new
authentication layer was built: the guard already accepted **either** a human
OIDC token **or** a signed machine proof, and already decided in Rego. Seven
read operations were added, each naming one data domain, with roles mapped in
`control_plane/humans.rego` and `control_plane/administration.rego`.

### Authorization matrix

| Operation | Covers | Human roles | Admin role |
|---|---|---|---|
| `identity_read` | agent registry, agent detail, tool catalogue | AUDITOR, IAM_ADMIN | `identity_admin` |
| `credential_read` | credential inventory, status, verification history, issuers | AUDITOR, IAM_ADMIN | `identity_admin` |
| `audit_read` | audit trail, decision history, event stream | AUDITOR, IAM_ADMIN | `identity_admin` |
| `approval_read` | approval queue, human principals, HITL config | AUDITOR, IAM_ADMIN, LOAN_OFFICER, PAYMENT_OFFICER | `identity_admin` |
| `grant_read` | JIT mandates, A2A ledger, payment instructions | AUDITOR, IAM_ADMIN, PAYMENT_OFFICER | `identity_admin` |
| `policy_read` | declared and live policy set | AUDITOR, IAM_ADMIN | `policy_admin` |
| `loan_read` | loan applications | AUDITOR, LOAN_OFFICER | `loan_admin` |

**The separations that bite**, each asserted by a named test:

- **IAM_ADMIN cannot read a loan.** It administers agent identity; the fact
  that it can suspend the agent processing a customer's file does not give it
  the file.
- **LOAN_OFFICER cannot read the audit trail, the registry or credentials.**
  Deciding one loan requires none of them.
- **Neither officer role can read the policy set.** Knowing which rules are
  live is the first half of evading them — specifically, which amount band to
  stay under.
- **The enforcement gateway reads nothing.** It drives `/authorize` and
  `/enforce` for any subject; if it could also read, one compromised
  automation credential would be both an enforcement path and a disclosure
  path.
- **An agent reads none of the administrative surface**, and claiming
  `roles: [AUDITOR]` as an agent grants nothing — human roles and agent
  capabilities are separate trust domains.

### Deliberately still public

Written as an allow-list in `tests/test_route_security_inventory.py`, each
with a reason, and asserted against the live route table:

liveness probes · RFC 9728 protected-resource metadata · DID documents and
the two public key registers (verification material by design) ·
`/api/v1/hitl/me` (returns the caller's own identity) · the challenge
endpoint (§5) · `/mcp` (OAuth, a different mechanism).

### Evidence

- Live probe: all 12 previously-open endpoints return **401**; the six
  intentionally-public ones still return 200.
- `tests/test_route_security_inventory.py` — 19 tests. Walks the **whole
  route table**, so a sensitive route added later with no guard fails by
  name. A route is public only if written in the allow-list with a reason.
- `tests/test_read_authorization.py` — 51 tests covering the matrix,
  vertical escalation, horizontal escalation, anonymous access, agents
  claiming human roles, and the matrix enforced over HTTP.

### Remaining limitation

**Authorization is domain-scoped, not row-scoped.** `audit_read` grants the
trail; it does not filter to the caller's own records. Query parameters
cannot escalate — filtering within a domain reaches nothing the role did not
already have — but a role that may read a domain reads all of it. Row-level
authorization would be a different design and is not implemented.

---

## 3. MEDIUM — no rate limiting · **FIXED**

**Affected:** all HTTP endpoints. **Risk:** credential guessing, assertion
replay, and resource exhaustion through expensive policy evaluations.

**Fix.** Redis-backed sliding-window limiter (`app/ratelimit/`), applied as
middleware so a route added tomorrow is limited the moment it exists.

| Tier | Default | Covers |
|---|---|---|
| `auth` | 20/60s | token, credential, verification and MCP endpoints |
| `expensive` | 60/60s | `/enforce`, `/authorize`, A2A submission, JIT issuance |
| `mutation` | 120/60s | all other state changes |
| `read` | 300/60s | everything else |

**Design decisions that matter:**

- **Sliding log, not a fixed bucket.** A fixed window lets a caller spend its
  whole allowance at 11:59:59 and the next window's at 12:00:00 — twice the
  limit in two seconds, which is the burst the limit exists to stop.
- **One atomic Lua script.** Read-then-write from Python would let concurrent
  requests each observe "under the limit" before any wrote.
- **Keyed on identity first, peer address second.** Keying only on IP
  punishes everyone behind one NAT and lets one abuser with many addresses
  through.
- **`X-Forwarded-For` is ignored** unless the request came from a configured
  trusted proxy. Otherwise a caller mints a fresh allowance per request by
  setting a header, which is not a rate limit.
- **Redis unavailable is never silent.** `fail_closed` (required in
  production) refuses with 503; `fail_open_local` counts in process memory
  and WARNs on every request. Production refuses the second because across N
  workers it is an N-times-looser limit that still reports as enforced.

**Evidence:** `tests/test_rate_limiting.py` — 32 tests against **real Redis**,
covering the window, reset, sliding behaviour, 20-way concurrency, multiple
identities, both unavailability policies, headers, the tier map against the
live route table, and five spoofing cases. Live: a 26-request burst on the
auth tier produced 18×200 and 8×429.

**Remaining limitation:** limits are global per tier, not per-endpoint or
per-tenant. No adaptive or reputation-based limiting.

---

## 4. MEDIUM — hardcoded CORS · **FIXED**

**Was:** `main.py` pinned two localhost origins with `allow_methods=["*"]`
and `allow_headers=["*"]`.

**Risk:** low in itself — it failed *safe* (a real console would not load) —
but undeployable, and the wildcards were wider than needed.

**Fix.** Origins, methods, headers, credentials and max-age are
configuration. Production refuses a wildcard origin with credentials, and
refuses any `http://` origin.

**Evidence:** `tests/test_cors_configuration.py` — 16 tests, including two
that assert **CORS is not authorization**: a request from a permitted origin
with no credentials is still refused by the route guard.

---

## 5. MEDIUM — replayable presentations · **FIXED**

**Was:** the presentation `challenge` was compared for equality but never
recorded. A captured presentation replayed cleanly against any verifier that
reused one. Documented in `app/credentials/presentation.py` since Phase 2 and
still open at the end of Phase 9.

**Fix.** A challenge ledger (`presentation_challenges`), issued and recorded
by `GET /api/v1/credentials/challenge`, consumed atomically during
verification.

- **Unpredictable** — `secrets.token_urlsafe(32)` (already true).
- **Recorded at issue** — so a value this verifier never issued is refused
  with `CHALLENGE_UNKNOWN`. Remembering only at first use would let an
  attacker invent one and have it accepted *because* it had never been seen.
- **Bound to a verifier** — the ledger enforces the audience too, so a
  verifier that forgot `expected_domain` is still protected.
- **Expiring** — against the server clock. Checked *before* the atomic claim,
  so an expired challenge is not burned and its owner can be told to refresh.
- **Single-use** — `UPDATE ... WHERE consumed_at IS NULL RETURNING`.

**One ordering decision worth recording.** The spend happens **after** the
holder proof *and* after the domain check. Spending before the domain check
would let an attacker relay a captured presentation to the **wrong** verifier
purely to burn the victim's challenge — turning replay protection into a
denial-of-service against the legitimate holder. This was found by a Phase 9
test failing for the wrong reason and was corrected.

**Signature verification, credential status and revocation checks all still
run.** A fresh challenge on a revoked credential is still refused.

**Evidence:** `tests/test_presentation_replay.py` — 25 tests: reuse, unknown,
expired, wrong audience, who-spent-it, housekeeping, the endpoint contract,
and **20 concurrent presentations of one challenge spending it exactly once**
on real connections.

**Remaining limitation:** `CHALLENGE_REQUIRED` defaults to true but is
configurable. A deployment that turns it off reopens the gap; the setting
exists because an offline audit of an archived presentation genuinely has no
freshness to check, and saying so explicitly is better than omission.

---

## 6. LOW — Redis unused but mandatory · **RESOLVED**

Phase 9 found Redis started by compose, declared a healthy-start dependency
of the API, and referenced nowhere but `config.py`.

**Resolution: it is now genuinely required.** It is the shared counter behind
rate limiting (§3). In production `RATELIMIT_REDIS_POLICY=fail_closed` makes
an unreachable Redis an API outage **by design** — the documented alternative
to serving an unenforced limit.

No new dependency: `redis==5.2.1` was already in `requirements.txt`.

---

## 7. Operational — TLS and Keycloak · **REQUIRES OPERATOR CONFIGURATION**

### TLS

Not provided by this repository, and it cannot be. What Phase 10 added is a
**refusal**: `ENV=production` rejects `http://` for `OPA_URL`,
`KEYCLOAK_BASE_URL`, `KEYCLOAK_ISSUER`, `MCP_RESOURCE_URI` and
`API_PUBLIC_URL`, with no opt-out flag. The service will not start until
something in front of it actually serves https.

There is no `verify=False` anywhere in the codebase, and a JWKS fetch failure
is an authentication failure rather than permission to skip the check.

**Internal service communication is a trusted-segment model, and that is an
accepted risk stated rather than hidden.** Anyone who can reach OPA directly
can return `ALLOW`. `docker-compose.prod.yml` publishes no ports for OPA,
PostgreSQL or Redis precisely because the segment boundary *is* the control.
Service-to-service mTLS is **not implemented**.

### Keycloak

`docker-compose.prod.yml` replaces `start-dev` with `start --optimized`
against a real PostgreSQL, with `KC_HOSTNAME_STRICT`, proxy headers, TLS
files and no plaintext listener.

**Demo users are still in the realm file** (`loan.officer`, `iam.admin`,
`auditor`, `payment.officer`) with known passwords. They exist so the gates
can run. **Removing them is an operator step and is not enforced by code** —
the single most likely item on the deployment checklist to be forgotten.

**Evidence:** `tests/test_production_configuration.py` — 29 tests.
**Unverified:** no production Keycloak has been stood up; the overlay is
reviewed, not run.

---

## 8. Operational — backup and key rotation · **DOCUMENTED**

[OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) covers database backup with
integrity verification, restore, migration recovery, rotation for all four
signing authorities, and compromise response.

Two things it is careful about:

- **Database and keystore must be backed up and restored together.** A
  database restored beside a different keystore can read its history and sign
  nothing, and the failure looks like a signing bug.
- **Rotation is not containment.** A rotated key stays published and its
  artifacts stay valid — correct for a scheduled change, useless for a
  compromise. The compromise procedure revokes first.

**`ApprovalAuthority.rotate()` was re-inspected** under the standing
instruction not to modify it. **No defect found** — atomic retirement, a lost
race raises `ConflictError` rather than creating a second active key, an
orphaned keystore entry is refused, and a post-generation failure deletes the
new key before re-raising. **Not modified.**

**Verified:** rotation (13 tests), revocation immediacy, migration
round-trips. **Not verified:** restore at production scale, RPO/RTO,
disaster-recovery rehearsal, the compromise procedure end-to-end.

---

## 9. Findings introduced or discovered during Phase 10

| Finding | Severity | Status |
|---|---|---|
| Challenge spend ordered before the domain check, allowing a relayed presentation to burn a victim's challenge | MEDIUM | **FIXED before release** (§5) |
| Gate scripts signed the query string, which the server excludes from the proof | LOW | **FIXED** — all gates and the test fixture |
| Rate limiting throttles the test suite | Informational | **ACCEPTED** — disabled for the suite, exercised by dedicated tests, and refused in production by the config validator |

---

## 10. Residual risk

| Risk | Classification |
|---|---|
| No independent security review | **UNRESOLVED** — the most significant item on this page |
| TLS termination, certificates, secrets management | **REQUIRES OPERATOR CONFIGURATION** |
| Demo users removed from the realm | **REQUIRES OPERATOR ACTION**, not enforced by code |
| Service-to-service mTLS | **ACCEPTED RISK** — trusted-segment model (§7) |
| Row-level read authorization | **ACCEPTED** — domain-scoped by design (§2) |
| MCP interoperability with a third-party client | **UNVERIFIED** |
| Disaster-recovery rehearsal, RPO/RTO | **UNVERIFIED** |
| Load, capacity, failover | **UNMEASURED** |
| Log aggregation, metrics, alerting | **NOT IMPLEMENTED** |
| Legal non-repudiation | **NOT PROVIDED** — signatures establish that a key signed a payload; binding a key to a legal person needs a trust framework this POC does not implement |
| Tool arguments stored unredacted | **ACCEPTED** for the current tool set; a tool taking a secret needs a redaction policy first |
| Threat model assumes an honest infrastructure operator | **ACCEPTED** — database or keystore access defeats these controls |

---

## 11. Verdict

- **POC: complete.** Phases 1–10 implemented, integrated and verified.
- **Security hardening: complete** for the findings in scope. Every Phase 9
  HIGH and MEDIUM finding is closed, with tests, and the HIGH one is verified
  on a running system.
- **Production configuration: complete in the application, incomplete in the
  environment.** The config surface is self-enforcing — it refuses to start
  insecure. TLS, secrets, certificates and realm cleanup are the operator's
  and are not done.
- **Production deployment: NOT READY.** Not because of an open application
  vulnerability, but because no independent security review has been
  performed, no disaster-recovery rehearsal has been run, nothing is
  monitored, and the infrastructure the application depends on does not yet
  exist.
