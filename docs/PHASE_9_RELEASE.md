# Phase 9 — Final Integration, Security Validation and Release Readiness

**Status: the system is complete and internally consistent as a proof of
concept. It is NOT production-ready, and this document says exactly why.**

Eight findings remain **open** (§4): one HIGH, three MEDIUM, four LOW. All
eight are on the deployment surface or on a demonstration path; none is an
open defect in the authorization architecture.

Four defects **were** found and fixed (§5), and two of them were real
security defects rather than deployment gaps — production accepting
plaintext URLs, and **policy deactivation silently reverting within fifteen
seconds**. The second was in the policy-administration layer itself, and it
defeated an administrative control the system advertises. It is recorded
here rather than glossed, because the system looked green while it was
present: it surfaced only as an intermittent gate failure.

---

## 1. What this phase did

Inspected the repository rather than trusting the phase markers, ran every
test and gate, probed the live system for unauthenticated access, built
seven cross-phase end-to-end scenarios, fixed three genuine defects, and
assessed deployment readiness honestly.

**No new features. No new phases. No dependency changes.**

---

## 2. Integration status, Phases 1–8

Verified against the running system, not read off a changelog.

| # | Component | Status | Evidence |
|---|---|---|---|
| 1 | Agent identity — DID, Ed25519 | **Verified** | gate 12/12; scenario A resolves a live DID |
| 2 | Credential trust — VC/VP, expiry, revocation | **Verified** | gate 30/30; scenario B revokes and access stops |
| 3 | ANS — registration, discovery, resolution | **Verified** | gate 40/40; scenario A discovers then is still authorized separately |
| 4 | Authorization — PIP/PDP/PAP/OPA/AEM | **Verified** | gate 31/31; every scenario routes through it |
| 4.5 | Control-plane hardening | **Verified** | gate 46/46; 11/11 privileged mutations reject anonymity |
| 5 | HITL — Keycloak/OIDC, approvals | **Verified** | gate 68/68; scenario E opens a real approval |
| 5.5 | Dual control, amount bands | **Verified** | gate 110/110; band chosen by amount, not caller |
| 6 | JIT — bounded grants, fresh authorization | **Verified** | gate 113/113; scenario F refused over the ceiling |
| 7 | A2A — signed transactions, replay, idempotency | **Verified** | gate 132/132 |
| 8 | MCP — OAuth identity, protocol, tool authorization | **Verified** | gate 38/38; scenario C lists then is refused |

**The seams hold.** Scenario B is the sharpest demonstration: revoking an
agent's capability credentials stopped the *same call* that had just
succeeded, while its OAuth token, DID, ANS registration and the policy set
were all untouched.

---

## 3. Security validation

### Verified by test and by live probe

| Property | How it was established |
|---|---|
| Authentication ≠ authorization | A valid OAuth token lists tools and invokes none (scenario C) |
| Discovery ≠ permission | ANS resolves an endpoint; MCP lists the catalogue; both still refused |
| Valid credential ≠ access | Purpose and resource scope still decide |
| Every protected action gets a fresh decision | No decision is cached anywhere; PIP re-reads state per call |
| Revocation is immediate | Scenario B, within an unexpired token's lifetime |
| Agent deactivation is immediate | `test_deactivating_the_agent_stops_the_next_call` |
| Policy change takes effect | `test_removing_the_policy_data_document_fails_closed`; and **deactivation now holds** — `test_policy_deactivation_is_durable.py` (defect found and fixed in this phase, §5.2) |
| JIT cannot bypass the PDP | Issuance runs the full evaluation first; use is re-decided |
| HITL/dual control cannot be bypassed | Band chosen by amount; unaffected by channel |
| A2A replay and duplicate execution prevented | `UNIQUE (sender_did, transaction_id)` + atomic claim |
| Signed values are the executed values | Four-way reconciliation (A2A), three-way (MCP) |
| Nonces, timestamps, signatures, proof purposes validated | 12-step ordered envelope check |
| **Privileged endpoints reject anonymity** | **11/11 probed live; whole route table asserted in `test_unauthenticated_surface.py`** |
| Fail-closed on dependency loss | OPA unreachable → `AUTHORIZATION_UNAVAILABLE`, never ALLOW |
| Errors do not leak schema, traces or credentials | `TestErrorsDoNotLeak` |

### Negative testing performed

Unauthorized access, expired credentials, revoked credentials, modified
payloads, replay attempts, concurrent duplicate requests, invalid signatures,
borrowed sessions, forged audit events, cross-service token reuse, algorithm
confusion (`alg: none`), identity confusion (`sub` vs `azp`), argument
smuggling, purpose forgery, self-asserted verdicts, and tool output posing as
instructions.

**This does not make the system "secure".** It means these specific attacks
were tried and refused. No penetration test, no cryptographic review and no
third-party assessment has been performed.

---

## 4. Findings

### HIGH — unauthenticated read access to the entire read API

**10 of 12 probed read endpoints serve an anonymous caller**, including:

| Endpoint | Discloses |
|---|---|
| `GET /api/v1/audit` | the complete security audit trail |
| `GET /api/v1/credentials` | the credential inventory |
| `GET /api/v1/agents` | the agent registry |
| `GET /api/v1/hitl/approvals` | the pending approval queue |
| `GET /api/v1/hitl/humans` | human principal identities |
| `GET /api/v1/loans` | applicant names, customer ids, amounts |
| `GET /api/v1/authorize/decisions` | authorization decision history |

Confirmed by live probe. The data here is synthetic, but the **shape** is
what matters: an anonymous observer reads who approved what, which agents
hold which credentials, and what every policy decision was.

**Not fixed in this phase, deliberately.** Closing it means deciding the
read API's authentication model — a service identity for the console versus
human OIDC on every read — and then changing ~10 routes, five gate scripts
and the console's API client. That is the broad refactor this phase was told
not to attempt, and the shape of the fix is a product decision, not a defect
correction.

**Remediation:** put the existing `ControlPlaneGuard` (or the Phase 5 OIDC
validator) in front of the read routes, give the console a service principal,
and update the gates to sign their reads. Estimated small-to-medium; must not
be rushed into a final hardening pass.

### MEDIUM — CORS origins are hardcoded to localhost

`main.py` pins `allow_origins` to `http://localhost:5173` and `:3000`. This
**fails safe** — a production console simply would not load — but it means
the service cannot be deployed with a real frontend without a code change.
Should be configuration.

### MEDIUM — no rate limiting anywhere

Neither the API nor the MCP endpoint limits request rate. The MCP tools
specification asks servers to rate limit tool invocations. Exactly-once
deduplication is **not** a rate limit: it stops a call repeating, not a
thousand distinct calls.

### MEDIUM — verifiable presentations are replayable

`/api/v1/credentials/present` checks the challenge but never records it as
used, so a captured presentation can be replayed against a verifier that
reuses a challenge. `app/credentials/presentation.py` documents this in its
own docstring; re-verified open on 2026-11-03.

**Why MEDIUM and not HIGH.** Every path that actually carries authority built
its own replay ledger rather than relying on this one: control-plane proofs,
ANS registration, A2A envelopes and MCP invocations each have a nonce or
request-id ledger backed by a unique constraint. The presentation endpoint is
a demonstration surface, not an authorization input — no policy decision in
this system depends on it. It becomes HIGH the moment anything does.

**Remediation:** a consumed-challenge table with a unique constraint, the
same pattern the other four paths already use.

### LOW — Redis is an unused startup dependency

`redis` appears only in `config.py`. Nothing reads or writes it. Yet
docker-compose starts it *and* `iam-api` declares `depends_on: redis:
service_healthy`, so an unused service can block the API from starting.

Either wire it up or remove it from the dependency chain. Leaving it is a
startup failure mode with no corresponding benefit.

### LOW — repeated seeding accumulates credentials

`seed_credentials.py` issues rather than replaces, so an agent accumulates
equivalent capability credentials across runs. Harmless (each is validated
independently) but it made one end-to-end scenario misleading until it was
corrected to revoke *all* granting credentials, not one.

### LOW — setup steps are not part of startup

`run_local.sh` starts the stack but does not seed credentials or provision
MCP OAuth clients. Without the first, every agent call denies; without the
second, every MCP call is 401. Both look like bugs rather than missing
setup. Phase 9 added the two commands to the script's closing output rather
than running them automatically — seeding *issues* rather than replaces (see
above), and provisioning requires Keycloak, which should not gate the API
coming up.

### LOW — demo data is served by the running system

Loan applications and payment instructions are in-process demo fixtures. They
are clearly marked synthetic in the payload (`disclaimer` field) but are
served by the same API as everything else.

---

## 5. Defects fixed in this phase

### 1. Production accepted plaintext URLs — **HIGH**, fixed

`ENV=production` started happily with `http://` for `opa_url`,
`keycloak_base_url`, `keycloak_issuer`, `mcp_resource_uri` and
`api_public_url`. Each carries something an attacker in the middle can forge:
a policy decision, a signing key, or a bearer token. Substituting the JWKS is
the worst of them — tokens then verify *honestly* against the attacker's key.

Fixed with a model validator that refuses to start, with no opt-out flag,
consistent with every other security switch in this codebase. Covered by
`tests/test_production_configuration.py` (24 tests).

### 2. Policy deactivation silently reverted within 15 seconds — **HIGH**, fixed

**The most serious defect found in this phase**, and it defeated an
administrative security control.

`policies/manifest.json` declares what each policy IS — owner, purpose,
shipped version — and every entry reads `"status": "ACTIVE"`, because the
file describes the *shipped* set. The *running* state is different:
`POST /api/v1/policies/{id}/deactivate` deletes the module from OPA and
records INACTIVE in the database.

But `reconcile()` and `load_all()` both read only the manifest. A policy an
operator had deliberately switched off therefore looked identical to a
policy missing because OPA had restarted — so it was pushed straight back
in. `main.py` runs that reconciler **every 15 seconds**, and its log line
reads `policy_set_incomplete ... reloading`, which looks like recovery
rather than reversion.

**Consequence:** an operator disabling a rule to contain an incident would
have watched it come back within fifteen seconds, with nothing in the log
that looked wrong.

**How it surfaced:** as an *intermittent* failure of the Phase 6 gate's
policy-change check (112/113 on one sweep, 113/113 on the next two). Whether
it passed depended on whether a reconciler tick landed between the
deactivate and the authorization. The underlying control was verified
deterministic in isolation — deactivate then authorize gave DENY
`NO_MATCHING_POLICY` four times out of four — which is what made the
intermittency worth chasing rather than dismissing.

**Fix:** an operator's deactivation, recorded in the database, now outranks
the manifest in both `reconcile()` and `load_all()`. The engine-restart
recovery the reconciler exists for is unaffected and is covered by its own
test. Nine regression tests in
`tests/test_policy_deactivation_is_durable.py`, including that
re-activation still works and that an untouched policy is not disturbed.

### 3. MCP could be provisioned for no real agent — **HIGH**, fixed

`provision_mcp_clients.py` read a single keystore. But `provision_agents.py`
gives every agent **its own** `.keystore-agents/<slug>/` directory — correct
key custody, and the reason the script found nothing. Before the fix it
skipped all ten deployed agents and provisioned only two probe identities.

Fixed by resolving each agent's own keystore first, falling back to the
service keystore. All ten agents now provision. The same assumption was
corrected in `scripts/phase8_gate.py`.

### 4. The Phase 8 gate missed a header — **LOW**, fixed in Phase 8, noted here

`dict(response.headers)` lost HTTP's case-insensitivity, so a correctly-sent
`www-authenticate` header read as absent. A gate-script bug that looked
exactly like a missing security header.

---

## 6. Test results

```
collected 1272
passed    1272
failed       0
skipped      0
```

Phase 9 added 55 tests: 29 production-configuration (including the
error-redaction guards), 17 unauthenticated-surface, 9 policy-deactivation
durability.

**On skips.** The historical benchmark of 1,123 was recorded with 0 skips, and
this run also has 0. The suite contains two environment-gated markers —
`llm` (needs Ollama with `llama3`) and `integration` (needs PostgreSQL) — and
both dependencies were available, so nothing skipped. On a memory-constrained
host the `llm` test skips loudly with the actual figures rather than being
weakened; that is an environment condition, not a regression.

**Count difference from the benchmark** (1123 → 1272) is Phase 8's 94 tests
plus Phase 9's 46, plus one Phase 7 guard test that Phase 8 split into two
when `AEM.enforce()` gained an optional parameter (see `PHASE_STATUS.md`).

---

## 7. Phase gate results

All eleven run against the live system — real PostgreSQL, real OPA evaluating
real Rego, real Keycloak issuing real tokens, real agent processes.

| Gate | Result |
|---|---|
| Phase 1 — identity | 12/12 |
| Phase 2 — credentials | 30/30 |
| Phase 3 — ANS | 40/40 |
| Phase 4 — authorization | 31/31 |
| Phase 4.5 — control plane | 46/46 |
| Phase 5 — HITL | 68/68 |
| Phase 5.5 — dual control | 110/110 |
| Phase 6 — JIT | 113/113 (deterministic after the §5.2 fix; verified 3 consecutive runs) |
| Phase 7 — A2A | 132/132 |
| Phase 8 — MCP | 38/38 |
| **Phase 9 — end-to-end** | **36/36** |

### Running the gates

Credentials are issued with a 3600-second TTL, so **re-seed before a gate
sweep** or the gates fail on expiry — which looks exactly like a regression
and is not one:

```bash
docker compose up -d postgres redis opa keycloak
scripts/run_local.sh
cd backend && python3 ../scripts/seed_credentials.py
python3 ../scripts/provision_mcp_clients.py      # Phase 8 OAuth clients
python3 ../scripts/phase9_e2e.py
```

Do **not** run the pytest suite concurrently with a gate sweep: both use the
same OPA instance, and one test deliberately removes a policy data document
to prove fail-closed behaviour.

---

## 8. Dependency status

**Unchanged.** `requirements.txt` was not modified in Phase 8 or Phase 9, and
no installed package version moved.

```
pydantic 2.10.4   anyio 4.7.0   starlette 0.41.3   fastapi 0.115.6   httpx 0.28.1
```

The MCP SDK remains deliberately absent (it requires `pydantic>=2.12`); the
protocol subset is implemented directly. See `PHASE_8_ARCHITECTURE.md` §2.

---

## 9. Deployment readiness

### Ready

- Migrations run forward and backward cleanly; schema matches the models with zero drift.
- Compose has healthchecks, ordered `depends_on`, and restart policies.
- Migrations run automatically on container start.
- Secrets are not in the repository: `.env`, keystores and `*.key.json` are gitignored and untracked.
- The development master key **cannot** be used when `ENV=production`.
- Five security switches cannot be turned off at all.
- Production now requires HTTPS on every security-critical URL.
- `/health` and `/ready` exist and are used by compose.

### Not ready

- **TLS is not configured anywhere.** The guard added in this phase forces an operator to supply https URLs, but terminating TLS is still their job.
- **The read API is unauthenticated** (§4, HIGH).
- **No rate limiting** (§4, MEDIUM).
- **CORS is hardcoded** (§4, MEDIUM).
- Verifiable presentations are replayable (§4, MEDIUM).
- Redis is an unused hard startup dependency (§4, LOW).
- No backup, restore or key-rotation runbook.
- No log aggregation, metrics or alerting.
- Keycloak runs in dev mode in compose.
- Capacity, load and failover behaviour are unmeasured.

### Production checklist

1. Terminate TLS; set every URL to its https public name.
2. Set `ENV=production` and a real `KEYSTORE_MASTER_KEY` (32 random bytes, base64).
3. Put authentication in front of the read API (§4).
4. Add rate limiting at the ingress.
5. Make CORS origins configuration.
6. Run Keycloak in production mode with a real database and TLS.
7. Replace the demo loan/payment fixtures with real integrations.
8. Establish keystore backup and a key-rotation procedure.
9. Add log aggregation, metrics and alerting on the fail-closed reasons.
10. Consume presentation challenges, or remove the presentation endpoint.
11. Wire up Redis or drop it from `depends_on`.
12. Commission an independent security review. **Nothing in this repository substitutes for one.**

---

## 10. Honest limits

- **This does not provide legal non-repudiation.** Ed25519 signatures over canonical JSON establish that a key signed a payload. Binding a key to a legal person requires a trust framework this POC does not implement.
- **MCP conformance is a documented subset**, proven by a spec-quoting test suite and **not** by interoperability testing against a third-party MCP client. That remains the largest single gap in the protocol evidence.
- **The threat model assumes an honest infrastructure operator.** Anyone with database or keystore access defeats these controls.
- **No formal verification.** The Rego policies are tested, not proven.
- **Single-region, single-instance.** No HA, no failover, no disaster recovery.
- **Cryptography has not been independently reviewed.**

---

## 11. Where to read further

| Document | Covers |
|---|---|
| `README.md` | running the system |
| `docs/ARCHITECTURE.md` | component architecture |
| `docs/SECURITY_MODEL.md` | the security model |
| `docs/PHASE_STATUS.md` | per-phase status, gaps and gate history |
| `docs/PHASE_7_ARCHITECTURE.md` | A2A design |
| `docs/PHASE_8_ARCHITECTURE.md` | MCP design and conformance matrix |
| **this document** | final integration, findings, release readiness |
