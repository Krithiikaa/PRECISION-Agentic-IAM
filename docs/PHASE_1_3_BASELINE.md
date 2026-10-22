# Phase 1–3 baseline checkpoint

**Captured:** 2026-08-30
**Purpose:** a frozen, verifiable record of the system as it stands after the
Phase 2/3 audit and hardening pass, taken *before* any Phase 4 work begins.

**No Phase 1, Phase 2 or Phase 3 source file was modified to produce this
checkpoint.** It is an observation, not a change.

---

## 1. Phase status

| Phase | Status |
|---|---|
| **PHASE 1** | **COMPLETE** |
| **PHASE 2** | **COMPLETE + HARDENED** |
| **PHASE 3** | **COMPLETE + VERIFIED** |

**Phase 1 — COMPLETE.** Agent runtime, registry, DID identity, Ed25519, DID
Documents, PostgreSQL persistence, agent lifecycle, operator CLI. Seven agent
identities, each holding its own private key; the registry cannot sign on their
behalf and returns an error saying so.

**Phase 2 — COMPLETE + HARDENED.** Verifiable Credentials: real issuing
authorities with their own keys, signed credentials, independent verification
across eight separate checks, revocation, expiry, and presentations with holder
proof. Hardened during the 2026-08-30 audit by three additive, backwards-compatible
changes: proof-purpose separation (S-1), audience binding (S-2), and verification
correlation (S-3).

**Phase 3 — COMPLETE + VERIFIED.** Agent Naming Service as a separate process
with a durable PostgreSQL registry, cryptographically authenticated registration,
capability- and credential-aware discovery, observed liveness, and a coordinator
with no endpoint table. Audited on 2026-08-30; **no Phase 3 source file was
modified**, and no defect was found that warranted modifying one. One known
authorization gap is recorded below as S-4.

---

## 2. Source revision

> **There is no git repository at this path.** `.git` does not exist and
> `git rev-parse` fails with *"not a git repository"*. **No commit hash can be
> recorded**, and none has been invented.
>
> A repository was **not** initialised, because doing so was outside what this
> checkpoint asked for. If you want this baseline pinned to a real commit, run
> `git init && git add -A && git commit` and re-record §2 — everything else in
> this document stays valid.

In place of a commit hash, a deterministic content fingerprint over the
**executable source** is recorded so the baseline is still pinnable:

| | |
|---|---|
| **Fingerprint** | `11d774c686155a82d9f5cab51495fca05407d3c0c665c06f2c5b131e21a0007c` |
| Algorithm | `sha256` over the sorted per-file `sha256sum` list |
| Files covered | **106** |
| Scope | `backend/app`, `backend/tests`, `backend/alembic`, `scripts` — `*.py` and `*.sh`, excluding `__pycache__` |

Reproduce with:

```bash
find backend/app backend/tests backend/alembic scripts -type f \
  \( -name '*.py' -o -name '*.sh' \) \
  -not -path '*__pycache__*' | sort | xargs sha256sum | sha256sum
```

**Documentation is deliberately excluded from the fingerprint.** This document
lives in `docs/`, so including `docs/*.md` would make the fingerprint reference
itself and be unreproducible. Excluding docs also means the source baseline
stays valid when documentation is edited — which is the property that actually
matters for pinning an implementation.

---

## 3. Test count

Full suite, run for this checkpoint against a real PostgreSQL:

| | Count |
|---|---:|
| **Collected** | **247** |
| **Passed** | **246** |
| **Failed** | **0** |
| **Skipped** | **1** (environmental — see below) |
| Errors | 0 |

### Per file

| File | Tests |
|---|---:|
| `test_ans_api.py` | 10 |
| `test_ans_discovery.py` | 24 |
| `test_ans_lifecycle.py` | 17 |
| `test_ans_registration.py` | 23 |
| `test_api.py` | 12 |
| `test_credential_issuance.py` | 20 |
| `test_credential_presentation.py` | 22 |
| `test_credential_verification.py` | 34 |
| `test_credentials_api.py` | 18 |
| `test_did.py` | 14 |
| `test_identity_crypto.py` | 14 |
| `test_llm_provider.py` | 8 |
| `test_registry.py` | 16 |
| `test_runtime.py` | 8 |
| `test_wallet.py` | 7 |
| **Total** | **247** |

### The one skipped test — reported, not worked around

```
SKIPPED [1] tests/test_llm_provider.py:79: Host cannot load llama3:latest:
MODEL_CANNOT_LOAD: the host does not have enough free memory to load
'llama3:latest'. Ollama said: {"error":"model requires more system memory
(4.6 GiB) than is available (3.4 GiB)"}
```

This is the resource-heavy live-Ollama test. It was **not run to completion and
not modified, disabled, mocked or marked xfail** — it detects the constraint
itself and skips loudly rather than passing against a fake. The host is a 6 GiB
machine with roughly 1 GiB free; the model needs 4.6 GiB.

**This is environmental, not a code defect.** The same test *passed* earlier in
the same session, before memory pressure rose. On a host that can load the model,
the expected result is **247 passed, 0 skipped**.

Command used:

```bash
cd backend && set -a && . ../.env && set +a
.venv/bin/python -m pytest tests -q -rs
```

---

## 4. Security test count

**103 security-relevant tests, 103 passing, 0 failing.**

Selected by name across the suite (tampering, expiry, revocation, holder proof,
challenge, domain, subject binding, spoofing, endpoint substitution, capability
escalation, nonce replay, self-issuance, stolen credentials, malformed input,
terminated/suspended identity, stale liveness):

```
103 passed, 144 deselected
```

These are genuinely adversarial tests — they perform real attacks and assert
they fail — not happy-path coverage. Representative properties held at this
baseline:

| Property | Held |
|---|---|
| Signature tampering fails | ✅ |
| Expired credential fails (by real elapsed time) | ✅ |
| Revoked credential fails, signature still valid | ✅ |
| Wrong holder proof fails | ✅ |
| Stolen credential presented by another agent fails | ✅ |
| Wrong challenge fails | ✅ |
| Wrong audience fails when `expected_domain` supplied | ✅ |
| Agent cannot self-issue a credential | ✅ |
| Spoofed ANS registration rejected, real endpoint untouched | ✅ |
| Endpoint substitution breaks the registration proof | ✅ |
| Capability escalation breaks the registration proof | ✅ |
| Registration nonce cannot be replayed | ✅ |
| Stale credential index cannot smuggle a revoked credential | ✅ |
| Heartbeat cannot move an agent's endpoint | ✅ |
| Terminated / suspended identity excluded from discovery | ✅ |

---

## 5. Current Phase 3 status

**COMPLETE + VERIFIED.** Audited 2026-08-30; **zero source changes made.**

| Mechanism | State |
|---|---|
| Cryptographic registration | ✅ Signed payload binds did · endpoint · capabilities · organization · nonce · timestamp, plus `proofPurpose: "ansRegistration"` for domain separation |
| Public key resolution | ✅ From the published DID Document — ANS keeps no second copy and cannot disagree with the identity authority |
| Endpoint binding | ✅ Inside the signed payload; a captured signature cannot be re-pointed |
| Nonce single-use | ✅ Partial unique index on `(agent_did, nonce) WHERE accepted` — failed attempts cannot burn a victim's nonces |
| Timestamp freshness | ✅ ±300s window |
| Capability discovery | ✅ SQL index narrowing, per-candidate explanations for matches and rejections |
| Credential-aware discovery | ✅ Re-verified **live** by the Phase 2 verifier on every query; the index is never a verdict |
| Deterministic ranking | ✅ `(-score, did)` — no randomness, no ML, nothing favouring a particular agent |
| No fallback | ✅ Unsatisfied queries return empty with `NO_MATCHING_AGENT` |
| Observed liveness | ✅ Sweeper demotes ACTIVE → STALE → OFFLINE; prober calls each `/health` |
| Heartbeat cannot move endpoint | ✅ Requires a fresh signed registration |
| Heartbeat / audit separation | ✅ All heartbeats persisted to `ans_heartbeats`; only status *changes* become audit events |
| Identity mirroring | ✅ Terminated/suspended identities are demoted in the registry |
| Coordinator routing | ✅ No endpoint table, no `RISK_AGENT_URL`, no keyword fallback; DID-Document cross-check of every ANS answer |
| Discovery ≠ authorization | ✅ Asserted in the service description, the registry, the discovery engine and every coordination response |
| Trust score | ✅ `NULL` until Phase 10 — no default invented; `min_trust_score` excludes unscored agents |
| Multi-process event flow | ✅ ANS → `audit_events` → monotonic `seq` → SSE |
| **Authorization of ANS operations** | ⚠️ **absent — see S-4 and gap 2 below** |

---

## 6. Known gaps

**None of these were fixed during this baseline step. They are recorded, not
addressed.**

### 1. S-4 — unauthenticated ANS heartbeat — **HIGH — DEFERRED**

`POST /api/v1/ans/heartbeat` accepts a bare DID with no signature. Behaviour is
**fail-open**:

```
unauthenticated heartbeat → liveness refreshed → agent remains discoverable
```

An attacker reaching the endpoint may keep an **unavailable agent discoverable**
(so the coordinator routes work to a dead endpoint), flip a healthy agent to
`DEGRADED`/`BUSY` to push it out of discovery, or report false load to
manipulate ranking.

**Bounded — not a takeover.** `heartbeat()` refuses to move the endpoint, so
traffic cannot be redirected without a valid signed registration, and the
coordinator independently cross-checks the endpoint against the DID Document.
Impact is denial-of-service and misrouting, not impersonation.

Deferred to authorization / control-plane hardening.

### 2. ANS query and deregistration authorization — **HIGH — DEFERRED**

`POST /discover`, `POST /unregister/{did}`, `GET /resolve/{did}`, `GET /agents`,
`GET /capabilities` and `POST /sweep` require no authentication. Anything that
can reach :8100 can enumerate the network or take any agent offline.
`requester_did` on a discovery query is an unverified claim, recorded as-is.

### 3. Human principal model — **ABSENT BY DESIGN**

Every DID is `did:poc:agent:*` or `did:poc:organization:*`, and `is_agent_did()`
gates ANS registration on the agent form. **Humans are not modelled at all.**
There is no human identity type, no Keycloak integration, no OIDC, no SAML and
no approval artifact. This is a prerequisite for HITL, documented as design only
in [HITL_READINESS.md](HITL_READINESS.md).

### 4. Presentation replay protection — **PARTIAL**

Challenges are generated and compared but **not recorded as used**, so a captured
presentation can be replayed against a verifier that reuses or omits a challenge.
`GET /api/v1/credentials/challenge` reports this honestly as
`"single_use_enforced": false`.

Audience binding (S-2, fixed) narrows a replay to a single audience; it does not
eliminate it. Single-use nonce storage needs cross-process shared state — the
Session State Synchroniser, Phase 9. **This is a hard prerequisite for any future
approval artifact**, because an approval that can be replayed is not an approval.

### 5. Audit-event integrity protection — **ABSENT**

`audit_events` is append-only **by convention only**. There is no hash chain, no
per-event signature and no external anchoring. Anything with database write
access can rewrite or delete history, including records of its own actions. The
monotonic `seq` provides ordering and gap detection, **not integrity**.
Phase 10.

### 6. Issuance / revocation authentication — **ABSENT**

`POST /credentials/issue` and `POST /credentials/{id}/revoke` are
unauthenticated. Anything that can reach the API can mint a credential from any
registered authority or revoke any credential.

**The key-custody boundary still holds:** issuer private keys never leave the
KeyStore and no agent holds one, so an agent still cannot mint a credential
about itself — a test performs that attack and asserts it fails
`ISSUER_UNKNOWN`. The gap is *access to the issuing service*, not key
compromise.

Also unauthenticated: `POST /api/v1/audit/events` (telemetry ingest from agent
processes). An event's `agent_did` is a claim, recorded with
`"unauthenticated": true`.

### 7. Live restart test — **CURRENTLY UNVERIFIED**

`scripts/phase1_restart_test.sh`, `phase2_restart_test.sh` and
`phase3_restart_test.sh` were **not executed** for this baseline. They require
the full stack, and only `postgres`, `redis` and `iam-api` are running (§8) —
the ANS service and the seven agent processes are down, and starting seven
LLM-backed agents on a host with ~1 GiB free would not have produced a
trustworthy result.

**Persistence is verified at the database level**: the entire 247-test suite runs
against a real PostgreSQL, and registration proofs, capability indexes and
discovery request/result rows are written and read back. But the live
cross-restart path is **reported as unverified rather than claimed**.

---

## 7. Database migration state

**Current revision: `22709fe1158d` (head). Up to date — no pending migrations.**

Verified against the live development database:

```
$ psql -U iam -d agentic_iam -tAc "select version_num from alembic_version;"
22709fe1158d
```

### Migration chain

| Order | Revision | down_revision | Description |
|---:|---|---|---|
| 1 | `154273d0644b` | `None` | phase1 agent identity plane |
| 2 | `74a919455a7a` | `154273d0644b` | phase2 verifiable credentials |
| 3 | **`22709fe1158d`** ← **head / current** | `74a919455a7a` | phase3 agent naming service |

**No migration was added by the Phase 2 hardening pass** — S-1, S-2 and S-3 were
all behavioural and required no schema change. S-3 populates
`credential_verification_events.presentation_id`, a column that already existed
in the Phase 2 migration.

### Schema — 18 tables in `agentic_iam`

| Group | Tables |
|---|---|
| Phase 1 — identity | `agents`, `agent_keys`, `agent_relationships`, `did_documents` |
| Phase 2 — credentials | `issuer_identities`, `credentials`, `credential_status`, `credential_presentations`, `credential_verification_events` |
| Phase 3 — ANS | `ans_agents`, `ans_capabilities`, `ans_agent_credentials`, `ans_heartbeats`, `ans_registration_proofs`, `ans_discovery_requests`, `ans_discovery_results` |
| Cross-cutting | `audit_events` |
| Alembic | `alembic_version` |

### Databases

| Database | Purpose | Migration state |
|---|---|---|
| `agentic_iam` | development | Alembic, at `22709fe1158d` |
| `agentic_iam_test` | test suite | **No `alembic_version` table** — by design |
| `postgres` | admin | — |

The test database is built with `Base.metadata.create_all()` per session rather
than by Alembic, so it carries no revision stamp. The suite hard-refuses to run
unless the target database name ends in `_test`, because it calls `drop_all`.

---

## 8. Service topology

### Defined in `docker-compose.yml` — 11 services

| Service | Port | Role |
|---|---|---|
| `postgres` | 5433 → 5432 | PostgreSQL 16, durable state for all phases |
| `redis` | 6380 → 6379 | Running but **unused** — Phase 9 writes to it |
| `iam-api` | 8000 | Identity + credential plane; serves the SSE stream |
| `ans` | 8100 | Agent Naming Service — own process, own lifecycle, sweeper + prober |
| `coordinator-agent` | 9001 | COORDINATOR — `coordinator-001` |
| `kyc-agent` | 9002 | KYC — `kyc-001` |
| `risk-agent` | 9003 | RISK — `risk-001` |
| `fraud-agent` | 9004 | FRAUD — `fraud-001` |
| `decision-agent` | 9005 | DECISION — `decision-001` |
| `risk-agent-2` | 9006 | RISK — `risk-002` |
| `risk-agent-3` | 9007 | RISK — `risk-003` |
| `frontend` | 5173 | React console — discovery, credentials, agents, live trace |

Plus an external dependency: **Ollama** on 11434 (host), reached from containers
via `host.docker.internal`.

### Actually running at capture time — 3 of 11

```
agentic-iam-iam-api-1     agentic-iam-iam-api   Up 4 hours (healthy)   0.0.0.0:8000->8000
agentic-iam-postgres-1    postgres:16-alpine    Up 4 hours (healthy)   0.0.0.0:5433->5432
agentic-iam-redis-1       redis:7-alpine        Up 4 hours (healthy)   0.0.0.0:6380->6379
```

**Not running:** `ans`, all seven agent services, `frontend`. This is why the
live restart tests are reported as unverified (gap 7). The 247-test suite does
not need them — it exercises ANS and agent logic in-process against the real
database.

### Data flow

```
7 agent processes ──signed registration──►  ANS :8100  ──┐
        │                                                │
        │ heartbeat (⚠ unauthenticated — S-4)            │
        ▼                                                ▼
   IAM API :8000  ◄──DID Document cross-check──   coordinator
        │                                          (no endpoint table)
        └──────────────► audit_events (monotonic seq) ──► SSE ──► browser
                              ▲
                              └── written by all nine processes
```

### Host / container `localhost` distinction

Documented in `docker-compose.yml` and unchanged. Under compose, an agent
advertises a service name (`AGENT_PUBLIC_URL=http://risk-agent:9003`); on a host
run it advertises `http://localhost:9003`. A container probing `localhost` would
probe **itself**, so container-to-container traffic must use service DNS. This is
configuration, not a bug.

---

## 9. What this baseline pins

| Item | Value |
|---|---|
| Phase 1 | COMPLETE |
| Phase 2 | COMPLETE + HARDENED |
| Phase 3 | COMPLETE + VERIFIED |
| Source revision | no git repo — code fingerprint `11d774c6…007c` over 106 files |
| Tests collected | 247 |
| Tests passing | 246 (1 environmental skip) |
| Tests failing | 0 |
| Security tests passing | 103 |
| Migration head | `22709fe1158d` |
| Schema | 18 tables |
| Services defined / running | 11 / 3 |
| Open gaps | 7, listed in §6 |
| Next phase | **Phase 4 — PDP / PIP / PAP, OPA + Rego, AEM** |

**Nothing in Phase 1, 2 or 3 was modified to produce this checkpoint.** No gap
listed in §6 was fixed. Phase 4 has not been started.

### Related documents

| | |
|---|---|
| [../PHASE_2_3_AUDIT.md](../PHASE_2_3_AUDIT.md) | the audit: findings S-1…S-4, fixes, deferrals |
| [PHASE_STATUS.md](PHASE_STATUS.md) | per-phase breakdown of what runs and what does not |
| [HITL_READINESS.md](HITL_READINESS.md) | design only — future human-approval plane |
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | key custody, trust chain, threat model |
