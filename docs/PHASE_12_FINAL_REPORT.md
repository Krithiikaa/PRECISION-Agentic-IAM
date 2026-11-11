# Phase 12 — Containment, enterprise security hardening and final framework completion

**Final numbered phase.** No Phase 13 is planned. This report states what was built, how it was verified, what is still external, and what risk remains. Requirement-level detail is in [REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md); the CSA framework assessment is in [FRAMEWORK_COMPLETION_REPORT.md](FRAMEWORK_COMPLETION_REPORT.md).

**Readiness verdict.** The POC is functionally complete against the feasible scope of the CSA framework and the workflow blueprint, and every Phase 12 control is verified by automated tests and live runs (§5). It is **not production-ready**: independent security review, HSM/KMS, production TLS/mTLS, a DPIA and production infrastructure remain **BLOCKED_EXTERNAL** (§4). Implemented functionality, infrastructure readiness and independent assurance are three different things; only the first is claimed.

---

## 1. Baseline, re-verified before changing anything

| Reported baseline | Found |
|---|---|
| Phases 1–10 closed, Phase 11 console live | Confirmed in code and docs |
| 1,520 passed / 0 failed / 1 skipped | Taken as the reference; re-measured in §5 |
| Audit trail not tamper-evident | Confirmed: single write path (`AuditRepository.record`), no integrity data |
| Loan workflow state in memory | Confirmed: `_WORKFLOWS`, `_DOCUMENTS` and workflow applications were module dicts |
| Agents/ANS hard-code CORS | Confirmed: `app/agents/service.py`, **and also `app/ans/service.py`** (not previously reported) |
| — | **Live finding:** `coordinator-001` had been auto-contained at 11:36 the same day. Root cause in §2-F (defect P12-6) |

## 2. Gap assessment and what was done

### A. Containment and emergency response

The kill switch already locked out the SSS ledger (enforced by the PDP on every protocol), suspended the identity, revoked JIT mandates, MCP sessions and the ANS entry, and cascaded to children. Bypass-oriented inspection found:

| # | Defect | Fix | Location | Test |
|---|---|---|---|---|
| P12-1 | An APPROVED-but-unspent human approval survived containment and was **spendable after reinstatement** | Containment cancels PENDING and APPROVED approvals in one conditional UPDATE (race-safe against `consume`). A separate `CONTAINMENT_TRANSITIONS` set; operators still cannot cancel a decided approval | `app/hitl/service.py::cancel_for_agent`, `app/sessions/authority.py` step 5b | T-P12C `TestApprovalsDoNotOutliveContainment` (5) |
| P12-2 | A PENDING approval could be approved by a human during the incident | Same | same | same |
| P12-3 | A cascade-contained child could be **reinstated while its parent was still contained** | Reinstatement runs a trust revalidation first: not terminated, not expired, ≥1 ACTIVE key, no inactive or locked-out ancestor. Refusals are audited with the check results | `SessionAuthority.revalidate` | T-P12C `TestReinstatementRevalidatesTrust` (5) |
| P12-4 | Reinstatement re-activated an identity without re-checking key or expiry | Same | same | same |

Unauthorized invocation was re-tested: anonymous, an agent containing or reinstating, the contained agent reinstating itself or spawning a child to escape, and the same administrator undoing their own containment are all refused (T-P12C `TestContainmentCannotBeInvokedOrUndoneByTheWrongParty`, 5). No second containment authority was introduced: the Session Authority calls each module's existing revocation method, and the PDP remains the only decider.

### B. Tamper-evident audit trail

Design (full rationale in `backend/app/audit/integrity.py`):

| Mechanism | What it detects | Where |
|---|---|---|
| **Write-time HMAC-SHA256** per row (key derived by HKDF from the keystore master key; never in the DB) | Rows inserted or edited by someone with DB access but not the key — **before and after sealing** | `AuditRepository.record`, `audit_events.integrity_mac` |
| **SHA-256 hash chain** in a separate append-only table; entry N commits to N-1 and to the canonical event (seq, timestamp, fields, metadata, MAC) | Modification, deletion, reordering, insertion of sealed rows | `audit_chain`, `AuditChain.seal` |
| **Ed25519-signed checkpoints** (≤30 s apart), verified against the keystore key or an auditor-pinned key, never a key read from the DB | Whole-chain rewrite after an edit; tail truncation | `audit_checkpoints` |
| **Append-only trigger** on all three tables | Ordinary UPDATE/DELETE (not the table owner — the chain covers that) | migration `d12a0c4e7b51` |

- **Concurrency.** One sealer chains rows *after* they commit, under `pg_advisory_xact_lock`, in a short transaction with no I/O; UNIQUE constraints turn any race into an error rather than a fork. Chain order is sealing order; a late-committing transaction is chained late, never skipped (per-tick seq look-back plus a periodic full sweep). Chaining at insert time was rejected: it would serialise every transaction that writes audit — including ones waiting on OPA or Keycloak — behind one lock until commit.
- **Genesis and backfill.** The migration's genesis records `covers_from_seq` = first post-migration seq. On the development host **710,340 legacy rows are outside coverage and reported as such** on every verification; sealing them would have attested only to their state today.
- **Restart.** The chain is in PostgreSQL and the key in the keystore; the sealer resumes from the head and runs a full sweep at start-up.
- **Signal.** A failed verification writes `AUDIT_INTEGRITY_VIOLATION` and a CRITICAL, unattributed `AUDIT_INTEGRITY` alert (de-duplicated per finding set). Runbook §5a.
- **Independent verification.** `scripts/verify_audit_chain.py` runs outside the API, read-only, with a pinned key and optional externally retained checkpoints.
- **API.** `GET /api/v1/audit/integrity`, `GET /api/v1/audit/integrity/checkpoints` (both `audit_read`). Existing audit APIs, export and event semantics are unchanged.

**Defect found by the tests (P12-5):** a lazily created genesis started coverage at the smallest *committed* seq, so a transaction in flight holding a lower seq would have been outside coverage for ever. Fixed (lazy genesis covers from seq 1); regression `test_a_transaction_that_commits_late_is_chained_late_not_skipped`.

**Not claimed:** immutable or legally compliant storage. Residuals in §6.

### C. Durable enterprise loan workflow

PostgreSQL tables (migration `e12c5f9a3d20`): `loan_applications`, `loan_documents`, `loan_workflows`, `loan_workflow_transitions`. The existing protected tools, AEM path and coordinator runner are unchanged in shape — no second workflow engine.

| Property | Mechanism |
|---|---|
| Persist state and transitions | Every change is a `loan_workflow_transitions` row **and** a `LOAN_WORKFLOW_TRANSITION` audit event with the AEM request id |
| HITL approvals survive restart | Approval binding stored on the workflow; approvals were already durable |
| No double processing | Claim = `SELECT … FOR UPDATE SKIP LOCKED` + a lease (token, expiry) |
| Stale run cannot overwrite | Outcome recording requires the lease token (fencing token) |
| Safe retries | An identical record by the same token is answered as an idempotent replay |
| No duplicate decision | `UPDATE … WHERE status='AWAITING_DECISION'`; a second decision is refused |
| Recovery without repetition | A re-claimed workflow whose application is already decided is recorded (`recovered: true`), never re-decided |
| Idempotent submission | Optional `Idempotency-Key`, unique per officer; same key + different body = 409 |
| Atomic with the audit | Durable tools write through the **AEM's own session** inside a SAVEPOINT; a failing handler leaves nothing behind |
| Authenticated actor | `session`, `request_id`, `subject_did` are injected by the AEM from the grant; callers cannot supply them; the recorded coordinator must be the caller |
| Authorization | Unchanged: tools via AEM/PDP; reads via `loan_read` (new `GET …/{id}/transitions` likewise) |

Synchronous authorization-path readers (PIP material attributes, approval binding, maker-checker) need the amount and officer of record. These **immutable** facts are cached write-through and, on a miss (restart, other worker), loaded by a short synchronous read; mutable state is only read from the DB. **Defect closed with it (P12-7):** maker-checker only fires when the officer of record is known; the hard stop now **fails closed** when it cannot be established (`MAKER_CHECKER_RESOURCES`).

Scope boundary: the Phase 4–7 demonstration fixtures (`loan-2201`, `pay-3310`, …) stay in memory — the gates reset and tamper with them by design. Payment executions are therefore not durable across restarts; A2A exactly-once is per transaction in the durable A2A ledger. No workflow step moves money.

### D. CORS

One validated configuration (`Settings.cors_middleware_options`) for the IAM API, the ANS and all nine agents. Every origin must be an exact `scheme://host[:port]` in every environment; `*` with credentials is refused everywhere; `*` is refused outright in production (previously allowed without credentials); production requires https. Agents no longer allow `*` methods/headers. Tests: T-CORS (20).

### E. Session and trust-state synchronisation

A matrix of stale-state scenarios was run against the real PDP/OPA/AEM (T-ST). Revoked credential, suspended/terminated/expired identity, a live JIT mandate after suspension, an approval after suspension (refused and **not burned**), approval bound to the exact resource, and OPA unreachable (fails closed) were already correct. **One real gap (P12-8):** a delegated child kept working when its parent was suspended, terminated, expired or locked out by any route other than containment. Fixed per the invariants: the PIP gathers the delegation chain (`subject.delegation`), `security/session.rego` v2 decides (`DELEGATION_CHAIN_INACTIVE`).

### F. Live operational defect

**P12-6.** `coordinator-001` was auto-contained because its 1-hour demo credential lapsed and the runner retried the claim every 5 s: 88 `CREDENTIAL_EXPIRED` denials, denial bursts, trust 25, automated containment. The detector was right; the runner was wrong. Fix: exponential back-off on refused claims (capped at 300 s), provably below the denial-burst threshold (`TestRefusalBackoff`, 3). The incident was reinstated through the API by a different principal with a written review; the new revalidation passed all four checks.

**P12-9 (test-harness defect, found by a failed gate sweep).** `run_gates.sh` and the first version of `phase12_restart_test.py` killed only the PID recorded in `.run/iam-api.pid` and then accepted *any* healthy answer on :8000. A normal-profile API (detector on) left running by the restart test therefore survived: the first gate sweep ran against it, the detector correctly contained `risk-001` mid-sweep, and gates 5.5, 6, 7 and 9 failed. The same flaw meant one restart-test run passed **without a real restart**; that result was discarded. Both harnesses now stop whatever actually holds the port, require it free, and verify that the listener is the newly started PID (the restart test prints old → new PID). `risk-001` was reinstated through the API by a different principal with a written review; no security table was edited by hand.

## 3. Requirement status

| Requirement | Implementation | Evidence | Tests | Status |
|---|---|---|---|---|
| Server-side containment of a compromised agent | `app/sessions/authority.py::contain` | Live E2E-E; incident reinstated in this phase | T-TC, T-P12C | COMPLETE |
| Containment stops outstanding access (sessions, grants, approvals) | contain steps 2–5b | approvals_cancelled in report | T-P12C (5), T-TC | COMPLETE |
| Revocation/deactivation effective on all enforcement paths | PIP + `credential_state.rego`, `session.rego` | — | T-ST (12), T-TC | COMPLETE |
| Containment attributable, auditable, resistant to unauthorized invocation | ControlPlaneGuard + Rego; INCIDENT_* events | — | T-P12C (5), T-TC `TestSecurityAPI` | COMPLETE |
| Recovery requires authorized action + trust revalidation | `reinstate` + `revalidate` | live reinstatement output | T-P12C (5) | COMPLETE |
| Emergency ops cannot bypass HITL / dual control | approvals cancelled, not auto-approved; reinstatement needs a different principal | — | T-P12C, E2E-C | COMPLETE |
| Tamper-evident audit (chain, verification, signal) | `app/audit/integrity.py`, `chain.py`, migration `d12a0c4e7b51` | live chain VERIFIED; standalone verifier exit 0 | T-AI (35), RT12 | COMPLETE (tamper-evident; not immutable) |
| Durable workflow, restart survival | `app/banking/store.py`, migration `e12c5f9a3d20` | RT12 18/18 | T-DW (23), T-LW (37) | COMPLETE |
| Concurrency, retry, idempotency, no duplicate decision | leases, fencing token, conditional UPDATE, Idempotency-Key | — | T-DW | COMPLETE |
| Durable payment instructions (Phase 7 demo fixtures) | in memory by design | — | — | PARTIAL (out of workflow scope) |
| CORS from configuration, restrictive | `Settings.cors_middleware_options` | — | T-CORS (20) | COMPLETE |
| Session/trust synchronisation | PIP delegation fact, `session.rego` v2 | — | T-ST | COMPLETE |
| Kill-switch playbook, disclosure policy | Runbook §5b, `SECURITY.md` | — | — | PARTIAL (owner/rehearsal EXT) |
| Independent security review / pen test | — | — | — | BLOCKED_EXTERNAL |
| HSM / KMS | `KeyStore` interface ready; procedure in PRODUCTION_DEPLOYMENT | — | — | BLOCKED_EXTERNAL |
| Production TLS / mTLS | https enforced by config; procedure + evidence list documented | — | `test_production_configuration.py` | BLOCKED_EXTERNAL |
| DPIA | data inventory in FRAMEWORK report §9 | — | — | BLOCKED_EXTERNAL |
| Production infrastructure, backup/DR approval, load test | runbook | — | — | BLOCKED_EXTERNAL |
| Remaining CSA items (ANS signing, token exchange, DPoP, ML detection, ZKP…) | — | — | — | NOT_APPLICABLE to this phase / DEFERRED, see FRAMEWORK §13 |

## 4. External dependencies

| Dependency | Code-side preparation | Integration procedure | Evidence required | Status |
|---|---|---|---|---|
| Independent security review | Threat matrix, test inventory, this report | Engage a reviewer; scope = this repo + deployment | Signed report; findings tracked to closure | BLOCKED_EXTERNAL |
| HSM/KMS | All signing behind `KeyStore`; audit MAC root is the master key | PRODUCTION_DEPLOYMENT "HSM / KMS" | Non-exportable keys; suites pass against HSM store | BLOCKED_EXTERNAL |
| TLS / mTLS certificates | `ENV=production` refuses http; no verify bypass exists | PRODUCTION_DEPLOYMENT "mTLS and certificates" | `openssl s_client` verification; unauthenticated client refused | BLOCKED_EXTERNAL |
| DPIA | Synthetic data only; minimisation enforced | DPO-led assessment | Signed DPIA | BLOCKED_EXTERNAL |
| Production infra, backup, approvals | Runbook §2 backup/restore verified locally | Operator rehearsal | DR rehearsal record, RPO/RTO | BLOCKED_EXTERNAL |

Nothing here is simulated: no HSM stub, no fake review, no "production-ready TLS" claim.

## 5. Validation results

All measured on 2026-11-11 on the 7 GiB development host, sequentially (never two suites at once). Nothing is copied from earlier reports.

| # | Validation | Result | Notes |
|---|---|---|---|
| 1 | Audit integrity incl. deliberate tampering | **35/35** (T-AI) | modification, deletion, reorder, insertion, chain rewrite, truncation, forged signer, concurrency, restart, standalone verifier |
| 2 | Containment and recovery | **15/15** (T-P12C) + existing T-TC | bypass attempts included |
| 3 | Revocation and session invalidation | **12/12** (T-ST) | |
| 4 | Durable workflow restart/recovery | **23/23** (T-DW); live **RT12 18/18** | listener PID changed 644573 → 645352 (a real restart) |
| 5 | Concurrency, retry, idempotency | in T-DW | separate DB connections decide winners |
| 6 | CORS allow-list and rejection | **20/20** (T-CORS) | |
| 7 | HITL and dual-control regression | in full suite + gates 5, 5.5 | |
| 8 | A2A and MCP regression | in full suite + gates 7, 8 | |
| 9 | Phase 1–9 gates (`scripts/run_gates.sh`, gate profile: detector off, rate limiting **on**) | **all 11 passed**: 12, 30, 33, 31, 46, 68, 110, 113, 132, 38, 35; no incidents opened | Phase 3 = 33 not 40: its LLM-routing section **skipped** (`MODEL_CANNOT_LOAD`) — not passed |
| 10 | Loan workflow E2E, **normal profile** (detector on, rate limiting on, every control) | **33/33** | |
| 11 | Console browser regression | **31/31** | against the running dev server on :5173 |
| 12 | Full backend suite | **1,613 collected · 1,612 passed · 0 failed · 1 skipped** | skip = `test_llm_provider::test_real_generation`, only on `MODEL_CANNOT_LOAD` (needs 4.6 GiB, 3.2 GiB free) |
| — | Standalone audit verifier on the live DB | **VERIFIED** | 710,340 legacy events reported outside coverage |

**Gate profile vs production validation.** The detector is off only in the documented gate profile (the gates attack as `risk-001` by design; production refuses the setting). Production-like validation — the loan E2E and RT12 — ran with every control on.

**Not run / not passed:** the live LLM generation test and Phase 3's 7 LLM-routing checks (host memory); load testing; anything requiring the external parties in §4.

**UI.** See §9: the five Phase 12 console integrations were added afterwards and validated (57/57 new browser checks, 31/31 existing).

## 6. Remaining risks

0. **Local session views trust the Redis push channel.** A forged push can make an agent refuse work locally (denial of service); it cannot grant anything, because the PostgreSQL ledger is read by the PDP on every request. Keep Redis on the trusted segment.

1. **Host / key compromise (High, infrastructural).** Without an HSM, whoever holds `KEYSTORE_MASTER_KEY` and the database can forge audit history *and* sign as any key in the file keystore.
2. **Audit residual windows (Medium).** A row deleted within the ~2 s between commit and sealing leaves no chain trace; truncating the tail together with every later checkpoint is detectable only against an externally retained checkpoint (procedure, not automation).
3. **No independent review.** All assurance is self-produced.
4. **Rule-based detection** with fixed thresholds; slow misuse evades it.
5. **Single-instance services**, no load test.
6. **Demo fixtures in memory** (Phase 4–7 loans and payments) — not workflow state, but a payment fixture's execution count resets on restart.
7. **Gates attack as `risk-001`**, isolated by the documented gate profile (detector off for gates only; refused in production).
8. **1-hour demo credentials** must be re-seeded; with P12-6 fixed, lapse no longer escalates to containment.

## 7. Commands

```bash
scripts/run_local.sh                                  # applies migrations with the stack stopped
cd backend && set -a && . ../.env && set +a
python3 ../scripts/seed_credentials.py && python3 ../scripts/provision_mcp_clients.py
python3 ../scripts/phase12_restart_test.py            # RT12, live restart
python3 ../scripts/verify_audit_chain.py --public-key <pinned> --check-macs
cd .. && scripts/run_gates.sh                         # Phase 1-9 gates + loan E2E
cd backend && python -m pytest -q                     # full suite (not concurrently with gates)
```

## 8. Files

New: `app/audit/integrity.py`, `app/audit/chain.py`, `app/banking/store.py`, `app/db/models/loan.py`, migrations `d12a0c4e7b51`, `e12c5f9a3d20`, `scripts/verify_audit_chain.py`, `scripts/phase12_restart_test.py`, `SECURITY.md`, tests `test_audit_integrity.py`, `test_phase12_containment.py`, `test_durable_loan_workflow.py`, `test_session_trust_sync.py`, `test_cors_configuration.py`.
Changed: `sessions/authority.py`, `hitl/service.py`, `authorization/pip.py`, `policies/security/session.rego` (v2) + manifest, `enforcement/tools.py`, `enforcement/aem.py`, `enforcement/resources.py`, `banking/adapters.py`, `workflows/loan.py`, `db/repositories/audit.py`, `db/models/audit.py`, `core/config.py`, `main.py`, `agents/service.py`, `ans/service.py`, routes `audit.py`, `loan_workflows.py`, `console.py`, `test_loan_workflow.py` (ported to durable API, assertions kept), `.env.example`, runbook, deployment guide, traceability, framework report.


---

## 9. Console integration and final validation (2026-11-11, after §5)

The five Phase 12 capabilities were integrated into the existing console (no new page, no new dependency, CSS animations respecting `prefers-reduced-motion`). Details, endpoints and fields: [OPERATIONS_CONSOLE.md](OPERATIONS_CONSOLE.md) "Phase 12 integrations"; demo: [FINAL_DEMO_GUIDE.md](FINAL_DEMO_GUIDE.md).

| Integration | Page | Endpoint / field |
|---|---|---|
| Audit integrity: verdict, coverage, findings, signed checkpoints; legacy events labelled **OUTSIDE INTEGRITY COVERAGE**, never VERIFIED | Audit & compliance | `GET /api/v1/audit/integrity`, `/integrity/checkpoints` |
| Persisted transition history (actor, request id, RESUMED/RECOVERY/FAILURE) | Loan workflow | `GET /api/v1/loan-workflows/{id}/transitions` |
| Server-confirmed containment incl. `approvals_cancelled` and audit evidence | Threat monitoring | `POST /security/incidents`, `GET /security/incidents/{id}` |
| Reinstatement `revalidation` on success and refusal | Threat monitoring | `POST /security/incidents/{id}/reinstate` (200 or 409) |
| Idempotent submission (key per logical submission, reused on retry) | Loan workflow | `Idempotency-Key` → `idempotent_replay` |

**Defects found during this work, each with a regression test:**

| # | Defect | Fix | Test |
|---|---|---|---|
| P12-10 | A refused reinstatement returned its revalidation results only as a sentence, so no client could show which check failed | Same 409 / `CONFLICT`, plus a structured `revalidation` list (`ReinstatementRefused`) | `test_phase12_containment.py::TestRefusalCarriesTheRevalidation` |
| P12-11 | **The test suite pushed SSS changes on the live channel.** Redis pub/sub channels ignore the database number, and test agents reuse real DIDs: running the backend tests made the live `risk-001` apply a test lockout to its local fast-fail view and refuse work (found when the loan E2E failed one check at `credit_analysis`). The ledger was never affected | The suite uses its own channel (`SSS_CHANNEL` in `tests/conftest.py`); stack restarted to clear the poisoned in-memory view | `test_trust_and_containment.py::test_the_suite_never_pushes_on_the_live_sss_channel` |

**Final validation (after every change above):**

| Test | Passed | Failed | Skipped | Not run |
|---|---:|---:|---:|---:|
| Frontend lint | — | — | — | **1** (no linter configured; none added) |
| Frontend type-check + production build (`tsc -b && vite build`) | 1 | 0 | 0 | 0 |
| Existing console browser suite (13 pages) | 31 | 0 | 0 | 0 |
| New Phase 12 UI browser tests | 57 | 0 | 0 | 0 |
| Backend affected tests (containment, security matrices, route inventory, read authorization) | 163 | 0 | 0 | 0 |
| Loan workflow E2E, normal profile (rerun after P12-11) | 33 | 0 | 0 | 0 |
| Full backend suite | **1,615** | **0** | **1** | 0 |
| Phase 1–9 gates | not rerun — the backend change touched only the reinstate route, which no gate calls; last sweep all 11 passed (§5) | | | |

The skip is `test_llm_provider::test_real_generation` (`MODEL_CANNOT_LOAD`: 4.6 GiB needed, 2.1 GiB free). Phase 3's 7 LLM-routing checks remain not run. No load test has been performed.

**Readiness, three separate statements.**
1. *Software engineering:* complete for the feasible scope; every in-scope requirement implemented and verified as above.
2. *Production infrastructure:* not ready — HSM/KMS, TLS/mTLS certificates, production infrastructure and load testing are BLOCKED_EXTERNAL / not performed.
3. *Independent assurance:* none — the security review and DPIA are BLOCKED_EXTERNAL. Passing tests are not a certification.
