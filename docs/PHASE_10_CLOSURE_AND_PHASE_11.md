# Phase 10 closure and Phase 11 (Operations Console)

## Phase 10 closure

### Fixes

Each fix has a regression test.

| # | Defect | Impact | Fix | Test |
|---|---|---|---|---|
| A1 | Starting the API with detection off, then turning it back on, resumed the old cursor. The detector then read the gate sweep as live behaviour | `risk-001` was auto-contained after every gate sweep | A detection-off start **suspends** the cursor (and is audited); re-enabling starts at the head. A crash keeps its cursor, so an outage is never a blind spot. Production refuses detection off | `test_trust_and_containment.py::TestDisabledDetectionIsNotReplayed`, `test_production_configuration.py::TestGateHarnessSwitchesCannotReachProduction` |
| A2 | **The rate limiter never keyed on identity.** It runs before authentication, so `control_plane_principal` was never set and every request counted against the peer IP | Nine agents, the gates and the console on one host shared ONE bucket and starved each other | Two counters: the claimed identity at the tier limit, plus the address at a 10× ceiling. An unverified claim gets a fair bucket; inventing identities is bounded by the address ceiling | `test_rate_limiting.py::TestIdentityKeyingActuallyRuns` |
| A2 | The gates were written before rate limiting | Phase 7–9 failed on 429 | The gates honour `Retry-After` (`scripts/cp_sign.py`). Timing-sensitive scenarios start with a fresh window. Phase 7 reads its audit arc by request id | all gates green **with rate limiting on** |
| — | **The PIP re-verified every credential a subject had ever held** (476 for `risk-001`, mostly revoked or expired) | ~2.4 s per decision; a 2-second JIT mandate expired before it could be used | Verify live credentials first; fall back to the full history only when none is valid, which is the only case policy reads invalid credentials. Decisions are identical. 2.37 s → 0.23 s | `test_pip.py::TestCredentialHistoryDoesNotSlowDecisions` |
| — | A rate-limited decision failed a loan workflow | A workflow under human review became FAILED | Agents retry on 429 with a fresh proof. A paused workflow stays paused | live E2E |
| — | Gate keystore paths were relative to the wrong directory when `.env` was exported | Whole gate sweeps failed with KEYSTORE_ERROR | `cp_sign` resolves paths against `backend/` | harness |

`scripts/run_gates.sh` is the single, deterministic way to run every gate followed by the loan E2E.

### Final results (2026-11-11, idle host)

| Run | Result |
|---|---|
| Full backend suite | **1,520 passed, 0 failed, 1 skipped**. The skip is the live LLM generation test, which skips only when the host cannot load `llama3`; 1,496/0/0 before the console work |
| Gates 1–9 (11 scripts), gate profile, **rate limiting on** | **all passed**: 12, 30, 33, 31, 46, 68, 110, 113, 132, 38, 35 |
| Loan workflow E2E, **detector and rate limiting on** | **33/33** |
| Console browser E2E | **31/31** |

Phase 3 runs 33 checks rather than 40. Its LLM-routing section skips itself because `llama3` (4.6 GiB) cannot load in this 7 GiB host's free memory. That is an environment constraint, reported by the gate itself.

### Remaining blockers and security limitations

- **Requires an external party:** independent security review and penetration test; HSM/KMS; TLS certificates and mTLS; DPIA.
- **Audit trail not tamper-evident:** no hash chain or signed checkpoints yet.
- **Gates still attack as `risk-001`.** They are isolated by the gate profile, not by dedicated identities; see FRAMEWORK_COMPLETION_REPORT §14.
- **Agent processes still hard-code their CORS origins.**

## Phase 11: Operations Console

A complete rebuild of `frontend/`. The pages are listed in [OPERATIONS_CONSOLE.md](OPERATIONS_CONSOLE.md).

### Defects found while building it

| Defect | Impact | Fix |
|---|---|---|
| `GET /api/v1/hitl/config` was put behind `approval_read` in Phase 10 | **No human could sign in to the console**: learning where Keycloak is required a Keycloak token | Public again, listed in the route-inventory allow-list with the reason; regression test |
| The SSE stream became `audit_read`; `EventSource` cannot send a bearer token | The live trace silently stopped in Phase 10 | Read with `fetch` and the bearer token |
| The old console header claimed JIT, A2A, MCP, sessions and the kill switch were unimplemented | Misleading | Replaced |

### Backend additions

All `audit_read`; all in the route inventory.

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/console/overview` | Every overview count, from the database |
| `GET /api/v1/console/health` | Every dependency probed per request, with latency and error |
| `GET /api/v1/console/mcp` | MCP sessions and invocations, plus the tool catalogue with eligibility |
| `GET /api/v1/jit` | Agent filter now optional |
| `GET /api/v1/a2a/transactions` | Sender/receiver filter now optional |

### Demo

```bash
scripts/run_local.sh && (cd backend && python3 ../scripts/seed_credentials.py)
cd frontend && npm run dev                      # http://localhost:5173
```

1. Sign in as `loan.officer` / `loan-officer-demo`, open **Loan workflow**, and submit ₹25,00,000.
2. Watch six agents run, then the pause for a human.
3. Sign in (fresh tab) as `loan.officer.2` / `loan-officer-2-demo` and approve it in **Human approvals**. The submitting officer is refused, by policy.
4. The workflow resumes to APPROVED.
5. As `iam.admin`, use **Threat monitoring** to contain an agent and watch the next workflow fail at that agent's step.

Screenshots of every page are in `docs/console/`.
