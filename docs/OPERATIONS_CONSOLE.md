# PRECISION Operations Console

A React console (Vite, Tailwind 4) on the live IAM API, ANS and Keycloak.

- **Real data only.** Every number, record and state comes from a backend call made by the page. There are no fixtures, and nothing is computed from cached guesses.
- **No client-side permission model.** The console offers actions and renders the server's answer, refusals included. A 401 renders as "sign in"; a 403 renders as "your role may not read this".

## Running it

```bash
scripts/run_local.sh                                 # API, ANS, 9 agents
(cd backend && python3 ../scripts/seed_credentials.py)
cd frontend && npm install && npm run dev            # http://localhost:5173
```

**Signing in.** Use the Keycloak demo users:

| User | Password | Role |
|---|---|---|
| `auditor` | `auditor-demo` | AUDITOR |
| `iam.admin` | `iam-admin-demo` | IAM_ADMIN |
| `loan.officer` | `loan-officer-demo` | LOAN_OFFICER |
| `loan.officer.2` | `loan-officer-2-demo` | LOAN_OFFICER |

**Session behaviour.** The token lives in memory only (see `src/auth/oidc.ts`). Reloading the page signs you out; the console navigates by hash so this does not happen during normal use.

**Browser test:** `python3 frontend/e2e/console_e2e.py`, run against `npx vite preview --port 5173`. It writes screenshots to `docs/console/`.

## Pages

| # | Page | What it shows | Live actions | Reads require |
|---|---|---|---|---|
| 01 | Overview | Agent, credential, decision, JIT, approval, A2A, MCP and alert counts; recent audit; probed service health | — | AUDITOR / IAM_ADMIN |
| ★ | Loan workflow | Submission form; per-workflow timeline (agent, PDP decision, reason, policy, duration, minimised findings); per-step authorization trace by correlation id; approval checkpoint; customer message; **persisted state history (Phase 12)** | Submit (LOAN_OFFICER) with an **Idempotency-Key** | LOAN_OFFICER / AUDITOR |
| 02 | Agent registry | Identity status, ANS discovery status and heartbeat, trust; per agent: Agent ID profile (SHA3-256 model hash, toolset), public key, credentials, global session state, delegation lineage | — | identity_read |
| 03 | Identity & credentials | Issuers and their public keys; VC inventory by status; claims; verification history | Verify now; revoke (IAM_ADMIN) | credential_read |
| 04 | Naming service | Registry, heartbeat age, endpoint probe, capability catalogue, discovery history | Run a discovery (shows match/rejection reasons; states it authorizes nothing) | public (ANS) / audit_read |
| 05 | Policies & decisions | Policy inventory (declared vs loaded vs drift), policy data, PDP decision log with per-stage timing and the deciding policy | — (policy changes are machine-admin only, by design) | policy_read / audit_read |
| 06 | JIT access | Mandates: binding, scope, uses, expiry, signing key | Revoke (IAM_ADMIN) | grant_read |
| 07 | Human approvals | Pending and history, amount, the policy explanation, officer of record, sign-offs with roles, signed artifact, dual-control progress | Approve / reject (LOAN_OFFICER, PAYMENT_OFFICER) | approval_read |
| 08 | A2A transactions | Ledger; four-way amount reconciliation; PDP decision; payload digest | — | grant_read |
| 09 | MCP security | Tool catalogue with "eligible over MCP" (discovery ≠ permission), sessions, invocations with decisions | — | audit_read |
| 10 | Threat monitoring | Trust scores, alerts (attributed vs not), incidents with reviews; **server-confirmed containment result incl. cancelled approvals; per-incident containment detail with audit evidence; reinstatement revalidation (Phase 12)** | Kill switch with blast-radius preview; reinstate | audit_read; contain/reinstate IAM_ADMIN |
| 11 | Audit & compliance | **Audit integrity verdict, coverage split and signed checkpoints (Phase 12)**; filterable trail (type, agent, decision, correlation id), full records, live SSE stream | Verify now; export CSV / JSON | audit_read |
| 12 | System & integrations | Each dependency probed per request: PostgreSQL, OPA, Keycloak, Redis, ANS, agent runtimes, MCP, A2A config, anomaly detector, LLM; plus what is NOT deployed | — | audit_read |

## API integration map

**Existing endpoints, reused unchanged:**
- `/api/v1/agents`, `…/{id}/credentials`, `…/did/{did}/lineage`
- `/api/v1/credentials*`, `/api/v1/policies`, `/api/v1/authorize/decisions`
- `/api/v1/hitl/approvals*`
- `/api/v1/security/*`
- `/api/v1/audit`, `/api/v1/events/stream`
- `/api/v1/loan-workflows*`
- ANS `/api/v1/ans/{agents,capabilities,discover}`

**Added for the console:** all are `audit_read`, all are covered by the route-inventory test, and all are tested in `tests/test_console_api.py`.

| Endpoint | Why |
|---|---|
| `GET /api/v1/console/overview` | Every overview count in one query set, with no client-side arithmetic over partial lists |
| `GET /api/v1/console/health` | Live probes with latency and error. "Up" means a probe just succeeded |
| `GET /api/v1/console/mcp` | MCP sessions and invocations had no read endpoint |

**Changed:**

| Endpoint | Change |
|---|---|
| `GET /api/v1/jit` | `agent_did` is now optional (all agents, newest first) |
| `GET /api/v1/a2a/transactions` | Sender/receiver filter is now optional |

The guards are unchanged.

## Defects in the previous console, fixed here

- **The live trace was broken by Phase 10.** The stream became `audit_read`, and `EventSource` cannot send an Authorization header. The console now reads the stream with `fetch` and the bearer token.
- **The header claimed JIT, A2A, MCP, sessions and the kill switch were "not implemented".**

## Limitations

- **Rate-limit refusals are not in the audit trail.** They are logged to the API log. A database row per refused request would amplify the very traffic being limited.
- **No live push for the overview counts.** Pages poll at 3–30 s; the audit page has a live SSE stream.
- **The loan management system is simulated** (labelled `simulated: true`). Since Phase 12 its workflow state is durable in PostgreSQL and survives an API restart.
- **The workflow's specialists call the AEM directly,** not through the MCP gateway or A2A, which have their own pages.
- **No policy editor.** No human role may change live policy, by design.
- **Fonts load from Google Fonts.** Offline, the console falls back to system fonts.

## Phase 12 integrations

Five additions to existing pages; no new page, no new dependency (animations are CSS, `prefers-reduced-motion` respected by the existing global rule). Every value shown comes from the response named below; nothing is inferred from a click.

| # | Page | What it shows | Endpoint / field | Source |
|---|---|---|---|---|
| 1 | Audit & compliance | Server verdict (VERIFIED / FINDINGS), verification time, entries checked, chain head, MACs checked, unsealed-in-grace; findings with entry and event seq; **a separate block labelled `OUTSIDE INTEGRITY COVERAGE` for the legacy events (never VERIFIED)**; expandable signed checkpoints and the trusted **public** key; "Verify now"; error state keeps a stale result visibly marked as not current | `GET /api/v1/audit/integrity` (`status, ok, verified_at, covers_from_seq, events_before_coverage, entries_checked, head_index, mac_checked, unsealed_within_grace, findings[], finding_count, checkpoints_verified, last_checkpoint_index, entries_after_last_checkpoint, scope_note, alert_id`); `GET /api/v1/audit/integrity/checkpoints` (`trusted_keys, checkpoints[]`) | `src/pages/Audit.tsx` (`AuditIntegrity`, `IntegrityReport`, `Checkpoints`) |
| 2 | Loan workflow | Expandable **State history**: from → to, actor (DID or officer), timestamp, request id, reason; chips for RESUMED, RECOVERY (lease expired), RECOVERED, FAILURE; refetched when the workflow's `version` changes | `GET /api/v1/loan-workflows/{id}/transitions` (`from, to, actor, reason, request_id, at, detail`) | `src/pages/Workflow.tsx` (`Transitions`) |
| 3 | Threat monitoring | After **Contain agent**: the server's report plus the incident read back — agent, reason, timestamp, session state, identity, **approvals cancelled (count and ids)**, JIT/MCP/ANS/credential actions, cascade, untouched agents, push delivery. Per incident: **Containment detail** with the stored actions and the matching audit events (`INCIDENT_CONTAINED`, `APPROVAL_CANCELLED`, …) | `POST /api/v1/security/incidents` (`actions.approvals_cancelled` …); `GET /api/v1/security/incidents/{id}` (`containment.actions`); `GET /api/v1/audit?agent_did=` | `src/pages/Threats.tsx` (`ContainmentResult`, `ContainmentDetail`) |
| 4 | Threat monitoring | **Reinstate**: "requested / revalidating" while in flight; then either REINSTATED (server-confirmed) with each revalidation check, or REFUSED with the server's reason and the checks (or a statement that revalidation did not run, e.g. separation of duties). The incident badge is always the server's status | `POST /api/v1/security/incidents/{id}/reinstate` → 200 `{status, revalidation[], still_required}` or **409 `{error, detail, revalidation}`** | `src/pages/Threats.tsx` (`ReinstateResult`) |
| 5 | Loan workflow | Submission sends an **Idempotency-Key**: one key per logical submission (bound to the exact payload), reused on retry, discarded only after the server confirms; button disabled and a synchronous guard against double clicks; a lost response is shown as "Not confirmed" (never "submitted"); the server's replay is shown as "Already received — nothing new was created"; 409 shown as refused | `POST /api/v1/loan-workflows` with header `Idempotency-Key` → `idempotent_replay` | `src/pages/Workflow.tsx` (`Submit`), `src/api/client.ts` |

**Backend change made for the UI (one).** A refused reinstatement used to return its reasons as a single string. It now returns the same 409 / `CONFLICT` plus the structured `revalidation` list (`ReinstatementRefused` in `app/sessions/authority.py`, route in `app/api/routes/security.py`), tested in `tests/test_phase12_containment.py::TestRefusalCarriesTheRevalidation`.

**Shared components added** (`src/components/ds.tsx`): `Disclosure` (animated expandable panel; content mounts on first open, so closed panels fetch nothing) and `CheckList` (server-reported checks). `ApiError` now keeps the server's JSON body. CSS keyframes `step-in`, `status-in` and a grid-rows disclosure transition in `src/index.css`.

### Browser tests

`frontend/e2e/phase12_ui_e2e.py` (run from `backend/` with `.env` exported, stack running, console on :5173). Real Keycloak logins (auditor, loan.officer, iam.admin), real server state. Where a state cannot be produced live — an API outage, a revalidation failure in the browser, an empty history, a slow verification — the test injects a response in the browser's `fetch` and its check label says **INJECTED**; such checks prove rendering only, never server behaviour.

| Area | Checks |
|---|---|
| Audit integrity (verdict, coverage, legacy label never VERIFIED, checkpoints, no private material, INJECTED 503 + Retry, INJECTED loading) | 13 |
| Transition history (all persisted rows, request ids, RESUMED label, INJECTED empty) | 7 |
| Unauthorized (loan officer gets the server's 403 on integrity) | 1 |
| Idempotency (double click = 1 request / 1 workflow; lost response = "Not confirmed" + server stored once; retry = same key, server replay, nothing new; new application = new key, new workflow) | 12 |
| Containment with a REAL pending approval (approvals_cancelled id, reason, incident id, detail + `APPROVAL_CANCELLED` evidence) | 7 |
| Reinstatement (same principal REFUSED, reason, no revalidation, still CONTAINED; INJECTED failed check; different principal REINSTATED with 4 PASSED; server status REINSTATED) | 9 |
| Logins, phone width (audit, workflow, threats at 390 px) | 8 |
| **Total** | **57 passed, 0 failed** (2026-11-11) |

The existing `frontend/e2e/console_e2e.py` (all 13 pages, anonymous, roles, UI loan submission to APPROVED, phone width) was rerun after the changes: **31 passed, 0 failed**.

Screenshots: `docs/console/40-audit-integrity.png`, `41-audit-integrity-error.png`, `42-workflow-transitions.png`, `43-idempotency-not-confirmed.png`, `44-idempotency-replay.png`, `45-containment-approvals-cancelled.png`, `46-reinstate-refused.png`, `47-reinstate-revalidation.png`, `50/51/52-mobile-*-phase12.png`; the 13 pages in `01`–`13`.

### Phase 12 UI limitations

- **No linter is configured** for the frontend; the static check is the strict TypeScript build (`strict`, `noUnusedLocals`, `noUnusedParameters`). No ESLint dependency was added.
- **Revalidation for past reinstatements** is in the audit trail (`INCIDENT_REINSTATED` metadata), not on the incident record, so the console shows revalidation for reinstatements performed in the current page session only.
- **Containment audit evidence** is matched among the agent's latest 300 audit events; older evidence is reachable through the Audit page filters.
- **An idempotency key lives in page memory.** A full page reload signs the user out (token in memory, by design) and discards an unconfirmed key; the server's per-officer key uniqueness still applies to any key that was sent.
