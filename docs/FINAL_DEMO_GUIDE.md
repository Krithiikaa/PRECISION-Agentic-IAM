# PRECISION — final demonstration guide

A 10–15 minute demonstration of the real, running system: nine agent processes, the IAM API, the Agent Naming Service, OPA, Keycloak, PostgreSQL and Redis on one host. Nothing in it is mocked. The banking back-ends (KYC registry, credit bureau, document store, fraud service, risk model, loan management system) are **simulated adapters**, and every record they return says `simulated: true`; everything around them — identity, credentials, discovery, authorization, enforcement, approval, containment, audit — is real.

Measured results quoted below are from 2026-11-11 on the 7 GiB development host. Where a step relies on an automated script rather than a click, the guide says so.

---

## A. Setup (allow 10 minutes before the audience arrives)

**Prerequisites.** Docker with Compose v2, Python 3.11–3.13, Node 20+, Google Chrome (browser tests only), Ollama with `llama3` (optional: see §E). Full prerequisites and one-time setup: [`QUICKSTART.md`](../QUICKSTART.md) and `scripts/setup.sh`.

**Configuration.** `.env` is created from `.env.example` by `setup.sh`. It holds only development values; the development `KEYSTORE_MASTER_KEY` is refused when `ENV=production`. Never commit `.env`, `backend/.keystore/` or `backend/.keystore-agents/` (all gitignored).

```bash
scripts/run_local.sh            # PostgreSQL, Redis, OPA, Keycloak (Docker); migrations; IAM API :8000;
                                # ANS :8100; provisions and starts 9 agents on :9001-9009
cd backend && set -a && . ../.env && set +a
python ../scripts/seed_credentials.py       # capability credentials (1-hour demo TTL: re-run if older)
python ../scripts/provision_mcp_clients.py  # MCP OAuth clients for the agents
cd ../frontend && npm run dev               # console on http://localhost:5173
```

**Database initialisation** is done by `run_local.sh` (`alembic upgrade head`, run with the API stopped, which the audit-chain genesis requires).

**Health check.** `curl -s localhost:8000/health` → `"status":"UP"`; `run_local.sh` prints `registered=True` for all nine agents; the console's **System & integrations** page probes every dependency live.

**Demo users** (Keycloak realm `agentic-iam`, demo-only passwords, listed in [`OPERATIONS_CONSOLE.md`](OPERATIONS_CONSOLE.md)): `loan.officer`, `loan.officer.2` (LOAN_OFFICER), `iam.admin` (IAM_ADMIN), `auditor` (AUDITOR). The console holds the token in memory: use a fresh tab (or sign out) to switch user.

**Before you start, check for leftover incidents:** Threat monitoring → Incidents should show nothing CONTAINED. If an agent is contained, reinstate it with a written review as a different principal; never edit security tables by hand.

---

## B. Demonstration sequence

| # | Action | Where | Expected result | Actual result (2026-11-11) | Evidence / test |
|---|---|---|---|---|---|
| 1 | Show the nine agents, their DIDs and status; open one agent's profile and DID Document | Console → **Agent registry**; `GET /api/v1/agents/did/{did}/did-document` (public) | Each agent ACTIVE with its own DID, Ed25519 key, SHA3-256 model hash; `run_local.sh` printed `registered=True` ×9 | 9/9 registered | `04-agents.png`; gate G1 12/12 |
| 2 | Verify a credential; show issuer and status | **Identity & credentials** → a credential → *Verify now* | Signature, issuer, status and expiry checks shown individually; VC validity is **not** authorization | Verified | `05-identity.png`; G2 30/30 |
| 3 | Run a discovery for `fraud_detection` | **Naming service** → *Run a discovery* | Matching agent with rejection reasons for the others; the page states discovery authorizes nothing | as expected | `06-ans.png`; G3 33 checks (7 LLM checks **not run**, §E) |
| 4 | Show a PDP decision with its PIP facts and deciding policy | **Policies & decisions** → decision log | Evaluation stages with timing (authentication, PIP, OPA), deciding Rego policy and version. The page shows the PIP **stage** and its summary, not the full fact document; its per-credential verdicts and verified capabilities are audited as `PIP_CONTEXT_COLLECTED` (Audit page, filter by the decision's correlation id) | as expected | `07-policies.png`; G4 31/31 |
| 5 | Authorized vs denied operation at the AEM | Automated: `ONLY="phase4" scripts/run_gates.sh` (gate profile) | STEP 2 ALLOW credit read; STEP 3 DENY payroll for the **same** agent and credential; STEP 4 DENY wrong purpose | 31/31 in the final sweep | `.run/gates/phase4.log` |
| 6 | Submit a ₹4,00,000 loan as `loan.officer` | **Loan workflow** → *Submit to the agents* | "Submitted wf-…" only after the server confirms; an `Idempotency-Key` is sent | as expected | `20-workflow-approved.png` |
| 7 | Watch the coordinator orchestrate six specialists | **Loan workflow** → the workflow → timeline; *Authorization trace* per step | KYC, risk, credit, documents, fraud, decision — each by its own agent, each through the AEM on its **own** credential; APPROVED in ~4–10 s | APPROVED | console test 31/31; loan E2E 33/33 |
| 8 | Human approval with dual control: submit ₹25,00,000; try approving as `loan.officer` (refused, maker-checker), approve as `loan.officer.2` | **Loan workflow**, **Human approvals** | AWAITING_APPROVAL; submitting officer refused by policy; second officer approves; workflow resumes to APPROVED | as expected | E2E scenario C; `03-approvals.png` |
| 9 | A2A transaction verification | Automated: `ONLY="phase7" scripts/run_gates.sh`; then **A2A transactions** page | Signed envelope → verify → PDP → execute; tampering, wrong receiver, replay and duplicate execution refused | 132/132 | G7; `09-a2a.png` |
| 10 | MCP tool authorization | Automated: `ONLY="phase8" scripts/run_gates.sh`; **MCP security** page | OAuth 2.1 with the agent's own key; `tools/list` (discovery) ≠ permission; each `tools/call` decided by the PDP | 38/38 | G8; `10-mcp.png` |
| 11 | Contain an agent that holds a pending approval: create a ₹25L workflow (it pauses on `decision-001`), then as `iam.admin` contain `decision-001` | **Threat monitoring** → Kill switch (preview the blast radius first) | Server-confirmed panel: lockout, identity SUSPENDED, ANS REVOKED, push delivered to 9 runtimes, other agents untouched | as expected | `45-containment-approvals-cancelled.png`; UI test C |
| 12 | Approval cancellation | Same panel → *Approvals cancelled*; incident → *Containment detail* | The pending approval id listed, with its `APPROVAL_CANCELLED` audit event; the workflow cannot be approved later | real approval id shown | UI test C; `test_phase12_containment.py` |
| 13 | Reinstatement trust validation: try reinstating as the **same** `iam.admin` (refused), then as a different principal | Incident → *Reinstate*; the second principal is the machine identity administrator (`scripts/cp_sign.py`) or a second IAM_ADMIN | Same principal → REFUSED (separation of duties; revalidation not run); different principal → REINSTATED with four PASSED checks; badge changes only when the server confirms | as expected | `46-reinstate-refused.png`, `47-reinstate-revalidation.png` |
| 14 | Audit chain verification and signed checkpoints | **Audit & compliance** → Audit integrity → *Verify now*; expand *Signed checkpoints*. Independently: `python ../scripts/verify_audit_chain.py --public-key <key shown in the panel> --check-macs` | VERIFIED inside coverage; checkpoints signed by the keystore key; the standalone verifier agrees | VERIFIED (standalone exit 0) | `40-audit-integrity.png`; `test_audit_integrity.py` 35 tests |
| 15 | Historical coverage | Same panel, right-hand block | **710,340 events labelled OUTSIDE INTEGRITY COVERAGE**, never VERIFIED: they predate the chain's genesis | as shown | UI test A |
| 16 | API restart and durable recovery | Automated: `python ../scripts/phase12_restart_test.py` (from `backend/`, `.env` exported) | A paused workflow survives a real API process restart (PID changes), keeps its approval, history, idempotency and maker-checker, resumes to APPROVED; chain verifies across the restart | 18/18 | script output; state history in **Loan workflow** (`42-workflow-transitions.png`) |
| 17 | Final health and overview | **Overview**, **System & integrations** | Live counts and per-dependency probes; anything not deployed is listed as such | as expected | `01-overview.png`, `13-system.png` |

**Timing guide:** steps 1–4 (3 min), 5 (1 min, or show the log), 6–8 (4 min), 9–10 (1 min, logs), 11–15 (4 min), 16 (1 min, run it in advance and show the output), 17 (30 s).

**Do not** run the phase gates against the normal profile by hand: they attack as `risk-001` by design and the anomaly detector will (correctly) contain it. `scripts/run_gates.sh` switches to the gate profile and back.

---

## C. Evaluator preparation

**Architecture (one paragraph).** Four layers from the CSA framework. *Identity*: each agent has a DID and its own Ed25519 key; verifiable credentials from two issuers. *Discovery*: the ANS answers "who can do X", never "may they". *Access control*: PIP gathers facts (credentials verified live, trust, session state, approvals, mandates, delegation chain), OPA/Rego decides with deny-overrides, the AEM enforces with a single-use grant per invocation. *Sessions*: the Session Authority and its PostgreSQL ledger are the kill switch; Redis only pushes. All protocols — direct API, MCP, A2A — reach the same PDP.

**Security model in one sentence each.** Identity ≠ authentication ≠ authorization; ANS discovery, VC validity, a signature and MCP tool listing each grant nothing; a JIT mandate and a human approval are inputs to a fresh PDP decision, never substitutes; the values OPA evaluated are the values executed; everything fails closed.

**Requirement mapping.** Every CSA requirement and its status: [`REQUIREMENTS_TRACEABILITY.md`](REQUIREMENTS_TRACEABILITY.md). Phase 12 summary table: [`PHASE_12_FINAL_REPORT.md`](PHASE_12_FINAL_REPORT.md) §3.

**Likely questions.**

| Question | Accurate answer |
|---|---|
| Is the audit trail immutable? | No. It is tamper-**evident**: per-event MAC, hash chain and signed checkpoints detect modification, deletion, reordering and insertion. A row deleted within ~2 s of commit, or tail truncation together with every later checkpoint, needs an externally kept checkpoint to detect. |
| Were the old 710k audit events verified? | No. They predate the chain and are shown as outside coverage. |
| What stops a compromised agent? | The SSS ledger lockout, read by the PIP on every decision on every protocol; plus identity suspension, JIT/MCP/ANS revocation, cancelled approvals, cascade to delegated children. Measured containment ~150–270 ms. |
| Can an admin contain and then quietly reinstate? | No: a different principal, a written review and a server-side trust revalidation are required, all audited. |
| Is the LLM making authorization decisions? | No. The workflow uses explicit capabilities; LLM output is never authoritative. |
| Are the banking integrations real? | No — simulated adapters, labelled on every record. The control path around them is real. |
| Is it production-ready? | No. Engineering scope is complete; HSM/KMS, production TLS/mTLS, an independent security review, a DPIA and production infrastructure are BLOCKED_EXTERNAL, and no load test has been run. |
| Why does a gate sweep turn the detector off? | The gates attack as `risk-001` and expect it to keep working; production refuses that setting. The loan E2E and the restart test run with every control on. |

---

## D. Known limitations to state up front

- Phase 3's 7 AI-routing checks and one live model test were **not run**: the host lacks the memory to load `llama3` (needs ~4.6 GiB).
- **No load test** has been performed.
- Single instance of every service; one trust domain (centralized deployment model).
- Demo credentials have a 1-hour TTL; re-run `seed_credentials.py` if the demo starts later.
- Phase 4–7 demonstration fixtures (`loan-2201`, `pay-3310`, …) are in memory by design; workflow state is durable.
- An agent's local fast-fail session view trusts pushes on its Redis channel; a forged push can only make an agent refuse work locally (the PostgreSQL ledger still decides every request). Keep Redis on the trusted segment.

## E. If the AI model cannot run

`llama3` needs ~4.6 GiB free. If Ollama reports `MODEL_CANNOT_LOAD`, say so: the LLM-routing part of the coordinator (Naming service page → "ask the coordinator") is then unavailable and the Phase 3 gate skips those checks itself. The loan workflow does not depend on the LLM. Do not present any recorded or simulated output as a live model run.

## F. External blockers (not demonstrable)

| Item | Status |
|---|---|
| Independent security review / penetration test | BLOCKED_EXTERNAL |
| HSM / KMS | BLOCKED_EXTERNAL (integration procedure in `PRODUCTION_DEPLOYMENT.md`) |
| Production TLS / mTLS | BLOCKED_EXTERNAL |
| DPIA | BLOCKED_EXTERNAL |
| Production infrastructure and operational approval | BLOCKED_EXTERNAL |
| Load testing | NOT PERFORMED |
