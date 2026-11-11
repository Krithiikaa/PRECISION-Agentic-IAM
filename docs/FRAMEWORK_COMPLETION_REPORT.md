# Framework completion report

**Scope.** This increment brings the POC up to the CSA reference framework (*Agentic AI IAM: A New Approach*, 2025, plus its presentation and the workflow blueprint). It does not open a new phase. Every requirement and its disposition is in [REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md). This report covers what was built and how it was verified, what the system is not, and what remains.

**Readiness verdict.** The POC now implements the paper's four core layers end to end:

| Layer | Content |
|---|---|
| 1 | Identity and credentials |
| 2 | Discovery and trust |
| 3 | Dynamic access control |
| 4 | Unified session management and enforcement |

It also has a working kill switch and the blueprint's loan journey, both verified live across nine agent processes.

It is **not production-ready**. That needs an independent security review, a KMS or HSM, TLS and mTLS, and load testing (§13). None of those can be supplied from inside this repository.

> **Phase 12 update (final phase).** Containment now withdraws human approvals and revalidates trust before reinstatement; the audit trail is tamper-evident (MAC + hash chain + signed checkpoints); loan workflow state is durable in PostgreSQL; CORS is one validated configuration for all services; a delegated child is denied when any ancestor is inactive. Full detail and final results: [PHASE_12_FINAL_REPORT.md](PHASE_12_FINAL_REPORT.md) (final suite 1,615 passed / 0 failed / 1 skipped; console 31/31 + 57/57; demo: [FINAL_DEMO_GUIDE.md](FINAL_DEMO_GUIDE.md)). Sections below that predate Phase 12 are kept as the historical record; §13 and §14 are updated.

---

## 1. Starting point, re-established

The historical baseline was 1,272 tests. The suite actually had **1,394 passing, 0 failed, 0 skipped** on this machine at the start of this increment: Phase 10 had added tests since the baseline was recorded. The Phase 9 security findings were re-checked against the code, not taken from the reports:

| Phase 9 finding | State found | Evidence |
|---|---|---|
| HIGH: sensitive read APIs unauthenticated | Already closed by the Phase 10 commit | `test_read_authorization.py`, `test_route_security_inventory.py` |
| MEDIUM: no rate limiting | Closed (Redis sliding window, fail-closed in production) | `test_rate_limiting.py` |
| MEDIUM: hard-coded CORS | Closed for the IAM API. **Still hard-coded in the agent processes** (`app/agents/service.py`) | listed in §14 |
| MEDIUM: replayable presentations | Closed (single-use challenge ledger) | `test_presentation_replay.py` |
| Redis unused but mandatory | Now used by the rate limiter **and** the SSS push | — |
| TLS / Keycloak production mode | Production config refuses plaintext; `docker-compose.prod.yml` runs Keycloak `start` | `test_production_configuration.py` |
| Backup and key-rotation runbooks | `OPERATIONS_RUNBOOK.md` exists | — |
| Independent security review | **Not done**, and cannot be done from inside the project | BLOCKED |

**One baseline claim was inaccurate.** Phase 9 reported "zero schema drift". Alembic autogenerate reports four cosmetic differences on existing tables: unique constraint versus unique index on `jit_authority_keys.kid`, `jit_grants.grant_id`, `mcp_sessions.session_id` and `presentation_challenges.challenge`, and one index on `approval_authority_keys.status`. Uniqueness is enforced either way. These are recorded, not silently "fixed" inside an unrelated migration.

## 2. Architecture (updated)

```
                        Keycloak (OIDC) ── humans: LOAN_OFFICER, IAM_ADMIN, AUDITOR, PAYMENT_OFFICER
                              │
 ┌─────────────── IAM API (FastAPI) ─────────────────────────────────────────────────────────┐
 │ ControlPlaneGuard (signed proofs / OIDC) ── Rego control-plane policy                      │
 │                                                                                             │
 │ Layer 1  registry · DID Documents + Agent ID profile (SHA3-256 model hash) · VC issuer/     │
 │          verifier · challenge ledger · DELEGATION SERVICE (sub-agent/ephemeral/fork)       │
 │ Layer 3  PDP ─ PIP ─ OPA/Rego (deny-overrides) · PAP · JIT authority · HITL authority       │
 │          PIP now reads: credentials, approval, mandate, A2A, MCP, TRUST, SESSION            │
 │ Layer 4  AEM (API, MCP, A2A all funnel here) · SESSION AUTHORITY (kill switch) ·            │
 │          SSS ledger (PostgreSQL, authoritative) ──push──▶ Redis pub/sub                     │
 │ Monitor  audit trail (seq) ─▶ ANOMALY DETECTOR (rules) ─▶ TRUST ENGINE ─▶ auto-containment │
 │ Adapters SIMULATED: KYC registry · credit bureau · document store · fraud · risk model ·    │
 │          loan management system (applications + workflow queue)                            │
 └───────────────────────────────────────────────────────────────────────────────────────────┘
        ▲ signed enforce (own key)            ▲ signed claim/record (own key)
 ┌──────┴──────────────── agent processes (9) ┴──────────────────────────────────────────────┐
 │ coordinator-001 ── LoanWorkflowRunner ──ANS discovery──▶ signed /work instructions ──┐      │
 │ kyc-001 · risk-001/002/003 · fraud-001 · docs-001 · decision-001 · payments-001 ◀────┘      │
 │ every runtime: SSS subscriber (local lockout view) · own keystore · wallet                  │
 └─────────────────────────────────────────────────────────────────────────────────────────────┘
 ANS (separate service): signed registration, capability discovery, heartbeats, REVOKED on containment
```

**Deployment model: centralized** (paper §6.1.1). One organisation operates the registry, issuers, PDP, Session Authority and ANS.

- **Why.** The POC has one trust domain and one operator. A decentralized or federated model would need a second organisation, or a ledger with a governance body, to be meaningful; building one would be theatre.
- **What it costs.** The paper's warning applies: the registry and Session Authority are a central point of trust. The mitigations present are signed requests end to end, offline-verifiable signatures, and an authoritative ledger in PostgreSQL rather than in a cache.

See §10 for the full deployment assessment.

## 3. What this increment built

| Area | Delivered | Files |
|---|---|---|
| Trust & Risk Engine | Score = 100 − unexpired signal weights. Bands TRUSTED/REDUCED/UNTRUSTED. Every point explained by a signal row | `app/trust/engine.py` |
| Anomaly detection | 9 deterministic rules over the audit trail. Only events with an authenticated subject move trust. Idempotent; multi-worker safe | `app/trust/detector.py` |
| Session Authority | Kill switch, impact analysis, reinstatement (needs a review and a different principal), cascade to delegated children | `app/sessions/authority.py` |
| Session State Synchronizer | PostgreSQL ledger (enforces) + Redis push (fast failure in 9 runtimes) | `app/sessions/sss.py`, `subscriber.py` |
| Policy | `security/session.rego` (lockout denies), `security/trust.rego` (REDUCED escalates, UNTRUSTED denies), `loan/workflow.rego` (one row per specialist) | `policies/` |
| Delegated identities | SUB_AGENT / EPHEMERAL / FORK. Authority is a subset of the parent's verified credentials. Depth, TTL and rate bounded. Provenance VC. Expiry sweep | `app/agents/delegation.py` |
| Rich Agent ID | Creator/deployer/owner/controller, SHA3-256 model hash, scope, toolset, protocols, timestamps. Versioned republish | `app/identity/profile.py` |
| Loan workflow | Officer submits → coordinator claims → ANS → signed instructions → specialists via the AEM on their own credentials → screening → decision agent → HITL pause/resume → outcome | `app/workflows/`, `app/banking/adapters.py`, `api/routes/loan_workflows.py` |
| Console | "Loan workflow" and "Security ops" tabs | `frontend/src/features/{workflows,security}` |
| Audit | `request_id` filter for per-step forensics | `api/routes/audit.py` |

**New control-plane operations:**
- `incident_contain`, `incident_reinstate`, `anomaly_scan`: identity admin
- `agent_spawn`: the agent itself, or the identity admin
- `agent_profile_publish`: identity admin
- `loan_workflow_submit`: LOAN_OFFICER, or the `loan_admin` machine principal

All of them are covered automatically by the existing route-inventory test.

### Defects found and fixed (each has a regression test)

| # | Defect | Where it came from | Fix |
|---|---|---|---|
| D-1 | Agents' startup identity check was an **unsigned** GET to a route Phase 10 put behind `identity_read`. Every agent started with `registered=False` and no wallet loaded | Phase 10 regression | Signed with the agent's own key; 9/9 now confirm |
| D-2 | Provisioning read an `AGENT_PUBLIC_URL_<slug>` variable nothing set. Freshly provisioned agents had **no service endpoint**, so discovery could never select them. `payments-001` (Phase 7) was affected too | Phase 5 latent bug | Endpoint defaults to the definition's port; versioned endpoint update repairs existing agents |
| D-3 | The anomaly detector's first live start **replayed months of gate traffic** as fresh behaviour and auto-contained a healthy agent | This increment | Detector starts at the head; events older than the signal TTL are ignored; signals expire relative to the behaviour. The live incident was reinstated through the audited path with a written review |
| D-4 | A contained agent never re-registered with the ANS after reinstatement (a refused re-registration cleared the flag that gates retries) | Phase 3 latent bug, exposed by containment | Re-register on any failed heartbeat |
| D-5 | A rate-limited outcome write left a workflow IN_PROGRESS for good | This increment | Retry with backoff; stale IN_PROGRESS workflows are reclaimed (approval binding preserved) |
| D-6 | The SSS state name is 37 characters; the audit `decision` column holds 32 | This increment | Short code in the column, full name in metadata |

## 4. Security assessment

The full Phase 10 assessment is in [PHASE_10_SECURITY_ASSESSMENT.md](PHASE_10_SECURITY_ASSESSMENT.md). This section covers what the new surface adds.

| Threat introduced by the new surface | Control | Test |
|---|---|---|
| Attacker forges requests naming a victim DID to get it auto-contained | Only authenticated-subject events move trust; claims raise unattributed alerts | T-TC `test_a_forged_identity_claim_alerts_but_never_moves_trust` |
| Caller asserts its own trust score | `trust_score` is a rejected context key; trust is read only by the PIP | T-TC `test_trust_cannot_be_asserted_through_request_context` |
| Redis outage un-revokes a contained agent | Ledger is authoritative in PostgreSQL; the push is advisory | T-TC `test_a_push_failure_is_reported_and_the_ledger_still_enforces` |
| One operator contains and reinstates (covering tracks) | Separation of duties enforced in the Session Authority | T-TC, E2E-E |
| Child agent escalates beyond its parent | Subset-of-verified-credentials invariant; depth/TTL/rate bounds; refusal is a trust signal | T-DI `TestDelegationCannotEscalate` |
| Degraded agent mints identities to mask activity (MAESTRO Table 5 #3) | Only TRUSTED parents may spawn | T-DI `test_a_degraded_parent_cannot_spawn` |
| Captured coordinator instruction replayed to another specialist | Signed audience, nonce cache, freshness window | T-LW `TestPeerInstructions` |
| Coordinator lends its authority to a specialist (confused deputy) | Specialist enforces with its OWN key and credentials | T-LW `TestSpecialistBoundaries` |
| Coordinator accumulates customer data | Specialists return findings only (allow-list per tool) | T-LW, E2E-A |
| Unauthenticated workflow submission | ControlPlaneGuard + Rego (LOAN_OFFICER) | E2E-F, T-LW |

**No unresolved critical defect is known.** The open HIGH-impact items are infrastructural and are listed in §13.

## 5. MAESTRO threat coverage matrix

Layers as named in paper §7.1. "Residual" is what remains after the listed controls.

| Layer | Threat (paper §7.2 / Table 5) | Attack surface here | Mitigation present | Evidence | Missing | Residual |
|---|---|---|---|---|---|---|
| L1 Foundation models | Model-based identity theft | LLM behind each agent | Identity is a key, not behaviour; LLM output never authorizes | `test_runtime.py` | Liveness proof for a stolen key (R-250) | Key theft = full impersonation until contained |
| L1 | Prompt injection (T5 #5) | `/task`, workflow inputs | The workflow uses no LLM routing; protected tools are invisible to the LLM | `test_runtime.py` | Prompt guardrails | Medium: `/task` output is advisory only |
| L1 | Model inversion (T5 #7) | Ollama local | Local model, no retrieval API exposed | — | — | Low |
| L2 Data operations | Registry / status-list poisoning | PostgreSQL | Writes only through guarded, audited paths | `test_unauthenticated_surface.py` | Signed registry rows | DB admin compromise |
| L2 | Identity data exfiltration | Read APIs | Role-scoped reads; findings minimisation | `test_read_authorization.py`, T-LW | Row-level read scoping | Domain-scoped, not row-scoped |
| L2 | PIP tampering | In-process | PIP in the same process as the PDP; facts never caller-supplied | `test_authorization_contracts.py` | — | Low |
| L2 | Data poisoning (T5 #6) | — | — | — | — | N/A: no training |
| L3 Agent frameworks | DID spoofing (T5 #1) | Discovery | Endpoint cross-checked against the DID Document; signed instructions | G3, T-LW | Resolver pinning | Low (single registry) |
| L3 | VC replay (T5 #2) | Presentations | Single-use challenges | `test_presentation_replay.py` | — | Low |
| L3 | Ephemeral agent abuse (T5 #3) | Spawn API | Rate limit, SPAWN_BURST, TRUSTED-only parents | T-DI | — | Low |
| L3 | Delegation escalation (T5 #4) | Spawn API | Subset invariant, depth limit | T-DI | Cross-agent collusion (R-55) | Collusion undetected |
| L3 | Session hijacking via framework bugs | MCP sessions | Per-request PDP; SA revokes sessions | `test_mcp_security.py`, T-TC | — | Low |
| L4 Deployment & infrastructure | DoS on IAM services | All endpoints | Distributed rate limits | `test_rate_limiting.py` | Load tests; HA | Single instance |
| L4 | IAM infrastructure compromise | Hosts | Production config refuses dev keys and plaintext | `test_production_configuration.py` | HSM, mTLS, hardening | **High** |
| L4 | Lateral movement | Flat network | Every call is authenticated | — | Segmentation | Medium |
| L5 Evaluation & observability | Audit log tampering | `audit_events` | **Phase 12:** write-time MAC, hash chain, Ed25519-signed checkpoints, append-only trigger, server + standalone verifier, CRITICAL alert | `test_audit_integrity.py` | HSM for the MAC/checkpoint keys; external checkpoint anchoring is procedural | **Medium**: detected, not prevented; undetectable only with the master key or by deleting a row within the ~2 s sealing window |
| L5 | Monitoring evasion | Detector | Thresholds per DID; denials always logged | T-TC | Learned baselines | Slow, low-volume misuse evades fixed thresholds |
| L5 | Data leakage via observability | Alert evidence | Evidence holds seq numbers, not payloads | T-TC | — | Low |
| L6 Security & compliance | Policy misconfiguration | Rego | Policy-as-code, tests against real OPA, deny-overrides | `test_pdp_opa.py` | Multi-party approval | Single-author changes |
| L6 | IAM key compromise | File keystores | Encrypted at rest; approval and JIT key rotation | `test_*_key_rotation.py` | HSM | **High** |
| L6 | Privacy non-compliance | Customer data | Synthetic data only; minimisation | T-LW | DPIA | Needs a DPO (BLOCKED) |
| L7 Agent ecosystem | Impersonation / DID spoofing | Peers | Signed instructions verified on DID Documents | T-LW | — | Low |
| L7 | Compromised ANS | ANS | Discovery verified against the identity authority; ANS never authorizes | G3 | Signed ANS responses (R-170) | Can deny service, not grant access |
| L7 | Collusion to falsify VCs | Issuers | Two issuers, separately keyed | `test_credential_verification.py` | Trust diversification | Issuer key theft |
| Cross-layer | Supply chain on IAM components | Dependencies | Pinned requirements; no new deps this increment | — | SBOM, signing | Medium |
| Cross-layer | Privilege escalation across layers | Control plane ↔ data plane | Separate Rego packages; humans never in data-plane policy | `test_control_plane_security_matrix.py` | — | Low |
| Cross-layer | Goal misalignment → IAM misuse | LLM agents | LLMs cannot select protected tools | `test_aem_enforcement.py` | — | Low |

No claim is made that MAESTRO threats are eliminated. Two residuals remain **High** and both are infrastructural: L4 host compromise and L6 key compromise without an HSM. (L5 audit tampering was High until Phase 12 made it detectable.)

## 6. Agent lifecycle and delegation assessment

| Lifecycle event | Mechanism | Evidence |
|---|---|---|
| Creation (persistent) | Authorized provisioning; agent-held keys | G1, `provision_agents.py` |
| Creation (delegated) | `POST /agents/did/{did}/delegations`; parent proves itself; scope narrowed from verified VCs | T-DI |
| Profile / update | Versioned DID Document republish with the old and new model hash in the audit | T-DI |
| Capability change | New capability VC issued; old one revoked | G2 |
| Credential renewal | Re-issue (1-hour TTL for the demo) | `seed_credentials.py` |
| Re-attestation | **Not automated** | gap (R-232) |
| Suspension | Identity status; PIP denies | G6 |
| Containment | Session Authority | T-TC, E2E |
| Expiry | PIP treats expired as inactive immediately; sweep terminates and destroys the key | T-DI |
| Revocation / termination | Key destroyed; DID Document status; ANS TERMINATED | `test_registry.py` |
| Archival | **Not modelled** (paper's `archived`) | gap (R-74) |

**Delegation verdict.** A child cannot exceed its parent. This is tested in the negative for a capability the parent lacks, a widened resource set, a revoked parent credential, a parent that is suspended or degraded, depth, and rate. A fork inherits nothing. Containment cascades. What delegation does **not** yet do: model an agent acting for several principals (R-42), or express delegation as OAuth token exchange (R-120–122).

## 7. Monitoring and incident response assessment

| Capability | State |
|---|---|
| Secure audit trail | Append-only, ordered, attributed, queryable by DID, type, decision, time and **request id**. **Not tamper-evident** (no hash chain) |
| Non-repudiation | A2A payments and control-plane requests are signed by the actor. Audit rows are not |
| Real-time events | SSE stream (existing) plus SSS push |
| Behavioural analytics / anomaly detection | 9 rules: scope violation, denial burst, credential replay, JIT escalation, rate spike, spawn burst, delegation escalation, unverified identity claim, trust collapse. **No ML** |
| Suspicious delegation detection | DELEGATION_ESCALATION, SPAWN_BURST |
| Trust changes | TRUST_UPDATED events; REDUCED_TRUST written to the SSS |
| Targeted suspension and revocation | Kill switch keyed on one DID (+ children) |
| Containment evidence | E2E-E: `fraud-001` contained in **145 ms**; `unaffected_active_agents ≥ 8`; the next workflow failed exactly at `fraud_detection`; every other specialist kept working; after reinstatement by a different principal the agent re-registered and workflows succeeded again |
| Impact analysis | `GET /security/impact/{did}`: credentials, live mandates, MCP sessions, open approvals, children, A2A counterparties, resources touched, alerts. Frozen into the incident |
| Alerting to email / SIEM | **Not implemented**; events are in the audit table and the SSE stream |

## 8. Enterprise loan workflow validation

Run `scripts/loan_workflow_e2e.py` against the live stack: **33/33** (§11).

| Path | Result |
|---|---|
| Happy path (₹4,00,000) | APPROVED by `decision-001` within its band. 5 specialists on 5 different agents. Every step through the AEM. ~4–10 s end to end on this host |
| Adverse findings (sanctions, HIGH fraud) | DECLINED; the decision agent is never asked |
| Missing documents | DECLINED (T-LW) |
| High value (₹25,00,000) | AWAITING_APPROVAL. Submitting officer refused (maker-checker). Second officer approves. Workflow resumes and is APPROVED |
| Human rejection | DECLINED |
| Specialist revoked or contained | FAILED, naming the step and the reason |
| Timeout / abandoned run | Reclaimed after 120 s with the approval binding preserved (T-LW `TestRecovery`) |
| Coordinator without a credential | Claims nothing (T-LW) |

**Simulated, and labelled as such on every record:** KYC registry, credit bureau, document store, fraud screening, risk model, loan management system. No real banking, bureau, KYC or fraud integration exists or is claimed.

**Blueprint step 14 is only partial.** The specialists call the AEM directly. The MCP gateway fronts the same AEM and PDP, but the workflow does not route through it.

## 9. Governance and privacy gap report

| Item | Technical control in the code | Needs a human owner | Disposition |
|---|---|---|---|
| DID method governance | `did:poc` | Method steward | DEFERRED (EXT) |
| ANS namespace governance | Signed registration; identity must exist | Registration authority, reserved names, disputes | PARTIAL |
| Issuer accreditation / trust registry | Issuer registry | Accreditation criteria and audits | PARTIAL |
| VC schema governance | `REQUIRED_CLAIMS` per type | Versioning board | PARTIAL |
| Policy authorship and approval | Git, manifest owner and version, tests | Multi-party sign-off | PARTIAL |
| Policy-as-code | Yes | — | VERIFIED |
| Emergency override | Containment requires justification; reinstatement requires a written review by a different principal | Review board | VERIFIED (technical) |
| Key management | Encrypted keystores, rotation | HSM, custody procedures | BLOCKED (EXT) |
| Cross-environment | — | — | DEFERRED (one environment) |
| DPIA | Data inventory: synthetic customer records, officer usernames, agent DIDs, audit metadata | DPO | BLOCKED (EXT) |
| Data minimisation | Findings-only workflow results; the coordinator sees no customer data at claim | — | VERIFIED |
| Bias and ethics review | — | Ethics owner | BLOCKED (EXT) |
| Vulnerability disclosure | — | Owner | NOT IMPL (W1: `SECURITY.md`) |
| Independent security review | — | External reviewer | BLOCKED (EXT) |

**Selective disclosure and ZKPs: evaluated and not built.** The paper motivates them for privacy-preserving verification (R-106, R-138, R-197).

- **Where they would matter.** In this POC the only verifier of an agent's credential is the PDP, which belongs to the same organisation that issued it. There is no third party from whom an attribute needs hiding, so there is no security requirement that selective disclosure would meet here.
- **What they would cost.** A new cryptographic dependency (BBS+ or SD-JWT) and a verification path that does not exist today.
- **Decision.** Building one without a verifier who must not see the hidden attributes would be unverifiable decoration. The disposition is DEFERRED until a cross-domain verifier exists, at which point **SD-JWT VC** is the practical first step.

## 10. Deployment and scalability assessment

| Aspect | State |
|---|---|
| Model | Centralized (justified in §2) |
| Multi-tenant isolation | None: single tenant |
| Cross-domain trust / federation | None; would need a second organisation |
| Policy interoperability | Rego is portable; no harmonisation layer |
| Cross-environment audit | Single audit store |
| Availability | Single instance of every service. The detector and cursor are multi-worker safe (`SKIP LOCKED`). Rate limits are Redis-backed for multiple workers |
| Fault tolerance | Redis down: rate limiting fails closed in production; the SSS push degrades and enforcement is unaffected. OPA down: authorization denies. Keycloak down: human approvals blocked, everything else runs |
| Recovery | Policy reconciler restores OPA; agents re-register; workflows reclaim abandoned runs; credentials must be re-seeded hourly (demo TTL) |
| Performance | Containment 145–250 ms. Workflow 4–10 s for 6 agent hops on a 7 GiB laptop. **No load test exists** |
| Scalability limits | In-memory loan applications and workflow queue (simulated LMS) are single-process by design; a real LMS replaces them |

Improvements beyond this were not built, per the instruction not to build a distributed platform the POC does not need.

## 11. Test and gate results

All results were measured on 2026-11-11 on the development host (7 GiB). None are copied from earlier reports.

**Unit and integration suite** (real PostgreSQL, real OPA, real Keycloak and Redis):

| Run | Collected | Passed | Failed | Skipped |
|---|---|---|---|---|
| Baseline, before this increment | 1,394 | 1,394 | 0 | 0 |
| Phase 10 final (before the console) | 1,496 | 1,496 | 0 | 0 |
| Phase 11 final | 1,521 | 1,520 | 0 | 1: `test_llm_provider::test_real_generation`, skipped only on `MODEL_CANNOT_LOAD` (3.3 GiB free, model needs 4.6 GiB, with all 9 agents running) |

New tests this increment:

| File | Tests | Covers |
|---|---|---|
| `test_trust_and_containment.py` | 44 | Trust, detector, the history-replay regression, policy effects, Session Authority, SSS push, API |
| `test_delegated_identities.py` | 24 | Spawning, escalation refusal, lifecycle, Agent ID profile, API |
| `test_loan_workflow.py` | 34 | Specialist boundaries, peer instructions, screening, the runner against real policy, recovery, API |

Updated tests:
- 3 in `test_pip.py`: trust and session are now real facts. Updated the same way the Phase 5 approval test was.
- 1 inventory test in `test_authorization_api.py`: six new protected tools, still asserted exactly.

**Live gates** (running 9-agent stack) — final run of `scripts/run_gates.sh`:

| Gate | Result | Profile |
|---|---|---|
| Phase 1 | 12/12 | gate profile |
| Phase 2 | 30/30 | gate profile |
| Phase 3 | 33/33 (its LLM section self-skips: `llama3` cannot load in this host's free memory) | gate profile |
| Phase 4 | 31/31 | gate profile |
| Phase 4.5 | 46/46 | gate profile |
| Phase 5 | 68/68 | gate profile |
| Phase 5.5 | 110/110 | gate profile |
| Phase 6 | 113/113 | gate profile |
| Phase 7 | 132/132 | gate profile |
| Phase 8 | 38/38 | gate profile |
| Phase 9 end-to-end | 35/35 | gate profile |
| **Loan workflow end-to-end** | **33/33** | **normal profile: detector ON, rate limiting ON** |

**The gate profile** is the anomaly detector off, with rate limiting **on**. The gates honour `Retry-After` through `scripts/cp_sign.py`.

The detector is off for the gates because they deliberately attack as `risk-001` and then expect `risk-001` to keep working. The setting is refused in production by the configuration validator. Switching detection off now **suspends** the detector's cursor, so turning it back on does not replay the gate traffic. That replay was the interference behind repeated containments of `risk-001`, and it is fixed and tested.

The detector and kill switch are proven by `T-TC` and by the loan end-to-end, which runs with every control on.

Measured: kill switch 121–250 ms end to end, including the impact snapshot; loan workflow 4–10 s for six agent hops.

## 12. Developer experience and management UI

The existing React console gained two tabs:
- **Loan workflow:** submit; per-step agent, decision and reason; customer message.
- **Security ops:** trust table, kill switch with blast-radius preview, incidents with reinstatement, alert feed.

Neither tab hides buttons by role: the server decides and its structured refusal is shown. The console header no longer claims that JIT, A2A, MCP, sessions and the kill switch are unimplemented.

**Superseded.** Phase 11 rebuilt the console (13 pages, including JIT, A2A and MCP views), and Phase 12 added the audit-integrity, transition-history, containment and reinstatement views and idempotent submission (OPERATIONS_CONSOLE.md). Still **not built**, by design: an agent-registration or spawn UI and a policy editor.

## 13. Remaining work (updated at Phase 12, the final phase)

Closed in Phase 12: tamper-evident audit (R-190/196), kill-switch playbook and `SECURITY.md` (R-237/240, documentation parts), agent-process CORS, durable workflow state. Everything below is either external or deliberately not built; there is no further numbered phase.

| Item | Requirement | Disposition |
|---|---|---|
| Independent security review, pen test, red team | R-239, R-262 | **BLOCKED_EXTERNAL** |
| HSM/KMS, mTLS, segmentation, production TLS certificates | R-57, R-102, R-238 | **BLOCKED_EXTERNAL** — integration procedure and evidence in `PRODUCTION_DEPLOYMENT.md` |
| DPIA, bias and ethics review | R-242, R-244 | **BLOCKED_EXTERNAL** — needs a DPO and an ethics owner |
| Production infrastructure, backup and DR rehearsal, load test | R-22, R-48, R-285 | **BLOCKED_EXTERNAL** |
| Toolset / `scopeOfBehavior` in the PDP input | R-75, R-77, R-269 | DEFERRED (no target): policy change across every specialist, not needed for any current control |
| Signed ANS responses, structured ANSName, semver ranges | R-139, R-140, R-167, R-170 | DEFERRED: discovery never authorizes; endpoints are cross-checked against DID Documents |
| Route the workflow through the MCP gateway | BP-14 | DEFERRED: same AEM/PDP either way |
| Archived lifecycle state; ownership transfer | R-74, R-05 | DEFERRED |
| KPI dashboard | R-276–284 | DEFERRED: values are measured and in the audit trail |
| RFC 8693 token exchange; DPoP for MCP | R-18, R-120–122 | DEFERRED: needs Keycloak and client changes |
| Collusion and communication-graph rules | R-55, R-205 | DEFERRED: needs a pairwise baseline |
| OpenID SSF transmitter | R-160 | DEFERRED (optional in the paper) |
| ML anomaly detection, ZKP, liveness proofs, natural-language policy | R-124, R-106, R-250, R-111 | Research; not built |

## 14. Known limitations

- Rule-based detection only. Thresholds are fixed, so slow, low-volume misuse can stay under them.
- ~~Audit rows are not tamper-evident.~~ **Closed in Phase 12** (tamper-evident; not immutable — see PHASE_12_FINAL_REPORT §B for the residual windows). 710,340 pre-Phase-12 rows on the development host are outside coverage and reported as such.
- ~~Workflow state lives in process memory.~~ **Closed in Phase 12** for workflow-created applications, documents and the queue. The Phase 4–7 demonstration fixtures (`loan-2201`, `pay-3310`, …) remain in-memory by design: the gates reset and tamper with them.
- ~~Agent processes hard-code CORS.~~ **Closed in Phase 12.**
- ~~Containment does not cancel pending approvals.~~ **Closed in Phase 12**: pending and approved-but-unspent approvals are cancelled.
- Reinstatement retires **all** of the agent's active trust signals, on the reviewer's judgement. A partial retirement is not offered.
- The SSS is "distributed" only in its push. The ledger is a single PostgreSQL.
- Credentials carry a 1-hour TTL in the demo, so the gates and the workflow need `seed_credentials.py` to have run within the hour.
- **The gates still attack as `risk-001`; they do not use dedicated test identities.** `scripts/run_gates.sh` isolates them through the gate profile instead. Separate identities would not be enough: the gates accumulate enough signals within a single gate to contain whichever identity they attack. Re-pointing them would mean restructuring each gate's fixtures, so it is deferred.
- The gates honour rate limits by waiting out `Retry-After`. A full sweep takes about 25 minutes.
