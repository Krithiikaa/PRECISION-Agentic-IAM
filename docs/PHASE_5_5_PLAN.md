# Phase 5.5 — HITL security hardening: plan

Scope: harden what Phase 5 built. **No Phase 6 work.** No JIT, no A2A, no MCP,
no Session Authority, no SSS, no monitoring build-out, no trust engine, no kill
switch.

## 1. Baseline (measured, not assumed)

Run on 2026-08-30 against the live PostgreSQL test database, real OPA and real
Keycloak:

```
backend/.venv/bin/python -m pytest -q
```

| | |
|---|---|
| collected | **567** |
| passed | **567** |
| failed | **0** |
| skipped | **0** |
| xfailed / xpassed / errors | **0** |

Every one of the 567 result characters emitted by pytest was `.`. The claimed
baseline of 567 is confirmed rather than assumed.

Live services at baseline: PostgreSQL 16 (:5433), Redis 7 (:6380), OPA 1.x
(:8181), Keycloak 26 (:8080, healthy), the IAM API (:8000), the ANS (:8100) and
seven agent processes.

Existing live gates, unchanged and to be re-run at the end: Phase 1 12/12,
Phase 2 30/30, Phase 3 40/40, Phase 4 31/31, Phase 4.5 46/46, Phase 5 67/67.

### Re-verified on 2026-09-16, at the close of the phase

The suite was re-run from scratch against a freshly restarted stack:

```
664 passed in 203.46s
```

**664 collected, 664 passed, 0 failed, 0 skipped, 0 xfail/xpass/errors.**
That is the 567 baseline plus the 97 tests this phase added
(`test_loan_amount_policy.py` 17, `test_dual_control.py` 15,
`test_approval_key_rotation.py` 18, `test_phase55_security_matrix.py` 47).
No test was deleted and none weakened.

All seven gates re-run green on the same stack: Phase 1 12/12, Phase 2 30/30,
Phase 3 40/40, Phase 4 31/31, Phase 4.5 46/46, Phase 5 67/67,
**Phase 5.5 110/110**.

One environment repair was needed first and is recorded because it explains the
gap between runs: the host had upgraded `/usr/bin/python3` from 3.13 to 3.14,
orphaning the backend virtualenv (its `python3` symlink resolved to an
interpreter that does not share its `site-packages`, so every entry point died
with `ModuleNotFoundError`). Repointing `.venv/bin/python3` at
`/usr/bin/python3.13` restored it. No dependency was reinstalled, no code
changed, and no test was touched.

## 2. The gaps this phase closes

| # | Gap | Where it is today |
|---|---|---|
| G-1 | `LOAN_OFFICER` may approve **any** amount. No amount appears in any authorization input. | `policies/security/sensitive.rego` escalates on the action name alone |
| G-2 | The approval binding does not cover the amount, so changing the amount after approval does not invalidate it. | `ApprovalBinding` = request/agent/action/resource/purpose |
| G-3 | No dual control. One human satisfies any approval. | `approval_requests` has a single approver |
| G-4 | Nothing prevents the same human satisfying two approvals, because there is only ever one. | — |
| G-5 | No self-approval / maker-checker separation. | — |
| G-6 | The approval-authority key never rotates and cannot be rotated. | `ApprovalAuthority.ensure()` explicitly refuses to regenerate |
| G-7 | OIDC access token in `sessionStorage`. | `frontend/src/auth/oidc.ts` |
| G-8 | The approval queue polls every 4s; the live trace does not carry HITL events at all. | `ApprovalsView.tsx`, `useEvents.ts` |

## 3. Design decisions, stated before the code

### 3.1 The amount is server-side, and the threshold is policy configuration

The amount is **never** taken from the caller. A new `material_attributes()`
resolver reads the loan application record server-side; the PIP places the
result in `input.pip.resource.attributes`. A caller can put anything in
`input.context`; policy does not read it.

Thresholds live in **`policies/data/loan_amount_policy.json`**, pushed by the
PAP into OPA as the data document `data.agentic_iam.config.loan`. Rules are
Rego; thresholds are configuration; neither is Python. If the data document is
absent, the loan rules **fail closed** — a `LOAN_POLICY_UNCONFIGURED` deny —
rather than silently permitting.

Tiers (the values are configuration; these are the ones shipped):

| Band | Amount | Outcome |
|---|---|---|
| autonomous | ≤ `agent_autonomous_limit_inr` | `ALLOW` on the agent's own credential |
| single | ≤ `single_approver_limit_inr` | `HUMAN_APPROVAL_REQUIRED`, 1 × `LOAN_OFFICER` |
| dual | above that | `HUMAN_APPROVAL_REQUIRED` / reason `DUAL_APPROVAL_REQUIRED`, 2 distinct humans |

Shipped values: `agent_autonomous_limit_inr = 1000000` (₹10,00,000),
`single_approver_limit_inr = 5000000` (₹50,00,000). §24's three scenarios
(₹5 lakh, ₹25 lakh, ₹2 crore) then land in the three bands **because of the
configuration**, not because the amounts are written into any rule.

A sensitive action whose amount cannot be resolved (a different resource type,
an unknown application) keeps the Phase 5 behaviour: `HUMAN_APPROVAL_REQUIRED`
with `SENSITIVE_ACTION_REQUIRES_HUMAN`. It still requires a human — it is not a
path to autonomy.

### 3.2 `DUAL_APPROVAL_REQUIRED` is a reason, not a fourth decision value

§23 requires the decision set to stay `ALLOW` / `DENY` /
`HUMAN_APPROVAL_REQUIRED`. Dual control is therefore carried as the **reason**
`DUAL_APPROVAL_REQUIRED` plus `required_approvals: 2` on the same
`HUMAN_APPROVAL_REQUIRED` verdict. The enforcement pipeline of §28 is unchanged
and no consumer has to learn a new verdict.

### 3.3 Dual control does not add a state

`PENDING` with one of two sign-offs recorded is still `PENDING` — it is still
waiting on a human. The §14 transition table is untouched. The count of
sign-offs is a separate fact, held in a new `approval_signoffs` table:

* `UNIQUE (approval_id, approver_issuer, approver_subject)` — **the database**
  refuses the same human twice, not an `if` in Python.
* `UNIQUE (approval_id, sequence)`.
* the flip to `APPROVED` is a conditional `UPDATE ... WHERE status = PENDING`,
  so exactly one concurrent sign-off completes the approval and signs.

The artifact carries `approvers` (every sign-off) and `requiredApprovals`.
`approver` stays present, naming the sign-off that completed it, so Phase 5
consumers are unaffected.

### 3.4 Self-approval

Maker-checker, server-side: the loan application record names the officer who
submitted it (`submitted_by`). Policy denies when the approver is that person.
Nothing is read from the request. The two existing refusals — an agent may not
approve, a machine administrator may not approve — stay.

### 3.5 Key rotation

A new `approval_authority_keys` table: `kid`, generation, `ACTIVE` /
`RETIRED` / `REVOKED`, `not_before`, `retired_at`. Rotation generates a new key,
retires the old one, and republishes the DID Document carrying **both**
verification methods.

* Signing always resolves the `ACTIVE` row → a retired key cannot issue.
* Verification resolves the key record by `kid`; a `RETIRED` key verifies
  artifacts whose proof `created` is at or before its `retired_at`, so history
  stays verifiable and forward-dating with a retired key is refused.
* A `kid` with no record, or a `REVOKED` one, is refused.
* Private key material never leaves the KeyStore — rotation is a `generate_key`
  call, and no route returns a private key.

Rotation is a control-plane operation (`approval_key_rotate`) requiring a
machine administrator holding `identity_admin`. A human cannot rotate it from a
browser; a loan officer certainly cannot.

### 3.6 `MACHINE_ADMIN` in the role matrix (§18) — stated interpretation

This system deliberately keeps machine/control-plane authority away from
browser sessions: `humans.rego` denies humans `policy_*`, `ans_*`, `pdp_query`
and `aem_enforce` by name. So `MACHINE_ADMIN` in the §18 matrix is implemented
and tested as the **machine administrator principal class**
(`did:poc:administrator:*` with `identity_admin` / `policy_admin` /
`registry_admin`), not as a new Keycloak realm role. Adding a human role that
could perform machine operations would undo an existing security property, so
it is not done. The matrix test covers the class either way.

### 3.7 Token storage (§11) — decided after review

**Decided: in-memory only.** The access token moved out of `sessionStorage` into
a module-scoped variable. It is a real reduction in exposure — nothing at rest,
nothing readable by a script arriving later, nothing surviving a reload — and it
is explicitly **not** XSS protection, which no browser-side storage choice
provides. `localStorage` was rejected outright as strictly worse than what
Phase 5 had. The PKCE verifier and `state` stay in `sessionStorage` because they
must survive the navigation to Keycloak and back. Full reasoning in
`docs/PHASE_5_5_ARCHITECTURE.md` §7.

### 3.8 What is deliberately NOT done

* No new decision value.
* No BFF / server-side session — that is Phase 9's Session Authority, and
  inventing one here would collide with it.
* No SAML implementation. Keycloak's realm has one OIDC client and no SAML
  federation is available to test against, so SAML stays **documented**.
* No replacement of polling with a new real-time subsystem; only reuse of the
  SSE stream that already exists.

## 4. Work items

| # | Item | Files |
|---|---|---|
| W-1 | `material_attributes()` server-side resolver; PIP exposes `pip.resource.attributes` | `enforcement/resources.py`, `authorization/pip.py` |
| W-2 | Amount in the approval binding + digest | `hitl/artifact.py` |
| W-3 | Threshold data document + PAP data loading + fail-closed | `policies/data/…`, `policies/manifest.json`, `authorization/pap.py`, `authorization/opa.py` |
| W-4 | Amount policy in Rego | `policies/loan/amount.rego`, `security/sensitive.rego`, `loan/approval.rego` |
| W-5 | `approval_signoffs`, dual control, DB-enforced distinctness | `db/models/hitl.py`, `hitl/service.py`, migration |
| W-6 | Self-approval refusal | `policies/control_plane/humans.rego`, `hitl/service.py` |
| W-7 | Key rotation: model, service, DID Document, verification window | `hitl/authority.py`, `hitl/artifact.py`, `db/models/hitl.py`, route |
| W-8 | Second Keycloak loan officer (dual control needs two people) | `keycloak/realm-agentic-iam.json` |
| W-9 | Audit events for sign-off, self-approval refusal, rotation, escalation tier | `monitoring/events.py`, services |
| W-10 | Token storage change + documented limitation | `frontend/src/auth/oidc.ts` |
| W-11 | SSE-driven approval refresh + HITL events in the live trace | `frontend/src/hooks/useEvents.ts`, `ApprovalsView.tsx` |
| W-12 | Phase 5.5 tests | `backend/tests/test_*` |
| W-13 | `scripts/phase55_gate.py`: three scenarios, nine negative demos, measured latency | `scripts/` |
| W-14 | Docs | `docs/PHASE_5_5_ARCHITECTURE.md`, `docs/HITL_SECURITY_MODEL.md`, `docs/PHASE_STATUS.md` |

## 5. Acceptance

Phase 5.5 is complete when every box in §32 of the specification is ticked, the
six existing gates are re-run green, no test has been deleted or weakened, and
the full suite passes with the new tests added.
