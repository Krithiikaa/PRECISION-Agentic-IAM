# Phase 6 — Just-In-Time temporary access: architecture

Phase 5.5 proved a human decision could be bound, signed and re-evaluated.
Phase 6 asks a different question: can that decision be carried **forward**, to
more than one action, without giving anything away?

The answer this phase implements is a **mandate**: a time-bounded, use-bounded,
cryptographically signed statement that the PDP permitted an action at a
specific moment, reusable within stated limits — and **re-decided on every
single use**.

---

## 0. The finding that shaped this phase

**This system already had no standing permission.** Every protected call runs
the full `AEM → PIP → OPA` path with nothing cached. The existing
`EnforcementGrant` is minted *after* a PDP `ALLOW`, is single-use, is never
persisted, and never leaves the process.

Authorization here was therefore *already* just-in-time. A grant that let an
agent reach a resource **without** re-running the PDP would not have added a
capability — it would have **introduced standing permission where none
existed**, and credential revocation, agent suspension and the Phase 5.5 amount
bands would all have stopped applying for the life of the grant.

> **A JIT grant is an input to authorization, never a substitute for one.**

That is the same position the human approval artifact occupies, and it is the
sentence every design decision below follows from.

### What a mandate actually carries

Only the **expensive** precondition. Everything cheap is re-established live:

| Re-checked on every use | Carried forward |
|---|---|
| credential validity (Phase 2 verifier, live) | the fact that the PDP permitted this action once |
| agent identity status | |
| resource scope and purpose | |
| Phase 5.5 amount bands | |
| the mandate's own window, budget and revocation state | |

---

## 1. VC vs PDP vs JIT grant vs AEM

The four are routinely conflated. They are not the same thing and each answers
a different question.

| | Question it answers | Lifetime | Issued by |
|---|---|---|---|
| **Verifiable Credential** | *What is this agent trusted to be capable of?* | hours–months | a credential issuer |
| **PDP decision** | *Is this action permitted, right now?* | one evaluation | OPA, from Rego |
| **JIT grant** | *Was this action permitted, and may that be reused within bounds?* | seconds–minutes, N uses | the JIT authority |
| **AEM** | *Enforce it.* | one invocation | — |

A credential says **capability**. A mandate says **a decision happened**.
Neither says **permitted now** — only the PDP does, and only at the moment of
acting.

### And `EnforcementGrant` is a fifth thing

| | `EnforcementGrant` (Phase 4) | `JITGrant` (Phase 6) |
|---|---|---|
| Lifetime | one invocation, microseconds | policy-capped window |
| Crosses a trust boundary | no — never leaves the process | yes — returned to the agent |
| Cryptography | none; a module-private sentinel | Ed25519 + canonical JSON |
| Persisted | no | yes — revocation and counting need state |
| Revocable | meaningless at that lifetime | required |

They are deliberately **not** merged, and the audit trail names them
separately (`grant_id` vs `jit_grant_id`).

---

## 2. The enforced chain

```
Agent
  ↓  control-plane proof (Ed25519 over method+path+body_sha256+nonce+timestamp)
Control-Plane Authentication      ← who is calling?
  ↓
PIP                               ← what is true? (credentials, resource, approval, MANDATE)
  ↓
PDP / OPA                         ← is it permitted NOW?
  ↓
AEM                               ← enforce, and spend one use
  ↓
Protected resource
```

The mandate enters at the **PIP**, as one more fact, and is weighed by **OPA**
alongside everything else. It does not shortcut any step.

---

## 3. The grant, and what each field stops

```
agent_did · action · resource_type · resource_ids[] · purpose · constraints
```
digested into `binding_sha256`, and every field also inside the signed body.

| Bound | Attack it stops |
|---|---|
| `grant_id` | grant substitution |
| `agent_did` | agent substitution; lending a mandate |
| `action` | a `read` mandate used to `write` |
| `resource_type` | `credit_records` used for `payroll_records` |
| `resource_ids[]` | a record outside the mandate |
| `purpose` | purpose substitution |
| `constraints` | scope escalation (e.g. an amount ceiling) |
| `maxUses` | re-presenting a larger budget than granted |
| `notBefore` / `expirationDate` | expiry bypass, forward-dating |
| `issuer` + `kid` | forgery; enables safe rotation |
| `nonce` | duplicate issuance (`UNIQUE` in the database) |
| `domain` | cross-service replay |
| `proofPurpose: jitGrant` | cross-proof confusion — the **sixth** domain separator |

### Two deliberate omissions

**The use-time `request_id` is not bound.** An approval binds it because an
approval authorizes exactly one request. A mandate is reusable by definition
and spans several requests; binding it would make every mandate single-use by
accident — the Phase 5 approval with extra steps. The *issuing* request id is
carried for audit correlation and never compared at use time.

**`constraints` and `resource_ids` are excluded from the binding comparison.**
Both are properties of the mandate that the live request knows nothing about,
so comparing them for equality would deny every mandate that had any.
Containment is answered by `covers_resource()`; ceilings by
`evaluate_constraints()` against **live server-side attributes**.

### Scope is a ceiling, and is intersected — never unioned

Effective authority at use time is `grant.scope ∩ live_policy_decision`. A
mandate can only ever **narrow**. If policy would deny now, the mandate does
not rescue it. That is what makes scope expansion structurally impossible
rather than merely checked.

---

## 4. Lifecycle

```
ACTIVE ──use (budget left)──▶ ACTIVE
  ├──use (last of budget)───▶ EXHAUSTED   (terminal)
  ├──expiry reached─────────▶ EXPIRED     (terminal)
  └──revoke─────────────────▶ REVOKED     (terminal)
```

An explicit transition table with **empty sets** for all three terminal states,
so `EXPIRED → ACTIVE`, `EXHAUSTED → ACTIVE` and `REVOKED → ACTIVE` are refused
by name. A mandate cannot be un-spent, un-expired or un-revoked.

`EXHAUSTED` is deliberately distinct from `EXPIRED`: *"you spent your budget"*
and *"your window closed"* are different operator situations.

---

## 5. Issuance

```
POST /api/v1/jit/request      signed control-plane request
  ↓
ControlPlaneGuard("jit_request")     authenticate · nonce · freshness · body digest
  ↓                                  agent_self.rego: an agent may ask for ITSELF only
AEM.issue_jit_grant()
  ├─ 1. FULL data-plane PDP evaluation for the action being mandated
  │      ALLOW                    → proceed
  │      HUMAN_APPROVAL_REQUIRED  → NO MANDATE (see §8)
  │      DENY                     → NO MANDATE, refused for the SAME reason
  ├─ 2. policies/jit/issuance.rego  eligibility · TTL ≤ max · uses ≤ max
  └─ 3. sign with the ACTIVE key → persist → JIT_ISSUED
```

**The property this buys:** a mandate can only ever be issued for something the
agent could do *at that instant*. It can never confer authority the PDP would
have refused.

There is no `if agent_is_valid: issue_grant()` anywhere — issuance is two
policy evaluations and a signature, and a test asserts the ordering
structurally.

---

## 6. Enforcement

```
AEM.enforce(..., jit_grant_id=...)
  ↓  request built from the TOOL'S OWN SPEC, never the caller
PIP verifies → a verdict in input.pip.jit:
     signature · kid within its window · proofPurpose · domain ·
     binding digest · agent · action · resource ∈ resource_ids · purpose ·
     notBefore ≤ now < expiresAt · status · budget · constraints vs live attributes
  ↓
OPA — EVERY ordinary rule still runs
  ↓
ALLOW → record_use() atomically → mint EnforcementGrant → tool()
```

**A mandate is opt-in.** It applies exactly when its id is offered, and is never
auto-discovered. Auto-discovery would let a live mandate *reduce* an agent's
baseline authority — one whose ceiling a record had outgrown would start denying
actions the agent's own credential already permits. A mandate must only ever be
able to help.

**A blocked call does not spend the budget.** A refused action must not cost a
unit of somebody's mandate.

---

## 7. Policy

| Module | Package | Decides |
|---|---|---|
| `policies/jit/issuance.rego` | `agentic_iam.jit` | may a mandate be issued, with what bounds |
| `policies/jit/use.rego` | `agentic_iam.authz` | does a presented mandate contribute, and how does it fail |
| `policies/loan/application_read.rego` | `agentic_iam.authz` | may a loan application be **read** (see below) |

### Why `read` on `loan_applications` exists

The mandate's financial ceiling (`max_amount_inr`) is compared on every use
against the amount the PIP reads server-side. Until this rule existed that
ceiling had **no live path**: the only JIT-eligible action was `read` on
`credit_records`, which carries no amount, and every amount-bearing action is
excluded from JIT by T-2. A real security control shipped with nothing
exercising it end to end.

Reading an application closes that honestly. It is a genuine operation, it
carries an amount, and it is **not an approval action** — so T-2 is untouched.
An agent holding a mandate to read loans up to a ceiling still cannot approve
any loan, at any amount, with or without a mandate. Three tests assert exactly
that boundary.

The module introduces **no new cross-module rule name** — it consumes only
helpers already defined in `decision.rego`, which OPA loads first — so the
compile-order model is preserved and no seeding was required. All 15 modules
were re-loaded and verified after the change.

Split deliberately: *"may a mandate be issued?"* is a different question from
*"is this action permitted?"*, and evaluating it inside the data-plane combining
algorithm would let an issuance rule contribute a deny to an ordinary action
that never asked for a mandate.

### Configuration, not rules

`policies/data/jit_policy.json` → `data.agentic_iam.config.jit`:

```json
{ "max_ttl_seconds": 900, "max_uses": 5,
  "jit_eligible_actions": { "read": ["credit_records"] },
  "excluded_actions": { "actions": ["approve_loan", "disburse_funds", "override_decision"] },
  "max_amount_inr": { "value": 1000000 } }
```

**There is no TTL literal in Python and none in the rules.** A test greps both
to keep it that way.

**Fail closed:** remove the document and every issuance is
`DENY / JIT_POLICY_UNCONFIGURED`. An unconfigured maximum TTL is never
"unlimited" — the same failure Phase 5.5 closed for loan thresholds, and the
test genuinely deletes it from the running OPA and restores it.

---

## 8. The Phase 5.5 boundary holds

**JIT cannot be used to get around a human approval.** Two independent defences:

1. **Issuance refuses.** A `HUMAN_APPROVAL_REQUIRED` verdict produces no
   mandate. A mandate is not a human, and policy asking for a person is not
   satisfied by asking for a grant instead.
2. **Use would not help anyway.** `human_approval.rego` decides escalation and
   a mandate contributes nothing to it. A fabricated mandate for `approve_loan`
   is tested directly — the action stays escalated.

### `approve_loan` is excluded from JIT entirely

Recorded in the configuration itself, because a future operator *will* be asked
to add it:

> A mandate carries a human decision forward across several actions. For a loan
> approval that is exactly what Phase 5.5 exists to prevent — one officer's
> approval covering a burst of loans would defeat maker-checker. The amount band
> **is** re-evaluated on every use, so a loan drifting into the dual-control band
> is caught. But the first failure is not a policy question: a human who approved
> one loan did not approve five. Excluding the action is the honest answer;
> relying on the band check would be trusting a backstop to carry a decision
> nobody made.

The amount band being re-evaluated per use is tested regardless, as defence in
depth.

---

## 9. Underlying trust — the agreed semantics

**A mandate never outlives what it rested on.**

| Change | Effect | Mechanism |
|---|---|---|
| credential revoked | mandate stops working | automatic — the PIP re-verifies every use |
| credential expired | mandate stops working | automatic |
| agent suspended / terminated | mandate stops working | see §12 |
| approval withdrawn | derived mandates revoked | `revoke_for_approval()` |
| operator containment | all agent mandates revoked | `revoke_for_agent()` |

Because each use re-runs the full PDP, this falls out of the architecture rather
than needing a cascade — which is itself the strongest argument for the
grant-as-input design.

The credential ids are additionally recorded in `justification` and asserted by
`jit_credentials_still_valid` in Rego, so the **intent** is reviewable rather
than emergent. Nobody reading this later should have to infer from the absence
of a check that mandates were meant to outlive revocation.

---

## 10. Replay, concurrency and expiry

**Bounded multi-use**, chosen over the alternatives:

| Model | Verdict |
|---|---|
| single-use | rejected — that *is* the approval artifact; adds a TTL and nothing else |
| unlimited within TTL | rejected — a stolen grant is a licence for the whole window |
| **bounded multi-use** | **adopted** — blast radius bounded in *both* dimensions, both policy-capped |

> A mandate is a **budget**, not a key.

### The database arbitrates

```sql
UPDATE jit_grants SET uses = uses + 1
WHERE grant_id = :id
  AND status = 'ACTIVE'
  AND uses < max_uses
  AND expires_at > :now      -- expiry is in the SAME atomic condition
RETURNING uses, max_uses
```

Twenty concurrent callers against a budget of five produce exactly five winners
— tested with real tasks on real connections. Expiry is folded into the same
condition, so there is no window in which a mandate expires between the check
and the spend. A `CHECK (uses <= max_uses)` constraint holds even against a
direct write.

`UNIQUE (grant_id, request_id)` makes a retried request **idempotent** — a
client that did not see a response cannot burn a second use.

### Expiry

Server clock only. `now >= expires_at` is expired — the boundary instant
**denies**, matching the approval artifact exactly. The sweep is
**housekeeping, not enforcement**: a mandate past expiry is already unusable
before any sweep runs, and a test asserts precisely that.

---

## 11. Threat model

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| 1 | Stolen grant | **Not a bearer token** — use requires a control-plane signature from the bound agent DID | Low |
| 2 | Replay | bounded budget + atomic counter + idempotency key + TTL | Low |
| 3 | Forgery | Ed25519 over canonical JSON; KeyStore never exports | Low |
| 4 | Scope escalation | scope is a ceiling, intersected with the live decision; every field signed | Low |
| 5 | Confused deputy | resource/action from the ToolSpec; `jitGrant` domain separator | Low |
| 6 | Agent substitution | `agent_did` bound; control-plane proof must match | Low |
| 7 | Resource substitution | `resource_ids` bound; membership checked | Low |
| 8 | Clock manipulation | server clock only; agent clocks never read | Low |
| 9 | Race on the last use | one conditional UPDATE | Low |
| 10 | Unauthorized issuance | control-plane auth + full PDP + issuance Rego | Low |
| 11 | Revoked credential | re-verified live every use | Low |
| 12 | **Database tampering** | signature covers scope and expiry, so an edited artifact fails — **but `uses` and `status` are not signable** | **Medium, accepted** |
| 13 | **Compromised agent** | bounded TTL and budget cap the blast radius; revocation is immediate | **Medium, by design** |
| 14 | Compromised issuer | rotation + revocation; **separate key from the approval authority** | Low |
| 15 | Excessive TTL | policy-capped, fails closed | Low |

Threat 12 is the honest limit of any database-backed revocation, including the
Phase 5 approval state. It is not new in Phase 6, and is recorded rather than
implied away.

---

## 12. A Phase 4 gap found and closed

While testing matrix item V (deactivated agent), a **pre-existing Phase 4 gap**
surfaced: the PIP has always reported `subject.active`, and **nothing read it**.
A SUSPENDED agent holding a still-valid credential was authorized exactly like
an active one — so suspending an agent did not actually stop it; only revoking
every credential it held did.

This was verified as pre-existing and entirely independent of Phase 6 (no
mandate involved). `security/credential_state.rego` is now **v2** and denies a
resolved-but-not-ACTIVE subject, with its own detail so *"we do not know who
this is"* stays distinguishable from *"we know exactly who this is, and it is
suspended"*.

**This corrects a claim in the approved Phase 6 plan**, which stated agent
suspension was already handled automatically via `subject.active`. It was not.
No existing test regressed.

---

## 13. Security boundaries

| Role | Principal | Cannot |
|---|---|---|
| authenticates the caller | control-plane proof, Ed25519 | — |
| decides | PDP → OPA | sign, enforce |
| **signs mandates** | `did:poc:service:jit-authority` | decide, administer anything |
| signs approvals | `did:poc:service:approval-authority` | mint a mandate |
| verifies | PIP, on every use | decide |
| enforces | AEM | decide |

**The JIT key is deliberately not the approval key.** Attesting that a human
decided something and minting temporary machine authority are different powers;
sharing a key would mean compromising it yields *both* — precisely the pair an
attacker would want together. Tested directly.

**Who may do what:**

| | `jit_request` | `jit_revoke` | `jit_key_rotate` |
|---|---|---|---|
| agent (about itself) | ✅ | ❌ | ❌ |
| agent (about another) | ❌ | ❌ | ❌ |
| machine administrator (`identity_admin`) | ✅ (`enforcement`) | ✅ | ✅ |
| any human role | ❌ | ❌ | ❌ |

Humans are denied `jit_request` and `jit_key_rotate` by name: a mandate is
machine authority obtained by proving control of a key, and a browser session
asking for authority to be minted for a principal that is not them is exactly
the escalation this boundary refuses.

---

## 14. Audit

| Event | When |
|---|---|
| `JIT_REQUESTED` | a mandate is asked for, before any decision |
| `JIT_DENIED` | policy refused issuance — carries the reason |
| `JIT_ISSUED` | signed and persisted — scope, TTL, budget, justification |
| `JIT_USED` | each use — `uses/max_uses` and the request it served |
| `JIT_REPLAY_BLOCKED` | a spent, expired or revoked mandate presented again |
| `JIT_EXHAUSTED` / `JIT_EXPIRED` / `JIT_REVOKED` | how it ended |
| `JIT_KEY_ROTATED` / `JIT_KEY_REVOKED` | key lifecycle, `private_key_exposed: false` |

Every event carries `request_id`, `grant_id`, agent DID, action, resource,
decision and timestamp, so a whole mandate is reconstructible from the trail.
No secrets, no key material, no bearer tokens — tested.

---

## 15. Measured cost

Ten real cycles against the running stack, measured twice on different days.
Nothing modelled.

| Stage | 2026-09-18 median | 2026-09-21 median |
|---|--:|--:|
| Mandate issuance (control plane + PDP + policy + signature) | 408 | 784 |
| Verification + PDP re-evaluation + enforcement, **with** a mandate | 393 | 767 |
| The same call **without** a mandate (Phase 4 baseline) | 387 | 754 |
| End-to-end: ask for a mandate, then use it | 798 | 1567 |
| **Mandate overhead on the enforcement path** | **+6.5** | **+13.3** |

All milliseconds.

**The absolute figures roughly doubled between the two runs, and the reason is
not Phase 6.** The PIP re-verifies *every* credential the subject holds on every
authorization call, and `risk-001` accumulates a fresh credential on each gate
run — by the second measurement it held well over a hundred. That cost is
Phase 4's shape and it dominates both columns equally, which is exactly why the
*baseline* row moved in lockstep with the mandate row.

**The number that actually describes Phase 6 is the last row: ≈ 6–13 ms.** That
is the cost of verifying a signature, comparing a binding and spending a use
atomically. The PDP evaluation happens either way — which is the point of the
design, and is visible here as the two middle rows staying within ~15 ms of
each other in both runs.

For comparison, Phase 5.5 measured end-to-end human approval at ≈867 ms. A
mandate is not faster than an approval — it removes the *human*, not the
machine work. What it buys is that the second, third and Nth operation need no
human at all, each still getting its own PDP decision.

*Operational note:* an environment that wants representative latency should
prune accumulated demo credentials first. Nothing in the system depends on
this; it is a property of running the same gate repeatedly against one agent.

## 16. What Phase 6 deliberately did not do

* no new `Decision` value — still `ALLOW` / `DENY` / `HUMAN_APPROVAL_REQUIRED`
* no A2A, no MCP security, no Session Authority, no kill switch, no trust
  scoring, no anomaly detection
* no change to `EnforcementGrant`
* no mandate for any action that requires a human
* no test deleted, and none weakened

### Clean integration points left for later phases

* `JITService.revoke_for_agent(did, reason)` — called by the control-plane route
  today; Phase 10 (threat detection) and Phase 12 (kill switch) are the callers
  that do not exist yet
* `jit_grants.session_id` — present and NULL, so Phase 9 can bind sessions
  without a migration

---

## 17. Known limitations

1. **A mandate is opt-in, so it constrains the mandated path, not the agent.**
   An agent that simply does not present a revoked mandate falls back to its
   ordinary credential authority — which is Phase 4 behaviour, unchanged. A
   mandate is a *pre-authorization* mechanism, not a *restriction* mechanism.
   Making a mandate mandatory for an action is a policy switch this design
   supports but does not ship.
2. **`uses` and `status` are database state and cannot be signed** (threat 12).
3. **Rotation is compensating, not transactional.** A failure between retiring
   the outgoing key and registering the new one rolls the retirement back so
   the authority can still sign. Found by running the gate twice, and now
   tested three ways. `ApprovalAuthority.rotate()` (Phase 5.5) has the same
   original shape and the same latent failure; it was left alone rather than
   edited under a Phase 6 change, and is worth revisiting.
4. **`jit_authority_keys` duplicates the shape of `approval_authority_keys`.**
   Generalising into a shared register is cleaner and also edits a table three
   green gates depend on; the duplication is the lower-risk move and is recorded
   rather than hidden.
5. **Only `read` on `credit_records` and `read` on `loan_applications` are
   JIT-eligible as shipped.** Widening the list is a configuration change that
   should be accompanied by the analysis §8 describes.

---

## 18. Verification

| | |
|---|---|
| Baseline before Phase 6 | 664 passed, 0 failed |
| **After Phase 6** | **856 passed, 0 failed, 0 skipped** |
| New tests | **192** |
| Phase 6 gate | **113 / 113** |

New test files: `test_jit_grant_artifact.py` (49), `test_jit_lifecycle.py` (40),
`test_jit_policy.py` (31), `test_jit_key_rotation.py` (26),
`test_phase6_security_matrix.py` (46).

All eight gates green on the same run: Phase 1 12/12, Phase 2 30/30, Phase 3
40/40, Phase 4 31/31, Phase 4.5 46/46, Phase 5 67/67, Phase 5.5 110/110,
Phase 6 113/113.

> A mandate is an input to authorization, never a substitute for one.
> Every use is re-decided — revoke the credential and the mandate stops.
> A mandate is a budget and a window, both capped by policy.
> A mandate is not a human.
>
> **Policy decides. The database arbitrates. The AEM enforces.**
