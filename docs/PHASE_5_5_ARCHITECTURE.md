# Phase 5.5 — HITL security hardening: architecture

Phase 5 proved a human could be put in the loop. Phase 5.5 is about what that
loop is *worth*. A human approval that does not name an amount, that one person
can satisfy twice, or that is signed by a key nobody can ever rotate, is a
control with the shape of a control and none of the substance.

This phase changed no decision values, added no new enforcement boundary and
built nothing from Phase 6. It closed eight specific gaps.

| # | Gap at the end of Phase 5 | Closed by |
|---|---|---|
| G-1 | `LOAN_OFFICER` could approve **any** amount — no amount reached any decision | §1 |
| G-2 | Approval binding excluded the amount, so the amount could move after approval | §2 |
| G-3 | No dual control — one human satisfied every approval | §3 |
| G-4 | Nothing stopped one human satisfying two approvals | §3 |
| G-5 | No maker-checker separation | §4 |
| G-6 | The approval-signing key could never rotate | §5 |
| G-7 | OIDC access token at rest in `sessionStorage` | §7 |
| G-8 | Approval queue polled; the live trace carried no HITL events | §8 |

---

## 1. Amount-based authorization

### The amount is an authorization input, not a display value

The single most important property: **the amount never comes from the caller.**

```
loan application record  ──▶  PIP  ──▶  input.pip.resource.attributes.amount_inr
   (server-side state)                        │
                                              ▼
                                        OPA decides
```

A caller may put anything in `input.context`. No rule reads it. The resolver is
`material_attributes()` in [resources.py](backend/app/enforcement/resources.py),
called by the PIP; a browser that displays ₹25,00,000 is *displaying* it, not
asserting it.

### Rules are Rego; thresholds are configuration

[`policies/loan/amount.rego`](policies/loan/amount.rego) contains no numeric
literal. The numbers live in
[`policies/data/loan_amount_policy.json`](policies/data/loan_amount_policy.json),
pushed by the PAP into OPA as `data.agentic_iam.config.loan`.

The split is deliberate: what an amount *means* is a security rule a reviewer
reads in Rego; what the numbers *are* is a lending decision a risk committee
changes without touching a rule.

**There is no `if amount > x` anywhere in Python.** Python gathers context and
enforces the result.

### The three bands

| Band | Condition | Outcome | Reason |
|---|---|---|---|
| autonomous | ≤ `agent_autonomous_limit_inr` | `ALLOW` | `WITHIN_AGENT_APPROVAL_AUTHORITY` |
| single | ≤ `single_approver_limit_inr` | `HUMAN_APPROVAL_REQUIRED` | `SENSITIVE_ACTION_REQUIRES_HUMAN` |
| dual | above that | `HUMAN_APPROVAL_REQUIRED` | `DUAL_APPROVAL_REQUIRED`, `required_approvals: 2` |

Shipped configuration: `agent_autonomous_limit_inr = 1000000` (₹10,00,000),
`single_approver_limit_inr = 5000000` (₹50,00,000).

The three demonstration scenarios land in the three bands **because of that
configuration**, not because any amount is written into a rule:

* ₹5,00,000 → autonomous → `ALLOW`
* ₹25,00,000 → single → one `LOAN_OFFICER`
* ₹2,00,00,000 → dual → two distinct humans

Below the autonomous limit the agent still needs everything Phase 4 required: a
valid credential, scoped to `loan_applications`, issued for this purpose. **The
amount removes the human, not the authorization.**

### `DUAL_APPROVAL_REQUIRED` is a reason, not a fourth decision

The decision set stays `ALLOW` / `DENY` / `HUMAN_APPROVAL_REQUIRED`. Dual
control rides as a *reason* plus `required_approvals: 2` on the same verdict, so
the enforcement pipeline is unchanged and no consumer learns a new value.

`required_approvals` is recomputed **live on every evaluation** from the
resource record — deliberately *not* read back from the approval record. An
attacker who could lower the stored number would otherwise lower the
requirement. The stored number is for the queue to display; the computed one
gates the action.

### Fail closed

If the data document is absent from the engine, every loan decision is
`DENY` / `LOAN_POLICY_UNCONFIGURED`. **An unconfigured threshold is never "no
limit"** — that is the single most dangerous way for a configuration document to
go missing. `tests/test_loan_amount_policy.py` genuinely removes it from the
running OPA and restores it afterwards.

If the amount cannot be established at all, the result is
`DENY` / `RESOURCE_ATTRIBUTES_UNAVAILABLE`. Nobody should be asked to approve an
amount nobody can state, and no agent should proceed on one either.

`disburse_funds` and `override_decision` keep their Phase 5 behaviour — always a
human — because widening an amount-based exemption to actions never analysed for
it is the wrong direction to be casual in.

---

## 2. Approval binding

`binding_sha256` is a SHA-256 over the canonical tuple of the fields that
*define* the request:

```
request_id · agent_did · action · resource_type · resource_id · purpose
           · amount_inr · currency · submitted_by          ← added in 5.5
```

At re-evaluation the PDP recomputes that digest from the **live** authorization
request and the **live** resource record and compares. Change any bound field
after approval and the digest differs, so the approval does not apply — there is
nothing to bypass, because the artifact was never about that action.

`differences()` names *which* field moved, so a denial is diagnostic: "the
resource changed" and "this is a different request" are very different
incidents.

### The full binding surface

Every field required by the specification, and where it lives:

| Bound | Where | Effect if changed |
|---|---|---|
| agent | `agent_did`, digest + signed body | binding mismatch |
| request | `request_id`, digest + signed body | binding mismatch |
| action | `action`, digest + signed body | binding mismatch |
| resource | `resource_type` + `resource_id`, digest | binding mismatch |
| purpose | `purpose`, digest + signed body | binding mismatch |
| amount / material financial attributes | `amount_inr`, `currency`, `submitted_by`, digest | binding mismatch |
| domain | proof `domain` + `proofPurpose: humanApproval` | signature failure |
| expiry | `expirationDate`, signed | refused after expiry |
| nonce | `nonce`, signed, `UNIQUE` in the database | replay refused |
| approver | `approver` + `approvers[]`, signed | signature failure |
| decision | `credentialSubject.decision`, signed | signature failure |
| required approvals | `requiredApprovals`, signed | signature failure |

The digest is belt and braces: every bound field is *also* inside the signed
document, so tampering with one is already a signature failure. The digest is
what lets policy express "is this approval about THIS request?" as one
comparison rather than twelve.

`proofPurpose: humanApproval` is a **domain separator inside the signed bytes**.
A credential proof, a holder proof, an ANS registration proof or a control-plane
proof can never verify as an approval, and an approval can never be presented as
any of them.

### Amount tampering, concretely

A loan of ₹25,00,000 is shown to a human, who approves it. The amount is then
amended to ₹2,50,00,000 through the only principal permitted to amend it (core
banking). On re-evaluation:

1. the PIP re-reads the amount **server-side** → 25000000
2. the binding is rebuilt → a different digest
3. `APPROVAL_BINDING_MISMATCH`, naming `amount_inr`
4. the PDP also now reaches the **dual** band, so even a fresh single approval
   would not satisfy it

**DENY.** The approval record itself is untouched — amending a loan does not
silently rewrite what a person agreed to; it makes what they agreed to no longer
match.

---

## 3. Dual control

### Dual control adds no state

An approval that needs two people and has one is still `PENDING` — it is still
waiting on a human, which is exactly what `PENDING` means. The transition table
is untouched. A `PARTIALLY_APPROVED` state would have been another
terminal-adjacent state to reason about, for no gain.

The count of sign-offs is a separate fact, in `approval_signoffs`.

### The database refuses the same human twice — not an `if`

```sql
UNIQUE (approval_id, approver_issuer, approver_subject)   -- one human, one sign-off
UNIQUE (approval_id, sequence)                            -- no gaps, no duplicates
```

This is the core of §6. Human A approves; Human A attempts a second sign-off;
the *database* rejects it, and the service reports
`APPROVER_ALREADY_SIGNED`. An application-level check would be a race with a
comfortable-looking shape. Human B then signs, the PDP re-evaluates, and the
action is permitted.

Each sign-off is **independently authenticated** — a fresh OIDC bearer token,
validated against Keycloak's JWKS, for every one.

### Completion is atomic

The flip to `APPROVED` is a conditional `UPDATE ... WHERE status = PENDING
RETURNING`. Two people completing a dual approval in the same instant both reach
that line; exactly one wins and signs. The loser is told the approval is no
longer pending rather than producing a second artifact for the same decision.

### Backwards compatibility

The artifact carries `approvers` (every sign-off, in order) and
`requiredApprovals`. `approver` remains, naming the sign-off that *completed*
the approval, so Phase 5 readers are unaffected.

---

## 4. Approver separation (maker-checker)

Server-side, from the resource record: the loan application names the officer
who submitted it (`submitted_by`). Policy denies when the approver is that
person — `SELF_APPROVAL_PROHIBITED`. Nothing is read from the request.

Whether this applies at all is configuration
(`separation_of_duties.prohibit_self_approval`), so turning it off is a
deliberate, reviewable change rather than something a code path decides.

A *different* officer may approve what the first submitted — that is the point
of maker-checker, not an accident of it.

Three refusals sit alongside it, each audited by name:

* `AGENT_MAY_NOT_APPROVE` — an agent may never satisfy a human approval
* `MACHINE_MAY_NOT_APPROVE` — administering the system does not confer the
  ability to approve loans
* `HUMAN_MAY_NOT_APPROVE_THIS` — wrong role

---

## 5. Approval authority key rotation

Phase 5 refused to rotate, because rotating would have invalidated every
artifact already issued. That is the right instinct and the wrong conclusion: a
signing key that can never change is a key you can never respond to a suspicion
about.

The fix is a **key register** rather than a single key.

```
generation 1   ACTIVE   ──rotate──▶  RETIRED at T1
generation 2                          ACTIVE (from T1)
```

| Property | Mechanism |
|---|---|
| exactly one key signs | signing resolves the `ACTIVE` row, never a `kid` somebody supplied |
| history stays verifiable | the DID Document publishes **every** non-revoked verification method |
| a retired key cannot issue | its validity window ends at `retired_at`; a later `created` is `APPROVAL_KEY_RETIRED` |
| an unknown key is refused | `APPROVAL_KEY_UNKNOWN` |
| no private key is exposed | rotation is a `generate_key` call; the KeyStore signs on request and never exports |

**Rotation is not revocation.** Rotation retires a key and keeps its history
valid; revocation says the key was never trustworthy and drops that history too.
Conflating them means either "we cannot rotate without an outage" or "a
compromised key keeps working". They are separate operations with separate
states (`ACTIVE` / `RETIRED` / `REVOKED`).

Rotation is a **control-plane** operation requiring a machine administrator
holding `identity_admin`. No human role can perform it from a browser — tested
explicitly. The key register is readable and carries no secret.

---

## 6. Security boundaries — who does what

This is the §10 answer, stated without overclaiming.

| Role | Principal | What it can do | What it cannot do |
|---|---|---|---|
| **authenticates** | Keycloak | states *who* a human is, issues the OIDC token | cannot manufacture an approval artifact; never sees the approval screen; has no idea what a loan is |
| **authorizes** | PDP → OPA | decides whether the action is permitted *now* | does not sign, does not enforce |
| **signs** | `did:poc:service:approval-authority` | the only principal able to sign an approval artifact | holds no policy authority; cannot decide |
| **verifies** | PDP, on re-evaluation | signature, purpose, binding, expiry, state | — |
| **enforces** | AEM | the boundary every action crosses | does not decide |

Deliberately excluded from signing:

* **not the agent** — if the agent's key signed, it could manufacture its own
  approval and the phase would be theatre. A test asserts the authority's key is
  no agent's key.
* **not Keycloak** — it signs *identity* tokens. Claiming it signs approvals
  would be false.
* **not the human** — people here hold no key material. Issuing one would be
  inventing a second PKI and would still be a key the person never controls.

What the artifact honestly means:

> "I, the approval authority, authenticated this human against Keycloak, showed
> them exactly this action, and they decided X."

It is attributable to the human *through* the service. That is the real strength
of this model, and the limit of it.

### The approval artifact is not an access token

It carries a specific human decision about a specific request, action, resource,
amount and context, with bounded validity and single use. It does **not** mean
"this agent is trusted". It cannot be carried to another resource, replayed
against a second action, presented by a different agent, or held indefinitely.

### The enforced order

```
AUTHENTICATION → AUTHORIZATION → APPROVAL → RE-AUTHORIZATION → ENFORCEMENT
```

Never authentication → approval → direct resource access. An approval is an
*input* to a later authorization decision, never a substitute for one. Human
approval answers "what did they agree to?"; only the PDP answers "is this
permitted now?".

---

## 7. Token storage decision

**Decision: the access token moved from `sessionStorage` to a module-scoped
variable — in memory only.**

Phase 5's `sessionStorage` was honestly labelled but strictly worse: a token at
rest in web storage survives navigation and can be read by any script that
reaches the origin at any point in the tab's life, not only while the page runs.

**What this buys:** the token is gone on reload, navigation and tab close; it is
not readable by a script that arrives after the fact; there is no persisted copy
to scrape from a shared or imaged machine; no other tab on the origin can reach
it. The refresh token is deliberately never read at all.

**What it does not buy, stated plainly because overclaiming is worse than the
gap:** *this is not XSS protection.* Script running in the page can read the
variable, or simply call the API with the browser's ambient state. No
browser-side storage choice fixes that. Only a backend-for-frontend holding the
token server-side behind an httpOnly cookie does — and that means server-side
sessions, which is **Phase 9's Session Authority**. Building a second one here
would collide with it.

**The accepted cost:** a page refresh signs you out. For a console whose only
privileged action is approving a loan, re-authenticating after a reload is the
right side of that trade.

`localStorage` was not considered: it is strictly worse than what Phase 5 had,
persisting across tabs and browser restarts.

The **PKCE verifier and `state` remain in `sessionStorage`, and must** — they
have to survive a full-page navigation to Keycloak and back, which is exactly
what an in-memory value cannot do. They are single-use, short-lived, useless
without the matching code, and deleted the moment the callback is handled.
`state` is what makes the callback CSRF-resistant, so storing it *is* the
security measure.

---

## 8. Approval-state updates

**Decision: reuse the existing SSE stream; keep polling as a slow backstop.**

The stream already exists, already carries approval-lifecycle events, and
already survives reconnection. Adding a socket layer for an approval queue would
be a large change to the least security-critical part of the system.

One `EventSource` is shared by every view; a second would double the server's
fan-out for nothing.

**What the events deliberately do not do: carry authorization meaning.** An
event says *"something changed, ask the server again"*. It never tells the
console that an approval succeeded — the console re-reads the queue and the
server answers. A UI that trusted an event's contents would be trusting a
broadcast to tell it what it is allowed to see.

Polling was made slower, not removed. SSE can drop; a backstop makes eventual
consistency certain.

Phase 5.5 also fixed a real omission: the HITL event types were declared in the
backend from Phase 5 but never subscribed to in the console, so **the live trace
showed everything except the human step it exists to demonstrate.**

---

## 9. SAML status

**OIDC is implemented. SAML federation remains a documented integration path,
and is not faked.**

```
Enterprise IdP ──SAML──▶ Keycloak ──OIDC──▶ this application
```

Keycloak is the SAML Service Provider. The application never parses a SAML
assertion and never sees one — it consumes only the OIDC token Keycloak issues.
Federating a real enterprise IdP means configuring an Identity Provider in the
realm and mapping attributes onto realm roles: **no application code changes**,
because the boundary was drawn there deliberately.

It is not demonstrated because no second real IdP is available to federate
against on this host, and a stubbed SAML endpoint would be a lie about what has
been proven. `TestSAMLStatus` enforces the honesty of that claim: no SAML
endpoint is exposed, no SAML parsing exists in the application, no SAML library
is a dependency, and the configured provider reports itself as OIDC.

---

## 10. Approval lifecycle

```
PENDING ──approve──▶ APPROVED ──consume──▶ CONSUMED
   │                    │
   ├──reject──▶ REJECTED└──expire──▶ EXPIRED
   ├──expire──▶ EXPIRED
   └──cancel──▶ CANCELLED
```

Transitions are an explicit table, not a convention. Anything absent is refused
by name. `REJECTED`, `EXPIRED`, `CANCELLED` and `CONSUMED` have **empty**
transition sets, so every one of the four forbidden moves fails:

* `CONSUMED → APPROVED` ✗ — an approval cannot be un-spent
* `REJECTED → APPROVED` ✗ — a refusal cannot be reinterpreted
* `EXPIRED → APPROVED` ✗
* `CANCELLED → APPROVED` ✗

**Expiry uses server-side time**, never the client's. A `PENDING` request past
its deadline cannot be decided at all. Expiry is folded into the *same atomic
condition* as consumption (`WHERE status = APPROVED AND expires_at > now`), so
there is no window in which an approval expires between the check and the
update. Nothing silently extends an expiry.

**Consumption is single-use and database-arbitrated**: one conditional `UPDATE
... RETURNING`. Two requests arriving together with the same approval both reach
it; one updates a row, the other updates none and is told the approval is
already consumed. Deliberately *not* a read-then-write.

Replay is refused on every axis — a different request, a different action or a
different agent each fail the binding comparison before consumption is even
reached, and the `nonce` is `UNIQUE` in the database.

---

## 11. Human roles

Realm roles in Keycloak: `LOAN_OFFICER`, `AUDITOR`, `IAM_ADMIN`.

| Principal | May | May not |
|---|---|---|
| `LOAN_OFFICER` | approve loans per the amount policy | modify IAM policy; rotate the signing key |
| `AUDITOR` | read the audit trail | approve a loan |
| `IAM_ADMIN` | administer identity | approve a loan |
| no-role human | authenticate | anything |
| machine administrator | control-plane operations, key rotation | approve a loan |
| agent | act on its own credential within its band | satisfy a human approval |

### `MACHINE_ADMIN` — a stated interpretation

The system deliberately keeps machine/control-plane authority away from browser
sessions: `humans.rego` denies humans `policy_*`, `ans_*`, `pdp_query` and
`aem_enforce` **by name**.

So `MACHINE_ADMIN` is implemented and tested as the **machine administrator
principal class** (`did:poc:administrator:*` holding `identity_admin` /
`policy_admin` / `registry_admin`), not as a new Keycloak realm role. Adding a
human role that could perform machine operations would undo an existing security
property, so it was not done. The matrix covers the class either way.

---

## 12. Audit

Every approval-lifecycle event carries `request_id`, `approval_id`, the human
principal, the agent DID, action, resource, decision and timestamp — so a
complete dual-control cycle is reconstructible from the trail alone. A measured
scenario-C cycle correlates **31 events under one `request_id`**.

Events added in this phase:

`APPROVAL_SIGNOFF_RECORDED` · `APPROVAL_DUPLICATE_APPROVER_REJECTED` ·
`APPROVAL_SELF_APPROVAL_REJECTED` · `APPROVAL_DUAL_CONTROL_SATISFIED` ·
`POLICY_ESCALATED` · `APPROVAL_KEY_ROTATED` · `APPROVAL_KEY_REVOKED`

`POLICY_ESCALATED` records **why** two people were needed — the tier and the
amount — so an escalation is explicable after the fact rather than merely
observable.

Refusals are audited as first-class events, by name: `SELF_APPROVAL_PROHIBITED`,
`APPROVER_ALREADY_SIGNED`, `HUMAN_MAY_NOT_APPROVE_THIS`, `AGENT_MAY_NOT_APPROVE`,
`MACHINE_MAY_NOT_APPROVE`.

**No secrets are logged.** Tested directly: no bearer token and no private key
material appears anywhere in the trail, and `APPROVAL_KEY_ROTATED` asserts
`private_key_exposed: false`.

---

## 13. Measured cost

Ten real cycles against the running stack on this host. Nothing modelled.

| Stage | min | median | p95 | max |
|---|---|---|---|---|
| OIDC validation | 9.99 | **11.08** | 14.00 | 15.53 |
| approval request creation | 353.23 | **377.32** | 442.95 | 517.19 |
| approval decision + signing | 55.44 | **62.54** | 80.35 | 81.57 |
| PDP re-evaluation + enforcement | 362.27 | **396.92** | 441.01 | 447.37 |
| end-to-end, single approval | 783.77 | **866.94** | 907.94 | 1046.14 |
| end-to-end, dual control | 842.48 | **867.82** | 922.25 | 926.54 |

All figures milliseconds.

### Against Phase 5

| Stage | Phase 5 | Phase 5.5 | |
|---|---|---|---|
| OIDC validation | ~10 | 11.08 | unchanged |
| decision + signing | ~36 | 62.54 | +27 |
| re-evaluation + enforcement | ~244 | 396.92 | +153 |
| end-to-end | ~531 | 866.94 | +336 |

The increases are real and explained, not mysterious: re-evaluation now also
resolves material attributes server-side and recomputes the binding digest, and
signing now resolves the active key from the register rather than using a single
fixed key. Dual control costs **essentially nothing extra end-to-end** (867.82
vs 866.94) — the second human's sign-off is concurrent with the first's, so two
people cost one cycle.

Nothing was optimised prematurely. Sub-second end-to-end for a flow that
includes a real human decision is not the bottleneck; the human is.

---

## 14. What Phase 5.5 deliberately did not do

* no new decision value — `ALLOW` / `DENY` / `HUMAN_APPROVAL_REQUIRED` stands
* no BFF or server-side session — that is Phase 9's Session Authority
* no SAML implementation — no real IdP to federate against; a stub would be a lie
* no replacement of polling with a new real-time subsystem — only reuse of the
  SSE stream that already existed
* no JIT access, no A2A, no MCP security, no SSS, no trust engine, no kill
  switch, no monitoring build-out
* no test deleted, and none weakened

---

## 15. Verification

| Gate | Result |
|---|---|
| Phase 1 | 12 / 12 |
| Phase 2 | 30 / 30 |
| Phase 3 | 40 / 40 |
| Phase 4 | 31 / 31 |
| Phase 4.5 | 46 / 46 |
| Phase 5 | 67 / 67 |
| **Phase 5.5** | **110 / 110** |
| Full suite | **664 passed, 0 failed, 0 skipped** |

Phase 5.5 added **97** tests: `test_loan_amount_policy.py` (17),
`test_dual_control.py` (15), `test_approval_key_rotation.py` (18),
`test_phase55_security_matrix.py` (47).

> The amount is an authorization input, not a display value.
> Two people means two people — one human signing twice is not dual control.
> Maker ≠ checker.
> A key can rotate without invalidating what it already signed.
>
> **Policy decides. The database arbitrates. The AEM enforces.**
