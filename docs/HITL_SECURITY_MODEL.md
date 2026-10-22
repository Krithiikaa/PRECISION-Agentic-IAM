# HITL Security Model

Phase 4 made `HUMAN_APPROVAL_REQUIRED` a decision value with nothing behind it.
This document describes what is now behind it — and, as importantly, what is
still not.

**Updated for Phase 5.5**, which hardened this model: the amount is now an
authorization input and part of the binding, dual control is enforced by the
database, maker ≠ checker, and the signing key can rotate without invalidating
history. Sections marked *(5.5)* are new or materially changed.
`docs/PHASE_5_5_ARCHITECTURE.md` carries the full design.

---

## 1. Five things, kept apart

| | Answers | Established by | Evidence |
|---|---|---|---|
| **Agent credential** | "the issuer says this agent has capability X" | Phase 2 verifier | VC, `assertionMethod` |
| **Human identity** | "Keycloak says this is Priya Raman" | OIDC validation | RS256 JWT via JWKS |
| **Human approval** | "Priya agreed to THIS action, once" | HITL service | Ed25519 artifact, `humanApproval` |
| **Authorization** | "this action may proceed" | PDP | OPA/Rego decision |
| **Enforcement** | "the tool may run" | AEM | single-use `EnforcementGrant` |

Each is produced by a different component, carries different evidence, and has
a different lifetime. The failure mode this table exists to prevent is
collapsing any two of them:

* **An OIDC token is not an approval.** It says who someone is, not what they
  agreed to. A system that accepted a token as consent would let anyone who can
  log in authorize anything they can reach.
* **An approval is not a credential.** It authorizes one action once; it never
  becomes standing permission, and it never grants the agent a capability.
* **An approval is not an authorization.** The PDP is asked again.
* **A human role is not an agent capability.** `LOAN_OFFICER` and
  `credit_analysis` live in different trust domains and never meet — no Rego
  rule reads a credential to decide a human's authority, and none reads a human
  role to decide an agent's.

---

## 2. Human identity

**Keycloak 26**, real, in `docker-compose.yml`, realm versioned at
`keycloak/realm-agentic-iam.json`.

| | |
|---|---|
| Realm | `agentic-iam` |
| Issuer | `http://localhost:8080/realms/agentic-iam` |
| Client | `agentic-iam-console` — public, Authorization Code + **PKCE (S256)** |
| Audience | `agentic-iam-api`, added by an explicit audience mapper |
| Roles | `IAM_ADMIN`, `LOAN_OFFICER`, `AUDITOR` |
| Port | published on **127.0.0.1:8080** only, as with OPA |

The audience mapper matters. Keycloak's default access-token audience is
`account`, which would make an `aud` check either impossible or vacuous. Rather
than skip the check, the realm states who the token is *for*.

### What is validated, on every request

| Check | Why it is there |
|---|---|
| Signature (RS256 via JWKS) | the only thing that makes any other claim meaningful |
| Algorithm **allowlist** | `alg: none` and HS256 key-confusion are the two classic JWT forgeries |
| Issuer, exact match | a token from another realm is a valid token about a different system |
| Audience contains ours | otherwise a token minted for any other client in the realm is accepted |
| `exp`, server clock, bounded skew | |
| `nbf` / `iat` | a post-dated token is not accepted early |
| `sub` present | no subject, no principal |

Claims are read only from a payload whose signature already verified. The JWKS
is fetched live and cached by `kid`; an unknown `kid` forces one refresh, so a
key rotation needs no restart. **A JWKS fetch failure is an authentication
failure**, never a fallback to an unverified decode.

### What is stored

`human_principals` holds the minimum: subject + issuer (unique together — a
`sub` is only unique within its issuer), provider, display fields, a local
status, and `last_seen_roles`.

**`last_seen_roles` is an audit record and is never read when deciding
anything.** Authorization roles come from the validated token on every request,
so removing `LOAN_OFFICER` in Keycloak takes effect on the next call with no
cache to invalidate and no window where a stored copy still says yes.

No password, no access token, no refresh token, no client secret, no session.

### Token storage in the console *(5.5)*

The console's access token is held in a **module-scoped variable — in memory
only**. Phase 5 kept it in `sessionStorage`; that was honestly labelled but
strictly worse, because a token at rest in web storage survives navigation and
is readable by any script reaching the origin at any point in the tab's life.

*What this buys:* the token is gone on reload, navigation and tab close; no
persisted copy exists to scrape; no other tab on the origin can reach it. The
refresh token is deliberately never read at all.

*What it does not buy, stated plainly:* **this is not XSS protection.** Script
running in the page can read the variable, or simply call the API with the
browser's ambient state. No browser-side storage choice fixes that — only a
backend-for-frontend holding the token behind an httpOnly cookie does, and that
means server-side sessions, which is **Phase 9's Session Authority**. Building a
second one here would collide with it.

*The accepted cost:* a page refresh signs you out. `localStorage` was rejected
outright — it persists across tabs and browser restarts, strictly worse than
what Phase 5 had.

The PKCE verifier and `state` remain in `sessionStorage` and **must**: they have
to survive the full-page navigation to Keycloak and back. They are single-use,
short-lived, useless without the matching code, and deleted the moment the
callback is handled. Storing `state` is what makes the callback
CSRF-resistant — it is the security measure, not a compromise of one.

---

## 3. SAML

**OIDC is implemented. SAML federation is a documented integration path, not a
faked one.**

    Enterprise IdP ──SAML──▶ Keycloak ──OIDC──▶ this application

Keycloak is the SAML Service Provider. The application never parses a SAML
assertion and never sees one — it consumes only the OIDC token Keycloak issues
afterwards. Federating a real enterprise IdP therefore means configuring an
Identity Provider in the realm and mapping its attributes onto the three realm
roles. **No application code changes**, because the boundary was drawn there
deliberately.

It is not demonstrated because no second real IdP is available to federate
against on this host, and a stubbed SAML endpoint would be a lie about what has
been proven.

*(5.5)* The honesty of that claim is now **enforced by tests**, not just
asserted here: `TestSAMLStatus` checks that no SAML endpoint is exposed, that no
SAML assertion parsing exists in the application, that no SAML library is a
dependency, and that the configured provider reports itself as OIDC. If anyone
ever stubs SAML, those tests fail.

---

## 4. The approval artifact

### Who signs it, and why not the obvious candidates

**Not the agent.** If its key signed the artifact, it could manufacture its own
human approval and the entire phase would be theatre.

**Not Keycloak.** Keycloak signs *identity* tokens. It never sees the approval
screen and has no idea what a loan is. Claiming it signs approvals would be
false.

**Not the human.** People here hold no key material. Issuing one to every human
would be a second PKI, and still a key they never actually control.

So: a distinct **service principal** with its own Ed25519 key, DID and
published DID Document, in the same KeyStore as everything else —

    did:poc:service:approval-authority

**What the artifact actually means**, stated without overclaiming:

> *"I, the approval authority, authenticated this human against Keycloak,
> showed them exactly this action, and they decided X."*

It is attributable to the human **through** the service. That is the honest
strength of the model.

Separation is real and tested: no agent, no credential issuer and no
control-plane administrator holds this key, and the authority holds **no
control-plane roles** — signing approvals confers no authority over agents,
credentials or policy.

### Format

The project's existing shape, not a new one: canonical JSON (RFC 8785 style) +
Ed25519 + `PocEd25519Signature2026`, signed through the **Phase 2
`signing_payload`** so the proof options are inside the signature. Flipping
`proofPurpose` on a signed artifact invalidates it rather than repurposing it.

Five proof purposes now exist, each its own domain:

| Proof | Purpose | Signed by |
|---|---|---|
| Credential | `assertionMethod` | the issuer |
| Presentation | `authentication` | the holder |
| ANS registration | `ansRegistration` | the agent |
| Control-plane request | `controlPlaneRequest` | the principal |
| **Human approval** | **`humanApproval`** | **the approval authority** |

A signature made for one can never verify as another.

---

## 5. Binding — the core requirement

The artifact does **not** say "a human approved this agent". It says:

> human `sub` at issuer `iss` approved agent `did` performing `action` on
> `resource_type`/`resource_id` for `purpose`, under request `request_id`,
> valid until `expires_at`, **once**.

`binding_sha256` is a digest over the request-defining tuple:

```
request_id · agent_did · action · resource_type · resource_id · purpose
           · amount_inr · currency · submitted_by          ← added in 5.5
```

At re-evaluation the PDP recomputes it **from the live authorization request and
the live resource record** and compares.

**Why the amount is in there *(5.5)*.** An approval means "I, a named person,
agreed to THIS". A person shown ₹25,00,000 agreed to ₹25,00,000. If the amount
can move afterwards while the approval stays valid, the signature attests to a
decision nobody made. The material attributes are read **server-side, on both
sides of the comparison** — never from a caller, and never from the browser that
displayed them.

So: approve ₹25,00,000, amend the loan to ₹2,50,00,000, and re-evaluation
produces `APPROVAL_BINDING_MISMATCH` naming `amount_inr`. **DENY.** The approval
record itself is untouched — amending a loan does not rewrite what a person
agreed to; it makes what they agreed to no longer match.

Change any one field and the approval simply does not apply — there is nothing
to bypass, because the artifact was never about that action. The denial names
the field that moved, so an operator learns *"the resource changed"* rather
than *"invalid"*.

Each bound field is also inside the signed document, so tampering is already a
signature failure. The digest is what lets policy ask *"is this approval about
THIS request?"* as one comparison instead of twelve.

The complete bound surface, and what breaks if each is changed:

| Bound | Where | Effect if changed |
|---|---|---|
| agent · request · action · resource · purpose | digest + signed body | binding mismatch |
| amount / material financial attributes *(5.5)* | `amount_inr`, `currency`, `submitted_by` | binding mismatch |
| domain | proof `domain` + `proofPurpose: humanApproval` | signature failure |
| expiry | `expirationDate` | refused after expiry |
| nonce | signed, `UNIQUE` in the database | replay refused |
| approver · decision | signed body | signature failure |
| `requiredApprovals` *(5.5)* | signed body | signature failure |

`proofPurpose: humanApproval` is a **domain separator inside the signed bytes**,
so a credential, holder, ANS or control-plane proof can never verify as an
approval, and an approval can never be presented as any of them.

**A retry under a new `request_id` is a new request and needs its own
approval.** That is the intended semantics, not a limitation, and the
escalation response says so explicitly (`retry_with_request_id`).

---

## 6. Lifecycle

```
PENDING ──approve──▶ APPROVED ──consume──▶ CONSUMED
   │                    │
   ├──reject──▶ REJECTED└──expire──▶ EXPIRED
   ├──expire──▶ EXPIRED
   └──cancel──▶ CANCELLED
```

Terminal is terminal, enforced by an explicit transition table.
`REJECTED`, `EXPIRED`, `CANCELLED` and `CONSUMED` have **empty** transition
sets, so all four forbidden moves fail by name: `CONSUMED → APPROVED` (an
approval cannot be un-spent), `REJECTED → APPROVED` (a refusal cannot be
reinterpreted), `EXPIRED → APPROVED`, `CANCELLED → APPROVED`.

**Dual control adds no state *(5.5)*.** An approval that needs two people and
has one is still `PENDING` — it is still waiting on a human, which is exactly
what `PENDING` means. The table above is untouched; what changed is that the
move to `APPROVED` requires N distinct sign-offs instead of one.

**Expiry** is server-side, written once at decision time, never silently
extended, and never read from a client clock. A `PENDING` request past its
deadline cannot be decided at all. Expiry is folded into the *same atomic
condition* as consumption, so there is no window in which an approval expires
between the check and the update.

**Consumption** happens at AEM enforcement — once — via a single conditional
`UPDATE ... WHERE approval_id = ? AND status = 'APPROVED' AND expires_at > now`.
The database decides the winner, so two concurrent requests presenting the same
approval cannot both proceed. A test races three separate connections and
asserts exactly one wins.

The approval is spent **before** the tool runs. If the tool then fails, the
approval is still gone: a human approved one attempt, and a failed attempt was
that attempt. Handing back a fresh chance would turn a single-use approval into
a retry budget nobody granted.

A `/authorize` call evaluates but does **not** consume. Asking is not acting.

---

## 7. PDP re-evaluation

There is no path from "a human clicked approve" to ALLOW that skips policy.

```
PIP  verifies the artifact  →  reports a VERDICT
Rego decides what the verdict means
```

Exactly the pattern credentials already use: Python establishes facts, Rego
decides. Rego never sees a signature.

| Policy | Rule |
|---|---|
| `security/sensitive.rego` **v2** | escalate a sensitive action **while it is unapproved** |
| `security/human_approval.rego` | expired / consumed / rejected / tampered / forged each deny **by name** |
| `loan/approval.rego` | ALLOW `approve_loan` only with a valid scoped credential **AND** a valid bound approval |

The v2 change to `sensitive.rego` is the whole mechanism. Without the approval
condition an approved action would escalate forever; with it, the second
evaluation can reach ALLOW.

A human approval is an **additional** requirement, never a substitute. An agent
with a signed approval and no credential is still denied: approving an action
does not give the agent the standing to perform it.

---

## 8. Authorizing the approver

Not every authenticated human may approve every action (§29). The question
*"may this person approve THIS?"* is itself an authorization decision, so it
goes to the same PDP and the same OPA — in `control_plane/humans.rego`.

The action being approved is read from the **approval record**, server-side,
never from the request body. A caller claiming `{"action": "read"}` to slip a
loan approval past a weaker check is exactly what that resolver prevents.

| Role | May | May not |
|---|---|---|
| `LOAN_OFFICER` | approve loan decisions | anything in IAM; any policy change |
| `IAM_ADMIN` | agents, credentials, identity signing, audit ingest | **approve loans** |
| `AUDITOR` | read the audit trail; view an approval | approve or change anything |
| *(no roles)* | authenticate | everything |

Neither administrative role is a superset of the other, and there is
deliberately no role that is both. **No human administers policy**: changing
what the system enforces requires a machine principal with a key, not a browser
session.

---

## 9. S-7, closed

| Operation | Human | Machine |
|---|---|---|
| `agent_create` | `IAM_ADMIN` | `identity_admin` |
| `agent_status_change` | `IAM_ADMIN` | `identity_admin` |
| `credential_issue` | `IAM_ADMIN` | `identity_admin` |
| `credential_revoke` | `IAM_ADMIN` | `identity_admin` |
| `credential_present` | `IAM_ADMIN` | `identity_admin` |
| `audit_ingest` | `IAM_ADMIN` | `identity_admin`, or an **agent for itself** |

Unauthenticated credential issuance was the sharpest of these: a caller could
mint itself a capability credential and the PDP would faithfully ALLOW on it.

Two consequences worth stating:

**Agents no longer create their own identities.** They used to POST
`/api/v1/agents` at startup, which meant anyone who could reach the port could
mint `did:poc:agent:risk-001` under their own key before the real agent
started. Provisioning is now an authorized administrative act
(`scripts/provision_agents.py`, run by `run_local.sh`), and an agent that finds
no identity **refuses to start** rather than serving unregistered.

**Agents sign their audit events.** Ingest was open, which made every event's
`agent_did` a claim and the trail forgeable in both directions — inventing
events, or burying real ones. An agent now writes only for itself, with the
same proof it uses for a heartbeat.

---

## 10. Fail closed

| Condition | Result |
|---|---|
| No token | 401, action blocked |
| Invalid / expired / wrong-issuer / wrong-audience token | 401 |
| **Keycloak unreachable** | 401 — no human can approve, action stays blocked |
| Human authenticated, wrong role | 403 |
| Agent or machine key attempting to approve | 403 |
| Approval missing, pending, rejected, expired, consumed | DENY |
| Approval bound to another request | DENY |
| Approval signature invalid, or signed by anything else | DENY |
| **OPA unreachable** | DENY / 403 |

`HITL_ENABLED` cannot be set to false — a validator refuses to start. An action
policy referred to a human must never proceed because a flag was flipped.

Verified live with Keycloak genuinely stopped: the provider reports
unavailable, approval is refused, the agent retries, and the decision stays
`HUMAN_APPROVAL_REQUIRED`. It never became ALLOW.

---

## 11. Audit

The full lifecycle, correlated by `request_id` and `approval_id`:

`HUMAN_AUTHENTICATED` · `HUMAN_AUTHENTICATION_FAILED` ·
`HUMAN_PRINCIPAL_REGISTERED` · `APPROVAL_REQUESTED` · `APPROVAL_VIEWED` ·
`APPROVAL_APPROVED` · `APPROVAL_REJECTED` · `APPROVAL_EXPIRED` ·
`APPROVAL_CANCELLED` · `APPROVAL_CONSUMED` · `APPROVAL_REPLAY_REJECTED` ·
`AUTHORIZATION_REEVALUATED`

`APPROVAL_VIEWED` is auditable evidence that the decision was **informed**: an
approval nobody opened is a different thing from one somebody read.
`AUTHORIZATION_REEVALUATED` is the evidence that a human decision did not
become an ALLOW on its own.

One real loan decision produces **28 correlated events** under a single request
id, from `AEM_INTERCEPT` to `TOOL_EXECUTED`.

**No secret is ever logged** — not the access token, not a refresh token, not a
password. Tested by asserting the live token does not appear in the trail.

---

## 12. Measured cost

10 real cycles against the running stack. Measured, not modelled.
**Re-measured for Phase 5.5**; the Phase 5 figures are kept for comparison.

| | min | median | p95 | max |
|---|--:|--:|--:|--:|
| OIDC validation (`GET /hitl/me`) | 9.99 | **11.08** | 14.00 | 15.53 |
| Approval request creation | 353.23 | **377.32** | 442.95 | 517.19 |
| Approval decision + signing | 55.44 | **62.54** | 80.35 | 81.57 |
| PDP re-evaluation + enforcement | 362.27 | **396.92** | 441.01 | 447.37 |
| End-to-end, single approval | 783.77 | **866.94** | 907.94 | 1046.14 |
| End-to-end, **dual control** | 842.48 | **867.82** | 922.25 | 926.54 |

All in milliseconds.

### Against Phase 5

| Stage | Phase 5 median | Phase 5.5 median | Δ |
|---|--:|--:|--:|
| OIDC validation | 10.36 | 11.08 | +0.7 |
| Approval decision + signing | 35.76 | 62.54 | +26.8 |
| PDP re-evaluation + enforcement | 243.75 | 396.92 | +153.2 |
| End-to-end | 531.27 | 866.94 | +335.7 |

The increases are real and explained, not mysterious. Re-evaluation now also
resolves material attributes server-side and recomputes the binding digest;
signing now resolves the active key from the register rather than using one
fixed key. Both are the cost of the properties this phase added.

**Dual control costs essentially nothing extra end-to-end** — 867.82 against
866.94 for a single approval. The second human's sign-off overlaps the first's,
so two people cost one cycle.

The large absolute figures remain dominated by the **PIP**, not by the approval
path: it re-verifies every credential the subject holds on every authorization
call, and `risk-001` has accumulated many since Phase 4. That was already the
shape of Phase 4's latency.

Nothing was optimised prematurely. For a flow that contains a real human
decision, sub-second machine time is not the bottleneck — the human is.

---

## 12a. Amount-based authorization *(5.5)*

Until Phase 5.5 a `LOAN_OFFICER` could approve **any** amount, because no amount
reached any decision — `approve_loan` escalated on the name of the action and
nothing else, so a five-lakh loan and a two-crore loan were the same
authorization question. They are not.

**The amount is never taken from the caller.** A server-side resolver reads the
loan application record; the PIP places it at
`input.pip.resource.attributes.amount_inr`. A caller may put anything in
`input.context` and no rule reads it.

**The rule is Rego; the numbers are configuration.** `policies/loan/amount.rego`
contains no numeric literal; thresholds live in
`policies/data/loan_amount_policy.json`, pushed into OPA by the PAP. What an
amount *means* is a security rule; what the numbers *are* is a lending decision.
**There is no `if amount > x` anywhere in Python.**

| Band | Outcome |
|---|---|
| ≤ `agent_autonomous_limit_inr` | `ALLOW` — the agent's own credential suffices |
| ≤ `single_approver_limit_inr` | one authorized `LOAN_OFFICER` |
| above that | `DUAL_APPROVAL_REQUIRED` — two distinct humans |

Below the autonomous limit the agent still needs a valid credential scoped to
the resource and issued for the purpose: **the amount removes the human, not the
authorization.**

`DUAL_APPROVAL_REQUIRED` is a **reason, not a fourth decision value** — the
decision set stays `ALLOW` / `DENY` / `HUMAN_APPROVAL_REQUIRED`, so the
enforcement pipeline is unchanged. `required_approvals` is recomputed live on
every evaluation rather than read back from the approval record: an attacker who
could lower the stored number would otherwise lower the requirement.

**Fail closed.** If the configuration is absent, every loan decision is
`DENY` / `LOAN_POLICY_UNCONFIGURED`. An unconfigured threshold is never "no
limit". If the amount cannot be established, `RESOURCE_ATTRIBUTES_UNAVAILABLE`.

---

## 12b. Dual control and approver separation *(5.5)*

**The database refuses the same human twice — not an `if` in Python:**

```sql
UNIQUE (approval_id, approver_issuer, approver_subject)
UNIQUE (approval_id, sequence)
```

Human A signs; Human A attempts a second sign-off; the *database* rejects it and
the service reports `APPROVER_ALREADY_SIGNED`. Human B signs, the PDP
re-evaluates, and the action is permitted. Each sign-off is **independently
authenticated** — a fresh OIDC token validated against the JWKS every time.

Completion is atomic for the same reason consumption is: the flip to `APPROVED`
is a conditional `UPDATE ... WHERE status = PENDING RETURNING`, so two people
completing at the same instant produce exactly one artifact.

**Maker ≠ checker.** The application record names the officer who submitted it
(`submitted_by`); policy denies when the approver is that person
(`SELF_APPROVAL_PROHIBITED`). Nothing is read from the request. Whether this
applies is configuration, so disabling it is a reviewable change rather than
something a code path decides. A *different* officer may approve what the first
submitted — that is the point of maker-checker.

Alongside it: `AGENT_MAY_NOT_APPROVE` (an agent may never satisfy a human
approval), `MACHINE_MAY_NOT_APPROVE` (administering the system does not confer
the ability to approve loans), `HUMAN_MAY_NOT_APPROVE_THIS` (wrong role).

The artifact carries `approvers` (every sign-off, in order) and
`requiredApprovals`; `approver` remains, naming the sign-off that *completed*
the approval, so Phase 5 readers are unaffected.

---

## 12c. Signing key rotation *(5.5)*

Phase 5 refused to rotate, because rotating would have invalidated every artifact
already issued. Right instinct, wrong conclusion: **a signing key that can never
change is a key you can never respond to a suspicion about.**

The fix is a **key register** rather than a single key.

```
generation 1   ACTIVE   ──rotate──▶  RETIRED at T1
generation 2                          ACTIVE (from T1)
```

* only the **ACTIVE** key signs — signing resolves the active row, never a `kid`
  somebody supplied, so a retired key cannot issue anything new
* the DID Document publishes **every** non-revoked verification method, so an
  artifact signed by generation 1 still verifies after generation 2 takes over
* a retired key's window ends at `retired_at`: an artifact *claiming* a later
  signing time is `APPROVAL_KEY_RETIRED`, while the history it really signed is
  untouched
* an unregistered `kid` is `APPROVAL_KEY_UNKNOWN`
* **no private key is exposed** — rotation asks the KeyStore to generate; it
  signs on request and never exports. No route returns private key material.

**Rotation is not revocation.** Rotation retires a key and keeps its history
valid; revocation says the key was never trustworthy and drops that history too.
Conflating them means either "we cannot rotate without an outage" or "a
compromised key keeps working".

Rotation is a **control-plane** operation requiring a machine administrator
holding `identity_admin`. No human role can perform it from a browser; a loan
officer certainly cannot. Both are tested.

---

## 13. What this does not do

**No JIT.** Approval expiry bounds how long a *decision* stays usable, not how
long an agent holds permission. The future shape is
`human approval → PDP → JIT grant → temporary access → expiry`; none of it is
built.

**No Session Authority or SSS.** `approval_requests.session_id` exists and is
always NULL, so Phase 9 can bind sessions without a migration.

**No A2A, MCP security, anomaly detection, trust engine or kill switch.**

**Humans are not an identity provider here.** Keycloak is authoritative; this
system holds a shadow row for audit and a local suspension flag.

**The console's token is not protected from XSS** *(revised in 5.5)*. It is no
longer in `sessionStorage` — it is held in memory and dies on reload — but that
is a reduction in exposure, **not** XSS protection. Script running in an
authenticated console page can read the variable, or simply call the API with
the browser's ambient state. This is the standard limitation of a public SPA
client, and only a backend-for-frontend with an httpOnly cookie removes it —
which means server-side sessions, i.e. **Phase 9's Session Authority**. See §2.

**The approval artifact is not an access token, and must never become one.** It
carries one human's decision about one request, action, resource, amount and
context, with bounded validity and single use. It does not mean *"this agent is
trusted"* — it cannot be carried to another resource, replayed against a second
action, presented by a different agent, or held indefinitely.

**An approval is an input to authorization, never a substitute for one.** The
enforced order is

```
AUTHENTICATION → AUTHORIZATION → APPROVAL → RE-AUTHORIZATION → ENFORCEMENT
```

never authentication → approval → direct resource access. Human approval answers
*"what did they agree to?"*; only the PDP answers *"is this permitted now?"*.

**`MACHINE_ADMIN` is a machine principal class, not a human role** *(5.5)*.
`humans.rego` denies browser sessions `policy_*`, `ans_*`, `pdp_query` and
`aem_enforce` by name. Machine/control-plane authority is therefore the
`did:poc:administrator:*` class holding `identity_admin` / `policy_admin` /
`registry_admin`. Adding a human role able to perform machine operations would
undo that property, so it was deliberately not done.
