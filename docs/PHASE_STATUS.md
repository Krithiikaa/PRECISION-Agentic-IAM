# Phase status

The single source of truth for what actually runs. A phase is marked complete
only when its behaviour works against the live system and is covered by tests.

| Phase | Scope | Status |
|------:|-------|--------|
| 1  | Agent runtime, registry, DID identity, Ed25519, DID Document, PostgreSQL, agent lifecycle, Identity Lab (API + CLI) | **✓ COMPLETE** |
| 2  | Verifiable Credentials: issuer, verifier, status, presentations | **✓ COMPLETE** · **✓ HARDENED FOR FUTURE AUTHORIZATION INTEGRATION** |
| 3  | Agent Naming Service: signed registration, capability + credential-aware discovery, heartbeats | **✓ COMPLETE** · **✓ VERIFIED** |
| 4  | PDP / PIP / PAP, OPA + Rego, AEM | **✓ COMPLETE** · **✓ VERIFIED** — real OPA runtime, Rego policy, enforced tool boundary |
| 4.5 | Control-plane hardening: signed control-plane requests, administrator principals, control-plane Rego, OPA isolation | **✓ COMPLETE** · **✓ VERIFIED** — closes S-4, S-5 and S-6 |
| 5  | Human-in-the-Loop: real Keycloak/OIDC human identity, approval request + UI, signed bound single-use approval artifact, PDP re-evaluation, loan demonstration | **✓ COMPLETE** — closes S-7 |
| 5.5 | HITL security hardening: amount-based authorization in Rego, amount in the approval binding, dual control, maker-checker, approval signing-key rotation, token storage, SSE approval updates | **✓ COMPLETE** · **✓ VERIFIED** |
| 6  | Just-In-Time temporary access: signed time- and use-bounded mandates, policy-capped, revocable, re-decided on every use | **✓ COMPLETE** · **✓ VERIFIED** |
| 7  | Secure A2A transactions: signed envelope, receiver binding, exactly-once execution, four-way amount reconciliation, PAYMENT_OFFICER HITL and real dual control | **✓ COMPLETE** · **✓ VERIFIED** |
| 8  | MCP tool gateway | Not started |
| 9  | Session Authority, Session State Synchroniser (Redis) | Not started |
| 10 | Monitoring, audit UI, trust/risk engine, rule-based anomaly detection | Partial: event bus, audit trail and SSE stream exist; anomaly and trust do not |
| 11 | Kill switch, global revocation, cross-protocol termination | Not started |
| 12 | Frontend: topology, live trace, demo scenarios, SOC views | Partial: discovery and credentials consoles with the live trace exist; topology, loan UI and SOC views do not |

## Audit status

Last audit: **2026-08-30** — see [../PHASE_2_3_AUDIT.md](../PHASE_2_3_AUDIT.md).

| Phase | Status |
|---|---|
| 1 | VERIFIED |
| 2 | VERIFIED + HARDENED |
| 3 | VERIFIED |
| 4 | VERIFIED |
| 4.5 | VERIFIED |
| 5 | VERIFIED |
| 5.5 | VERIFIED |
| 6 | VERIFIED |
| 7 | VERIFIED |

| Finding | Severity | Status |
|---|---|---|
| S-1 credential verifier did not validate `proofPurpose` | LOW | **FIXED** |
| S-2 presentation audience (`domain`) signed but never enforced | MEDIUM | **FIXED** |
| S-3 `credential_verification_events.presentation_id` always NULL | LOW | **FIXED** |
| S-4 ANS heartbeat unauthenticated | HIGH | **FIXED** (Phase 4.5) |
| S-5 authorization / policy-administration APIs unauthenticated | HIGH | **FIXED** (Phase 4.5) |
| S-6 `/agents/{id}/sign` and `/identity/sign` are unauthenticated signing oracles | HIGH | **FIXED** (Phase 4.5) |
| S-7 Phase 1/2 identity control plane unauthenticated (agent creation and status change, credential issuance and revocation, holder-proof production, audit ingest) | HIGH | **FIXED** (Phase 5) |

Tests: **1123 passing, 0 failures, 0 skips.** Phase 1-3
baseline was 247; Phase 4 added 127; Phase 4.5 added 66; Phase 5 added 127;
Phase 5.5 added 97; Phase 6 added 192; Phase 7 added 267.

HOST NOTE, recorded because it is a real constraint rather than a flake: the
live Ollama generation test and the Phase 3 gate's coordinator steps need
`llama3:8b`, which wants 4.6 GiB. Keycloak takes about a gigabyte of this 6 GiB
host. Under memory pressure the Ollama test SKIPS loudly with the actual
figures rather than being weakened, and the Phase 3 gate reports the LLM as
unavailable rather than guessing. Both pass with memory available: the run
above is a full green suite, and the Phase 3 gate was confirmed 40/40 with
Keycloak stopped.

Live gates: Phase 1 **12/12**, Phase 2 **30/30**, Phase 3 **40/40**,
Phase 4 **31/31**, Phase 4.5 **46/46**, Phase 5 **68/68**,
Phase 5.5 **110/110**, Phase 6 **113/113**, Phase 7 **132/132**.
All nine confirmed green in one sweep on 2026-10-22.

Two gate assertions were rewritten in Phase 7, and neither weakened a control.
The Phase 4.5 gate hardcoded "7 agents" and now derives the count from the
agent catalogue -- adding an agent should not fail a control-plane
authentication gate. The Phase 5 gate asserted an exact list of attested
capabilities and now asserts the PROPERTY instead (the attested capability is
shown; DECLARED-only ones are not), because the list legitimately grew when
Phase 7 issued a second capability credential. Phase 5 went 67 -> 68 because
that one check became two.

PHASE 3 GATE: confirmed **40/40 on 2026-09-21**, in the same sweep as every
other gate. It had been temporarily blocked on 2026-09-18 by the host memory
constraint below -- its coordinator section needs `llama3` (4.6 GiB) and the
host had 3.7 GiB free even with the whole stack stopped. That was an
environment condition, never a code one, and it cleared on its own.

ENVIRONMENT NOTE (2026-09-16): the host upgraded `/usr/bin/python3` from 3.13 to
3.14, which orphaned the backend virtualenv — its `python3` symlink pointed at a
version whose `site-packages` it does not share, so every entry point failed with
`ModuleNotFoundError`. Fixed by repointing `.venv/bin/python3` at
`/usr/bin/python3.13`. No dependency was reinstalled and no code changed.

Next: **Phase 8 — MCP tool gateway** (NOT started).

## Phase 7 — what is real

Design: [PHASE_7_ARCHITECTURE.md](PHASE_7_ARCHITECTURE.md).

* **A valid A2A signature is NOT authorization.** It makes a transaction
  evaluable. Every transaction runs the full PIP -> OPA -> PDP path with the
  SENDER as subject, and a perfectly signed envelope from an agent whose
  credential was revoked a second ago is refused by the same Phase 4 rule that
  refuses an ordinary request.
* **Receiver binding is enforced three times**: the `receiverDid` is inside the
  signature, the control-plane guard requires the submitting principal to BE
  that DID, and policy asserts it again. The replay-toward-another-receiver
  attack is refused by `agent_self.rego`'s pre-existing `acts_on_self` rule --
  Phase 7 added one word to a set. **No administrator holds `a2a_submit`**,
  because one that did would be a privileged bypass of exactly that binding.
* **A payment executes AT MOST ONCE**, decided by the database:
  `UNIQUE (sender_did, transaction_id)` admits one processing path and a
  conditional `UPDATE ... WHERE status='AUTHORIZED'` admits one execution.
  Twenty concurrent submissions of one instruction produce exactly one
  execution and nineteen idempotent answers, tested with real tasks on real
  connections. Uniqueness is COMPOSITE so one sender cannot squat on another's
  id namespace.
* **A retry returns the recorded outcome and is never re-decided** -- the
  amount band, the credential state or an approval could all have moved since.
  The one exception is a transaction waiting for a human, which RESUMES, because
  that retry is how an approval takes effect.
* **The amount is signed, established server-side, authorized and executed --
  and all four must agree.** Four columns, four reconciliation points. A signed
  amount is evidence of what the sender intended, never evidence of the figure
  on the record. Disagreement denies and nothing moves, including when the
  record shifts between the decision and the handler.
* **A forged submission cannot burn a legitimate sender's transaction id**: the
  signature verifies BEFORE the ledger is written, and rejected envelopes go to
  `a2a_transaction_attempts` only.
* **Dual control on a payment is real, with Phase 5.5 untouched.** Routing
  through `approval_satisfied` would have consulted `required_approvals`, which
  `loan/amount.rego` defines as 1 for any non-loan action -- dual control would
  silently have become single control while passing every existing test. The
  A2A module counts the distinct approvers inside the VERIFIED artifact
  directly. One PAYMENT_OFFICER cannot release an above-threshold payment; two
  distinct ones can.
* **PAYMENT_OFFICER is a dedicated role**, not LOAN_OFFICER. Neither is a
  superset of the other, and both refusals are tested.
* **JIT cannot authorize a payment.** `execute_payment` is excluded by name AND
  absent from the allow-list, and issuance is refused by the stronger reason
  anyway: outside an A2A transaction the action is not permitted at all.
* **The ANS is not on the verification path.** Public keys come from the Phase 1
  DID Document registry, which the directory does not control, so an ANS
  compromise degrades to denial of service rather than unauthorized execution.
* **`decision.rego` and `security/sensitive.rego` are unmodified.** Phase 7
  introduces zero new cross-module Rego names -- the Phase 6 `rego_unsafe_var_error`
  hazard is closed by construction, and removing the A2A module leaves the rest
  of the set compiling and fails CLOSED.
* **No new signing authority.** An A2A transaction attests to what the SENDER
  instructed, so the sender's Phase 1 key is the correct signer. Two new proof
  purposes (`a2aTransaction`, `a2aResponse`) bring the domain separators to
  eight, and a proof made for any other purpose cannot verify as a transaction.

### Phase 7 — known gaps

* **No agent key-rotation OPERATION.** `KeyStatus.ROTATED` and
  `AgentKey.rotated_at` have existed since Phase 1 and nothing sets them.
  Phase 7 implements and tests the VERIFICATION side of the key window against
  those columns; the operator-facing rotation flow is Phase 1 identity-plane
  work and was out of scope.
* **Single currency.** Whole-rupee integers, matching Phase 5.5. A non-INR
  transaction cannot be expressed.
* **`ApprovalAuthority.rotate()` is still the known Phase 5.5 issue** and was
  deliberately not touched. It is now in the A2A blast radius, because the
  middle band uses the approval path. Operational caveat: do not rotate the
  approval authority while A2A transactions are pending approval.
* **`AgentRuntime.signing_payload()` still has no proof purpose** -- the only
  signature in the system without a domain separator. Not exploitable against
  the A2A envelope, but the discipline is not uniform there.
* **A transaction to an OFFLINE agent cannot be submitted at all.** Only the
  receiver may submit. That is fail-closed and correct; the cost is that a
  sender's timeout is UNKNOWN rather than a denial, and must be retried under
  the same transaction id.
* **`PAYMENT_OFFICER` needs a realm re-import.** `--import-realm` only applies
  to a realm that does not yet exist.
* **A2A `read` is not eligible.** One agent asking another to read on its
  behalf is the confused-deputy shape and needs its own analysis first.

## Phase 6 — what is real

Design: [PHASE_6_ARCHITECTURE.md](PHASE_6_ARCHITECTURE.md).

* **A JIT grant is an INPUT to authorization, never a substitute for one.** This
  system already had no standing permission, so a grant that authorised access
  on its own would have *removed* a property rather than added one. A mandate
  carries forward only the expensive precondition; credential validity, agent
  status, resource scope, purpose and the Phase 5.5 amount bands are all
  re-established live on every single use.
* **A mandate is a budget and a window**, both capped by policy configuration
  (`policies/data/jit_policy.json`). There is no TTL literal in Python and none
  in the rules; a test greps both. Missing configuration **fails closed**
  (`JIT_POLICY_UNCONFIGURED`), verified by removing it from the running OPA.
* **Issuance runs the FULL data-plane PDP evaluation first**, so a mandate can
  only ever be issued for something the agent could do at that instant. There is
  no `if agent_is_valid: issue_grant()` — a test asserts the ordering
  structurally.
* **JIT cannot bypass HITL.** A `HUMAN_APPROVAL_REQUIRED` verdict refuses the
  mandate outright, and `approve_loan` / `disburse_funds` / `override_decision`
  are excluded from JIT eligibility by name. A fabricated mandate for
  `approve_loan` is tested directly and the action stays escalated.
* **A mandate is not a bearer token.** Using one requires a control-plane
  signature from the agent DID it names, so the document alone buys nothing.
* **The budget is enforced by the database**: one conditional `UPDATE ... WHERE
  uses < max_uses AND expires_at > now RETURNING`. Twenty concurrent callers
  against a budget of five produce exactly five winners, tested with real tasks
  on real connections. `UNIQUE (grant_id, request_id)` makes a retry idempotent.
* **Revocation is immediate** and there are three paths: one mandate, every
  mandate for an agent (the Phase 10/12 containment integration point), and
  every mandate derived from a withdrawn approval.
* **A separate signing key from the approval authority** — compromising one must
  not yield the power to forge both a human decision and the mandate carrying
  it forward. Rotation keeps history verifiable; a retired key cannot issue.
* **Five terminal-state transitions are refused by name**, and `EXHAUSTED` is
  kept distinct from `EXPIRED`.

### Phase 6 — known gaps

* A mandate is **opt-in**, so it constrains the mandated path rather than the
  agent. An agent that does not present a revoked mandate falls back to its
  ordinary credential authority — Phase 4 behaviour, unchanged. A mandate is a
  pre-authorization mechanism, not a restriction one.
* `uses` and `status` are database state and cannot be signed, so a privileged
  database writer could reset a counter. The same limit applies to the Phase 5
  approval state; it is not new.
* `jit_authority_keys` duplicates the shape of `approval_authority_keys`.
  Consolidation is available later and was not taken now because it edits a
  table three green gates depend on.
* Only `read` on `credit_records` and `read` on `loan_applications` are
  JIT-eligible as shipped. Reading a loan was added so the mandate's
  financial ceiling has a live path; approving one remains excluded.
* Rotation compensates on failure rather than being transactional.
  `ApprovalAuthority.rotate()` (Phase 5.5) has the same original shape and the
  same latent failure -- retiring the outgoing key before the replacement is
  known to be creatable. It was deliberately NOT edited under a Phase 6 change,
  and is worth revisiting on its own.

### ⚠ Phase 4 gap found and closed during Phase 6

`security/credential_state.rego` is now **v2**. The PIP has always reported
`subject.active` and **nothing read it**, so a SUSPENDED agent holding a valid
credential was authorized exactly like an active one — suspending an agent did
not actually stop it. Verified as pre-existing and independent of Phase 6 (no
mandate involved). Now denied, with its own detail so "we do not know who this
is" stays distinguishable from "we know, and it is suspended". This corrects a
claim in the approved Phase 6 plan, which wrongly stated suspension was already
handled. No existing test regressed.

## Phase 5.5 — what is real

Design: [PHASE_5_5_ARCHITECTURE.md](PHASE_5_5_ARCHITECTURE.md).
Model: [HITL_SECURITY_MODEL.md](HITL_SECURITY_MODEL.md).

* **The amount is an authorization input**, read server-side from the loan
  application record by the PIP. It is never taken from the caller, and no rule
  reads `input.context`.
* **The amount policy is Rego; the thresholds are configuration.**
  `policies/loan/amount.rego` holds no numeric literal; the numbers live in
  `policies/data/loan_amount_policy.json` as an OPA data document. There is no
  `if amount > x` anywhere in Python. Missing configuration **fails closed**
  (`LOAN_POLICY_UNCONFIGURED`), verified by removing it from the running OPA.
* **Three bands, one credential:** below the autonomous limit the agent decides
  on its own authority; above it one `LOAN_OFFICER`; above the single-approver
  limit two distinct humans. `DUAL_APPROVAL_REQUIRED` is a *reason*, not a
  fourth decision value — the decision set is unchanged.
* **The amount is in the approval binding.** Approve ₹25,00,000, amend to
  ₹2,50,00,000, and re-evaluation denies with `APPROVAL_BINDING_MISMATCH`
  naming `amount_inr`. The approval record is untouched.
* **Dual control is enforced by the database**, not by an `if`:
  `UNIQUE (approval_id, approver_issuer, approver_subject)`. The same human
  signing twice is `APPROVER_ALREADY_SIGNED`. Each sign-off is independently
  authenticated against Keycloak.
* **Maker ≠ checker.** The officer named `submitted_by` on the application
  cannot sign it off (`SELF_APPROVAL_PROHIBITED`). Agents and machine
  administrators may never satisfy a human approval.
* **The approval signing key rotates.** A key register with ACTIVE / RETIRED /
  REVOKED generations: only the active key signs, the DID Document publishes
  every non-revoked method so history stays verifiable, a retired key cannot
  issue, an unknown `kid` is refused, and no private key is ever exposed.
  Rotation is a control-plane operation needing `identity_admin` — no human role
  can do it.
* **Completion and consumption are atomic**, both conditional
  `UPDATE ... RETURNING`. Exactly one concurrent caller wins.
* **Token storage:** the console's access token moved from `sessionStorage` to
  memory only. This reduces exposure; it is **not** XSS protection, and the doc
  says so. A BFF would be Phase 9's Session Authority.
* **Approval updates ride the existing SSE stream**, with polling kept as a slow
  backstop. Events say "something changed, ask again" — they carry no
  authorization meaning. The HITL event types are now in the live trace, which
  previously showed everything except the human step.
* **SAML remains documented, not faked** — and that honesty is now test-enforced
  (no endpoint, no parsing, no dependency, provider self-reports OIDC).

### Phase 5.5 — known gaps

* The console token is not protected from XSS; only a server-side session would
  fix that, and that is Phase 9.
* SAML federation is not demonstrated — no second real IdP is available on this
  host, and stubbing it would be a lie.
* `MACHINE_ADMIN` is the machine principal class, not a Keycloak realm role.
  Adding a human role able to perform machine operations would undo an existing
  security property, so it was deliberately not done.

## Phase 5 — what is real

Verified against the running system, and by `scripts/phase5_gate.py` (67/67):

- **A real Keycloak 26** on :8080 (loopback only), realm imported from
  `keycloak/realm-agentic-iam.json`. Real RS256 tokens, real realm roles,
  validated against the live JWKS on every request. `alg: none` and HS256
  key-confusion are both refused by an algorithm allowlist.
- **Human identity is not human approval.** An OIDC token says who someone is.
  A separate, signed artifact says what they agreed to.
- **The approval artifact is signed by `did:poc:service:approval-authority`** —
  not the agent (it could then approve itself), not Keycloak (it has no idea
  what a loan is), not the human (people hold no keys here).
- **Bound to one action**: request, agent, action, resource, purpose, plus a
  digest recomputed from the live request at re-evaluation. Moving an approval
  to another loan denies and names the field that moved.
- **Single-use**, consumed by an atomic conditional UPDATE. A test races three
  separate database connections and asserts exactly one wins.
- **Expiring**, on the server clock, never silently extended.
- **PDP RE-EVALUATION**: the human decision is a FACT the PIP establishes and
  Rego weighs. `sensitive-action` went to v2 so the escalation is conditional
  on the action being unapproved — that conditionality is the whole mechanism.
- **Least privilege between humans**: `LOAN_OFFICER` approves loans and has no
  IAM authority; `IAM_ADMIN` administers identity and **cannot approve a loan**;
  `AUDITOR` reads. No human administers policy.
- **No agent self-approval**: the agent, and a machine administrator, are both
  refused by name.
- **S-7 closed**: agent creation, agent termination, credential issuance and
  revocation, holder-proof production and audit ingest all require an
  authorized principal. Agents no longer create their own identities — they are
  provisioned, and refuse to start unprovisioned.
- **Fails closed on a real Keycloak outage**: verified with the container
  stopped. No human can approve, and the action stays blocked.

Measured (10 real cycles, not modelled): OIDC validation median 10.36ms,
approval decision + signing 35.76ms, PDP re-evaluation + enforcement 243.75ms,
end-to-end HITL cycle 531.27ms.

See [PHASE_5_ARCHITECTURE.md](PHASE_5_ARCHITECTURE.md) and
[HITL_SECURITY_MODEL.md](HITL_SECURITY_MODEL.md).

## Phase 4.5 — what is real

Verified against the running system, and by `scripts/phase45_gate.py` (46/46):

- **Signed control-plane requests.** Heartbeat, deregistration, registry sweep,
  PDP query, AEM enforcement, policy administration and identity signing all
  require an Ed25519 proof binding the principal, method, path, body digest,
  a single-use nonce and a bounded timestamp — using the SAME Phase 1 key. No
  bearer token, no shared secret, no second PKI.
- **The seven running agent processes heartbeat with real signed proofs**, zero
  failures, over their own keys which the API never holds.
- **A genuine agent cannot act for another.** `PRINCIPAL_IS_NOT_THE_SUBJECT`,
  even with a valid key, a valid proof and a valid identity.
- **Administrator principals** (`did:poc:administrator:*`) with roles granted by
  configuration and enforced in Rego. Three of them, so least privilege is
  demonstrable: the identity administrator is refused policy activation.
- **A separate Rego package** (`agentic_iam.control_plane`) with its own
  deny-overrides/default-deny combining algorithm. Data-plane semantics are
  untouched. There is no privilege rule in Python.
- **Replay is refused** by a database unique index, and a captured proof cannot
  be redirected to another endpoint or have its body swapped.
- **OPA's admin API is bound to loopback**, verified with `ss` and by a refused
  connection from the host's LAN address.
- **Fails closed on a real OPA outage**: a valid proof from a legitimate
  principal is still refused, with `CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE`.

Measured overhead (40 real requests on an idle host, not modelled): unguarded
read median 17.36ms; guarded write median 35.00ms — the guard adds **17.6ms**,
of which authentication (proof verification + replay ledger) is 6.29ms and
authorization (PDP -> OPA -> Rego) is 9.52ms.

See [CONTROL_PLANE_SECURITY.md](CONTROL_PLANE_SECURITY.md).

## Phase 4 — what is real

Verified against the running system:

- **A real OPA runtime** (`openpolicyagent/opa:latest`, 1.20.1) on :8181,
  evaluating real Rego v1 modules. There is no Python policy engine and no
  fallback evaluator: if OPA is down, every decision is DENY.
- **Five policy modules** loaded through OPA's Policy API by the PAP, each with
  an id, version, owner, purpose, scope and status.
- **Contextual authorization**: subject + action + resource + purpose +
  credential state, never `agent == X`. No policy names an agent DID.
- **Phase 2 feeds Phase 4**: the PIP calls the credential verifier and passes
  the *verdict* to policy. Rego never re-checks a signature.
- **Fine-grained, demonstrated**: the same agent, same identity and same valid
  credential is ALLOWED `credit_records` and DENIED `payroll_records`.
- **Purpose is enforced separately from action** — the same read for a different
  purpose is denied.
- **Enforced, not advisory**: protected tools are absent from every agent's tool
  registry and refuse to run without a single-use `EnforcementGrant` that only
  the AEM can mint. A direct call raises.
- **Self-asserted authorization is ignored**: an agent sending `"allow": true`
  is denied and the attempt is recorded.
- **Fail-closed everywhere** — and `AUTHORIZATION_FAIL_CLOSED` cannot be
  disabled; the service refuses to start if it is.
- **Real deactivation**: removing a policy DELETEs it from OPA. Because the
  combining algorithm is default-deny, removing policy makes the system more
  restrictive.
- **Measured latency**, not modelled: OPA evaluation median 11.86ms, end-to-end
  `/authorize` median 197.41ms over 20 live requests.
- **Self-healing policy**: OPA holds policy in memory, so an OPA restart would
  otherwise leave the system denying everything forever. A reconciler detects
  the missing modules and restores the declared set.

## Phase 4 — known gaps

- The **authorization API is itself unauthenticated**, like the rest of the POC.
  Anything that can reach `/api/v1/authorize` can ask for a decision, and
  anything that can reach the policy endpoints can deactivate a policy. The PDP
  is not bypassable; the endpoints in front of it are open. Same class as S-4/S-5.
- **PIP verification cost is linear in credentials held.** A subject holding 34
  credentials pays full cryptographic verification for each on every decision —
  this is why the measured PIP stage dominates. No caching was invented.
- **No decision caching.** Every request is fully evaluated.
- `HUMAN_APPROVAL_REQUIRED` is a **decision value only**. No approval flow, no
  approval artifact, no human principal, no Keycloak/OIDC/SAML.

## Phase 1 — what is real

Verified against the running system, not asserted:

- **Five agent processes**, one per agent, each with its own PID, port, HTTP
  surface and runtime state. Not one process pretending to be five.
- **Agent-held private keys.** Each agent generates its own Ed25519 key pair in
  its own keystore and registers only the public half. The registry cannot sign
  on their behalf and returns an error saying so if asked.
- **Real Ed25519.** `cryptography`'s Ed25519 throughout. Signing, verification,
  tamper detection and wrong-key rejection are all genuine.
- **DID Documents** published per agent, resolvable through the API, carrying
  the public key in `did:key`-style multibase (`z6Mk...`).
- **Real LLM calls** to Ollama. No fallback text exists anywhere: if the model
  did not run, the task returns FAILED with the reason.
- **Persistence** in PostgreSQL through Alembic migrations, surviving a full
  restart of the database and every process.
- **Audit trail** of every identity-lifecycle event, including events forwarded
  from the agent processes, plus a live SSE stream fed by the real event bus.

## Phase 2 — what is real

Verified against the running system:

- **Two issuing authorities**, each with its own Ed25519 key pair. No agent
  holds an issuer key, so an agent cannot mint a credential about itself — and
  a test proves that attack is rejected as `ISSUER_UNKNOWN`.
- **Real signed credentials.** Ed25519 over JCS-canonical JSON. Editing any
  field breaks the proof; tests cover eight distinct tampering variants.
- **Independent verification** with eight reported checks, never a bare boolean.
- **Revocation** that takes effect immediately and survives restarts, while the
  signature itself remains mathematically valid — the distinction that makes
  credential status necessary.
- **Expiry** enforced by comparing timestamps in the backend. `expirationDate`
  is inside the signature, so it cannot be extended.
- **Presentations with holder proof**: the agent process signs with its own
  Phase 1 key, because the IAM API does not have it.
- **A credentials console** driven entirely by the backend event stream.
- **Proof-purpose separation** enforced on both halves of the verifier pair:
  `assertionMethod` for credential proofs, `authentication` for holder proofs,
  `ansRegistration` for ANS registration proofs. A proof made for one purpose is
  not accepted for another. (Audit S-1.)
- **Audience binding.** `PresentationVerifier.verify()` accepts an
  `expected_domain`; the presentation's signed `domain` must equal it, otherwise
  verification fails with `DOMAIN_MISMATCH`. Omitting `expected_domain` keeps
  the previous behaviour — a verifier that declared no audience cannot demand
  one — and the presentation's declared domain is still reported. (Audit S-2.)
- **Verification correlation.** A credential verified inside a presentation
  records that presentation's id on its verification event, so the trail reads
  credential → presentation → verification event. NULL is preserved for
  standalone verification. (Audit S-3.)

## Phase 2 — known gaps

- Presentations are **replayable**: the challenge is checked but not recorded
  as used. Single-use nonces need cross-process state — Phase 9. Audience
  binding (above) narrows a replay to one audience; it does not eliminate it.
  This is a hard prerequisite for any future human-approval artifact.
- Issuance and revocation are **unauthenticated**, like everything else before
  Phase 4.
- Required claims per credential type are a Python constant, not a published
  schema registry.
- The proof suite is `PocEd25519Signature2026`, not W3C `Ed25519Signature2020`.
  See [PHASE_2.md](PHASE_2.md) section 8.
- The SOX compliance credential is synthetic demo data, labelled as such in the
  UI and in its own claims.

## Phase 3 — what is real

Verified against the running system:

- **A separate ANS service** on :8100 with its own lifecycle, a durable
  PostgreSQL registry, a liveness sweeper and an endpoint prober.
- **Seven agents that register themselves**, each signing its registration
  with its existing Phase 1 Ed25519 key. Registration is refused without a
  valid proof — a spoofed registration for `risk-001` is rejected as
  `INVALID_REGISTRATION_PROOF`, and the real agent's endpoint is untouched.
- **The endpoint is inside the signed payload**, so a signature over one
  endpoint cannot be reused to point a DID somewhere else.
- **Single-use nonces**, with only successful registrations consuming one.
- **Capability-aware discovery** through an index, with per-candidate
  explanations for both matches and rejections.
- **Credential-aware discovery** that re-verifies with the Phase 2 verifier on
  every query. A stale index row claiming ACTIVE cannot smuggle a revoked
  credential through; there is a test that plants exactly that row.
- **Observed liveness**: heartbeats carry real in-flight task counts, and the
  prober actually calls each agent's `/health`.
- **A coordinator with no endpoint table.** It asks ANS for the live capability
  catalogue, has the LLM choose from it, discovers, and then cross-checks the
  answer against the DID Document the ANS does not control.
- **Honest failure**: when nothing matches, the answer is an empty result with
  a reason. No fallback agent exists to fall back to.

## Phase 3 — known gaps

### ⚠ S-4 — unauthenticated heartbeat — **HIGH** — **DEFERRED**

**Status: DEFERRED TO AUTHORIZATION / CONTROL-PLANE HARDENING.**

`POST /api/v1/ans/heartbeat` accepts a bare DID with no signature. Current
behaviour is **fail-open**:

```
unauthenticated heartbeat  →  liveness refreshed  →  agent remains discoverable
```

An attacker able to reach the heartbeat endpoint may influence liveness state:
keep an **unavailable agent discoverable** so the coordinator routes work to a
dead endpoint, flip a healthy agent to `DEGRADED`/`BUSY` to push it out of
discovery, or report false load to manipulate ranking.

**Bounded, not a takeover.** `heartbeat()` refuses to move the endpoint, so
traffic cannot be redirected without a valid signed registration, and the
coordinator independently cross-checks the endpoint against the DID Document.
The impact is denial-of-service and misrouting, not impersonation.

**Intended direction:** authenticated/authorized control-plane operations as
part of the later authorization architecture — a signed heartbeat payload (the
agent already holds the key, and the registration-proof pattern applies
directly), or ANS mutations behind the PDP. Deliberately not pre-empted, and no
temporary mechanism was introduced.

### Other gaps

- The ANS API is **unauthenticated apart from registration**. Anyone who can
  reach :8100 can run queries or deregister an agent. Phase 4.
- **Discovery is not authorization**, and every response says so.
- Trust scores are **NULL** until Phase 10 builds the engine. `min_trust_score`
  excludes unscored agents rather than assuming a value.
- No TLS or mutual authentication between the ANS and agents.
- The health prober confirms an endpoint answers and reports the expected DID;
  it does not verify a signature from that endpoint.

## Phase 1 — what is deliberately absent

Named here so nothing in the UI or the docs implies otherwise:

- **No authorization.** Nothing consults a policy engine yet. Any caller that
  can reach the API can register an agent, issue a credential or revoke one.
  AEM and the PDP arrive in Phase 4.
- ~~**No agent-to-agent communication.**~~ CLOSED IN PHASE 7: a sender signs a
  transaction envelope, the receiver relays it with its own control-plane proof,
  and the IAM plane verifies, authorizes and executes it.
- **No tools and no banking data.** Every agent's tool registry is empty.
  Phases 5 and 8.
- **No sessions.** Redis runs but nothing writes to it. Phase 9.
- **No anomaly detection, no trust score, no kill switch.** Phases 10 and 11.
- **No loan workflow, topology view or SOC console.** Phase 12. The frontend
  today covers credentials, agents and the live trace only.

### Known gaps inside Phase 1

- ~~`POST /api/v1/audit/events` is **unauthenticated**.~~ CLOSED IN PHASE 5
  (S-7): ingest is behind the control-plane guard, and the recorded event names
  who wrote it and under which principal type.
- The `EncryptedFileKeyStore` is a development backend. It encrypts private keys
  at rest with AES-256-GCM under an HKDF-derived per-key data key, but the
  master key lives in the process environment, so a host compromise defeats it.
  Production would bind `KeyStore` to a KMS/HSM. The interface is already shaped
  for that: private keys never leave the store, callers only ever ask it to sign.
- `did:poc:` is a POC method. The document shape follows W3C DID Core, but there
  is no resolver network and no registered method.
