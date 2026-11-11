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
| 8  | MCP tool gateway | **✓ COMPLETE** · **✓ VERIFIED** — documented subset of MCP 2025-06-18 |
| 9  | Integration, security validation, release readiness (the original "Session Authority" scope moved to the framework-completion increment below) | **✓ COMPLETE** |
| 10 | Production security hardening: authenticated reads, rate limiting, CORS, single-use presentations | **✓ COMPLETE** |
| — | **Framework completion** against the CSA reference: trust & risk engine, rule-based anomaly detection, Session Authority + SSS + kill switch, delegated identities (sub-agent/ephemeral/fork), rich Agent ID profile, end-to-end loan workflow (simulated adapters), security-ops and workflow console tabs | **✓ IMPLEMENTED** — see [FRAMEWORK_COMPLETION_REPORT.md](FRAMEWORK_COMPLETION_REPORT.md) and [REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md) |

This table previously listed Phases 8-12 as "not started" while the sections
below described 8-10 as complete; it had not been updated after Phase 7. The
original Phase 11 (kill switch, global revocation) and the trust/anomaly half
of the original Phase 10 are delivered by the framework-completion increment.
The original Phase 12 frontend scope is PARTIAL: workflow and security-ops
views exist; topology and SOC dashboards beyond those do not.

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

Tests: **1272 collected, 1272 passing, 0 failures, 0 skips.** Phase 1-3
baseline was 247; Phase 4 added 127; Phase 4.5 added 66; Phase 5 added 127;
Phase 5.5 added 97; Phase 6 added 192; Phase 7 added 267; Phase 8 added 94;
Phase 9 added 55.

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
Phase 5.5 **110/110**, Phase 6 **113/113**, Phase 7 **132/132**,
Phase 8 **38/38**, Phase 9 end-to-end **36/36**.
The first nine were confirmed green in one sweep on 2026-10-22; Phase 8 was
added and confirmed on 2026-10-24; all eleven were re-confirmed in one sweep
on 2026-11-03.

GATE PREREQUISITE, recorded because it has now cost two debugging sessions:
capability credentials carry a 3600-second TTL, so a gate sweep run more than
an hour after the last seeding fails with `RESOURCE_NOT_ALLOWED` or
`PURPOSE_NOT_ALLOWED` everywhere. That looks exactly like an authorization
regression and is not one. Run `scripts/seed_credentials.py` first. Phase 8
additionally needs `scripts/provision_mcp_clients.py`.

ONE TEST WAS WIDENED IN PHASE 8, and it is recorded here rather than left
for a reviewer to find. `test_the_aem_enforce_signature_is_unchanged` pinned
the exact parameter set of `AEM.enforce()`, because Phase 7 promised to leave
that method alone and gave A2A its own `enforce_a2a()` instead. Phase 8 added
one optional parameter, `mcp`, and renamed the test to
`test_the_aem_enforce_signature_is_additive_only`.

The reasoning: an MCP `tools/call` asks the SAME question as the direct API,
so an `enforce_mcp()` twin would have meant a second copy of escalation,
grant minting, spending and execution -- a parallel authorization path, which
is the thing this architecture most needs not to have. (A2A earned its own
method for the opposite reason: it must verify a signed envelope and derive
the tool from it before any of that runs.)

The guard is STRONGER than it was: it still pins the exact parameter set, and
it now also asserts that everything Phase 8 added is optional and defaults to
None, so no caller written before Phase 8 can behave differently. A second,
behavioural test asserts an untouched Phase 4 call still runs end to end.
Two further Phase 7 guards -- that the MCP package contains no second JSON
serialisation, and that the AEM does not second-guess the PDP -- were left
untouched and the CODE was changed to satisfy them.

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

Next: the targets in FRAMEWORK_COMPLETION_REPORT.md §13 (W1-W3, plus items
that need an external party). Previously this read "nothing planned"; Phase 10
was the final hardening phase; see
[PHASE_10_SECURITY_ASSESSMENT.md](PHASE_10_SECURITY_ASSESSMENT.md) for the
final findings, [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md) for
deployment, and [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) for backup
and key rotation.

## Phase 10 — what is real

Final production security hardening. **Every Phase 9 HIGH and MEDIUM finding
is closed**, and the HIGH one is verified on a running system.

* **The read API is authenticated.** 26 routes now carry the SAME
  `ControlPlaneGuard` as every mutation -- no new auth layer was built,
  because the guard already accepted either a human OIDC token or a signed
  machine proof and already decided in Rego. Seven read operations, one per
  data domain, mapped to roles.

  The separations are the point, and each is a named test: **IAM_ADMIN
  cannot read a loan** (it administers agents; suspending the agent that
  processes a file does not give it the file); LOAN_OFFICER cannot read the
  audit trail or the registry; **no officer role can read the policy set**,
  because knowing which rules are live is the first half of evading them;
  and the enforcement gateway reads nothing at all.

  `tests/test_route_security_inventory.py` walks the WHOLE route table, so a
  sensitive route added later with no guard fails by name. A route is public
  only if it is written in the allow-list with a reason.

* **Rate limiting is distributed.** Redis-backed sliding window, one atomic
  Lua script, keyed on identity before address. `X-Forwarded-For` is ignored
  unless the peer is a configured trusted proxy -- otherwise a caller mints
  a fresh allowance per request by setting a header. A Redis outage is never
  silent: production requires `fail_closed`, because a per-process counter
  across N workers is an N-times-looser limit that still reports as
  enforced. ZERO new dependencies -- `redis==5.2.1` was already declared.

* **Presentations are single-use.** The challenge ledger closes a gap this
  codebase had documented since PHASE 2 and carried through Phase 9.
  Recorded at issue (so an invented value is refused), bound to its
  verifier, expiring, and spent by one atomic conditional UPDATE -- 20
  concurrent presentations of one challenge spend it exactly once.

  ONE ORDERING DECISION WORTH RECORDING: the spend happens after the domain
  check, not before. Spending first would let an attacker relay a captured
  presentation to the WRONG verifier purely to burn the victim's challenge,
  turning replay protection into a denial-of-service against the legitimate
  holder. Found by a Phase 9 test failing for the wrong reason.

* **Redis is no longer an unused dependency.** It is the rate-limit backend,
  and in production an outage is an API outage by design.

* **CORS is configuration**, and production refuses a wildcard with
  credentials or any plaintext origin. Two tests assert that CORS is NOT
  authorization: a request from a permitted origin with no credentials is
  still refused by the route guard.

* **`ApprovalAuthority.rotate()` was re-inspected and NOT modified.** No
  defect was found: atomic retirement, a lost race raises `ConflictError`
  rather than creating a second active key, an orphaned keystore entry is
  refused, and a post-generation failure deletes the new key before
  re-raising.

### Phase 10 — known gaps

* **No independent security review.** Still the most significant open item,
  and nothing in this repository substitutes for one.
* **TLS, certificates and secrets are the operator's.** The application
  refuses to start without https in production; it cannot provide it.
* **Demo users remain in the realm file** and must be removed before
  deployment. NOT enforced by code -- the likeliest checklist item to be
  forgotten.
* **Read authorization is domain-scoped, not row-scoped.** `audit_read`
  grants the trail, not a filtered view of it.
* **Service-to-service mTLS is not implemented** -- a trusted-segment model,
  accepted and documented.
* **No disaster-recovery rehearsal, no RPO/RTO, no load testing, no
  monitoring.**

## Phase 9 — what is real

Final integration, security validation and release readiness:
[PHASE_9_RELEASE.md](PHASE_9_RELEASE.md).

**The headline is a refusal, not a claim: the system is complete and
internally consistent as a POC, and it is NOT production-ready.** One HIGH
finding remains open by design (the read API is unauthenticated), because
closing it means changing the read authentication model across ten routes,
five gate scripts and the console -- a broader change than a final hardening
pass should make, and one whose shape is a product decision.

* **All ten prior phases were verified against the running system**, not read
  off their phase markers. Seven cross-phase end-to-end scenarios
  (`scripts/phase9_e2e.py`) exercise the seams: identity to audit, revocation,
  MCP discovery versus invocation, A2A, human approval, JIT bounds, and
  unauthenticated refusal.

* **No privileged mutation is reachable anonymously.** Probed live (11/11
  refused) and then asserted structurally over the WHOLE route table in
  `tests/test_unauthenticated_surface.py`, so a mutating route added later is
  covered without anyone remembering to write a test.

* **THREE GENUINE DEFECTS WERE FOUND AND FIXED:**

  `ENV=production` accepted plaintext `http://` for the OPA URL, the Keycloak
  base and issuer, the MCP resource URI and the advertised API base. Each
  carries something forgeable in the middle -- a policy decision, a signing
  key, a bearer token. Substituting the JWKS is the worst: tokens then verify
  honestly against the attacker's key. Now refuses to start, with no opt-out,
  matching every other security switch here.

  **Policy deactivation silently reverted within 15 seconds.** The manifest
  declares every policy `"status": "ACTIVE"` because it describes the
  SHIPPED set; the RUNNING state lives in the database, which is what
  `/policies/{id}/deactivate` writes. But `reconcile()` and `load_all()`
  read only the manifest, so a deliberately-disabled policy looked exactly
  like one missing because OPA had restarted -- and the 15-second
  reconciler pushed it back in, logging `policy_set_incomplete ...
  reloading`, which reads like recovery. An operator disabling a rule to
  contain an incident would have watched it return. Found via an
  INTERMITTENT Phase 6 gate failure (112/113 once, 113/113 twice); the
  underlying control was deterministic in isolation, which is what made the
  intermittency worth chasing. The database's verdict now outranks the
  manifest in both paths; engine-restart recovery is untouched and has its
  own test.

  `provision_mcp_clients.py` read ONE keystore, but `provision_agents.py`
  gives each agent its own `.keystore-agents/<slug>/` -- correct key custody,
  and the reason the script silently skipped all ten deployed agents and
  provisioned only two probes. MCP was provisionable for nobody real. Fixed;
  all ten provision.

* **Dependencies unchanged.** `requirements.txt` untouched across Phases 8
  and 9; no installed version moved.

### Phase 9 — known gaps

* **HIGH: the read API is unauthenticated.** 10 of 12 probed read endpoints
  serve an anonymous caller: the audit trail, credential inventory, agent
  registry, approval queue, human principals, loan records and decision
  history. Synthetic data, but the shape is the point. Remediation is in
  PHASE_9_RELEASE.md §4.
* **MEDIUM: no rate limiting** anywhere, including the MCP endpoint.
* **MEDIUM: CORS origins are hardcoded** to localhost. Fails safe, but needs
  a code change to deploy a real console.
* **LOW: seeding accumulates credentials** rather than replacing them.
* **TLS is not configured.** The new guard forces https URLs in production;
  terminating TLS is still the operator's job.

## Phase 8 — what is real

Design and conformance matrix: [PHASE_8_ARCHITECTURE.md](PHASE_8_ARCHITECTURE.md).

**Scope statement, stated first because overstating it would be the easiest
mistake here: this is an implementation of a DOCUMENTED SUBSET of MCP
revision 2025-06-18, not a complete MCP implementation.** Section 3 of the
architecture document enumerates what is implemented and tested, what is not
applicable, what is intentionally unsupported, and what remains unverified.

* **ZERO new runtime dependencies.** `requirements.txt` is unchanged and no
  installed version moved. The official `mcp` SDK (2.3.0) was measured and
  rejected: it requires `pydantic>=2.12` against this project's pinned
  2.10.4, plus `anyio>=4.9` and a second HTTP stack -- 18 packages in all.
  Upgrading the model layer of a security system to gain a transport helper
  is the wrong trade, so the wire protocol is implemented directly on
  FastAPI. The cost is that conformance is ours to prove, which
  `test_mcp_conformance.py` does by quoting the spec clause each test
  asserts.

* **No second credential root.** An agent authenticates to Keycloak with
  `private_key_jwt` / **EdDSA**, signing the assertion with the SAME Ed25519
  key it has held since Phase 1. Its Keycloak `clientId` IS its DID, so the
  access token's `azp` carries the DID verbatim. No client secret is
  created, and the private key never leaves the KeyStore. Verified end to
  end against live Keycloak by `scripts/phase8_gate.py`.

* **Identity binds on `azp`, never on `sub`.** `sub` is a Keycloak
  service-account UUID unrelated to the agent. Binding on it would
  authenticate successfully and attribute the call to the wrong principal.
  Tested by giving the two claims different values.

* **A valid token is not a valid agent.** Keycloak knows nothing about agent
  lifecycle, so a token stays cryptographically valid after an agent is
  suspended. The PIP re-reads agent and credential state inside EVERY
  evaluation, which is what makes revocation effective within a token's
  lifetime -- tested in both directions.

* **Discovery is not permission.** `tools/list` returns the catalogue
  unfiltered, without consulting policy. Deliberate: a list that shrank with
  the caller's credentials would be an oracle for which credentials an agent
  holds, and filtering would put a second copy of "what may be called"
  beside the real one in Rego. An agent can see a tool it may never call.

* **`mcp/invocation.rego` contributes DENY rules only**, and that is the
  central decision of the phase. MCP is a transport for actions other
  modules already decide, so an `allow` here would be a SECOND way to permit
  something that already had one -- and under deny-overrides a second allow
  is a widening. The channel can narrow what is reachable; it can never
  widen it.

* **Zero new cross-module Rego names.** `decision.rego` and
  `security/sensitive.rego` are untouched, exactly as in Phase 7.

* **Payments are not reachable over MCP.** `execute_payment` is absent from
  the eligible actions. Over A2A a payment arrives inside an envelope signed
  by the instructing agent's key, bound to a receiver and reconciled four
  times; an MCP call carries a bearer token and nothing else. Exposing
  payments here would be a strictly weaker path to the same action.

* **HITL and dual control survive the channel.** `approve_loan` IS
  MCP-eligible, which is not the same as performable: an MCP client can at
  most open an approval request, and a high-value application still requires
  two distinct humans.

* **The purpose problem is solved without inventing a protocol field.**
  `tools/call` has no purpose, so the client states one in `params._meta`
  under a non-reserved key -- an extension of this deployment, documented as
  one and never described as part of MCP. The statement is a SELECTOR, never
  a grant: `allowed_purposes` in `decision.rego` derives only from
  credentials the Phase 2 verifier accepted, so a purpose no credential
  attests is denied.

### Phase 8 — known gaps

* **No interoperability test against a third-party MCP client.** The
  conformance evidence is a spec-quoting test suite, not an interop run
  against Claude Desktop or an SDK client. This is the largest gap in the
  evidence and is recorded as "unverified" rather than claimed.
* **Plaintext HTTP.** The POC runs on `http://localhost`; the MCP
  authorization spec requires HTTPS for authorization endpoints.
* **Tool arguments are stored unredacted.** Safe for the current tool set,
  which takes record identifiers; a tool taking a secret would need a
  redaction policy first.
* **Keycloak client lifecycle is a separate script**, not automatic on agent
  registration. Revocation is still effective because the PDP decides.
* **No rate limiting.** Exactly-once deduplication is not a rate limit.
* **No legal non-repudiation.** A bearer token proves possession, not
  authorship. Nothing in this phase produces a signed record of intent the
  way an A2A envelope does -- which is precisely why payments are excluded.

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
  says so. A BFF would fix it properly. NOTE (Phase 9): the Session Authority
  this once pointed at was never built -- Phase 9 became final integration
  and release readiness instead, and no further phase is planned. The gap is
  real and remains open.
* **Approval updates ride the existing SSE stream**, with polling kept as a slow
  backstop. Events say "something changed, ask again" — they carry no
  authorization meaning. The HITL event types are now in the live trace, which
  previously showed everything except the human step.
* **SAML remains documented, not faked** — and that honesty is now test-enforced
  (no endpoint, no parsing, no dependency, provider self-reports OIDC).

### Phase 5.5 — known gaps

* The console token is not protected from XSS; only a server-side session
  would fix that. It was expected to come with a Session Authority phase that
  was never built -- Phase 9 became final integration instead -- so this gap
  is open and unplanned rather than deferred.
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
  as used. Audience binding (above) narrows a replay to one audience; it does
  not eliminate it.
  **STILL OPEN as of Phase 9, and now unplanned.** It was expected to be
  closed by a Session Authority phase that was never built. Re-verified on
  2026-11-03: no challenge is consumed anywhere, and
  `app/credentials/presentation.py` still says so in its own docstring.
  Mitigating context, which is why it is MEDIUM and not HIGH: every path that
  actually carries authority built its own replay ledger instead --
  control-plane proofs, ANS registration, A2A envelopes and MCP invocations
  each have one. The `/credentials/present` path is a demonstration surface,
  not an authorization input.
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
- **No sessions.** Redis runs but nothing writes to it.
  **STILL TRUE as of Phase 9, and now unplanned.** Re-verified 2026-11-03:
  `redis` is referenced only in `config.py`, yet docker-compose starts it AND
  `iam-api` lists it as a healthy-start dependency. It is an unused service
  that can block startup -- see PHASE_9_RELEASE.md.
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

---

## Phase 12 — final phase (2026-11-11): COMPLETE for feasible scope

Containment closes approvals and revalidates on reinstatement; tamper-evident audit (MAC + hash chain + signed checkpoints); durable loan workflow; configuration-driven CORS everywhere; delegation-chain enforcement. Gates 1–9 all pass, loan E2E 33/33, live restart 18/18. Console integration of the five Phase 12 features: new UI browser tests 57/57, existing console 31/31. Final full suite 1,615 passed / 0 failed / 1 skipped (live LLM test, host memory). Lint not run (no linter configured). No load test. External items BLOCKED_EXTERNAL. Details: [PHASE_12_FINAL_REPORT.md](PHASE_12_FINAL_REPORT.md).

