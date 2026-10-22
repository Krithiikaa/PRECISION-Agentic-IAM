# Phase 7 — Secure Agent-to-Agent Transactions

Status: **COMPLETE · VERIFIED**
Gate: **132/132**  ·  Suite: **1123 passing, 0 failures, 0 skips**

---

## The one sentence this phase exists to enforce

> **A valid A2A signature is not authorization. It makes a transaction
> evaluable.**

Everything below is a consequence of that. A signature establishes that the
holder of a particular private key produced particular bytes. It says nothing
about whether the sender holds a valid credential, whether the resource is in
scope, whether the purpose matches, what the amount means, or whether a human
must be asked. Every one of those is decided afterwards, by Rego, on facts the
PIP established — and any one of them still denies.

---

## 1. What Phase 7 adds

Before this phase, the agent `/task` endpoint was **completely
unauthenticated** and `TaskRequest.sender_did` was a bare string claim that
was interpolated into an LLM prompt and nothing else. The coordinator could
*find* and *verify* an agent but never sent it anything.

Phase 7 adds a real transaction channel:

| Capability | Mechanism |
|---|---|
| Canonical signed envelope | JCS canonical JSON + Ed25519, proof purpose `a2aTransaction` |
| Sender authentication | public key resolved from the **Phase 1 DID Document**, not the ANS |
| Receiver binding | signed `receiverDid` **and** the control-plane guard requiring the submitter to be that DID |
| Replay protection | `UNIQUE (sender_did, transaction_id)` plus a partial nonce index |
| Exactly-once execution | unique INSERT + conditional `UPDATE … WHERE status='AUTHORIZED'` |
| Idempotent replay | a settled transaction returns its recorded outcome; nothing is re-decided |
| Authorization | the full existing PDP path, with the **sender** as subject |
| Amount integrity | four representations, reconciled at four points |
| HITL | the existing Phase 5/5.5 machinery, with a dedicated `PAYMENT_OFFICER` role |
| Dual control | genuine two-person control above the single-approver limit |
| Audit | the whole arc retrievable by one `request_id` |

---

## 2. The transaction lifecycle

```
Agent A                                   Agent B                 IAM plane
   │                                         │                        │
   │ 1. ANS discovery ───────────────────────┼──────────────────────▶ ANS
   │    (WHO, not MAY — a routing hint)      │                        │
   │ 2. cross-check the endpoint against     │                        │
   │    B's DID Document ────────────────────┼──────────────────────▶ Phase 1 registry
   │ 3. build + SIGN the envelope            │                        │
   │    (A's Phase 1 key, purpose a2aTransaction)                     │
   │ 4. POST /a2a/inbound ──────────────────▶│                        │
   │                                         │ 5. relay UNCHANGED,    │
   │                                         │    with B's OWN        │
   │                                         │    control-plane proof▶│ a2a_submit guard
   │                                         │                        ├─ 1. verify the envelope
   │                                         │                        ├─ 2. register atomically
   │                                         │                        ├─ 3. reconcile the amount
   │                                         │                        ├─ 4. PIP  (subject = A)
   │                                         │                        ├─ 5. OPA / PDP
   │                                         │                        ├─ 6. HITL if required
   │                                         │                        ├─ 7. reconcile again
   │                                         │                        ├─ 8. claim execution
   │                                         │                        └─ 9. AEM → protected tool
   │                                         │◀── outcome ────────────┤
   │◀─ 6. SIGNED response ───────────────────┤                        │
   │    (B's key, purpose a2aResponse)       │                        │
```

### 2.1 Verification order — itself a security property

```
 1. present              → A2A_ENVELOPE_MISSING
 2. structure            → A2A_ENVELOPE_MALFORMED
 3. protocol + version   → A2A_PROTOCOL_UNSUPPORTED
 4. proof purpose        → A2A_PROOF_PURPOSE_INVALID
 5. RECEIVER BINDING     → A2A_RECEIVER_MISMATCH
 6. sender resolution    → A2A_SENDER_UNKNOWN / _NOT_ELIGIBLE / _NOT_RESOLVABLE
 7. signing-key window   → A2A_KEY_UNKNOWN / _RETIRED / _REVOKED
 8. SIGNATURE            → A2A_SIGNATURE_INVALID
 9. audience             → A2A_DOMAIN_MISMATCH
10. freshness + TTL      → A2A_TRANSACTION_STALE / _EXPIRED / _TTL_EXCEEDS_MAXIMUM
11. payload digest       → A2A_ENVELOPE_MALFORMED
12. binding hash         → A2A_ENVELOPE_MALFORMED
───────────── the signature has verified ─────────────
13. REGISTER (atomic)    → A2A_REPLAY_BLOCKED / A2A_TRANSACTION_ID_REUSE
14. reconcile the amount → A2A_AMOUNT_MISMATCH
15. PIP → OPA → PDP
16. reconcile again, then claim execution, then the AEM
```

**Step 8 before step 13 is the ordering that matters.** A forged envelope
never reaches the ledger, so an attacker cannot burn a legitimate sender's
transaction id with a unique-constraint collision. Rejected submissions are
recorded in `a2a_transaction_attempts` and nowhere else.

### 2.2 State machine

```
RECEIVED ──verified──────────▶ VERIFIED
         └─refused───────────▶ REJECTED    (terminal)

VERIFIED ──ALLOW─────────────▶ AUTHORIZED
         ├─DENY──────────────▶ DENIED      (terminal)
         ├─needs a human─────▶ PENDING_APPROVAL
         └─expiry────────────▶ EXPIRED     (terminal)

PENDING_APPROVAL ──retry, ALLOW──▶ AUTHORIZED      ← THE HITL RETRY
                 ├─retry, DENY───▶ DENIED  (terminal)
                 └─expiry────────▶ EXPIRED (terminal)

AUTHORIZED ──atomic claim────▶ EXECUTING ──▶ EXECUTED (terminal)
           │                            └──▶ FAILED   (terminal)
           └─reconciliation refused────────▶ FAILED   (terminal)
```

Every terminal state has an **empty** transition set, so `EXECUTED →
EXECUTING` is refused *by name* rather than by nobody having written the code.

---

## 3. Receiver binding — bound three times

### 3.1 Cryptographically
`receiverDid` is inside the signed envelope. Changing it invalidates the
signature.

### 3.2 By authentication — the strong one
The route is guarded with `a2a_submit`, whose target resolver reads the
envelope's own `receiverDid`. The **pre-existing** `agent_self.rego` rule then
does the rest:

```rego
acts_on_self if {
    input.target.id != null
    input.target.id == input.principal.did
}
```

```
A → B, submitted by B    receiverDid == principal  → AGENT_ACTING_ON_SELF
A → B, submitted by C    receiverDid != principal  → PRINCIPAL_IS_NOT_THE_SUBJECT
A → B, submitted by A    receiverDid != principal  → PRINCIPAL_IS_NOT_THE_SUBJECT
```

Phase 7 added **one word** to a set to achieve this. The replay-toward-another-
receiver attack is refused by a rule that already existed and was already
tested.

The third case matters as much as the second: if a **sender** could submit an
envelope addressed to somebody else it would control both ends of the flow and
the receiver's consent to receive would not exist.

### 3.3 No administrator holds `a2a_submit`
Deliberately absent from `administration.rego`. An administrator with it would
be a privileged bypass of exactly that binding — `enforcement` can already
drive `/authorize` and `/enforce` for any subject. The cost is that automation
and the gate must sign as the receiving **agent**. That is the correct cost.

---

## 4. Amount integrity — four representations, four reconciliations

There is a genuine tension between "the amount must be covered by the
signature" and Phase 5.5's rule that "material attributes are read
server-side, never from the caller". **Both, and they must agree.**

| # | Representation | Column | Answers |
|---|---|---|---|
| 1 | what the **sender signed** | `amount_inr` | "what was instructed?" |
| 2 | what the **record says** | `server_amount_inr` | "what is true?" |
| 3 | what the **PDP decided on** | `authorized_amount_inr` | "what may be moved?" |
| 4 | what **actually moved** | `executed_amount_inr` | "what happened?" |

A single column could not express a disagreement, and a disagreement is
precisely the incident worth detecting.

### The four reconciliation points

| Where | Compares | On disagreement |
|---|---|---|
| A2A service, after registration | signed vs server | `A2A_AMOUNT_MISMATCH`, PDP still asked, policy denies |
| `a2a/transaction.rego` | asserts `amount_reconciled` | **DENY** — stated as policy, not left to the service |
| AEM, after the decision | authorized vs signed | `FAILED` / `A2A_AMOUNT_MISMATCH`, nothing claimed |
| `execute_payment_instruction` | authorized vs the live record | `AmountReconciliationError` → `FAILED`, inside the boundary |

**No Rego band rule reads the signed amount.** The bands compare
`input.pip.resource.attributes.amount_inr`, read server-side. A test greps the
rule bodies to assert it.

### The acceptance matrix, as implemented and tested

| Case | Scenario | Outcome | Test |
|---|---|---|---|
| A | signed = server = authorized | **ALLOW**, executes once | `TestCaseA_AllThreeAgree` |
| B | signed ≠ server | **DENY** `A2A_AMOUNT_MISMATCH` | `TestCaseB_SignedDiffersFromServer` |
| C | signed = server, authorized differs | **FAILED**, nothing executes | `TestCaseC_AuthorizedDiffersFromSigned` |
| D | authorized = signed, execution would differ | **FAILED**, handler refuses | `TestCaseD_ExecutionDiffersFromAuthorized` |
| E | amount edited after signing | **signature failure**, PDP never asked | `TestCaseE_AmountModifiedAfterSigning` |
| F | above threshold | HITL / dual control | `TestCaseF_AmountAboveThreshold` |
| G | concurrent duplicate | **exactly one** execution | `TestCaseG_ConcurrentDuplicate` |

---

## 5. Replay and idempotency

**Exactly-once execution, with idempotent replay of the previously determined
result.**

| Submission | Outcome |
|---|---|
| First | processed: verify → register → reconcile → PDP → execute |
| Same envelope, transaction **settled** | the recorded outcome is returned. No re-execution, **no second PDP evaluation** |
| Same envelope, transaction **PENDING_APPROVAL** | **resumed** — re-enters the pipeline so a human decision can take effect |
| Same envelope, transaction **in flight** | answered idempotently; a concurrent duplicate |
| Same id, **different content** | hard DENY, `A2A_TRANSACTION_ID_REUSE` — an attack, not a retry |

### Why `resumed` has to exist
An escalated transaction is retried under the **same** transaction id — that
is the whole point of deriving the authorization request id from it, so the
approval binding is reproducible. If every duplicate were answered
idempotently, a payment a human had just approved would be told "still
pending" forever. Exactly-once is not weakened, because execution is gated
separately by the atomic claim.

### Why a replay is never re-decided
The amount band, the credential state or an approval could all have moved
since. Re-evaluating would mean a transaction that already executed could be
reported as denied.

### Why uniqueness is composite
`UNIQUE (sender_did, transaction_id)`, not a global unique. A global one would
let sender X pre-register `txn-0001` and permanently deny it to sender Y. The
transaction id is **the sender's** business identifier.

### On the nonce, stated honestly
The nonce is **not** the primary replay defence. `transactionId` is signed, so
an attacker cannot forge a fresh id around a captured payload, and the unique
constraint catches the exact-envelope replay. It is kept for two secondary but
real reasons: it puts unpredictable bytes inside the signed payload, and all
six existing proof types carry one — a seventh that did not would be a thing a
reviewer has to stop and think about.

---

## 6. Dual control — real, with Phase 5.5 untouched

### The defect this design had to avoid

`approval_satisfied` (in `security/human_approval.rego`) requires
`distinct_approvers >= required_approvals`, and `required_approvals` is
defined **only** by `loan/amount.rego`:

```rego
required_approvals := 2 if { requires_dual_control } else := 1
```

`requires_dual_control` is guarded on `input.action == "approve_loan"`. So for
a **payment**, `required_approvals` evaluates to **1** — and a payment that
must have two humans would be satisfied by one, **silently, while passing
every existing test.**

### The resolution

`a2a/transaction.rego` asserts the count **directly**:

```rego
a2a_two_approvers if {
    a2a_approval_usable
    input.pip.approval.distinct_approvers >= 2
}
```

`distinct_approvers` is computed by the approval verifier from the
`(issuer, subject)` pairs inside the **signed artifact** — not from a table
row an attacker might edit.

The rest of the chain then works unchanged:

| Step | Mechanism | Changed? |
|---|---|---|
| policy raises `human_required` with `required_approvals: 2` | new module | — |
| the AEM reads that off the Rego document | `_required_approvals` | **unchanged** |
| `decide()` collects two sign-offs before signing | `record.required_approvals` | **unchanged** |
| the same person twice is refused | `UNIQUE (approval_id, issuer, subject)` | **unchanged** |
| the artifact carries both approvers | `_sign` | **unchanged** |
| the verifier recomputes `distinct_approvers` | `artifact.py` | **unchanged** |

**Zero lines of Phase 5.5 changed, and payments above the single-approver
limit get genuine two-person control.**

### The required negative, as a test

`test_a2a_hitl.py::TestDualControlAboveTheThreshold::test_ONE_officer_CANNOT_approve_an_above_threshold_payment`

One authorized `PAYMENT_OFFICER` signs off. The approval stays `PENDING`, no
artifact is produced, the payment does not move, and the instruction is
observably untouched.

---

## 7. Rego changes

### Headline: `decision.rego` and `security/sensitive.rego` are untouched

Phase 7 introduces **zero new cross-module rule names**. Every name the module
reads (`valid_credentials`, `capabilities`, `allowed_resources`,
`allowed_purposes`, `approval_satisfied`) is already defined or already seeded
in `decision.rego`, which loads first. Every name it defines (`deny`, `allow`,
`human_required`) is already seeded there too.

Splitting the payment bands into a second module would have introduced exactly
the dependency the Phase 6 finding warns about — OPA compiles the whole set on
every `PUT`, so an unloaded dependency raises `rego_unsafe_var_error` and takes
**every** gate down at once. One module removes that failure mode entirely.

### Why `execute_payment` is not in `sensitive.rego`

`sensitive.rego` escalates its action set to one human and guards itself out of
the two bands `loan/amount.rego` owns — both loan-scoped. Adding
`execute_payment` would escalate **every** payment, including a trivial one.
Referring every small payment to a person manufactures rubber-stamping, which
is a worse control than not asking. `loan/amount.rego` only needed those guards
because `approve_loan` was already in the set from Phase 5; Phase 7 has no such
legacy.

### Changes

| File | Change | Cross-module names |
|---|---|---|
| `policies/a2a/transaction.rego` | **new** | **zero** |
| `policies/data/a2a_policy.json` | **new** | n/a |
| `policies/manifest.json` | one policy entry, one data entry | — |
| `policies/data/jit_policy.json` | `execute_payment` into `excluded_actions` | data only |
| `policies/control_plane/agent_self.rego` | `"a2a_submit"` into `self_operations` | zero |
| `policies/control_plane/administration.rego` | `"a2a_administer": "identity_admin"` | zero |
| `policies/control_plane/humans.rego` | `PAYMENT_OFFICER` rules; `a2a_*` into `human_only_denied` | zero |
| **`policies/decision.rego`** | **UNCHANGED** | — |
| **`policies/security/sensitive.rego`** | **UNCHANGED** | — |
| **`policies/loan/*`, `policies/jit/*`** | **UNCHANGED** | — |

### Verified, not assumed

* every declared module loads in manifest order from an empty engine — 16/16
* `a2a/transaction.rego` compiles with **only** `decision.rego` present, exactly
  as `loan/credit.rego` does
* adding it to the complete Phase 1–6 set compiles; **removing it again leaves
  that set compiling**
* removing it fails **closed**: no other rule allows `execute_payment`

---

## 8. Database

Two new tables. **No `ALTER TABLE` anywhere** — every prior phase's schema is
untouched.

### `a2a_transactions` — verified submissions only

```
UNIQUE (sender_did, transaction_id)                    the exactly-once invariant
UNIQUE (sender_did, nonce) WHERE signature_verified    the replay ledger, partial
CHECK  amount_inr IS NULL OR amount_inr = abs(amount_inr)
CHECK  (amount_inr IS NULL) = (currency IS NULL)
```

The `abs()` idiom rather than `>= 0` is deliberate: Phase 5.5 guards against
amount thresholds leaking into the application by grepping for a comparison
between an amount and a numeric literal, and a **domain** check should not
require that guard to be loosened. The same idiom appears in
`is_wellformed_amount`, with the reasoning in the docstring.

### `a2a_transaction_attempts` — every submission, accepted or not

Rejected envelopes are recorded **only** here. If a forged submission could
write to `a2a_transactions`, it could burn a legitimate sender's transaction id.
Every column is named `claimed_*` because on a rejected submission those values
are assertions that failed verification, not facts.

### Migration

`e7d2a41c8b09_phase7_a2a_transactions.py`, `down_revision = c9e4b81f2a37`.
Verified forward, backward and forward again against a real PostgreSQL, and
diffed against `Base.metadata.create_all` — **zero drift**, 52 and 16 columns,
12 and 5 indexes respectively.

---

## 9. Keys

| Question | Answer |
|---|---|
| A2A signing key | the **sender agent's Phase 1 Ed25519 key** |
| New signing authority | **none** |
| `key_id` | `did:poc:agent:<slug>#key-1` |
| Rotated key | still **verifies** its history; cannot sign anything new (`A2A_KEY_RETIRED`) |
| Revoked key | verifies **nothing**, including its own history (`A2A_KEY_REVOKED`) |
| Approval-authority key | **never** signs a transaction (tested) |
| JIT-authority key | **never** (tested) |
| Administrator key | **never** (tested) |

### Why no new authority
Phase 5 needed an approval authority because *a human's decision* had to be
attested by something that is not the agent. Phase 6 needed a JIT authority
because *temporary machine authority* had to be minted by something that is not
the agent. An A2A transaction attests to **what the sender instructed** — the
sender is the correct signer. A "transaction authority" would attest to nothing
the PDP decision and the audit row do not already record, while adding a key, a
register, a rotation path and a compromise surface. A test asserts the A2A
package creates no service principal and generates no key material.

### Why the Phase 1 key is correct
`build_did_document` has listed the agent kid under `authentication` since
Phase 1, with the comment *"The agent authenticates with this key (A2A)"*.
Separation is achieved by `proofPurpose` inside the signed bytes — now the
**seventh and eighth** domain separators (`a2aTransaction`, `a2aResponse`),
alongside `assertionMethod`, `authentication`, `ansRegistration`,
`controlPlaneRequest`, `humanApproval` and `jitGrant`. A test asserts that a
proof made for any of the other six cannot verify as a transaction.

---

## 10. Audit

### Events added

```
A2A_REQUEST             (was declared and never emitted — now emitted)
A2A_SIGNATURE_VERIFIED
A2A_REJECTED
A2A_REPLAY_BLOCKED
A2A_AMOUNT_MISMATCH
A2A_EXPIRED
A2A_EXECUTED
A2A_FAILED
A2A_RESPONSE            (was declared and never emitted — now emitted)
```

### Deliberately **not** added
A2A-specific authorization events. The PDP already emits
`AUTHORIZATION_REQUESTED`, `PIP_CONTEXT_COLLECTED`, `OPA_DECISION`,
`PDP_EVALUATION` and `POLICY_ALLOW`/`POLICY_DENY`, all carrying `request_id`.
Duplicating them would create two records of one decision that can disagree.

### The deliverable is correlation, not the event list

```
GET /api/v1/audit?request_id=a2a-{transaction_id}
```

returns the complete arc: received, verified, PIP, OPA, PDP, escalation,
approval, re-evaluation, AEM, tool, executed.

### What is never written
No private key. The `signature` column is truncated to 256 characters — enough
to correlate two presentations, never enough to replay one. No payload body in
audit metadata, only `payload_sha256` (tested). On a forged envelope the event
is **not** attributed to the claimed sender: `agent_did` is NULL and the claim
sits in metadata, so an attacker's assertion never lands in a victim's history.

---

## 11. Security matrix — all 29 threats

| # | Threat | Mitigation | Verified |
|---|---|---|---|
| 1 | forged transaction | Ed25519 against the published DID Document | ✓ |
| 2 | modified payload | payload + digest inside the signature | ✓ |
| 3 | modified amount | signed; and reconciled four ways | ✓ |
| 4 | sender substitution | signed; substituted DID's key does not verify | ✓ |
| 5 | receiver substitution | signed `receiverDid` | ✓ |
| 6 | replay | `UNIQUE (sender_did, transaction_id)` | ✓ |
| 7 | concurrent replay | unique INSERT + atomic claim | ✓ |
| 8 | duplicate financial execution | 20-way concurrency → exactly one | ✓ |
| 9 | stale transaction | server-clock freshness, both directions | ✓ |
| 10 | revoked sender credential | PIP re-verifies live; `CREDENTIAL_REVOKED` | ✓ |
| 11 | deactivated sender | refused at resolution **and** by `credential_state.rego` | ✓ |
| 12 | unknown sender | `A2A_SENDER_UNKNOWN` | ✓ |
| 13 | unknown key | key register lookup | ✓ |
| 14 | retired key | window check vs `proof.created` | ✓ |
| 15 | key rotation | history still verifies | ✓ |
| 16 | compromised sender | **bounded**, not prevented — bands, scope, purpose still apply; containment stops the next one | ✓ |
| 17 | compromised receiver | **bounded** — can withhold (DoS), cannot alter or replay | ✓ |
| 18 | ANS failure | ANS is **not on the verification path**; compromise degrades to DoS | ✓ |
| 19 | DID resolution failure | `A2A_SENDER_NOT_RESOLVABLE`, fail-closed | ✓ |
| 20 | OPA failure | `AUTHORIZATION_UNAVAILABLE`, DENY | ✓ |
| 21 | policy failure | `A2A_POLICY_UNCONFIGURED`, config genuinely removed in test | ✓ |
| 22 | confused deputy | decision subject = **sender**; receiver's authority never borrowed | ✓ |
| 23 | purpose manipulation | signed; purpose enforced separately from action | ✓ |
| 24 | action manipulation | signed; **tool derived**, never named by a caller | ✓ |
| 25 | resource manipulation | signed; `resource_scope.rego` against the sender's credentials | ✓ |
| 26 | JIT scope manipulation | `JIT_GRANT_BINDING_MISMATCH` | ✓ |
| 27 | HITL bypass | `execute_payment` JIT-excluded twice; fabricated approval refused | ✓ |
| 28 | amount escalation | three independent refusals | ✓ |
| 29 | cross-agent forwarding | signed field **and** `PRINCIPAL_IS_NOT_THE_SUBJECT` | ✓ |

---

## 12. Non-repudiation — what this proves and what it does not

**Proves:** the holder of the private key registered in the DID Document for
`sender_did`, at the time `proof.created` claims, produced these exact
canonical bytes; and the bytes have not changed since. Plus an append-only,
monotonically-sequenced audit trail.

**Does NOT prove, and this system does not claim:**

* **Legal non-repudiation.** No qualified certificate, no trusted timestamping
  authority, no accredited CA. `did:poc:` is not a registered DID method and
  there is no resolver network.
* **That a *person* intended the transaction.** An agent's key signs; a person
  may never have seen it.
* **That the key was not shared, copied or stolen.** The
  `EncryptedFileKeyStore` master key lives in the process environment, so a
  **host compromise forges signatures indistinguishably.** Production would
  bind `KeyStore` to a KMS/HSM; the interface is already shaped for it.
* **Ordering between independent transactions.** `proof.created` is the
  sender's clock. `audit_events.seq` orders what the *server* observed.
* **That the audit trail cannot be altered by a database administrator.**
  Append-only by convention and by the absence of an update path — not by
  cryptographic chaining.

> Phase 7 provides cryptographic **authenticity and integrity** of
> agent-to-agent transactions under the implemented key-custody model,
> together with a tamper-evident, correlated audit trail. It does **not**
> provide legal non-repudiation.

---

## 13. Known limitations

1. **No agent key-rotation operation.** `KeyStatus.ROTATED` and
   `AgentKey.rotated_at` have existed since Phase 1 and nothing sets them.
   Phase 7 implements and tests the **verification** side of the key window
   against those columns; building the operator-facing rotation flow is Phase 1
   identity-plane work and is outside this phase.
2. **Single currency.** `amount_inr`, whole-rupee integers, matching Phase 5.5.
   This system cannot express a non-INR transaction. Introducing a minor-unit
   scheme would create a second money vocabulary.
3. **`ApprovalAuthority.rotate()` remains unfixed.** It retires the active key
   *before* checking for a keystore collision, so a collision leaves the
   authority with no ACTIVE key — the ordering `JITAuthority.rotate` explicitly
   fixed. Phase 7's middle band depends on the approval path, so this is in its
   blast radius. **Per instruction it was not modified.** Operational caveat:
   *do not rotate the approval authority while A2A transactions are pending
   approval.*
4. **`AgentRuntime.signing_payload()` has no proof purpose.** The only
   signature in the system without a domain separator. Not exploitable against
   the A2A envelope (disjoint key sets ⇒ disjoint canonical bytes), but it is
   the one place the discipline is not uniform. A Phase 1 artifact; untouched.
5. **Availability depends on the receiver being live.** Only the receiver may
   submit, so a transaction to an offline agent cannot be submitted at all.
   Fail-closed and correct. The sender cannot distinguish "B is down" from "B
   refused" on a bare timeout, so a timeout must be treated as **unknown** and
   retried under the **same** transaction id — which the idempotency model
   makes safe. `/a2a/send` says so in its error.
6. **The realm needs re-importing.** `PAYMENT_OFFICER` and the two officer
   accounts are in `keycloak/realm-agentic-iam.json`, which `--import-realm`
   applies only to a realm that does not yet exist. A running instance needs
   either a force-recreate or the admin-API equivalent.
7. **A2A `read` is not eligible.** One agent asking another to read a record on
   its behalf is the confused-deputy shape and needs its own analysis before
   being enabled, rather than being permitted because it looks harmless.

---

## 14. Performance

Measured against the running stack. Nothing modelled.

| Measurement | median |
|---|---|
| envelope construction + Ed25519 signature (in process) | **0.54 ms** |
| verify + PDP + AEM + execute, end to end | 849 ms |
| the same protected call **without** A2A (Phase 4 baseline) | 832 ms |
| idempotent replay of a settled transaction | **44 ms** |
| **A2A overhead on the enforcement path** | **+17 ms** |

The absolute figures are dominated by the PIP, which re-verifies **every**
credential the subject holds on every evaluation — the property that makes
revocation immediate. On this long-lived development database the demo agent
has accumulated 189 credentials from repeated seeding, so ~780 ms of each call
is that accumulation and not an A2A cost. The gate prints the per-stage
breakdown so the numbers explain themselves.

**The +17 ms delta is the Phase 7 cost:** verifying an Ed25519 signature,
resolving the sender from its DID Document, registering the transaction
atomically and reconciling the amount. The PDP evaluation happens either way —
which is the point.
