# Phase 2 / Phase 3 audit + hardening pass

**Date:** 2026-08-30
**Type:** audit, minimal hardening, and forward-looking documentation.

| Phase | Status |
|---|---|
| **PHASE 1** | **VERIFIED** |
| **PHASE 2** | **VERIFIED + HARDENED** |
| **PHASE 3** | **VERIFIED** |

| Finding | Severity | Status |
|---|---|---|
| S-1 — credential verifier did not validate `proofPurpose` | LOW | **FIXED** |
| S-2 — presentation audience (`domain`) signed but never enforced | MEDIUM | **FIXED** |
| S-3 — `credential_verification_events.presentation_id` always NULL | LOW | **FIXED** |
| S-4 — ANS heartbeat unauthenticated | HIGH | **FIXED in Phase 4.5** — see [docs/CONTROL_PLANE_SECURITY.md](docs/CONTROL_PLANE_SECURITY.md) |

**Test baseline (before):** 234 tests, 234 passing, 0 failures.
**After:** 247 tests, 246 passing, 0 failures, 1 environmental skip (see §7).

### Scope boundary observed

Not implemented, not stubbed, not partially wired: **PDP, PIP, PAP, OPA, Rego,
AEM, JIT, HITL, Keycloak, OIDC, SAML, approval tokens, Session Authority, SSS,
Trust Engine, Anomaly Detection, Kill Switch.** The `authorization/`,
`enforcement/`, `sessions/`, `banking/` and `protocols/` packages remain empty,
as their docstrings say they should.

**No Phase 3 source file was modified.** ANS discovery, registration, liveness
architecture and Coordinator routing are untouched.

---

## 1. Current architecture

```
PHASE 1 — IDENTITY
  app/identity/            Ed25519 keys, KeyStore, DID, DID Document, Signer
  app/agents/registry.py   agent identities, key custody boundary
        │  the DID Document is the only trust anchor anything below re-uses
        ▼
PHASE 2 — VERIFIABLE CREDENTIALS
  canonical.py       JCS-style canonicalisation, floats rejected
  vc.py              VC/VP construction, proof options, proof purposes
  issuer_registry.py issuing authorities with their own key pairs
  issuer.py          mint + sign
  verifier.py        8 independent checks, per-check report
  status.py          revocation / expiry reconciliation
  presentation.py    VP construction + holder-proof payload
  presenter.py       VP building and VP verification
        │  discovery calls the Phase 2 verifier verbatim — no second implementation
        ▼
PHASE 3 — AGENT NAMING SERVICE (separate process, :8100)
  ans/proof.py       signed registration (did, endpoint, caps, nonce, timestamp)
  ans/registry.py    registration, liveness, sweep, probe, resolve, unregister
  ans/discovery.py   capability + credential-aware discovery, deterministic rank
  agents/coordinator.py  capability resolution → discovery → DID cross-check

CROSS-CUTTING
  audit/service.py → audit_events (BIGINT Identity `seq`, append-only)
                   → api/routes/events.py  SSE tails the TABLE, not a process bus
```

Nine processes write audit events: the IAM API, the ANS, and seven agent
services. The SSE stream is served by the IAM API but reads `audit_events`, so
ANS and agent events genuinely appear. This is the correct design for a
multi-process system and was left untouched.

---

## 2. Phase 2 implementation — as found

### 2.1 The credential data model already carries every required concept

| Concept | Present | Field |
|---|---|---|
| credential ID | ✅ | `id` (`urn:uuid:…`) |
| issuer | ✅ | `issuer` |
| subject | ✅ | `credentialSubject.id` |
| holder | ✅ | `holder` — on the **presentation**, correctly not on the credential |
| credential type | ✅ | `type: ["VerifiableCredential", "<specific>"]` |
| issued_at | ✅ | `issuanceDate` |
| expires_at | ✅ | `expirationDate`, inside the signature |
| status | ✅ | `credentialStatus` → live endpoint, deliberately not a baked-in boolean |
| proof | ✅ | `proof` (`PocEd25519Signature2026` / `poc-jcs-eddsa-2026`) |
| schema / version | ⚠️ partial | `@context` carries `…/credentials/v1`; per-type required claims are a Python constant, not a published registry |
| audience | ⚠️ → ✅ | `domain` was signed but never enforced — **S-2, now fixed** |
| nonce / challenge | ✅ | `challenge` on the presentation proof, signature-covered |

**No field was added to the credential model.** `schema`/`version` was
deliberately left alone: adding a `credentialSchema` field would change the
signed bytes of every future credential for a registry that does not exist yet
(Phase 6).

### 2.2 The signing payload — a genuinely strong design

`signing_payload()` places the proof options **inside** the signed body:

```python
body = {k: v for k, v in document.items() if k != "proof"}
return {**body, "proof": proof_options}     # proof_options = proof minus proofValue
```

So `created`, `verificationMethod`, `proofPurpose`, `challenge` and `domain` are
all covered by the signature. Swapping a proof's `verificationMethod` to another
key invalidates it rather than silently redirecting the verifier. This
materially reduces the severity of S-1 and is what makes S-2's audience binding
trustworthy.

### 2.3 The verifier

Eight independent, individually reported checks in a fixed order:

```
structure → issuer → signature → subject → not_before → expiration → status → claims
```

It never returns a bare `{"valid": true}`. **Signature, expiry and status are
three separate checks and are never collapsed into one boolean** — a revoked
credential reports `signature: true, status: false`, which is precisely the
distinction that makes credential status necessary.

### 2.4 The presentation layer — issuer proof vs holder proof

| | Signed by | `proofPurpose` | Answers |
|---|---|---|---|
| Issuer proof (on each VC) | issuer key, held by no agent | `assertionMethod` | "the authority attests these claims about this DID" |
| Holder proof (on the VP) | the agent's **own** Phase 1 key | `authentication` | "I am that DID, presenting these now" |

`PresentationVerifier` binds `expected_subject=holder_did` when verifying each
contained credential, so a stolen credential presented by a different agent
fails `SUBJECT_MISMATCH` despite a genuine signature. `CredentialPresenter`
refuses to build a holder proof for an agent whose key is `external`.

**This distinction was preserved exactly. It was not replaced with, or extended
toward, human approval.**

### 2.5 Challenge / nonce — audited, found correct, NOT modified

- Generation: `secrets.token_urlsafe(16)`.
- Binding: inside the signed proof options. ✅
- Verification: equality-checked when `expected_challenge` is supplied;
  otherwise records "no challenge required by this verifier". ✅ Correct — a
  verifier that never issued a challenge cannot demand one.
- Replay: used challenges are **not recorded**. Honestly documented in
  `presentation.py`, and `GET /credentials/challenge` returns
  `"single_use_enforced": false`.

Single-use nonces need cross-process shared state (Phase 9). **No change made.**

---

## 3. Phase 3 implementation — as found (audit only)

### 3.1 Cryptographic registration

The signed payload binds `did · endpoint · capabilities (sorted) · organization
· nonce · timestamp`, plus `proofPurpose: "ansRegistration"` — the ANS proof
already has its own domain separator, so an ANS registration signature can never
be replayed as a VC or VP proof. **This is the same property S-1 found missing
on the credential side, and it is already correct here.**

Nine ordered checks; a rejection returns HTTP 403 naming the failing check — an
answer, not a server error.

Verified properties:

- The public key comes from the **published DID Document** — the same trust path
  a third party takes. ANS keeps no second copy of a public key.
- The endpoint is inside the signed payload, so a captured signature cannot be
  re-pointed.
- Nonces are single-use via a **partial unique index** on
  `(agent_did, nonce) WHERE accepted` — rejected attempts are fully recorded for
  audit but cannot be used to burn a victim's nonces. A well-judged detail.
- Freshness ±300s using `abs(delta)`, tolerating modest clock drift. Deliberate
  and documented.

### 3.2 Liveness vs audit — correctly separated, preserved

Every heartbeat is written to `ans_heartbeats` (the durable liveness record the
sweeper and ranking read), but an `ANS_HEARTBEAT_RECEIVED` **audit** event is
emitted only when the status actually changed:

```python
if previous != status:
    await self.audit.record(Event(EventType.ANS_HEARTBEAT_RECEIVED, ...))
```

The in-code comment records why: seven agents at 15s intervals previously
produced 60% of the entire audit trail. **This separation was preserved and no
heartbeat noise was reintroduced into the audit stream.**

`heartbeat()` also refuses to move the endpoint — moving traffic requires a
fresh signed registration, otherwise the registration proof would be bypassable.

### 3.3 Discovery

- Narrows in SQL through the capability index, then evaluates nine constraints
  per candidate with per-candidate explanations for matches *and* rejections.
- Credential requirements are re-verified **live** by the Phase 2 verifier. The
  `ans_agent_credentials` table is explicitly an index, never a verdict, and a
  test plants a stale ACTIVE index row for a revoked credential and asserts it
  cannot smuggle the agent through.
- Ranking is deterministic: `(-score, did)`. No randomness, no ML.
- **No fallback.** An unsatisfied query returns empty with `NO_MATCHING_AGENT`.
- **Discovery is not authorization**, asserted in the ANS service description,
  in `registry.py`, in `discovery.py`, and in every coordination response.

### 3.4 Coordinator — verified free of hardcoded routing

Confirmed by inspection and grep across `app/`:

```
$ grep -nE "https?://[^\"' ]*:(900[0-9]|8100|8000)" app/agents/coordinator.py
  (no matches)
```

- **No endpoint table, no `RISK_AGENT_URL`, no keyword fallback, no routing map.**
  The only ports in the codebase are in `agents/definitions.py`, which is how
  each agent process learns *its own* port — not a routing table.
- Endpoints are obtained solely via `ans.capabilities_catalogue()` and
  `ans.discover()`.
- The LLM is constrained to the **live** catalogue; a chosen capability not in it
  is rejected. When the LLM is unavailable the coordinator raises rather than
  guessing.
- `verify_selection()` cross-checks the ANS answer against the DID Document
  served by the Phase 1 registry, which ANS does not control — so a directory
  compromise is detectable.

---

## 4. Existing tests

234 before this pass, all passing against a real PostgreSQL. The suite is
genuinely adversarial — it contains real attacks (self-issuance, credential
theft, endpoint substitution, capability escalation, stale-index smuggling), not
just happy paths.

Two tests assert the **exact set** of credential-verifier check names
(`test_every_check_is_reported_not_just_a_boolean`,
`test_verify_reports_every_check`). This directly constrained how S-1 could be
fixed — see §6.

---

## 5. Findings

Each was confirmed empirically with a throwaway probe before being written down.
Nothing here is speculative, and severities are not inflated.

### S-1 — Credential verifier did not validate `proofPurpose` — LOW — **FIXED**

**Component:** `app/credentials/verifier.py`

**Problem.** `presentation_structure_problems()` enforced
`proofPurpose == "authentication"` on holder proofs, but `CredentialVerifier`
never inspected `proof.proofPurpose` at all. The two halves of the verifier pair
were asymmetric about proof-purpose domain separation.

**Evidence.**
```
PROBE credential check names: ['structure','issuer','signature','subject',
                              'not_before','expiration','status','claims']
PROBE mentions proofPurpose in credential verifier: False
```

**Severity is genuinely LOW and inflating it would be dishonest.**
`proofPurpose` is inside the signed payload, so it cannot be flipped on an
issued credential:
```
PROBE proofPurpose flipped: reason= SIGNATURE_INVALID
```
There is **no exploit against the system as it stands**. The reason to fix it is
consistency now and domain separation later: today there are three purposes
(`assertionMethod`, `authentication`, `ansRegistration`); any future artifact
adds a fourth. Without a purpose check on the credential path, a signature made
by a registered issuer key *for a different purpose* would be structurally
acceptable as a credential proof wherever the document shape overlapped.

**Fix.** Folded into the existing `structure` check — **not** added as a ninth
check, because two tests assert the exact set of check names and weakening them
was not acceptable. Purposes are now shared constants
(`CREDENTIAL_PROOF_PURPOSE`, `PRESENTATION_PROOF_PURPOSE` in `vc.py`) used by
the issuer, the presentation builder and both verifiers, so the two sides cannot
drift apart. Every credential the system has ever issued is signed with
`assertionMethod`, so no existing credential's outcome changes. The
cryptographic model is unchanged.

---

### S-2 — Presentation audience (`domain`) signed but never enforced — MEDIUM — **FIXED**

**Component:** `app/credentials/presenter.py`, `app/api/routes/credentials.py`

**Problem.** `domain` was created, signed, stored in
`credential_presentations.domain`, transmitted, and even sent by
`phase2_gate.py` as `"domain": "loan-service"` — but
`PresentationVerifier.verify()` had **no `expected_domain` parameter and no
domain check whatsoever**. A verifier had no way to say "this presentation was
not made for me".

**Evidence.**
```
PROBE domain: valid= True checks= {'structure': True, 'holder': True,
                                   'holder_proof': True, 'challenge': True,
                                   'credentials': True}
PROBE verify params: ['document','expected_challenge','required_claims',
                      'verifier','request_id']
```
A presentation minted for `https://service-a.example` verified clean, with no
mechanism to reject it as the wrong audience.

**Why MEDIUM rather than LOW.** It compounds the already-documented
challenge-replay gap. Challenges are not recorded as used (Phase 9), so a
captured presentation can be relayed to any verifier that reuses or omits a
challenge. Audience binding is the second, independent brake on exactly that
relay. Half the mechanism already existed — only the comparison was missing.

**The security property now established:**

```
SIGNED DOMAIN  +  EXPECTED VERIFIER DOMAIN  =  AUDIENCE BINDING
```

**Fix.** Optional `expected_domain` on `PresentationVerifier.verify()`, wired
through `VerifyPresentationRequest` to the HTTP surface, with a new reason code
`DOMAIN_MISMATCH`.

**Chosen compatibility behaviour, documented deliberately:**

| `expected_domain` | Behaviour |
|---|---|
| supplied, matches | `domain` check passes |
| supplied, different | fails `DOMAIN_MISMATCH` |
| supplied, presentation has **no** domain | fails `DOMAIN_MISMATCH` |
| omitted | check passes, recording that this verifier declared no audience — and the presentation's declared domain is still **reported in the check detail**, not silently discarded |

The permissive default is what preserves backwards compatibility for every
existing caller, test and gate script, and it is also the only honest behaviour:
a verifier that never told the holder which audience to bind to cannot then
demand one. It mirrors `expected_challenge` exactly. **The domain is not
ignored** — it is enforced whenever the verifier states its audience, and
surfaced in the report when it does not.

Note the ordering: `domain` is signature-covered, so *tampering* with it breaks
the holder proof and never reaches the audience comparison. A `DOMAIN_MISMATCH`
therefore always means the holder genuinely signed for a different audience —
not that someone edited it in transit. Both paths are tested.

---

### S-3 — `credential_verification_events.presentation_id` always NULL — LOW — **FIXED**

**Component:** `app/credentials/verifier.py`, `app/credentials/presenter.py`

**Problem.** The column is declared and indexed, and
`CredentialRepository.record_verification()` accepts `presentation_id`, but no
caller ever passed one.

**Evidence.**
```
PROBE verification events: [('urn:uuid:69143e95-…', None)]
```

**Why it matters.** The model docstring states these rows exist because "the PIP
in Phase 4 will consume them as attributes". An attribute source that cannot
distinguish "verified standalone" from "verified as part of presentation X" is
materially weaker for both a future PDP and any approval trail.

**Fix.** An optional keyword-only `presentation_id` on
`CredentialVerifier.verify()`, passed by `PresentationVerifier` from the
presentation id it already holds. No ID is invented. The correlation chain is
now:

```
Credential → Presentation → Verification Event → presentation_id
```

`NULL` is preserved where the event genuinely represents a standalone credential
verification — asserted by its own test.

---

### S-4 — ANS heartbeat is unauthenticated — HIGH — **FIXED IN PHASE 4.5**

**Status: CLOSED.** The heartbeat now requires an Ed25519 control-plane proof
over the same Phase 1 key, and policy requires the proven principal to be the
subject. See [docs/CONTROL_PLANE_SECURITY.md](docs/CONTROL_PLANE_SECURITY.md).
The analysis below is preserved as it was written at audit time.

**Original status: DEFERRED TO AUTHORIZATION / CONTROL-PLANE HARDENING.**

**Component:** `app/ans/service.py`, `app/ans/registry.py`

**Problem.** `POST /api/v1/ans/heartbeat` accepts a bare DID and no signature:

```python
class HeartbeatRequest(BaseModel):
    did: str
    status: ANSStatus = ANSStatus.ACTIVE
    endpoint: str | None = None
    active_tasks: int | None = Field(default=None, ge=0)
    timestamp: str | None = None
```

There is no proof of control of the DID being reported on.

**Risk.** An attacker able to reach the heartbeat endpoint may influence
liveness state. Current behaviour is **fail-open**:

```
unauthenticated heartbeat
        ↓
last_seen refreshed, status set
        ↓
agent remains discoverable
```

Concretely, such an attacker could:

- keep an **unavailable agent discoverable** by refreshing its liveness, so the
  sweeper never demotes it to STALE/OFFLINE and the coordinator routes real work
  to a dead endpoint;
- flip a healthy agent to `DEGRADED` or `BUSY` to push it down the ranking or out
  of discovery entirely;
- report false `active_tasks` to manipulate ranking.

**Why it is called out separately.** The previously documented Phase 3
authorization gaps are *discovery* and *deregistration*. Heartbeat is a **third**
unauthenticated mutation and was not on that list. It is arguably the most
impactful of the three: `unregister` only takes an agent *offline* (fail-closed,
and the agent re-registers on its next heartbeat), whereas a forged heartbeat
keeps a dead agent **in** the answer set.

**Blast radius is bounded by existing design — this is not a takeover.**
`heartbeat()` explicitly refuses to move the endpoint, so an attacker cannot
redirect traffic without a valid signed registration; and the coordinator
independently cross-checks the endpoint against the DID Document. The identity
plane holds. The impact is denial-of-service and misrouting, not impersonation.

**Intended future direction.** Authenticated/authorized control-plane operations
should be introduced as part of the later authorization architecture — either a
signed heartbeat payload (the agent already holds the key, and the
`RegistrationPayload` pattern applies directly), or ANS mutations placed behind
the PDP/AEM. **Not decided here, and deliberately not pre-empted.**

**No fix, no temporary mechanism, no fake security was introduced.**

**On adding a test.** The instruction permitted a test *only if* it could
document current behaviour without locking in the wrong future architecture.
**No test was added**, and that is the deliberate answer to the conditional: any
test asserting "an unauthenticated heartbeat succeeds" would have to be deleted
or inverted the moment the gap is closed, which is precisely the lock-in to
avoid. The invariant that genuinely must survive any future authentication
design — that a heartbeat cannot move an agent's endpoint, and therefore cannot
redirect traffic — is **already covered by two existing tests**
(`test_ans_lifecycle.py::test_heartbeat_cannot_move_the_endpoint` and
`test_ans_api.py::test_heartbeat_cannot_move_the_endpoint`), which were left
untouched.

---

### Reviewed, found correct, no action taken

| Area | Finding |
|---|---|
| Signature validation | Real Ed25519; returns a result object rather than raising, so "invalid" is recorded, not crashed on |
| Canonicalisation | JCS-style; floats **rejected at issuance** because ECMAScript number formatting is not reproducible across languages |
| Proof coverage | Proof options inside the signed payload; `verificationMethod` cannot be redirected |
| Issuer key separation | No agent holds an issuer key; the self-issuance attack is tested and fails `ISSUER_UNKNOWN` |
| Subject binding | `expected_subject` bound to the proven holder inside VP verification |
| Expiry | `expirationDate` inside the signature; the verifier compares wall clock and does not depend on the sweep |
| Revocation | Separate table, live lookup, signature stays valid — the distinction is preserved |
| ANS nonce reuse | Partial unique index on accepted rows only; failed attempts cannot burn nonces |
| ANS endpoint binding | Endpoint inside the signed payload; heartbeat cannot move it |
| DID resolution | ANS keeps no second copy of a public key |
| Coordinator | No endpoint table, no keyword fallback, DID-Document cross-check |
| Heartbeat vs audit | Correctly separated; routine heartbeats excluded from the audit stream |
| Multi-process events | SSE tails `audit_events` by monotonic `seq`, not an in-process bus |
| Trust score | `NULL` until Phase 10; `min_trust_score` excludes unscored agents rather than assuming one |
| Host/container `localhost` | Already handled and commented in `docker-compose.yml` — `AGENT_PUBLIC_URL` is a service name under compose (`http://risk-agent:9003`) and `localhost` on a host run, because a container probing `localhost` would probe itself. No bug found; nothing changed |

### Noted but not fixed

**Holder key not checked against the `authentication` array — LOW, DEFERRED.**
`public_key_from_document(doc, proof["verificationMethod"])` resolves the key by
id but does not confirm it appears in the DID Document's `authentication` array.
Not exploitable: every DID Document this system issues carries exactly one key,
listed in both `authentication` and `assertionMethod`. Fixing it now would change
verified Phase 2 behaviour for a multi-key configuration that cannot currently
exist.

**`CHECK_REASONS["status"] = Reason.REVOKED` — INFORMATIONAL, not fixed.**
A registry-`EXPIRED` credential would report `CREDENTIAL_REVOKED` if the status
check were the first to fail. Unreachable: `CHECK_ORDER` places `expiration`
before `status`, and `sweep_expired()` only marks a credential EXPIRED under the
same condition the `expiration` check uses. Recorded so a future reordering of
`CHECK_ORDER` does not silently introduce a real mis-report.

**`self.issuers` in `CredentialVerifier` is a dead attribute** (`_issuer_lookup`
is what `verify()` uses). Harmless. Not removed — that is aesthetics, not
correctness.

---

## 6. Changes made

All additive, backwards-compatible, and confined to Phase 2.

### Files changed (6)

| File | Change |
|---|---|
| `backend/app/credentials/vc.py` | S-1: added `CREDENTIAL_PROOF_PURPOSE` / `PRESENTATION_PROOF_PURPOSE` constants |
| `backend/app/credentials/issuer.py` | S-1: signs with the shared constant instead of a literal |
| `backend/app/credentials/presentation.py` | S-1: builds and validates holder proofs against the shared constant (same string, no behaviour change) |
| `backend/app/credentials/verifier.py` | S-1: `proofPurpose` validated inside the `structure` check. S-3: optional `presentation_id`, recorded on the verification event |
| `backend/app/credentials/presenter.py` | S-2: `expected_domain` parameter, `domain` check, `DOMAIN_MISMATCH` reason. S-3: passes the presentation id through |
| `backend/app/api/routes/credentials.py` | S-2: `expected_domain` on `VerifyPresentationRequest`, wired to the verifier |

### Test files changed (3) — 13 tests added, none deleted or weakened

| File | Added |
|---|---|
| `backend/tests/test_credential_verification.py` | `TestProofPurpose` — 4 tests |
| `backend/tests/test_credential_presentation.py` | `TestAudienceBinding` — 6 tests; `TestVerificationEventCorrelation` — 2 tests |
| `backend/tests/test_credentials_api.py` | HTTP-level audience enforcement — 1 test |

### Files created (2)

- `PHASE_2_3_AUDIT.md` (this file)
- `docs/HITL_READINESS.md` — design documentation only

### Files updated (1)

- `docs/PHASE_STATUS.md` — Phase 2 marked hardened; S-4 recorded as a known
  Phase 3 gap

---

## 7. Test results

| | Before | After |
|---|---:|---:|
| Collected | 234 | **247** |
| Passing | 234 | **246** |
| Failing | **0** | **0** |
| Skipped | 0 | 1 (environmental) |
| Deleted or weakened | — | **0** |

The single skip is `test_llm_provider.py::…` — the live-Ollama test, which skips
loudly rather than passing against a fake:

```
SKIPPED [1] Host cannot load llama3:latest: MODEL_CANNOT_LOAD: the host does not
have enough free memory to load 'llama3:latest'. Ollama said: {"error":"model
requires more system memory (4.6 GiB) than is available (3.5 GiB)"}
```

**This is environmental, not a regression.** The same test *passed* in the
baseline run earlier in this session; host memory dropped during the session
(`free -g` reports 1 GiB available on a 6 GiB box). It is unrelated to every file
changed here — no LLM code was touched.

---

## 8. Security regression check

| Check | Result | Covered by |
|---|---|---|
| Signature tampering fails | ✅ | `test_tampered_capability_claim`, `test_any_field_edit_breaks_the_proof`, `test_flipped_signature_byte`, `test_editing_the_purpose_still_breaks_the_signature` |
| Expired credential fails | ✅ | `test_valid_before_expiry_invalid_after`, `test_real_elapsed_time_expires_a_short_credential` |
| Revoked credential fails | ✅ | `test_revoked_credential_is_rejected`, `test_revoked_credential_fails_inside_a_valid_presentation` |
| Wrong holder proof fails | ✅ | `test_tampered_holder_proof_is_rejected`, `test_stolen_credential_cannot_be_presented_by_another_agent` |
| Wrong challenge fails | ✅ | `test_challenge_mismatch_is_rejected` |
| Wrong domain fails when `expected_domain` supplied | ✅ | `test_presentation_for_another_audience_is_rejected`, `test_missing_domain_fails_when_an_audience_is_required`, `test_expected_domain_is_enforced_over_http` |
| Matching domain succeeds | ✅ | `test_matching_domain_verifies` |
| `presentation_id` recorded correctly | ✅ | `test_verification_inside_a_presentation_records_its_id`, `test_standalone_verification_leaves_presentation_id_null` |
| Existing valid credentials still work | ✅ | `test_untouched_credential_verifies`, `test_a_genuine_credential_still_carries_assertion_method`, `test_an_existing_domainless_presentation_still_verifies` |
| Phase 3 registration still works | ✅ | `test_ans_registration.py` — 18 tests, incl. spoofing, endpoint substitution, capability escalation, nonce replay |
| Phase 3 discovery still works | ✅ | `test_ans_discovery.py` — 22 tests, incl. the stale-index smuggling attack |
| ANS persistence still works | ⚠️ partial — see below | `test_request_and_results_are_persisted`, `test_every_attempt_is_recorded`, `test_capabilities_are_indexed_for_lookup` |
| Coordinator has no hardcoded peer endpoint table | ✅ | grep verified — §3.4 |

A targeted run of the 52 security-relevant tests: **52 passed, 0 failed.**

**On ANS persistence — stated precisely.** Persistence is verified at the
database level: the entire suite runs against a real PostgreSQL, and the
registration-proof, capability-index and discovery-request/result rows are
written and read back. The **live cross-restart script**
(`scripts/phase3_restart_test.sh`) was **not run**, because it needs the full
stack and only `postgres`, `redis` and `iam-api` are currently up — the ANS
service and the seven agent processes are not running, and starting seven agents
on a host with 1 GiB free would not have produced a trustworthy result. No Phase
3 code was modified, so no persistence behaviour changed; but this is reported as
partial rather than claimed as verified.

---

## 9. Things deliberately NOT changed

| Not changed | Why |
|---|---|
| `AgentCapabilityCredential` | Not redesigned into a human-approval type. Agent trust (DID + VC + VP) and human authorization (identity + approval + action/resource binding) are different concepts and stay separate |
| Any Phase 3 source file | Phase 3 passed its gate; no defect warranted touching it. ANS discovery, registration, liveness and Coordinator routing are untouched |
| ANS heartbeat authentication | S-4: documented, deferred. No temporary mechanism, no fake security |
| ANS discovery / deregistration authorization | Deferred to the authorization architecture, as previously documented |
| Trust score `NULL` | No default of 0/50/75/90/100 invented. Discovery still excludes unscored agents when `min_trust_score` is requested |
| Challenge single-use | Correct as documented; cross-process nonce storage is Phase 9 |
| Heartbeat/audit separation | Preserved exactly; no heartbeat noise returned to the audit stream |
| `audit_events` → SSE flow | Not replaced with an in-process bus; it must stay able to carry events from independent processes |
| Deployment architecture | Host/container `localhost` distinction already handled in `docker-compose.yml`. No bug found |
| Credential `schema`/`version` field | Would change signed bytes for a registry that does not exist yet (Phase 6) |
| `authentication`-array gate | Not exploitable with single-key DID Documents |
| Approval event types | No `APPROVAL_*` constants added. Recommended names are documented in `HITL_READINESS.md` rather than pre-wired — reserving names for an unbuilt mechanism would be exactly the partial implementation this pass was told to avoid |
| The cryptographic model | Unchanged. No new key material, no new algorithm, no change to canonicalisation or to what is signed |

---

## 10. Architectural boundary after this pass

```
PHASE 1   Agent Identity · DID · Ed25519                    COMPLETE
   ↓
PHASE 2   VC · VP · Verification · Expiry · Revocation      COMPLETE + HARDENED
          + proof-purpose separation (S-1)
          + audience binding (S-2)
          + verification correlation (S-3)
   ↓
PHASE 3   ANS · Registration · Discovery · Liveness         COMPLETE
          ⚠ S-4 unauthenticated heartbeat — HIGH, DEFERRED
   ↓
PHASE 4   PDP · PIP · PAP · OPA · Rego · AEM                FUTURE — NOT STARTED
   ↓
HITL      Keycloak · OIDC/SAML · Human approval             FUTURE — DESIGN ONLY
          · Approval artifact                               (docs/HITL_READINESS.md)
```

HITL was **not** moved into the Phase 2/3 implementation.

---

## 11. Remaining concerns

1. **S-4 (HIGH) is open.** An unauthenticated heartbeat can keep an unavailable
   agent discoverable. Bounded to denial-of-service and misrouting — not
   impersonation, because the endpoint is immutable without a signed
   registration and the coordinator cross-checks the DID Document. It should be
   closed as part of control-plane hardening, not left indefinitely.
2. **Presentations remain replayable.** Audience binding (S-2) narrows a replay
   to a single audience; it does not eliminate it. Single-use challenge storage
   is a hard prerequisite for any future approval artifact, and is Phase 9 work.
3. **The audit trail has no integrity protection.** `audit_events` is append-only
   by convention only — no hash chain, no per-event signature. Anything with
   database write access can rewrite history, including records of its own
   actions. The monotonic `seq` provides ordering and gap detection, not
   integrity. Phase 10.
4. **Issuance and revocation remain unauthenticated**, as does every ANS
   operation except registration. Previously documented; unchanged by this pass.
5. **The live Phase 3 restart test was not executed** (§8) — the full stack is
   not running on this host. No Phase 3 code changed, but the claim is
   partial rather than verified.
6. **One test is skipping for host memory**, not for any code reason. On a host
   that can load the model, the expected result is 247 passing.
