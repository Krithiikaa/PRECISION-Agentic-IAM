# Control-Plane Security

Phase 4 proved that a valid identity holding a valid credential is still denied
a resource its credential does not name. That was worth very little while an
unauthenticated caller could reach the machinery producing the decision.

This document describes what Phase 4.5 added, and — as importantly — what it
deliberately did not.

---

## 1. Two planes

    DATA PLANE                          CONTROL PLANE

    agent                               principal (agent or administrator)
      |                                   |
      v                                   v
    AEM                                 AUTHENTICATION   (DID + Ed25519 proof)
      |                                   |
      v                                   v
    protected tool                      AUTHORIZATION    (PDP -> OPA -> Rego)
      |                                   |
      v                                   v
    resource                            ANS / PDP / PAP / identity signing

The data plane asks **"may this agent read this record?"**. The control plane
asks **"may this principal change how that question gets answered?"**.

They are kept apart deliberately, in three ways:

* **Different principals.** The data plane authorizes agents only. The control
  plane also recognises administrators, which are not agents and hold no
  credentials.
* **Different policy.** `agentic_iam.authz` and `agentic_iam.control_plane` are
  separate Rego packages with separate combining algorithms. Hardening the
  control plane cannot alter resource-authorization semantics.
* **Different authority.** A capability credential describes what an agent may
  do with DATA. No accumulation of credentials confers authority over the
  decision machinery — `cp-agent-self` denies an agent every administrative
  operation, by name, with `AGENT_MAY_NOT_ADMINISTER`.

They share the components that must not diverge: one PDP, one PIP, one OPA
runtime, one signature verifier, one canonicaliser, one audit trail.

---

## 2. Machine identity

No new identity system was introduced. A control-plane principal is the same
thing every other principal here is:

    a DID + an Ed25519 key pair in the KeyStore + a published DID Document

| | Agent | Administrator |
|---|---|---|
| DID | `did:poc:agent:risk-001` | `did:poc:administrator:platform-security` |
| Key | Phase 1 key, unchanged | its own, created at startup |
| Published as | DID Document in the agent registry | DID Document in the principal registry |
| Public key resolved from | that document | that document |
| Roles | **none, ever** | granted by configuration |
| May act for | itself only | whatever its roles permit |

Explicitly rejected, per the spec and for good reasons:

* **bearer tokens / API keys / shared secrets** — a secret that authenticates
  is a secret that can be copied, and it names nobody
* **IP allowlists and localhost checks** — network position is not identity
* **agent-name-only authentication** — a name is a claim
* **trusting the DID in the request body** — that is S-4 restated

### Who signs

The party performing the operation, with a key it already holds. An agent signs
its own heartbeat in `ANSClient`; an operator signs administration with an
administrator key. The private key never leaves the KeyStore — the server sees
only a signature and the public key it independently resolves.

### What is signed

```
{
  "principal":    "did:poc:agent:risk-001",
  "method":       "POST",
  "path":         "/api/v1/ans/heartbeat",
  "body_sha256":  "<sha256 of the exact request body bytes>",
  "nonce":        "<128 bits, single use>",
  "timestamp":    "2026-08-30T09:14:22.481Z",
  "proofPurpose": "controlPlaneRequest"
}
```

Canonicalised by `app.credentials.canonical` — the same RFC-8785-style
canonicaliser used by issuer proofs, holder proofs and ANS registration proofs.

Every field is load-bearing:

| Field | Attack it stops |
|---|---|
| `principal` | — the identity being claimed |
| `method` + `path` | a captured heartbeat proof presented at `/unregister` |
| `body_sha256` | signing for your own DID and swapping the victim's into the body |
| `nonce` | replaying the identical request |
| `timestamp` | reusing a captured proof indefinitely |
| `proofPurpose` | presenting a credential or registration proof as a heartbeat |

That last row is domain separation, and it is why four proof types can share one
canonicaliser and one key without ever being confusable. The purpose is *inside*
the signed bytes:

| Proof | Purpose | Signed by |
|---|---|---|
| Credential | `assertionMethod` | the issuer |
| Presentation | `authentication` | the holder |
| ANS registration | `ansRegistration` | the agent |
| Control-plane request | `controlPlaneRequest` | the principal |

### How the verifier resolves the key

The same path a third party would take, with no shortcut and no cache:

* agent → DID Document published by the Phase 1 registry
* administrator → DID Document published by the principal registry

A caller may state which key id it used (`X-CP-Key-Id`); it does not get to
choose one. A mismatch is refused rather than ignored.

### Wire format

    X-CP-Principal   did:poc:agent:risk-001
    X-CP-Key-Id      did:poc:agent:risk-001#key-1
    X-CP-Nonce       9wS2v3kQ...
    X-CP-Timestamp   2026-08-30T09:14:22.481Z
    X-CP-Signature   <base64 Ed25519>

Headers, not body fields — the body must stay byte-identical to what was hashed,
and several request schemas are `extra="forbid"`.

---

## 3. Replay prevention

Two independent mechanisms, matching the ANS registration design:

**Nonce, single use.** `UNIQUE (principal_did, nonce) WHERE accepted` on
`control_plane_proofs`. A database constraint, not a read-then-write in Python,
so two concurrent presentations of the same nonce cannot both win.

**Freshness window.** `CONTROL_PLANE_FRESHNESS_SECONDS`, default 300s, bounded
in *both* directions — a proof timestamped an hour in the future is as
suspicious as one an hour old, and accepting it would hand an attacker a proof
valid for as long as they chose to post-date it.

Two supporting properties:

* Only an **accepted** proof consumes its nonce. Rejected attempts are recorded
  in full, so an attacker cannot lock a legitimate agent out by replaying its
  nonces with garbage signatures.
* The nonce is consumed when the proof is **presented**, committed before the
  operation runs. A proof is not released because the operation later failed.

---

## 4. Authorization stays in OPA

```
ControlPlaneGuard
    -> ControlPlaneAuthenticator          WHO is calling?
    -> PolicyDecisionPoint.decide_control_plane()
    -> OPAClient.evaluate(control_plane_decision_url)
    -> package agentic_iam.control_plane  MAY they?
```

`decide_control_plane()` is a method on the existing PDP, not a second decision
point: there is exactly one component in this system that turns a question into
a policy verdict.

**There is not one privilege rule in `guard.py` or `authenticator.py`**, and a
test asserts it. The authenticator records which roles a principal was granted;
Rego decides what they permit. A reviewer asking "what can a `policy_admin` do?"
reads Rego.

| Policy | Rule |
|---|---|
| `cp-combining` | deny-overrides, default-deny; seeded empty so removing every policy fails closed rather than failing to compile |
| `cp-agent-self` | an agent may heartbeat, deregister and be the subject of a PDP/AEM call **for itself**; explicit denies for acting as another agent and for any administrative operation |
| `cp-administration` | maps each administrative operation to the single role it requires |

### Roles

| Role | Permits | Held by |
|---|---|---|
| `policy_admin` | policy reload / activate / deactivate | `platform-security` |
| `registry_admin` | ANS sweep, deregistering another agent | `platform-security` |
| `identity_admin` | signing as a registry-custodied identity | `identity-authority` |
| `enforcement` | PDP query and AEM enforcement on behalf of a subject | `enforcement-gateway` |

Three principals rather than one, so **least privilege is demonstrable rather
than asserted**: the identity administrator is genuinely refused policy
activation, the policy administrator is genuinely refused identity signing. If
the roles were decorative those tests would pass anyway.

---

## 5. Endpoint classification

| Class | Requirement | Examples |
|---|---|---|
| Public / low-risk read | none | `/health`, `GET /agents`, `GET /policies`, `GET /audit`, `POST /credentials/verify` |
| Controlled read | none (§15: must keep working) | `POST /ans/discover`, `GET /ans/resolve/{did}` |
| Authenticated mutation | proof of the subject | `POST /ans/heartbeat`, `POST /authorize` |
| Authorized mutation | proof + role, or self | `POST /ans/unregister/{did}`, `POST /enforce`, `POST /ans/sweep` |
| High-risk administration | proof + role | `POST /policies/*`, `POST /agents/{id}/sign`, `POST /identity/sign` |

Reads stay open on purpose. Closing them would break the console and the
coordinator without protecting anything that can be changed — a discovery result
is a routing hint the caller must still authenticate and authorize against.

---

## 6. The three findings this closed

### S-4 — unauthenticated ANS heartbeat

Liveness was whatever the first caller said it was. Anyone who could reach the
port could keep a dead agent in discovery, or send `status: OFFLINE` and remove
a healthy one — a single unauthenticated request that stopped work being routed
to an agent.

Now the principal must prove control of the DID it names, and `cp-agent-self`
requires the proven principal to *be* the subject. A genuine agent with a
genuine key, signing a genuine proof for itself, is still refused when it names
someone else: `PRINCIPAL_IS_NOT_THE_SUBJECT`.

Endpoint mutation via heartbeat remains impossible, as before: moving where
traffic goes requires a fresh signed **registration**, a different proof with a
different purpose.

### S-5 — unauthenticated authorization APIs

Two distinct problems behind one label.

**`/enforce` was the serious one.** It is the only route to a protected tool.
Unauthenticated, any caller could name `risk-001` and receive real credit data.
The PDP was deciding correctly — about an identity nobody had checked. Now the
caller proves it is the subject, or holds `enforcement`.

**Policy administration was the other.** An unauthenticated caller could
deactivate every policy. That failed *closed* — the combining algorithm then
denies everything — so it was denial of service rather than escalation. A
security control anyone can switch off is still not a security control.

### S-6 — the signing oracle (found during this phase)

`POST /api/v1/agents/{id}/sign` and `POST /api/v1/identity/sign` sign an
**arbitrary caller-supplied message** with a registry-custodied agent's private
key, unauthenticated. That is not a weak endpoint; it is a universal forgery
oracle for every DID proof in the system:

    GET  /api/v1/agents             find the victim
    POST /agents/{id}/sign          sign the control-plane payload
    POST /ans/heartbeat             present a signature that really does verify

S-4 could not be closed while it stayed open, so it is closed here:
`identity_admin` only. Agents holding their own keys (every running agent
service) were never exposed — the registry refuses and says so.

`/identity/verify` stays open: verification needs only a public key, changes
nothing, and is precisely what a third party must be able to do alone.

---

## 7. Fail-closed

Every one of these produces 401 or 403, and the operation never runs:

| Condition | Status | Reason |
|---|---|---|
| no proof presented | 401 | `CONTROL_PLANE_PROOF_MISSING` |
| empty or oversized proof header | 401 | `CONTROL_PLANE_PROOF_MALFORMED` |
| principal not registered | 403 | `PRINCIPAL_UNKNOWN` |
| identity terminated / suspended | 403 | `PRINCIPAL_NOT_ELIGIBLE` |
| no DID Document published | 403 | `PRINCIPAL_NOT_RESOLVABLE` |
| signature does not verify | 403 | `CONTROL_PLANE_SIGNATURE_INVALID` |
| timestamp outside the window | 403 | `CONTROL_PLANE_TIMESTAMP_STALE` |
| nonce already spent | 403 | `CONTROL_PLANE_NONCE_REPLAYED` |
| principal is not the subject | 403 | `PRINCIPAL_IS_NOT_THE_SUBJECT` |
| agent attempting administration | 403 | `AGENT_MAY_NOT_ADMINISTER` |
| administrator without the role | 403 | `MISSING_CONTROL_PLANE_ROLE` |
| operation has no rule | 403 | `UNKNOWN_CONTROL_PLANE_OPERATION` |
| **OPA unreachable** | 403 | `CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE` |

The last row was verified against a genuinely stopped OPA: a valid proof from a
legitimate principal is still refused when policy cannot be consulted. There is
no "we could not check, so proceed".

`CONTROL_PLANE_AUTHENTICATION_REQUIRED` cannot be set to false — a pydantic
validator refuses to start. A switch that turns a proof requirement into a no-op
is a bypass with a configuration file in front of it.

---

## 8. OPA isolation

    caller -> IAM control plane -> PAP / PDP -> OPA        supported
    caller -> OPA admin API                                not reachable

OPA's administrative API (`PUT`/`DELETE /v1/policies`) can load a rule granting
the caller everything, which the PDP would then faithfully enforce — bypassing
the IAM control plane entirely, because the attacker never goes through it.

The published port is therefore bound to `127.0.0.1:8181` rather than
`0.0.0.0`. It stays published at all only because a host-run backend and the
host test suite must reach the same engine the containers use; in a real
deployment it is not published, and OPA is reachable only on the compose
network. Verified: `ss -ltn` shows `127.0.0.1:8181`, and the host's LAN address
refuses the connection.

No route in either application proxies to OPA's administrative API. The only
path to policy is the PAP, which is itself behind `policy_admin`.

---

## 9. Audit

Every security-sensitive control-plane action produces an event carrying
`request_id`, principal, action, target, decision, reason, classification and
timestamp.

| Event | Meaning |
|---|---|
| `CONTROL_PLANE_AUTHENTICATED` | the caller proved control of the DID it claimed |
| `CONTROL_PLANE_REJECTED` | authentication failed — we could not tell who this is |
| `CONTROL_PLANE_AUTHORIZED` | policy permitted the operation |
| `CONTROL_PLANE_DENIED` | we know exactly who this is, and they may not |
| `CONTROL_PLANE_REPLAY_DETECTED` | evidence of a captured proof |
| `ANS_HEARTBEAT_ACCEPTED` / `_REJECTED` | per-operation, for an ANS operator |
| `ANS_DEREGISTRATION_ACCEPTED` / `_REJECTED` | " |
| `AUTHORIZATION_API_REJECTED` | " |

Authentication and authorization are separate events deliberately: *"we could
not tell who you are"* and *"we know who you are and you may not"* are different
incidents.

**Refusals are committed before the exception is raised.** FastAPI's session
dependency rolls back on an exception, which would have erased the record of an
attack exactly when it mattered. An attacker cannot make their failed attempts
disappear by ensuring the request ends in an error.

No secrets are logged. The proof ledger stores the body's **digest**, never the
body, and truncates the signature to 256 characters — enough to correlate two
presentations of the same proof, never enough to replay one.

---

## 10. What this does not do

**HITL is not implemented.** No approval flow, no approval artifact, no human
principal type. `HUMAN_APPROVAL_REQUIRED` remains a decision value with nothing
behind it, and a test greps the codebase to keep it that way.

**Administrators are machine principals, not people.** A DID and a key, not a
login. There is no session, no password, no MFA and no human accountability
beyond "this key signed this request".

**S-7 — the Phase 1/2 identity control plane is still unauthenticated.** Agent
creation, agent status change, credential issuance, credential revocation,
holder-proof production and audit ingest remain open. Credential issuance is the
significant one: anyone who can reach the port can mint themselves a capability
credential and receive `ALLOW` from the PDP. It is inventoried in
`docs/PHASE_4_5_PLAN.md` with its recommended protection, and named again in the
Phase 4.5 report — not quietly left out.

The mechanism to close it now exists and would be a small change (an
`identity_admin` guard on each route). It was deferred because those endpoints
are driven by the human-facing console, which holds no key and cannot produce a
proof; giving the console a principal is the human identity model this phase was
explicitly told to leave to HITL.

---

## 11. Future integration

The boundary is deliberately clean:

    CONTROL-PLANE AUTHENTICATION       <- an external IdP replaces THIS step
            |
            v
    CONTROL-PLANE AUTHORIZATION        <- unchanged
            |
            v
    PDP -> OPA -> Rego                 <- unchanged
            |
            v
    future HITL -> human approval

When human identity arrives, an OIDC/SAML provider federates *into* the
principal model: it becomes another way to establish "this request is from
principal P holding roles R". Everything downstream — the guard, the PDP, every
Rego rule, the audit taxonomy — stays as it is. The role names already in
`policies/control_plane/administration.rego` become the claims that provider
asserts.

Nothing in this phase needs to be undone to get there.

---

## 12. Measured cost

40 real requests each, idle host. Measured, not modelled.

| | n | min | median | p95 | max |
|---|--:|--:|--:|--:|--:|
| unguarded read (`GET /policies`) | 40 | 15.73 | **17.36** | 48.27 | 196.99 |
| guarded write (`POST /ans/heartbeat`) | 40 | 31.83 | **35.00** | 45.96 | 127.56 |
| — authentication (proof verify + ledger) | 40 | 5.30 | 6.29 | 8.48 | 36.04 |
| — authorization (PDP → OPA → Rego) | 40 | 8.71 | 9.52 | 14.01 | 29.21 |

All in milliseconds. **The guard adds ~17.6ms at the median**, split roughly
40/60 between authentication and authorization.

Authentication is one Ed25519 verification plus two database round trips (the
nonce lookup and the ledger insert); the ledger insert is the larger half.
Authorization is one HTTP round trip to OPA. Both scale with request rate, not
with how many credentials a subject holds — unlike the data-plane PIP, which
is linear in credentials and dominates a `/authorize` call at ~170ms.

Under load (measured during a concurrent LLM inference) the authorization p95
rose to 457ms. That is CPU contention on a 6 GiB host, not a property of the
design, and it is recorded here rather than smoothed away.

---

## 13. Verifying it

    python3 scripts/phase45_gate.py

46 checks against the running stack: refusals, spoofing, replay, redirection,
body swapping, least privilege, the authorized paths, OPA isolation, the audit
trail, and measured overhead. Nothing in it is simulated.

    cd backend && .venv/bin/python -m pytest tests/test_control_plane_auth.py \
                                             tests/test_control_plane_security_matrix.py

66 tests covering the mechanism and the security matrix.
