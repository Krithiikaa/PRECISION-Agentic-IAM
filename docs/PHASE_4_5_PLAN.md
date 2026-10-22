# Phase 4.5 — Control-Plane Hardening: plan

Phase 4 proved that a valid identity holding a valid credential is still denied
a resource its credential does not name. That is worth very little if an
unauthenticated caller can reach the machinery that produces the decision.

This phase closes that. It adds **authentication** in front of security-critical
control-plane operations, and routes the resulting principal through the
**existing PDP and the existing OPA runtime** for an authorization decision.

    CONTROL-PLANE REQUEST
            |
            v
    AUTHENTICATION      who is calling?   (DID + Ed25519 proof + freshness)
            |
            v
    AUTHORIZATION       may this principal do this?   (PDP -> OPA -> Rego)
            |
            v
    OPERATION           heartbeat / deregister / policy mutation / sign

No new cryptographic identity system is introduced. No policy logic is moved
into the authentication layer.

---

## 1. Baseline (recorded before any code changed)

    $ .venv/bin/python -m pytest
    374 passed in 113.24s

| | |
|---|---|
| Collected | 374 |
| Passed | 374 |
| Failed | 0 |
| Skipped | 0 |

Matches the expected Phase 4 baseline exactly. Infrastructure present for the
run: PostgreSQL 16, Redis 7, OPA (`openpolicyagent/opa:latest`, healthy),
Ollama reachable with the configured model.

---

## 2. Control-plane endpoint inventory

Every route in both FastAPI applications, classified. `AUTH` = requires a
proven principal after this phase.

### IAM API (`app.main`, port 8000)

| Endpoint | Method | Purpose | Class | Auth before | Auth after |
|---|---|---|---|---|---|
| `/health`, `/ready` | GET | liveness | public read | none | none |
| `/api/v1/agents` | GET | list identities | public read | none | none |
| `/api/v1/agents/{id}`, `/did/{did}`, `…/did-document`, `…/credentials`, `…/audit` | GET | identity reads | public read | none | none |
| `/api/v1/agents` | POST | **create identity** | high-risk mutation | none | none — **S-7, deferred** |
| `/api/v1/agents/{id}/status` | POST | **suspend / terminate identity** | high-risk mutation | none | none — **S-7, deferred** |
| `/api/v1/agents/{id}/sign` | POST | **sign arbitrary bytes as an agent** | high-risk mutation | none | **AUTH** `identity_admin` |
| `/api/v1/identity/sign` | POST | **sign arbitrary bytes as an agent** | high-risk mutation | none | **AUTH** `identity_admin` |
| `/api/v1/identity/verify` | POST | verify a signature | public read | none | none |
| `/api/v1/credentials/issue` | POST | **mint a credential** | high-risk mutation | none | none — **S-7, deferred** |
| `/api/v1/credentials/{id}/revoke` | POST | **revoke a credential** | authorized mutation | none | none — **S-7, deferred** |
| `/api/v1/credentials/present` | POST | produce a holder proof | authorized mutation | none | none — **S-7, deferred** |
| `/api/v1/credentials/verify`, `/verify-presentation`, `/challenge` | POST | verification services | public read | none | none |
| `/api/v1/credentials`, `/issuers`, `…/status`, `…/verifications`, `/{id}` | GET | credential reads | public read | none | none |
| `/api/v1/audit` | GET | audit trail | public read | none | none |
| `/api/v1/audit/events` | POST | **ingest an audit event** | authorized mutation | none | none — **S-7, deferred** |
| `/api/v1/events/stream` | GET | live SSE | public read | none | none |
| `/api/v1/authorize` | POST | **PDP decision** | authenticated evaluation | none | **AUTH** self or `enforcement` |
| `/api/v1/enforce` | POST | **AEM: reach a protected tool** | authenticated mutation | none | **AUTH** self or `enforcement` |
| `/api/v1/enforce/tools` | GET | tool catalogue | public read | none | none |
| `/api/v1/policies` | GET | policy lifecycle | public read | none | none |
| `/api/v1/policies/reload` | POST | **push the policy set to OPA** | high-risk mutation | none | **AUTH** `policy_admin` |
| `/api/v1/policies/{id}/activate` | POST | **load a policy into OPA** | high-risk mutation | none | **AUTH** `policy_admin` |
| `/api/v1/policies/{id}/deactivate` | POST | **remove a policy from OPA** | high-risk mutation | none | **AUTH** `policy_admin` |
| `/api/v1/authorize/decisions` | GET | decision log | public read | none | none |
| `/api/v1/authorize/health` | GET | engine posture | public read | none | none |

### Agent Naming Service (`app.ans.service`, port 8100)

| Endpoint | Method | Purpose | Class | Auth before | Auth after |
|---|---|---|---|---|---|
| `/health`, `/ready` | GET | liveness | public read | none | none |
| `/api/v1/ans/register` | POST | register an agent | authorized mutation | **signed registration proof** | unchanged (already authenticated) |
| `/api/v1/ans/heartbeat` | POST | **update liveness** | authenticated mutation | **none — S-4** | **AUTH** self |
| `/api/v1/ans/unregister/{did}` | POST | **remove from discovery** | authorized mutation | **none — S-4** | **AUTH** self or `registry_admin` |
| `/api/v1/ans/sweep` | POST | **force a liveness sweep** | authorized mutation | none | **AUTH** `registry_admin` |
| `/api/v1/ans/discover` | POST | capability discovery | controlled read | none | none (§15: must keep working) |
| `/api/v1/ans/resolve/{did}`, `/agents`, `/capabilities`, `/agents/{did}/health`, `/discovery/{id}` | GET | registry reads | public read | none | none |

### OPA (port 8181)

| Surface | Class | Before | After |
|---|---|---|---|
| `PUT/DELETE /v1/policies/*` | administrative | published on `0.0.0.0:8181` | published on `127.0.0.1:8181` only; unreachable from the network |
| `POST /v1/data/*` | evaluation | same | same |

---

## 3. New finding: S-6, the signing oracle

`POST /api/v1/agents/{id}/sign` and `POST /api/v1/identity/sign` sign an
**arbitrary caller-supplied message** with a registry-custodied agent's private
key, with no authentication.

That is not merely a Phase 1 weakness. It is a **complete bypass of anything
built on agent DID proofs**, including the heartbeat authentication this phase
adds:

    attacker -> GET  /api/v1/agents                  (find risk-001)
             -> POST /api/v1/agents/{id}/sign        (sign the heartbeat payload)
             -> POST /api/v1/ans/heartbeat           (present a genuine signature)

The proof would verify, because it *is* risk-001's signature. S-4 therefore
cannot be closed without closing S-6, so S-6 is in scope for this phase.

Agents that hold their own keys (`keystore_backend == "external"`, which is
every running agent service) were never exposed — the registry refuses and says
so. The exposure is registry-custodied identities, which is what the test suite
and the console create.

---

## 4. Mechanism

### 4.1 What signs, and what is signed

The Phase 1 machine identity, unchanged: an Ed25519 key in the KeyStore, a DID,
and a published DID Document. No second identity system, no bearer token, no
shared secret, no IP allowlist.

The proof travels in headers so no existing request schema changes (several use
`extra="forbid"`, and the body must stay byte-identical to what is signed):

    X-CP-Principal   did:poc:agent:risk-001
    X-CP-Key-Id      did:poc:agent:risk-001#key-1
    X-CP-Nonce       <128 bits, urlsafe>
    X-CP-Timestamp   2026-08-30T09:14:22.481Z
    X-CP-Signature   <base64 Ed25519>

The signed payload is canonicalised with the **same** `app.credentials.canonical`
used by issuer proofs, holder proofs and ANS registration proofs:

    {
      "principal":   "<did>",
      "method":      "POST",
      "path":        "/api/v1/ans/heartbeat",
      "body_sha256": "<hex of the exact request body bytes>",
      "nonce":       "<nonce>",
      "timestamp":   "<iso8601>",
      "proofPurpose":"controlPlaneRequest"
    }

Each field is load-bearing:

* `principal` — the identity being claimed.
* `method` + `path` — binds the proof to one operation. A captured heartbeat
  proof cannot be replayed against `/unregister`.
* `body_sha256` — binds the proof to the exact body. The `did` inside a
  heartbeat body cannot be swapped after signing.
* `nonce` — single-use per principal, enforced by a unique index.
* `timestamp` — bounded freshness, so a captured proof dies even if the nonce
  table is pruned.
* `proofPurpose` — domain separation. A control-plane proof can never be
  mistaken for a credential proof, a holder proof or a registration proof, and
  none of those can be replayed as a control-plane proof.

### 4.2 How the verifier resolves the public key

Exactly the path a third party would take, with no shortcut:

* agent principal → the DID Document published by the Phase 1 agent registry
* administrator principal → the DID Document published by the control-plane
  principal registry

Both yield a `publicKeyMultibase`, verified with the existing
`app.identity.signer.verify_signature`. Nothing new verifies Ed25519.

### 4.3 Replay prevention

Two independent mechanisms, matching the ANS registration design:

1. **Nonce**, single-use, `UNIQUE (principal_did, nonce)` on
   `control_plane_proofs`. A second presentation of the same nonce is rejected
   by the database, not by a race-prone read-then-write.
2. **Freshness window** (`CONTROL_PLANE_FRESHNESS_SECONDS`, default 300s).
   Bounded so a captured proof expires on its own.

Body, method and path binding means a replay is only ever possible against the
*identical* request — which the nonce already refuses.

### 4.4 Human administrators

Per §20 no Keycloak, OIDC or SAML. An administrator is the simplest secure
principal this architecture already supports: **a DID with an Ed25519 key and a
published DID Document**, created idempotently at startup from
`CONTROL_PLANE_ADMINISTRATORS`.

    did:poc:administrator:platform-security     policy_admin, registry_admin
    did:poc:administrator:identity-authority    identity_admin
    did:poc:administrator:enforcement-gateway   enforcement

Three principals rather than one, so least privilege is demonstrable rather
than asserted: the identity administrator is refused policy activation.

When HITL arrives, Keycloak/OIDC federates *into* this principal model — the
authentication step is replaced, the authorization step and every policy stay
as they are.

### 4.5 Authorization stays in OPA

Authentication answers *who*. Authorization answers *may they* — and it is
answered where every other authorization decision in this system is answered:

    ControlPlaneGuard
        -> ControlPlaneAuthenticator     (who?)
        -> PolicyDecisionPoint.decide_control_plane()
        -> OPAClient.evaluate()
        -> package agentic_iam.control_plane   (Rego)

Same PDP component, same PIP component, same OPA runtime, same fail-closed
posture. A **separate Rego package** with its own deny-overrides/default-deny
combining algorithm, so the data-plane semantics of `agentic_iam.authz` are not
touched (§15).

New policies:

| policy_id | module | rule |
|---|---|---|
| `cp-combining` | `agentic_iam/control_plane/decision` | deny-overrides, default-deny |
| `cp-agent-self` | `agentic_iam/control_plane/agent_self` | an agent may heartbeat and deregister **itself**, and ask the PDP about **itself** |
| `cp-administration` | `agentic_iam/control_plane/administration` | an administrator holding the required role may perform that administrative action |

### 4.6 Fail closed

Missing, malformed, stale, replayed or invalid proof; unknown principal;
ineligible identity; OPA unavailable; no matching policy — every one produces
**403** (or **401** when no proof was presented at all) and the operation never
runs. There is no configuration that turns any of these into success.

---

## 5. Deliberately out of scope

No HITL, Keycloak, OIDC, SAML, JIT, A2A, MCP security, Session Authority, SSS,
monitoring or kill switch. `HUMAN_APPROVAL_REQUIRED` stays a decision value.

**S-7 (deferred, documented):** the Phase 1/2 identity control plane — agent
creation, agent status change, credential issuance, credential revocation,
holder-proof production, audit ingest — stays unauthenticated. Those endpoints
are driven by the human-facing console, which holds no key and cannot produce a
proof; giving it one is the human identity model that §20 explicitly defers to
HITL. They are inventoried above with their recommended protection, and named
again in the final report rather than quietly left out.


---

## 6. Outcome

Everything planned above was implemented and verified against the running
system. Final state:

| | |
|---|---|
| Tests | 440 collected, 440 passing, 0 failures, 0 skips |
| Baseline | 374 (Phase 4) |
| Added | 66 |
| Phase 1 gate | 12/12 |
| Phase 2 gate | 30/30 |
| Phase 3 gate | 40/40 |
| Phase 4 gate | 31/31 |
| Phase 4.5 gate | 46/46 |

S-4, S-5 and S-6 are closed. S-7 remains open and is recorded in
`docs/PHASE_STATUS.md` and `docs/CONTROL_PLANE_SECURITY.md` §10.

Design details are in [CONTROL_PLANE_SECURITY.md](CONTROL_PLANE_SECURITY.md).
