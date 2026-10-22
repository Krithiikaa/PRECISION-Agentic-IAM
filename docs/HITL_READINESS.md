# HITL readiness — design documentation

> **STATUS: FUTURE DESIGN — NOT IMPLEMENTED.**
>
> Nothing described in this document exists in the codebase. There is no
> Keycloak integration, no OIDC client, no SAML federation, no approval
> artifact, no approval endpoint, no PDP and no AEM. No credential type in this
> system represents a human decision.
>
> This document exists to answer one question, asked during the Phase 2/3 audit:
> **does the current credential architecture prevent a human-approval layer from
> being added later without rewriting the Phase 2 verifier?**
>
> The answer is no — it does not prevent it. This document records why, and what
> such a layer would need, so that the decision is deliberate rather than
> discovered.

---

## 1. The two planes, and why they must not merge

The single most important rule in this document:

**Agent trust and human authorization are different questions, answered by
different mechanisms, about different principals.**

```
        AGENT PLANE                              HUMAN PLANE
        (built, Phases 1-3)                      (future)

        AGENT IDENTITY                           HUMAN IDENTITY
        DID + Ed25519                            Keycloak
              │                                  OIDC / SAML
              ▼                                        │
        AGENT TRUST                                    ▼
        VC + VP + Verification                   HUMAN AUTHENTICATION
              │                                  "who is the human?"
              ▼                                        │
        AGENT DISCOVERY                                ▼
        ANS                                      HUMAN APPROVAL
                                                 "what did they approve?"
                                                       │
                                                       ▼
                                                 FUTURE APPROVAL ARTIFACT
                                                       │
                                                       ▼
                                                 FUTURE PDP  → ALLOW / DENY
                                                       │
                                                       ▼
                                                 FUTURE AEM  (enforcement)
```

The two planes meet only at the PDP, which takes input from both and produces a
decision. They do not meet inside a credential.

### What each layer answers

| Layer | Answers | Does **not** answer |
|---|---|---|
| DID + Ed25519 | "Which agent is this, and did it really sign this?" | anything about permission |
| VC | "What did a trusted authority assert about this agent?" | whether the agent may act now |
| VP | "Is the agent presenting these actually their subject?" | whether a human agreed |
| ANS | "Which agent is suitable for this capability?" | whether the request is authorized |
| Keycloak / OIDC / SAML | "Who is this human?" | what that human approved |
| Human approval | "What specific action did that authenticated human approve?" | whether the system will honour it |
| PDP | "Is this specific action allowed, right now?" | how to stop it |
| AEM | enforcement of the PDP's decision | — |

---

## 2. Human authentication ≠ human authorization

This distinction is the reason this document exists.

```
OIDC / SAML     answers   "WHO IS THE HUMAN?"
Human approval  answers   "WHAT SPECIFIC ACTION DID THAT HUMAN APPROVE?"
```

These are not the same, and one cannot be substituted for the other.

### Do not equate a token with an approval

**An OIDC ID token is not an approval.**
It asserts that an identity provider authenticated a human at some point, and
carries claims about who they are (`sub`, `email`, `groups`, `roles`). It says
nothing about any action, any resource, or any agent. A human who merely logged
in this morning has approved nothing.

**A Keycloak access token is not an approval.**
It authorizes the bearer to call *a service* — it is about API access, not about
a business decision. Its audience is a service, its scopes are coarse, and it is
typically valid for minutes across every action that service exposes. Treating
"holds a valid access token" as "approved this loan" would mean any request made
during the token's lifetime is silently approved, which is precisely the failure
mode a human-in-the-loop control exists to prevent.

| | OIDC ID token / access token | Approval artifact |
|---|---|---|
| Asserts | an identity was authenticated / may call a service | a human decided about one action |
| Bound to | a session and an audience service | an action, a resource, an agent, a request |
| Granularity | per session | per decision |
| Lifetime | minutes to hours, action-independent | as short as the decision is valid |
| Reusable | yes, for any call in scope | must be single-use for its action |
| Answers | "who is this?" | "what did they agree to?" |

The correct relationship is sequential, not equivalent:

```
Human
  ↓
Keycloak                       ← human identity provider
  ↓
OIDC / SAML federation
  ↓
Authenticated human identity   ← "who is the human?"  (token proves THIS ONLY)
  ↓
Approval UI                    ← the human is shown the specific action
  ↓
Specific approval              ← "what did they approve?"
  ↓
Approval artifact              ← signed, bound, expiring, single-use
  ↓
Future PDP                     ← decides using agent trust AND human approval
  ↓
Future AEM                     ← enforces the decision
```

The authenticated identity is an **input** to producing an approval. It is not
the approval.

---

## 3. What a future approval must be bound to

An approval that is not bound is not an approval — it is a reusable permission
slip. A future approval artifact should bind at least:

| Binding | Why it is required |
|---|---|
| **approver** | which human decided — the whole point of the control |
| **agent** | which agent may act on it; otherwise any agent can use it |
| **action** | approving "read" must not authorize "transfer" |
| **resource** | approving loan-7842 must not authorize loan-9999 |
| **purpose** | limits reuse in a different business context |
| **request / session** | ties the approval to the specific flow that asked |
| **issued time** | establishes when the decision was made |
| **expiry** | a decision made an hour ago may no longer be valid |
| **decision** | APPROVED and DENIED must both be representable and recorded |
| **nonce / challenge** | single use — a replayed approval is not an approval |
| **audience / domain** | which service may act on it |

Note that the last two are exactly the mechanisms Phase 2 already models for
presentations (§5).

### Example — FUTURE DESIGN, NOT IMPLEMENTED

```json
{
  "approval_id": "...",
  "approver": "...",
  "agent_did": "...",
  "action": "APPROVE_LOAN",
  "resource": "loan-7842",
  "purpose": "loan_decision",
  "request_id": "...",
  "session_id": "...",
  "decision": "APPROVED",
  "issued_at": "...",
  "expires_at": "...",
  "nonce": "...",
  "domain": "loan-service"
}
```

> **FUTURE DESIGN — NOT IMPLEMENTED.**
> This is an illustration of the binding requirements above. It is **not** a
> credential type, it is not registered in `CredentialType`, it is not in
> `REQUIRED_CLAIMS`, no issuer can mint it, and no verifier accepts it. It must
> not be added as an active credential type as part of any Phase 2/3 work.

### The rule that must not be broken

**`AgentCapabilityCredential` must not be redesigned into a
`HumanApprovalCredential`.** They are different artifacts:

| | AgentCapabilityCredential | Future approval artifact |
|---|---|---|
| Says | "this issuer attests this agent has capability X" | "this human approved action Y on resource Z" |
| Subject | an agent DID | an action/resource, decided by a human |
| Issuer | an organisational authority | an authenticated human's decision |
| Lifetime | hours to days, capability-scoped | minutes, decision-scoped |
| Reuse | expected — it is shown repeatedly | forbidden — single use |
| Revocation | issuer withdraws an attestation | approver withdraws a decision |
| Answers | "what can this agent do in general?" | "was this one act agreed to?" |

Collapsing them would mean an agent's standing capability was indistinguishable
from a human's one-off decision — which destroys the audit trail that HITL exists
to create.

---

## 4. Where the human plane enters — and where it must not

```
                    ┌─────────────────────────────┐
   agent trust ────►│                             │
   (DID/VC/VP)      │        FUTURE PDP           │──► ALLOW / DENY ──► AEM
   human approval ─►│                             │
   (approval        └─────────────────────────────┘
    artifact)
```

The two planes converge **only at the PDP**. Specifically:

- **Not in the credential.** A VC states what an authority asserts about an
  agent. Adding human decisions to it conflates two trust chains.
- **Not in the VP.** A presentation proves the holder controls the subject DID.
  Adding approval would change what the holder proof means.
- **Not in ANS.** ANS answers "which agent is suitable?" — discovery is not
  authorization, and this boundary is asserted throughout the Phase 3 code and
  in every discovery response payload.
- **Not in the agent's own logic.** An agent must not be able to decide it was
  approved. Enforcement belongs to the AEM.

---

## 5. What Phase 2 already provides

The audit ([PHASE_2_3_AUDIT.md](../PHASE_2_3_AUDIT.md)) checked whether the
existing architecture blocks any of the above. It does not. Concretely:

| Requirement of a future approval | Already present in Phase 2 |
|---|---|
| A signed, tamper-evident artifact | Ed25519 over JCS-canonical bytes; editing any field breaks the proof |
| Proof options covered by the signature | `signing_payload()` puts the proof options **inside** the signed body, so `created`, `verificationMethod`, `proofPurpose`, `challenge` and `domain` are all covered |
| Purpose separation between artifact kinds | `proofPurpose` is enforced on **both** halves since audit finding S-1: `assertionMethod` for credentials, `authentication` for presentations, `ansRegistration` for ANS. A fourth purpose slots in without touching the others |
| Audience binding | `expected_domain` on `PresentationVerifier.verify()` since audit finding S-2 — the `domain` is signed **and** compared |
| Nonce / challenge modelling | `challenge` is generated, bound into the signed proof and compared |
| Separate signature / expiry / status | Three independent checks, never collapsed into one boolean — an approval needs exactly this: "was it really approved", "is it still in its window", "was it withdrawn" |
| Post-issuance revocation | Status is a **live lookup**, not a boolean baked into the signed document, so withdrawal after signing is representable by construction |
| More than one artifact type | `REQUIRED_CLAIMS` is a dict keyed by type and `specific_type()` reads the type off the document — the verifier is not hardcoded to one type |
| An audit spine | `audit_events` already carries `session_id`, `request_id`, `resource`, `action`, `decision` and `reason` — the exact columns an approval decision needs. No schema change required to record approval events |
| Correlation of verifications | `credential_verification_events.presentation_id` is populated since audit finding S-3 |

### What is still genuinely missing

Named honestly, so nobody assumes readiness means partial implementation:

1. **Human principals are not modelled at all.** Every DID is
   `did:poc:agent:*` or `did:poc:organization:*`, and `is_agent_did()` gates ANS
   registration on the agent form. There is no human identity type.
2. **Single-use nonce storage does not exist.** Challenges are compared but not
   recorded as used, so presentations are replayable — documented in
   `presentation.py` and reported by `GET /api/v1/credentials/challenge` as
   `"single_use_enforced": false`. Cross-process nonce state is Phase 9. **An
   approval that can be replayed is not an approval**, so this is a hard
   prerequisite for HITL, not an optional hardening.
3. **No PDP and no AEM.** Nothing consumes an approval or enforces a decision.
4. **No authorization anywhere.** Issuance, revocation, and every ANS operation
   except registration are unauthenticated (see audit findings S-4 and S-5).
5. **No approval event types.** `EventType` reserves constants for Phases 4–11
   but none for approvals. When the time comes, the natural additions are
   `APPROVAL_REQUESTED`, `APPROVAL_GRANTED`, `APPROVAL_DENIED`,
   `APPROVAL_EXPIRED` and `APPROVAL_WITHDRAWN`. **These were deliberately not
   added** — reserving names for an unbuilt mechanism is the sort of partial
   implementation this audit was told to avoid.

---

## 6. Summary

- The current architecture **does not prevent** a future HITL layer.
- Agent trust (DID + VC + VP) and human authorization (identity + approval +
  action/resource binding) **remain separate**, and must stay that way.
- **Human authentication ≠ human authorization.** An OIDC ID token or a Keycloak
  access token establishes identity or service access; it is never, by itself,
  an approval of a specific action.
- The mechanisms an approval will need — signature coverage of its own options,
  proof-purpose separation, audience binding, challenge binding, and independent
  signature/expiry/status checks — are all present and tested.
- The prerequisites that are genuinely absent are **human identity modelling**,
  **single-use nonce storage (Phase 9)**, and **the PDP/AEM themselves
  (Phase 4)**.

Nothing in this document has been implemented.
