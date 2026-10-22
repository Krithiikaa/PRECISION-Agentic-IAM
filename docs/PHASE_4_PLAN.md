# Phase 4 plan — fine-grained authorization (PDP / PIP / PAP / OPA / Rego / AEM)

**Written before any code was modified.** This is the architecture study and
implementation plan required by §1.

---

## 1. Baseline confirmed

Full suite run immediately before planning:

| | |
|---|---:|
| Collected | **247** |
| Passed | **247** |
| Failed | **0** |
| Skipped | **0** |

Phase 1: COMPLETE · Phase 2: COMPLETE + HARDENED · Phase 3: COMPLETE + VERIFIED.
Migration head `22709fe1158d`. See [PHASE_1_3_BASELINE.md](PHASE_1_3_BASELINE.md).

> The live-Ollama test passed on this run. It is resource-dependent and skips
> loudly when the host cannot load the model; either outcome is reported
> honestly and the test is never modified to force a pass.

---

## 2. What the existing architecture already gives Phase 4

The inspection found the codebase was genuinely shaped for this phase. Three
findings materially reduce the work and constrain the design:

### 2.1 `ToolSpec` already carries the authorization triple

`backend/app/agents/base.py`:

```python
@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    # The capability the agent must hold to call this tool. Holding the
    # capability is necessary but never sufficient: from Phase 4 the AEM/PDP
    # decide every actual invocation.
    required_capability: str
    resource: str
    action: str
```

`resource`, `action` and `required_capability` are exactly the fields the
authorization request needs. **The tool contract will not be redesigned.**

### 2.2 `ToolRegistry` is empty by design

Every agent runs with an empty registry today, documented as "the honest state,
not a stub". Phase 4 therefore introduces the *first* real tools — which means
the protected path can be built correctly from the start, with no legacy
unprotected call path to retrofit.

### 2.3 The event taxonomy already reserves Phase 4 constants

`backend/app/monitoring/events.py` already declares `PDP_EVALUATION`,
`POLICY_ALLOW`, `POLICY_DENY` and `AEM_INTERCEPT` marked `# Phase 4`. These will
be used rather than invented, and a small number of additional Phase 4 constants
added alongside them.

### 2.4 Empty packages reserved for exactly this

`app/authorization/` ("Phase 4 — PDP / PAP / PIP over OPA + Rego") and
`app/enforcement/` ("Phase 4 — AEM"), both currently empty with honest
docstrings. Phase 4 fills them.

### 2.5 `policies/README.md` already specifies the layout

It states the rule this phase must honour:

> Authorization rules belong here, as Rego. They must not be reimplemented as
> Python `if` statements in the AEM: the AEM enforces, the PDP decides.

---

## 3. OPA — real runtime, verified before planning

**`openpolicyagent/opa:latest` pulled and executed:**

```
Version: 1.20.1
Build Timestamp: 2026-08-28T07:25:34Z
Platform: linux/amd64
```

**Consequence that shapes every policy file: OPA 1.x means Rego v1 syntax is
mandatory** — `if` is required on rule bodies, and partial sets use `contains`.
Policies written in the pre-1.0 dialect will not compile. This was established
by running the real binary, not assumed.

### Deployment

| | |
|---|---|
| Service name | `opa` |
| Image | `openpolicyagent/opa:latest` (1.20.1) |
| Port | 8181, published to the host so the host-run test suite reaches it |
| Host URL | `http://localhost:8181` |
| Container URL | `http://opa:8181` (service DNS — never `localhost` from another container) |
| Health check | `GET /health` |
| Startup dependency | `iam-api` depends on `opa` being healthy |
| Policy loading | pushed by the PAP through OPA's Policy API, not baked into the image |

The host/container URL split follows the existing convention already used for
`ANS_BASE_URL` and `OLLAMA_BASE_URL`.

---

## 4. Component design

```
  Agent
    │  wants to call a protected tool
    ▼
  AEM  (app/enforcement/)                     ENFORCES — never decides
    │  builds AuthorizationRequest
    ▼
  PIP  (app/authorization/pip.py)             GATHERS — never decides
    │  · calls the PHASE 2 VERIFIER for credential state (no crypto re-implementation)
    │  · agent identity + ANS registration status
    │  · resource metadata, environment, time
    │  · unavailable attributes → explicit null, never a default
    ▼
  PDP  (app/authorization/pdp.py)             DECIDES — never executes
    │  builds the OPA input document
    ▼
  OPA  (real container, :8181)
    │
    ▼
  Rego (policies/*.rego, Rego v1)
    │
    ▼
  Decision: ALLOW | DENY | HUMAN_APPROVAL_REQUIRED  + policy id/version + reason
    │
    ▼
  AEM  ── ALLOW → mint EnforcementGrant → execute tool → resource
       ── DENY  → block
       ── HUMAN_APPROVAL_REQUIRED → block/pause (no approval flow in Phase 4)
```

### 4.1 PDP — decides only

Receives an `AuthorizationRequest`, asks the PIP for context, calls OPA, maps
the Rego result to an `AuthorizationDecision`. It must not execute the action,
must not read the database on the agent's behalf, must not call tools, and must
not trust anything the LLM or the agent asserts about permission.

### 4.2 PIP — gathers only, invents nothing

Critical rule from §6 and §14 of the brief: **the PIP consumes the existing
Phase 2 verifier**; cryptographic credential validity is never re-implemented in
Rego or in the PIP. Rego receives *verified claims and status*, not raw
signatures.

Unavailable attributes are represented explicitly:

```
trust_score: null          # Phase 10 owns this — not defaulted to any number
session:     null          # Phase 9 owns this
approval:    null          # HITL owns this
```

Unknown must never resolve to trusted.

### 4.3 PAP — lifecycle only

Owns create / update / version / activate / deactivate / list. Rego files are
the policy source; the PAP records identity, version, owner, purpose, scope and
status in a database table and pushes active modules into OPA through OPA's
Policy API (`PUT /v1/policies/{id}`, `DELETE` to deactivate). Deactivation is
therefore real — the module leaves the engine.

PDP consumes policies; PAP manages them. No lifecycle logic inside the PDP.

### 4.4 AEM — enforces only

The enforcement boundary. It builds the authorization request, calls the PDP,
and acts on the verdict. **It contains no policy logic of its own** — no Python
`if` that could disagree with Rego.

---

## 5. The enforcement property (§12) — how it is made real

The brief requires that this be *impossible*:

```
Agent → direct tool/database call → protected resource
```

A convention ("please go through the AEM") would not be enforcement. The design:

- Protected tools are **never registered in the agent's `ToolRegistry`**, so the
  agent's LLM cannot select one directly.
- A protected tool's callable requires an `EnforcementGrant` that **only the AEM
  can mint**, and only after a PDP `ALLOW`. The grant is bound to the request
  id, the tool name and the resource, and is single-use.
- Invoking a protected tool without a valid grant raises `EnforcementBypassError`
  — a hard failure, not a log line.

This makes the security property testable rather than asserted (matrix items 11
and 32).

---

## 6. Data contracts

Following existing repository conventions (snake_case fields, `to_dict()`,
dataclasses for domain objects, Pydantic for the HTTP surface, per-check
explanation objects as in the Phase 2 verifier).

### AuthorizationRequest

```
request_id      correlation id, reused across audit rows
subject         {type: "agent", did: "..."}
action          "read"
resource        {type: "credit_record", id: "customer-007", classification: ...}
purpose         "loan_assessment"
credentials     credential ids the subject offers (verified by the PIP)
context         caller-supplied, untrusted, never a decision input on its own
session         null in Phase 4 (Phase 9)
```

### AuthorizationDecision

Never a bare boolean — mirrors the Phase 2 verifier's "explain every check" style:

```
decision        ALLOW | DENY | HUMAN_APPROVAL_REQUIRED
request_id
policy_id       + policy_version   (e.g. loan-credit-read v1)
reason          VALID_CREDENTIAL_AND_POLICY_MATCH | CREDENTIAL_EXPIRED | ...
evaluation      per-stage detail + the PIP context actually used
latency         measured per stage, never fabricated
timestamp
```

---

## 7. Rego policy model

Package `agentic_iam.authz`, Rego v1. Combining algorithm — **deny-overrides
with default-deny**:

```
any deny            → DENY
else any human_required → HUMAN_APPROVAL_REQUIRED
else any allow      → ALLOW
else                → DENY / NO_MATCHING_POLICY     ← fail closed
```

Policies decide on **claims and context**, not on agent identity strings.
`if agent == "risk-001"` is exactly what §10 forbids; matching is on verified
capability, credential validity, resource type, action and purpose.

Planned policies (§20):

| # | Policy | Outcome |
|---|---|---|
| 1 | valid credit capability + READ + `credit_records` + `loan_assessment` | ALLOW |
| 2 | same agent, same credential, READ + `payroll_records` | DENY `RESOURCE_NOT_ALLOWED` |
| 3 | missing credential | DENY `MISSING_CAPABILITY` |
| 4 | expired credential | DENY `CREDENTIAL_EXPIRED` |
| 5 | revoked credential | DENY `CREDENTIAL_REVOKED` |
| 6 | sensitive action | HUMAN_APPROVAL_REQUIRED `SENSITIVE_ACTION_REQUIRES_HUMAN` |
| — | wrong purpose | DENY `PURPOSE_NOT_ALLOWED` |

Policy 6 produces **only the decision**. No approval flow, no approval artifact,
no human principal — those are HITL, explicitly out of scope.

---

## 8. Fail-closed behaviour (§26)

| Condition | Result |
|---|---|
| OPA unreachable / timeout | **DENY** `AUTHORIZATION_UNAVAILABLE` |
| OPA returns a malformed document | **DENY** `AUTHORIZATION_UNAVAILABLE` |
| No policy matches | **DENY** `NO_MATCHING_POLICY` |
| Policy deactivated / absent | **DENY** |
| Malformed request | **rejected** (422), never evaluated |
| PIP cannot resolve the subject | **DENY** `UNKNOWN_SUBJECT` |
| Agent asserts `"allow": true` | **ignored** — only the PDP decides |

No error path may produce ALLOW.

---

## 9. Phase 2 and Phase 3 integration — boundaries preserved

**Phase 2.** The PIP calls `CredentialVerifier` (and, where a presentation is
involved, `PresentationVerifier` **with `expected_domain` supplied** — the S-2
audience protection must not be silently dropped, per §17). Rego receives the
verdict, never the signature.

**Phase 3.** ANS still answers "which agent?"; the PDP answers "may it act?".
**No authorization logic will be added to ANS**, and no ANS file will be
modified. The coordinator is not given authorization decisions to make.

---

## 10. Files to create

```
backend/app/authorization/
    contracts.py     AuthorizationRequest / AuthorizationDecision / reasons
    pip.py           context gathering (calls the Phase 2 verifier)
    opa.py           real OPA HTTP client, fail-closed
    pdp.py           decision point
    pap.py           policy lifecycle + OPA policy push
backend/app/enforcement/
    aem.py           enforcement boundary, EnforcementGrant
    tools.py         protected tool adapters (MCP-shaped, MCP itself is future)
    resources.py     POC credit/payroll data behind the boundary
backend/app/api/routes/authorization.py    POST /authorize, /enforce, policy admin
backend/app/db/models/authorization.py     policies + authorization_decisions
backend/alembic/versions/<rev>_phase4_authorization.py
policies/loan/credit.rego
policies/loan/payroll.rego
policies/security/sensitive.rego
policies/decision.rego        combining algorithm
backend/tests/test_authorization_contracts.py
backend/tests/test_pip.py
backend/tests/test_pdp_opa.py
backend/tests/test_aem_enforcement.py
backend/tests/test_authorization_api.py
backend/tests/test_authorization_security_matrix.py
docs/PHASE_4_ARCHITECTURE.md
docs/diagrams/phase4-authorization.svg
scripts/phase4_gate.py
```

## 11. Files to modify (additively only)

```
docker-compose.yml                  add the opa service
backend/app/core/config.py          OPA_URL and related settings
backend/app/main.py                 mount the authorization router; PAP load at startup
backend/app/monitoring/events.py    Phase 4 event constants
docs/PHASE_STATUS.md                Phase 4 status
README.md                           doc index
frontend/.../LiveTrace.tsx          render the real Phase 4 events
```

**No Phase 1, 2 or 3 logic file will be modified.** In particular: nothing in
`app/identity/`, `app/credentials/`, `app/ans/`, or `app/agents/coordinator.py`.

---

## 12. Test strategy

Baseline 247 must continue to pass unchanged — no test deleted or weakened. New
tests cover the full 15-item security matrix from §25 plus the failure matrix
from §42, including the two that matter most: **direct protected-resource access
is blocked**, and **an agent-supplied `"allow": true` is ignored**.

Tests that need OPA will detect its absence and skip loudly with the reason —
the same honest pattern the existing live-Ollama test uses — rather than
silently passing against a fake. **No fake OPA class will exist in this
codebase** (§44).

---

## 13. Explicitly out of scope

HITL, approval artifacts, Keycloak, OIDC, SAML, human principals, JIT, A2A, MCP
security hardening, Session Authority, SSS, monitoring/anomaly detection, trust
scoring, kill switch. `HUMAN_APPROVAL_REQUIRED` is introduced **as a decision
value only**.
