# Architecture

## Target architecture

The system being built, with the phase that delivers each part:

```
                              USER
                               |
                       BANKING WEB APP                        (Phase 12)
                               |
                      COORDINATOR AGENT                       (Phase 1 runtime)
                               |
                 +-------------+-------------+
                 |                           |
                ANS                         A2A               (Phases 3, 7)
                 |                           |
          AGENT DISCOVERY            SPECIALIST AGENTS
                                             |
                          +------------------+------------------+
                          |                  |                  |
                         KYC                RISK               FRAUD
                          |                  |                  |
                          +------------------+------------------+
                                             |
                                            MCP                 (Phase 8)
                                             |
                                     MCP TOOL GATEWAY
                                             |
                                            AEM                 (Phase 4)
                                             |
                                   DID + VC + CONTEXT
                                             |
                                            PDP                 (Phase 4, OPA)
                                             |
                                      ALLOW / DENY
                                             |
                                  BANKING DATA SERVICES         (Phase 5)
                                             |
                                         POSTGRES
```

Security plane:

```
Monitoring -> Anomaly Detection -> Trust/Risk Engine -> Session Authority
                                                             |
                                                        SSS / Redis
                                                             |
                                                       AEM instances
                                                             |
                                             A2A / MCP / API enforcement
```

**Built today:** the agent runtimes, their identities, the credential layer,
the naming/discovery layer and the audit/event spine. Everything else is named above with the phase that will
deliver it. See [PHASE_STATUS.md](PHASE_STATUS.md).

## Terminology

Used exactly as in the source architecture:

| Term | Meaning |
|------|---------|
| **AEM** | **Adapter Enforcement Middleware** — the enforcement point. Intercepts, verifies, asks the PDP, enforces the answer. Contains no business authorization rules. |
| **PDP** | Policy Decision Point — **decides**. OPA evaluating Rego. |
| **PAP** | Policy Administration Point — where policy is authored (`policies/`). |
| **PIP** | Policy Information Point — supplies the attributes the PDP needs. |
| **ANS** | Agent Naming Service — registration, capability registry, discovery. |
| **SA** | Session Authority — owns global session state and revocation. |
| **SSS** | Session State Synchroniser — distributed low-latency source of truth for session validity (Redis). |
| **A2A** | Agent-to-Agent communication. |
| **MCP** | Model Context Protocol — the tool access path. |
| **JIT** | Just-In-Time access — short-lived, narrowly scoped credentials. |

PDP decides. AEM enforces. They are never the same component.

## Processes that run today

| Process | Port | Role |
|---------|-----:|------|
| `postgres` | 5433 | identity and audit persistence |
| `redis` | 6380 | reserved for the SSS (Phase 9); unused today |
| `ans` | 8100 | Agent Naming Service: registration, discovery, liveness |
| `iam-api` | 8000 | registry, DID resolution, sign/verify, credentials, audit, event stream |
| `coordinator-agent` | 9001 | Loan Coordinator Agent runtime |
| `kyc-agent` | 9002 | KYC Verification Agent runtime |
| `risk-agent` | 9003 | Credit Risk Analysis Agent runtime |
| `fraud-agent` | 9004 | Fraud Detection Agent runtime |
| `decision-agent` | 9005 | Loan Decision Agent runtime |
| `risk-agent-2` | 9006 | second credit risk agent (so discovery must choose) |
| `risk-agent-3` | 9007 | third credit risk agent |
| `frontend` | 5173 | console: discovery, credentials, agents, live trace |

Each agent is a separate OS process with its own keystore directory, its own
runtime state and its own HTTP surface.

## The agent runtime

`app/agents/runtime.py`. Every agent process instantiates one:

```
AgentRuntime
  ├── identity      AgentIdentity: DID, kid, public key, capabilities
  ├── memory        AgentMemory: bounded turns + facts, fed into the next prompt
  ├── llm           LLMProvider (OllamaProvider today)
  ├── tools         ToolRegistry — empty until Phase 5/8
  ├── wallet        CredentialWallet: credentials issued ABOUT this agent
  ├── signer        Signer over the agent's own KeyStore
  └── event_sink    telemetry to the local SSE stream and the central audit trail
```

`execute_task()` emits `AGENT_TASK_STARTED`, calls the LLM, emits `LLM_CALL`,
signs the result with the agent's own key, emits `AGENT_TASK_COMPLETED`. When
the LLM is unreachable it emits `AGENT_TASK_FAILED` and returns empty output —
there is no path that invents a result.

The runtime never decides whether an action is permitted. That separation is
what will make "the LLM cannot bypass IAM" true once Phase 4 lands, rather than
a claim resting on prompt wording.

## Identity model

```
did:poc:agent:risk-001                     the agent's identifier
did:poc:agent:risk-001#key-1               its verification method (kid)
did:poc:organization:bank-demo             the controller
```

Agent boot sequence (`app/agents/service.py`):

```
open own keystore
  -> generate Ed25519 key pair if absent      (private key stays on this host)
  -> POST /api/v1/agents with the PUBLIC key
  -> 201: registered, DID Document published
  -> 409: fetch the published key and compare
           match    -> continue
           mismatch -> IDENTITY CONFLICT, refuse to start
  -> check Ollama reachable and model pulled
  -> serve
```

Key custody has two modes, and the registry records which applies:

- **agent-held** (`keystore_backend = "external"`) — the running agents. The
  registry stores only the public key and refuses to sign for them.
- **registry-held** (`keystore_backend = "encrypted_file"`) — agents created
  through the API or CLI without a public key, e.g. ephemeral helper agents
  provisioned on behalf of a parent.

## The credential layer (Phase 2)

```
ISSUER                          HOLDER                      VERIFIER
did:poc:organization:bank-demo  did:poc:agent:risk-001      AEM/PDP later; today
own Ed25519 key                 own Ed25519 key (Phase 1)   the API and the console
      |                               |                            |
      | signs the credential          | signs the presentation     |
      v                               v                            v
  issuer proof                   holder proof            resolve issuer key,
  "these claims are mine"        "I am the subject"      verify both, check
                                                         subject/expiry/status/claims
```

Key separation is the load-bearing property: **no agent holds an issuer key**,
so an agent can sign but cannot attest about itself. A self-issued credential
resolves to an unregistered issuer and is rejected before its signature is even
evaluated.

Holding a credential is evidence, not permission. Nothing in Phase 2 makes an
access decision; that is the PDP's job in Phase 4.

## Discovery (Phase 3)

```
COORDINATOR                         ANS                      IDENTITY REGISTRY
     |                               |                              |
     |-- what capabilities exist? -->|                              |
     |<------- live catalogue -------|                              |
     |                               |                              |
  [LLM picks one, constrained to that catalogue]                    |
     |                               |                              |
     |-- who provides it? ---------->|                              |
     |                          evaluate each candidate:            |
     |                          capability, status, identity,       |
     |                          liveness, credentials (Phase 2      |
     |                          verifier), org, trust, health       |
     |<--- ranked + explained -------|                              |
     |                                                              |
     |-- is this endpoint the one you published? ------------------>|
     |<-- DID Document (ANS does not control this) -----------------|
     |
   [selection verified]  ->  Phase 7 sends the actual task
```

The coordinator holds no endpoint table. The cross-check in the last step is
what makes a compromised directory detectable: ANS can claim any endpoint it
likes, but it cannot forge the DID Document the identity authority publishes.

## Data model

Phase 1 (identity):

```
agents ──┬── agent_keys           public key + keystore reference; never a private key
         ├── did_documents        the published DID Document, versioned
         └── agent_relationships  delegation edges (parent -> ephemeral helper)

audit_events                      append-only; the spine Phase 10 builds on
```

Phase 2 (credentials):

```
issuer_identities                 issuing authorities and their public keys
credentials ──┬── credential_status              mutable lifecycle, separate on purpose
              └── (document column)              the signed artefact, immutable
credential_presentations          what was presented, by whom, with which challenge
credential_verification_events    one row per verification, with per-check results
```

Status lives outside the signed document because revocation happens after
signing — a verifier has to look it up rather than read it from the artefact.

`audit_events` already carries the full event contract from the specification
(timestamp, event_type, agent_did, session_id, request_id, resource, action,
decision, metadata) so later phases add rows, not columns.

Phase 3 (naming and discovery):

```
ans_agents ──┬── ans_capabilities        indexed capability -> agent
             └── ans_agent_credentials   claimed credentials (a pre-filter, never a verdict)

ans_heartbeats             liveness history
ans_registration_proofs    every registration attempt, accepted or rejected
ans_discovery_requests ──── ans_discovery_results   per-candidate match/reject reasons
```

Tables for policies, sessions, anomalies, trust, banking data and loan
applications arrive with the phases that use them. Creating them empty now
would misrepresent what the system does.

## Event flow

```
any process (IAM API, ANS, an agent)
      -> Event
          -> AuditService.record()
              -> audit_events (PostgreSQL, durable, monotonic `seq`)

IAM API /api/v1/events/stream
      -> tails audit_events by seq
          -> SSE to the console
```

The stream tails the table rather than an in-process bus. That change was
forced by Phase 3: ANS discovery happens in a different process, so a bus
inside the API could never see it, and those events would have silently never
reached the browser. Tailing the durable record is the only way the trace can
be complete in a multi-process system.

The frontend renders only what the backend actually emitted.
