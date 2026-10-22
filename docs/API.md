# API

Base URL `http://localhost:8000`. Interactive docs at `/docs`.

Endpoints listed here exist and work. Endpoints in the target design that are
not yet built are listed at the bottom, unimplemented and unrouted.

## Health

| Method | Path | Notes |
|--------|------|-------|
| GET | `/health` | Always 200. Reports database, LLM (provider, model, models present) and keystore backend, and whether the development master key is in use. |
| GET | `/ready` | 200 only when the database and the LLM are both usable; 503 otherwise, with per-check detail. |

## Agents

| Method | Path | Notes |
|--------|------|-------|
| POST | `/api/v1/agents` | Register an agent. Assigns the DID, binds a key, publishes the DID Document. Pass `public_key_multibase` to register an agent-held key; omit it to have the registry generate one. `parent_did` + `ttl_seconds` create a delegated ephemeral agent. 409 on a duplicate slug. |
| GET | `/api/v1/agents` | List. Filters: `status`, `agent_type`, `capability`, `limit`, `offset`. |
| GET | `/api/v1/agents/{id}` | By UUID. |
| GET | `/api/v1/agents/did/{did}` | By DID. |
| GET | `/api/v1/agents/did/{did}/did-document` | Resolve the DID Document. |
| GET | `/api/v1/agents/{id}/did-document` | Same, by UUID. |
| POST | `/api/v1/agents/{id}/sign` | Sign with a registry-custodied key. 400 if the agent holds its own key — ask the agent's own `/sign` instead. |
| POST | `/api/v1/agents/{id}/status` | `ACTIVE` / `SUSPENDED` / `TERMINATED`. Termination also revokes and destroys the signing key. |
| GET | `/api/v1/agents/{id}/audit` | This agent's audit events. |

### Example

```bash
curl -s -X POST http://localhost:8000/api/v1/agents \
  -H 'content-type: application/json' -d '{
    "slug": "helper-001",
    "name": "Loan Document Processing Helper",
    "agent_type": "HELPER",
    "capabilities": ["document_read"],
    "parent_did": "did:poc:agent:risk-001",
    "ttl_seconds": 900
  }'
```

Response carries the DID, status and the **public** key. No response shape in
this API can carry a private key.

## Identity

| Method | Path | Notes |
|--------|------|-------|
| POST | `/api/v1/identity/sign?did=...` | Sign by DID (registry-custodied keys only). |
| POST | `/api/v1/identity/verify` | `{did, message, signature}`. Verifies against the public key in the DID Document. An invalid signature is **200 with `valid: false`**, never an error. |

## Credentials (Phase 2)

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/v1/credentials/issuers` | Registered issuing authorities and their public keys. |
| GET | `/api/v1/credentials/issuers/{did}/did-document` | An issuer's DID Document — the trust root a verifier resolves. |
| POST | `/api/v1/credentials/issue` | Issue and sign. Body: `issuer`, `subject`, `credential_type`, `claims`, `expires_in_seconds`. Claim keys may be snake_case; the signed document uses camelCase. 404 for an unregistered issuer or a subject that is not a registered agent. |
| POST | `/api/v1/credentials/verify` | Verify. Optional `expected_subject` and `required_claims` (list = presence, object = presence and value). **Always 200** — `valid: false` is a verdict. Returns `checks` (flat booleans) and `check_details` (ordered, with reasons). |
| GET | `/api/v1/credentials` | List. Filters: `subject`, `issuer`, `credential_type`. |
| GET | `/api/v1/credentials/{id}` | The signed document plus a summary. |
| GET | `/api/v1/credentials/{id}/status` | `ACTIVE` / `REVOKED` / `EXPIRED`, with `seconds_remaining`. Reports EXPIRED from wall-clock time even before the sweep has run. |
| POST | `/api/v1/credentials/{id}/revoke` | Revoke. 409 if already revoked. |
| GET | `/api/v1/credentials/{id}/verifications` | Verification history with per-check results. |
| GET | `/api/v1/credentials/challenge` | A nonce for a presentation. Reports `single_use_enforced: false` — replay protection is Phase 9. |
| POST | `/api/v1/credentials/present` | Build and sign a presentation for a **registry-custodied** holder. 400 for a self-custodying agent — ask the agent instead. |
| POST | `/api/v1/credentials/verify-presentation` | Verify the holder proof, then every contained credential with the holder as expected subject. |
| GET | `/api/v1/agents/{id}/credentials` | An agent's credential inventory. |
| GET | `/api/v1/agents/did/{did}/credentials` | Same by DID. `?include_document=true` returns the full signed documents (used by agent wallets). |

`GET /api/v1/agents/{id}` and `/api/v1/agents/did/{did}` now include a
`credentials` array. List responses omit it.

### Example

```bash
curl -s -X POST http://localhost:8000/api/v1/credentials/issue \
  -H 'content-type: application/json' -d '{
    "issuer": "did:poc:organization:bank-demo",
    "subject": "did:poc:agent:risk-001",
    "credential_type": "AgentCapabilityCredential",
    "claims": {
      "capability": "credit_analysis",
      "allowed_actions": ["READ_CREDIT_PROFILE"],
      "allowed_resources": ["credit_records"],
      "purpose": "loan_assessment"
    },
    "expires_in_seconds": 3600
  }'
```

## Agent Naming Service (Phase 3)

Served by the ANS process on **`http://localhost:8100`**, not the IAM API.

| Method | Path | Notes |
|--------|------|-------|
| POST | `/api/v1/ans/register` | Signed registration. Body: `did`, `endpoint`, `capabilities`, `organization`, `nonce`, `timestamp`, `signature`. **201** on success; **403** with the failing check named on refusal. The endpoint and capabilities are inside the signed payload. |
| POST | `/api/v1/ans/heartbeat` | Liveness and load. Cannot change the endpoint — that needs a fresh signed registration (400 if attempted). |
| POST | `/api/v1/ans/discover` | Query: `capability`, `capabilities`, `required_credentials`, `organization`, `status`, `purpose`, `min_trust_score`, `require_healthy_endpoint`, `limit`. Returns ranked `results`, `rejected` with reasons, `selected`, and `ans_latency_ms`. Never falls back: no match is `results: []` with `reason: NO_MATCHING_AGENT`. |
| GET | `/api/v1/ans/resolve/{did}` | Endpoint, status, capabilities, credential index, liveness, and the DID Document from the Phase 1 registry. |
| GET | `/api/v1/ans/agents` | The registry. Filters: `agent_status`, `capability`. |
| GET | `/api/v1/ans/capabilities` | Capability catalogue with provider counts. |
| GET | `/api/v1/ans/agents/{did}/health` | Probe the endpoint now. Distinguishes "registry says ACTIVE" from "the endpoint answers". |
| POST | `/api/v1/ans/unregister/{did}` | Graceful deregistration. |
| GET | `/api/v1/ans/discovery/{request_id}` | A past query with its per-candidate reasons. |
| POST | `/api/v1/ans/sweep` | Run the liveness sweep on demand (it also runs on a timer). |
| GET | `/health`, `/ready` | Registry size, agents by status, thresholds. |

### Example

```bash
curl -s -X POST http://localhost:8100/api/v1/ans/discover \
  -H 'content-type: application/json' -d '{
    "capability": "credit_analysis",
    "required_credentials": ["ComplianceCredential"],
    "requester_did": "did:poc:agent:coordinator-001"
  }'
```

## Audit and events

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/v1/audit` | Filters: `event_type`, `agent_did`, `decision`, `since`, `limit`, `offset`. Newest first. |
| POST | `/api/v1/audit/events` | Telemetry ingest from agent processes. **Unauthenticated in Phase 1** — events are stored with `"unauthenticated": true`. Phase 7 will require a signature. |
| GET | `/api/v1/events/stream` | SSE. Tails `audit_events` by its monotonic `seq`, so events from **every** process (IAM API, ANS, agents) appear — an in-process bus could only ever see its own. `?replay=N` replays the last N events before going live. Emits only real backend events; sends `: keepalive` when idle. |

## Agent process API

Each agent serves these on its own port (9001–9005).

| Method | Path | Notes |
|--------|------|-------|
| GET | `/health` | Identity, registration state, LLM availability, runtime counters. |
| GET | `/ready` | 503 unless the runtime is up, registration succeeded and the LLM is available. |
| GET | `/identity` | Public identity: DID, kid, public key, capabilities. |
| GET | `/did-document` | Resolved through the registry — the same path a peer would take. |
| POST | `/task` | Runs a real LLM task. 503 if the LLM is unavailable, rather than returning invented output. |
| POST | `/sign` | Signs with the agent's own private key. |
| POST | `/verify` | Verifies against the agent's own public key. |
| GET | `/credentials` | The agent's wallet: what it holds and which capabilities are attested. |
| POST | `/present` | Builds a presentation signed with **this agent's** private key. The IAM API cannot do this — it does not hold that key. Body: `capability`, `credential_type`, `credential_ids`, `challenge`, `domain`. |
| GET | `/ans` | This agent's view of its own ANS registration and heartbeats. |
| POST | `/coordinate` | **Coordinator only.** Resolves the capability from the live ANS catalogue via the LLM, discovers, and cross-checks the result against the identity authority. 422 if no registered capability fits or the LLM is unavailable — it will not guess. |
| GET | `/events/stream` | SSE of this agent's runtime events. |

### Example

```bash
curl -s -X POST http://localhost:9003/task \
  -H 'content-type: application/json' -d '{
    "instruction": "Given credit_score=762 and DTI=31.2%, summarise the lending risk.",
    "context": {"applicant": "USER-007"}
  }'
```

The response includes the real `llm` block (provider, model, latency, token
counts) and an Ed25519 `signature` over the canonical result payload.

## Not implemented yet

Present in the target design, deliberately unrouted so a caller gets 404 rather
than a stub:

```
POST /api/v1/authorization/check                                           Phase 4
POST /api/v1/a2a/tasks                                                     Phase 7
POST /api/v1/mcp/tools/call                                                Phase 8
POST /api/v1/jit/request                                                   Phase 6
GET  /api/v1/sessions                 POST /api/v1/sessions/{id}/revoke    Phase 9
POST /api/v1/demo/prompt-injection    POST /api/v1/demo/unauthorized-access Phase 11
```

## Error format

```json
{"error": "CONFLICT", "detail": "An agent with slug 'risk-001' already exists"}
```

| Code | HTTP |
|------|-----:|
| `NOT_FOUND` | 404 |
| `CONFLICT` | 409 |
| `IDENTITY_ERROR` | 400 |
| `KEYSTORE_ERROR` | 500 |

Request validation failures return FastAPI's standard 422.
