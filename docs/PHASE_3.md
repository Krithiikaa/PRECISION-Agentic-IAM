# Phase 3 — Agent Naming Service

Phase 1 answered *who is this agent?* Phase 2 answered *what has a trusted
authority attested about it?* Phase 3 answers **how does one agent find the
right agent, without being told where it lives?**

---

## 1. What is the ANS?

A registry that maps capabilities to agents. An agent registers what it can
do and where it can be reached; another agent asks "who can do X, under these
constraints?" and gets back a ranked, explained answer.

It runs as its own service on `:8100`, with its own lifecycle and background
work. It shares the database and the identity/credential libraries with the
IAM API — it does not reimplement DID resolution or credential verification,
it calls them.

## 2. Why hardcoded service discovery is insufficient

`RISK_AGENT_URL=http://risk-agent:9003` fails on every axis that matters here:

| Problem | What hardcoding does | What the ANS does |
|---|---|---|
| The agent moves | stale config, silent failure | registration updates the endpoint |
| The agent dies | requests time out | heartbeat lapses, agent stops being returned |
| Several agents can do the job | you pick one forever | all candidates ranked on observed signals |
| The agent loses a required credential | you route to it anyway | filtered out, with the reason |
| The agent's identity is revoked | you route to it anyway | excluded before anything else runs |
| A new agent appears | redeploy the caller | it registers itself and is immediately findable |

The deeper point is that in an agentic system the *set of participants is not
known at deploy time*. Helper agents are created during a task, specialists
come and go, and credentials expire mid-flight. A static endpoint table cannot
express any of that.

## 3. Agent registration

Every agent registers itself at boot. The registration is **signed** with the
agent's existing Phase 1 Ed25519 key:

```
did + endpoint + capabilities + organization + nonce + timestamp
      -> JCS canonical JSON  (the same canonicalisation credentials use)
      -> Ed25519 sign with the AGENT's key
      -> POST /api/v1/ans/register
```

The ANS then runs nine checks in order, and records the attempt either way:

| # | Check | Rejection reason |
|---|---|---|
| 1 | DID is well formed | `MALFORMED_REGISTRATION` |
| 2 | DID exists in the Phase 1 registry | `DID_UNKNOWN` |
| 3 | identity is not TERMINATED/SUSPENDED | `AGENT_NOT_ELIGIBLE` |
| 4 | DID Document resolves to a public key | `DID_NOT_RESOLVABLE` |
| 5 | endpoint is a syntactically valid http(s) URL | `ENDPOINT_INVALID` |
| 6 | capability names are well formed | `CAPABILITIES_INVALID` |
| 7 | timestamp is within the freshness window | `STALE_REGISTRATION_TIMESTAMP` |
| 8 | nonce has not been used before | `REGISTRATION_NONCE_REPLAYED` |
| 9 | signature verifies against the DID Document | `INVALID_REGISTRATION_PROOF` |

### Why signing matters

Without step 9, anyone who can reach the ANS could register
`did:poc:agent:risk-001` pointing at an endpoint they control. Every
coordinator that discovered "the risk agent" would then be routed to the
attacker. This is the single most damaging attack on a naming service, and it
is why the endpoint is *inside* the signed payload: a signature over one
endpoint cannot be reused for another.

Only a **successful** registration consumes a nonce (a partial unique index),
so an attacker cannot burn nonces by spamming failures.

## 4. DID resolution

`GET /api/v1/ans/resolve/{did}` returns the endpoint, status, capabilities,
credential index, liveness and the **DID Document from the Phase 1 registry**.
The ANS keeps no second copy, so it cannot disagree with the identity
authority about an agent's public key.

## 5. Capability discovery

`POST /api/v1/ans/discover` with a capability narrows candidates through the
`ans_capabilities` index — an indexed join, not a table scan — then evaluates
each candidate against every constraint.

## 6. Credential-aware discovery

A query may require credential types:

```json
{"capability": "credit_analysis", "required_credentials": ["ComplianceCredential"]}
```

Each candidate's credentials are re-verified by the **Phase 2 verifier**, live,
on every query. There is no second implementation of expiry, revocation or
signature checking.

The `ans_agent_credentials` table is an *index of what the agent claimed at
registration*, used as a fast pre-filter and an audit record. It is never a
verdict: there is a test that plants a stale index row saying ACTIVE for a
credential that has since been revoked, and asserts discovery still refuses.

## 7. Heartbeats

Agents report every `ANS_HEARTBEAT_INTERVAL_SECONDS` (default 15) with their
status and their **real in-flight task count**, which feeds ranking.

```
last heartbeat < 45s   ACTIVE     discoverable
45s .. 120s            STALE      not discoverable
> 120s                 OFFLINE    not discoverable
```

A heartbeat may report liveness and load. It may **not** move the endpoint —
that requires a fresh signed registration, otherwise the proof would be
bypassable. There is a test for this.

Liveness is *observed*, not asserted. A background sweeper demotes agents that
stopped reporting, and a prober actually calls each agent's `/health`, so
"the registry says ACTIVE" and "the endpoint answers" are distinguishable
(the latter produces `DEGRADED`).

## 8. Agent lifecycle

```
STARTING ──register──> ACTIVE ──┬── heartbeat ──> ACTIVE
                                ├── quiet 45s ──> STALE ──quiet 120s──> OFFLINE
                                ├── SIGTERM ────> OFFLINE  (graceful, immediate)
                                ├── endpoint down > DEGRADED
                                └── identity revoked > REVOKED / TERMINATED
```

Graceful shutdown matters: an agent receiving SIGTERM deregisters in its
lifespan handler, so it stops receiving work immediately instead of after a
two-minute timeout.

Identity revocation is *mirrored*: a reconciliation pass marks agents whose
Phase 1 identity became TERMINATED or SUSPENDED, so a revoked agent stops being
handed out promptly rather than waiting for its heartbeat to lapse.

## 9. Registration security

| Attack | Defence |
|---|---|
| Register someone else's DID | Ed25519 proof against their DID Document |
| Substitute the endpoint | endpoint is inside the signed payload |
| Escalate capabilities | capabilities are inside the signed payload |
| Replay a captured registration | single-use nonce + freshness window |
| Move an endpoint via heartbeat | heartbeats cannot change the endpoint |
| Register an unknown identity | DID must exist in the Phase 1 registry |
| Register a revoked identity | identity eligibility is checked |
| Burn nonces by spamming failures | only accepted registrations consume one |

Every attempt, accepted or rejected, is stored in `ans_registration_proofs`.

## 10. Discovery ranking

Deterministic, over signals the ANS genuinely observes:

```
+40  status is ACTIVE
+10  per satisfied credential requirement
+    trust_score / 10        (only when Phase 10 has supplied one; NULL is neutral)
-2   per task in flight      (reported by the agent, real)
+10  endpoint probe succeeded
-    latency_ms / 100        (measured by the ANS, capped at 10)
```

Ties break on DID so repeated queries give identical order. No ML, no
randomness, and no agent is hardcoded to win — `test_load_lowers_a_candidates_rank`
asserts that adding load actually changes the order.

`min_trust_score` **excludes** agents with no score rather than assuming one.
Inventing a trust number before Phase 10 builds the engine would be exactly the
kind of fake this project forbids.

## 11. Coordinator integration

The coordinator holds no endpoint table. `POST http://localhost:9001/coordinate`:

```
1. ask ANS for the live capability catalogue
2. ask the LLM to choose one, CONSTRAINED to that list
3. ask ANS which agents provide it, under the required constraints
4. VERIFY the answer against the identity authority
5. select the top-ranked candidate
```

Step 2 is genuinely LLM-driven; the model is given the real catalogue and its
answer is rejected if it is not in it. If the LLM is unavailable, coordination
**fails** — there is deliberately no keyword fallback, because a hidden rule
table would be the hardcoded routing this phase exists to remove.

Step 4 is the "do not trust the directory" rule: the coordinator fetches the
agent's DID Document from the Phase 1 registry and checks that the endpoint ANS
returned is the one published there. ANS does not control the DID Document, so
an endpoint substitution in the registry is detectable by the caller.

## 12. Security limitations

- **The ANS API is unauthenticated apart from registration.** Anyone who can
  reach `:8100` can run discovery queries or deregister an agent. Registration
  is the one operation that proves identity. Authorization for the rest is
  Phase 4.
- **Discovery is not authorization.** Matching a credential requirement means
  the agent *holds* a valid credential. Whether it may then perform an action
  is the PDP's decision. Every discovery response says so explicitly.
- **The health prober trusts DNS/network.** It checks that the endpoint answers
  and reports the expected DID, but there is no TLS or mutual authentication
  between the ANS and agents in this POC.
- **Trust scores do not exist yet.** The column is NULL until Phase 10.

### Deployment note: endpoints are relative to where things run

An agent registers the endpoint it was told to advertise (`AGENT_PUBLIC_URL`).
Under docker-compose that is a service name (`http://risk-agent:9003`); in a
host run it is `http://localhost:9003`.

Pointing a containerised ANS at a database seeded by a host run therefore makes
it probe `localhost` from inside its own container, fail, and mark every agent
`DEGRADED` — after which discovery correctly returns nothing. That is the
prober telling the truth about reachability from where *it* stands, not a bug,
but it means the two deployment styles should not be mixed against one shared
database. The same applies to the Phase 2 keystore, for the same reason.

## 13. APIs

```
POST /api/v1/ans/register              signed registration
POST /api/v1/ans/heartbeat             liveness + load
POST /api/v1/ans/discover              capability/credential-aware query
GET  /api/v1/ans/resolve/{did}         endpoint + DID Document + status
GET  /api/v1/ans/agents                the registry
GET  /api/v1/ans/capabilities          capability catalogue
GET  /api/v1/ans/agents/{did}/health   probe the endpoint now
POST /api/v1/ans/unregister/{did}      graceful deregistration
GET  /api/v1/ans/discovery/{id}        a past discovery, with per-candidate reasons
POST /api/v1/ans/sweep                 run the liveness sweep on demand

POST http://localhost:9001/coordinate  the coordinator's full discovery flow
GET  http://localhost:900X/ans         an agent's own view of its registration
```

## 14. Database

| Table | Holds |
|---|---|
| `ans_agents` | the registry: endpoint, status, liveness, load, observed health |
| `ans_capabilities` | indexed capability -> agent mapping |
| `ans_agent_credentials` | index of claimed credentials (a pre-filter, never a verdict) |
| `ans_heartbeats` | liveness history |
| `ans_registration_proofs` | every registration attempt with its proof and outcome |
| `ans_discovery_requests` | every query, its latency and its selection |
| `ans_discovery_results` | per-candidate match/reject with the full reason breakdown |

Alembic revision `22709fe1158d`. It also adds `audit_events.seq` — see below.

## 15. Event model

Phase 3 emits `ANS_AGENT_REGISTERED`, `ANS_AGENT_UPDATED`,
`ANS_REGISTRATION_REJECTED`, `ANS_SIGNATURE_INVALID`, `ANS_HEARTBEAT_RECEIVED`,
`ANS_AGENT_STALE`, `ANS_AGENT_OFFLINE`, `ANS_AGENT_REVOKED`,
`ANS_AGENT_RESOLVED`, `ANS_DISCOVERY_STARTED`, `ANS_DISCOVERY_MATCH`,
`ANS_DISCOVERY_REJECTED`, `ANS_DISCOVERY_NO_MATCH`, `ANS_AGENT_SELECTED`,
`COORDINATOR_CAPABILITY_RESOLVED`, `COORDINATOR_DISCOVERY_COMPLETE`,
`COORDINATOR_DISCOVERY_FAILED`.

**The live stream had to change for this.** Until Phase 3 the SSE endpoint
served an in-process event bus, which could only ever see events produced
inside the IAM API. ANS discovery happens in a *different process*, so those
events would have silently never reached the browser. The stream now tails the
`audit_events` table using a new monotonic `seq` column, so every process's
events appear. This is the only way the trace can be complete in a multi-process
system.

## 16. Demo scenarios

```bash
scripts/run_local.sh                     # postgres, redis, IAM API, ANS, 7 agents
python3 scripts/seed_credentials.py --replace
python3 scripts/phase3_gate.py           # every mandatory acceptance test
bash scripts/phase3_restart_test.sh      # registry persistence
```

Walkthroughs are in [DEMO.md](DEMO.md), steps 18–24: normal discovery, multiple
candidates and ranking, the compliance filter, an agent going offline, a
credential being revoked, and a spoofed registration being refused.

## 17. Tests

74 Phase 3 tests, 234 in total.

```bash
cd backend && .venv/bin/python -m pytest tests -q
```

- `test_ans_registration.py` — valid registration, spoofing, endpoint
  substitution, capability escalation, wrong key, unknown DID, replay,
  staleness, eligibility, audit.
- `test_ans_discovery.py` — capability match/mismatch, multi-attribute filters,
  credential filtering (missing/expired/revoked/stale-index), identity and
  liveness exclusion, ranking determinism and load sensitivity, persistence.
- `test_ans_lifecycle.py` — heartbeats, endpoint immutability, sweeps,
  identity mirroring, deregistration, resolution.
- `test_ans_api.py` — the HTTP surface, including the 403 shape of a refused
  registration.
