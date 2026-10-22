# Agentic AI Identity & Access Management — POC

A working proof of concept for identity and access management in autonomous
multi-agent systems, built around a retail-banking loan scenario.

The banking data will be synthetic. The agents, the cryptography and the IAM
mechanisms are real.

> **Status: Phases 1, 2 and 3 complete.** Five real agent processes, each with its
> own Ed25519 identity, DID Document and LLM-backed runtime, plus a working
> verifiable-credential layer: real issuing authorities, signed credentials,
> independent verification, revocation, expiry and presentations with holder
> proof; and a real Agent Naming Service with cryptographically authenticated
> registration and capability- and credential-aware discovery. Authorization,
> tools, sessions and the kill switch are later phases and are **not**
> implemented — see
> [docs/PHASE_STATUS.md](docs/PHASE_STATUS.md) for the honest breakdown of
> what runs and what does not.

## What "real" means here

An agent in this system is a running process that receives tasks, calls an LLM,
keeps runtime state, holds a unique cryptographic identity and signs its own
output. It is not a database row, a UI node, or a canned JSON response.

Verifiable right now:

```bash
docker compose up -d postgres redis opa keycloak
scripts/run_local.sh                  # IAM API, ANS, 8 agent processes
python3 scripts/seed_credentials.py   # issue the demo credential set

python3 scripts/phase1_gate.sh        # 12/12   identity
python3 scripts/phase2_gate.py        # 30/30   credentials
python3 scripts/phase3_gate.py        # 40/40   naming + discovery
python3 scripts/phase4_gate.py        # 31/31   authorization
python3 scripts/phase45_gate.py       # 46/46   control-plane hardening
python3 scripts/phase5_gate.py        # 68/68   human-in-the-loop
python3 scripts/phase55_gate.py       # 110/110 HITL hardening
python3 scripts/phase6_gate.py        # 113/113 JIT temporary access
python3 scripts/phase7_gate.py        # 132/132 secure A2A transactions
```

All nine gates run against the LIVE system -- a real PostgreSQL, a real OPA
evaluating real Rego, a real Keycloak and real agent processes. None of them
is satisfied by a substitute.

- Five OS processes on five ports, five DIDs, five distinct key pairs.
- The risk agent signs a message with a private key that exists only on its own
  host; the IAM API verifies it in a different process using nothing but the
  published DID Document.
- Change one character of the message and verification fails.
- A real Ollama call, with the model's own latency and token counts reported.
- Stop Ollama and the agent returns an error instead of an invented answer.
- An issuing authority signs a credential with a key **no agent holds**; edit
  one claim and verification fails with `SIGNATURE_INVALID`.
- Revoke it and verification fails with `CREDENTIAL_REVOKED` — while the
  signature itself still verifies, which is precisely why status exists.
- The agent presents its credentials signed with its own key; the IAM API
  verifies the holder proof it could not have produced.
- Seven agents register themselves with the naming service, each signing its
  registration; a spoofed registration for `risk-001` is refused and the real
  agent's endpoint is untouched.
- The coordinator has **no endpoint table**: it asks the ANS what capabilities
  exist, has the LLM pick one, discovers a provider, and cross-checks the
  answer against the DID Document the ANS does not control.
- Stop an agent and it stops being discovered. Revoke its compliance credential
  and it stops matching queries that require one. Nothing is substituted —
  discovery returns `NO_MATCHING_AGENT`.

## Requirements

| | |
|---|---|
| Python | 3.11+ (developed on 3.13) |
| Docker | with Compose v2 — runs PostgreSQL and Redis |
| Ollama | running locally, with a model pulled |
| Node | 20+ (frontend) |

```bash
ollama pull llama3        # or set OLLAMA_MODEL to whatever you have
ollama list
```

## Setup

```bash
git clone <repo> && cd agentic-iam-poc
cp .env.example .env

python3 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements-dev.txt

scripts/run_local.sh
```

Then open http://localhost:8000/docs.

To run it all in containers instead:

```bash
docker compose up --build
```

Set `KEYSTORE_MASTER_KEY` and `OLLAMA_MODEL` in `.env` first — compose refuses
to start without them rather than guessing.

## Layout

```
backend/app/
  agents/       runtime, per-agent service process, registry, catalogue
  identity/     Ed25519 keys, KeyStore, DID, DID Document, signer
  llm/          LLMProvider interface + OllamaProvider
  api/          routes and schemas
  db/           models, repositories, session management
  monitoring/   event taxonomy and in-process bus
  audit/        durable audit service
  cli.py        operator CLI

  credentials/  canonicalisation, VC/VP documents, issuer, verifier, status,
                presentations, issuer registry
  ans/          registration proof, registry, discovery engine, ANS service
  agents/       + wallet.py, ans_client.py, coordinator.py

  authorization/ enforcement/ sessions/ banking/ protocols/
                ^ reserved for Phases 4-11, currently empty

backend/tests/  1123 tests, run against a real PostgreSQL
frontend/       React console: discovery, credentials, agents, live trace
scripts/        run_local.sh, stop_local.sh, phase{1..7}_gate, restart tests,
                provision_agents.py, seed_credentials.py, screenshot.py
docs/           ARCHITECTURE, SECURITY_MODEL, API, DEMO, and one architecture
                document per phase
policies/       Rego: data plane (4), control plane (4.5), human approval (5),
                loan amount bands (5.5), JIT issuance + use (6),
                A2A transactions (7), and the data/ documents they read
keycloak/       the Keycloak realm: human identities and roles (5, 7)
data/seed/      synthetic banking data
frontend/       React app (Phase 12, partial)
```

## Testing

```bash
cd backend
set -a && . ../.env && set +a
.venv/bin/python -m pytest tests -q              # all 1123
.venv/bin/python -m pytest tests -q -m "not llm" # skip the live-Ollama tests
```

Tests run against a real PostgreSQL database (`agentic_iam_test`, created
automatically) because persistence across restarts is one of the properties
being asserted. The suite calls `drop_all`, so it forces `DATABASE_URL` to the
test database and refuses to start unless that database's name ends in
`_test` — it must never be pointed at a development database. The tests marked `llm` genuinely call Ollama and skip loudly if
it is unreachable rather than passing against a fake.

## CLI

```bash
cd backend && set -a && . ../.env && set +a
.venv/bin/python -m app.cli create-agent risk-002 "Risk Agent" RISK --capability credit_analysis
.venv/bin/python -m app.cli list
.venv/bin/python -m app.cli did-document did:poc:agent:risk-002
.venv/bin/python -m app.cli sign        did:poc:agent:risk-002 "I am the Risk Analysis Agent"
.venv/bin/python -m app.cli verify      did:poc:agent:risk-002 "<message>" "<signature>"
.venv/bin/python -m app.cli terminate   did:poc:agent:risk-002
.venv/bin/python -m app.cli audit

# Phase 2
.venv/bin/python -m app.cli issuers
.venv/bin/python -m app.cli issue-credential did:poc:agent:risk-002 AgentRoleCredential \
    --claim role=risk_analyst --claim department=credit_risk --ttl 3600
.venv/bin/python -m app.cli credentials --subject did:poc:agent:risk-002
.venv/bin/python -m app.cli verify-credential urn:uuid:...
.venv/bin/python -m app.cli revoke-credential urn:uuid:... --reason COMPROMISED
```

## Security notes

- Private keys never leave the `KeyStore`; it signs, it does not export. No API
  response, log line, database column or frontend payload can carry one.
- The development keystore encrypts keys at rest with AES-256-GCM under an
  HKDF-derived per-key data key. It is **not** an HSM — see
  [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).
- `ENV=production` with the shipped development master key is a hard startup
  failure.
- **Authorization is enforced** (Phase 4) and the **control plane is
  authenticated** (Phase 4.5). Heartbeats, deregistration, policy
  administration, PDP queries, protected tool calls and identity signing all
  require an Ed25519 proof of DID control, and are then authorized by Rego.
  See [docs/CONTROL_PLANE_SECURITY.md](docs/CONTROL_PLANE_SECURITY.md).
- **Human-in-the-loop is real** (Phase 5). A high-value loan decision is
  referred to a person who authenticates against a real Keycloak, sees exactly
  what they are approving, and whose decision becomes a signed, bound,
  expiring, single-use artifact that the **PDP re-evaluates**. A human approval
  is evidence, never an ALLOW on its own.
- **S-7 is closed**: agent creation and termination, credential issuance and
  revocation, holder-proof production and audit ingest all require an
  authorized principal — a human `IAM_ADMIN` or a machine `identity_admin`.
  Agents are now provisioned by an operator rather than creating their own
  identities. See [docs/HITL_SECURITY_MODEL.md](docs/HITL_SECURITY_MODEL.md).
- **ANS registration was always the exception**: it requires a signed proof of
  DID control, so an agent's name and endpoint cannot be hijacked.
- **Discovery is not authorization.** Every discovery response says so.
- Issuer keys are never held by agents, so an agent cannot mint a credential
  about itself — a test performs that attack and asserts it fails.
- **Temporary access is bounded** (Phase 6). A JIT mandate is an INPUT to
  authorization, never a substitute for one: it is time- and use-bounded,
  policy-capped, revocable, and **every use is re-decided by the PDP**. Revoke
  the credential it rested on and the mandate stops working.
  See [docs/PHASE_6_ARCHITECTURE.md](docs/PHASE_6_ARCHITECTURE.md).
- **Agent-to-agent transactions are signed and authorized** (Phase 7). A
  sender signs a canonical envelope with its Phase 1 key; the receiver relays
  it unchanged with its own control-plane proof; the IAM plane verifies it and
  then asks the PDP with the **sender** as subject. A valid signature is never
  authorization. An envelope addressed to B cannot be presented by C. A
  payment executes **at most once**, decided by the database under real
  concurrency. The amount is signed, established server-side, authorized and
  executed — and all four must agree.
  See [docs/PHASE_7_ARCHITECTURE.md](docs/PHASE_7_ARCHITECTURE.md).

## Documentation

| | |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, terminology, data model, event flow |
| [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | key custody, trust chain, threat model |
| [PHASE_2.md](docs/PHASE_2.md) | credentials: issuance, verification, revocation, presentations, limitations |
| [PHASE_3.md](docs/PHASE_3.md) | the naming service: signed registration, discovery, ranking, coordinator integration |
| [PHASE_4_ARCHITECTURE.md](docs/PHASE_4_ARCHITECTURE.md) | authorization: PDP, PIP, PAP, OPA/Rego, AEM, enforcement boundary |
| [API.md](docs/API.md) | every endpoint, including what is deliberately not routed yet |
| [DEMO.md](docs/DEMO.md) | step-by-step demonstration script |
| [PHASE_STATUS.md](docs/PHASE_STATUS.md) | what is built, what is not, known gaps |
| [PHASE_1_3_BASELINE.md](docs/PHASE_1_3_BASELINE.md) | frozen Phase 1-3 checkpoint: counts, migration state, topology, gaps |
| [HITL_READINESS.md](docs/HITL_READINESS.md) | **design only** — how the agent trust plane will meet a future human-approval plane |
| [PHASE_5_5_ARCHITECTURE.md](docs/PHASE_5_5_ARCHITECTURE.md) | HITL hardening: amount bands in Rego, dual control, maker-checker, key rotation |
| [PHASE_6_ARCHITECTURE.md](docs/PHASE_6_ARCHITECTURE.md) | JIT temporary access: signed mandates, budgets, windows, revocation |
| [PHASE_7_ARCHITECTURE.md](docs/PHASE_7_ARCHITECTURE.md) | secure A2A: envelope, receiver binding, exactly-once, amount reconciliation |
| [CONTROL_PLANE_SECURITY.md](docs/CONTROL_PLANE_SECURITY.md) | the control-plane operation catalogue and its authentication |
| [HITL_SECURITY_MODEL.md](docs/HITL_SECURITY_MODEL.md) | the human trust plane: who may approve what, and why |
| [PHASE_2_3_AUDIT.md](PHASE_2_3_AUDIT.md) | the Phase 2/3 audit: findings, fixes, deferrals |
