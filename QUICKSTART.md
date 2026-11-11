# Quickstart — run it and see the results

## 1. Prerequisites (cannot live in a venv — install once per machine)

| | |
|---|---|
| Docker + Compose v2 | runs PostgreSQL, Redis, OPA, Keycloak |
| Python **3.11–3.13** | for the backend venv (3.14 is not supported by the pinned deps; `setup.sh` can fetch 3.13 via `uv` if present) |
| Node 20+ | for the web console |
| Ollama | the agents' LLM; ~6 GB free RAM to load `llama3` |

Linux or macOS. On Windows, use WSL2.

## 2. One-time setup

```bash
scripts/setup.sh
```

This builds `backend/.venv` from the pinned requirements, installs the console's `node_modules`, creates `.env` from `.env.example` and pulls the Ollama model. You can safely run it again.

## 3. Start

```bash
scripts/run_local.sh                       # infra + IAM API + ANS + 9 agents
cd frontend && npm run dev                 # web console (separate terminal)
```

Then give the agents credentials and OAuth clients. Credentials expire after 1 h, so re-run this before each demo:

```bash
cd backend
.venv/bin/python ../scripts/seed_credentials.py
.venv/bin/python ../scripts/provision_mcp_clients.py
```

## 4. See the results

| What | Where |
|---|---|
| Web console | http://localhost:5173 |
| IAM API (interactive Swagger) | http://localhost:8000/docs |
| Agent Naming Service | http://localhost:8100/docs |
| One agent's live state | `curl -s localhost:9003/health \| python3 -m json.tool` |
| Keycloak admin | http://localhost:8080 |

Demo human logins (Keycloak realm `agentic-iam`):

| user | password | role |
|---|---|---|
| `loan.officer` | `loan-officer-demo` | LOAN_OFFICER |
| `iam.admin` | `iam-admin-demo` | IAM_ADMIN |
| `auditor` | `auditor-demo` | AUDITOR |
| `payment.officer` | `payment-officer-demo` | PAYMENT_OFFICER |

### Every phase, verified against the live system

```bash
scripts/run_gates.sh
```

This runs the Phase 1–9 security gates plus the loan-workflow end-to-end test. It prints one `PASSED`/`FAILED` line per phase. Full logs go to `.run/gates/<phase>.log`. It takes a while because each LLM call takes 25–70 s on CPU.

To run a single phase by hand: `cd backend && .venv/bin/python ../scripts/phase7_gate.py`.

### Unit / integration tests

```bash
cd backend
set -a && . ../.env && set +a
.venv/bin/python -m pytest tests -q -m "not llm"    # skip live-Ollama tests
.venv/bin/python -m pytest tests -q                 # everything
```

Do not run pytest while `run_gates.sh` is running. Both use the same OPA instance.

### Guided walkthrough

[docs/DEMO.md](docs/DEMO.md) has step-by-step `curl` demonstrations (identity, sign/verify/tamper, credentials, revocation, discovery). [docs/PHASE_STATUS.md](docs/PHASE_STATUS.md) lists what is and isn't built.

## 5. Stop

```bash
scripts/stop_local.sh               # stops API, ANS, agents, postgres, redis
scripts/stop_local.sh --keep-infra  # leave the containers running
```

## 6. Move it to another machine

```bash
scripts/package.sh                  # -> ../agentic-iam-poc-YYYYMMDD.zip
```

On the other machine:

```bash
unzip agentic-iam-poc-*.zip && cd agentic-iam-poc
scripts/setup.sh && scripts/run_local.sh
```

The zip contains source only, never `.env`, keys, `.venv` or `node_modules`. A venv cannot be moved between machines: it hard-codes absolute paths and links to the host's own Python. `setup.sh` rebuilds it on the target from the pinned versions. The new machine also generates its own agent keys and starts with an empty database. That is intentional, because private keys must not travel in an archive.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `ABORT: ports already in use` | It's already running. Run `scripts/stop_local.sh` first. |
| `PURPOSE_NOT_ALLOWED` everywhere | Credentials expired (1 h TTL). Re-run `seed_credentials.py`. |
| agent health shows `llm=False` / HTTP 500 `model requires more system memory` | Ollama is not running or there isn't enough free RAM. Close the browser or set a smaller `OLLAMA_MODEL` in `.env`. |
| `risk-001` suddenly denied after a gate run | The anomaly detector contained it. That is expected; see `docs/OPERATIONS_RUNBOOK.md`. |
| `KEYSTORE_ERROR` / agents `DEGRADED` | You mixed `docker compose up` (full stack) with `run_local.sh` against one database. Use one style, or `docker compose down -v` between them. |
