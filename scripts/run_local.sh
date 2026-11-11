#!/usr/bin/env bash
# Start the whole POC locally: postgres + redis (docker), the IAM API, and one
# process per agent. Aborts rather than starting on top of something already
# bound to a port -- a silent bind failure leaves old code serving.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib.sh"
RUN="$ROOT/.run"
mkdir -p "$RUN"
cd "$ROOT"

# Every `python3` below (provisioning, the health-line formatter) must be the
# venv's: the helper scripts import the backend, whose dependencies exist only
# there. Relying on the system python3 worked only by accident on hosts that
# happen to have pydantic et al. installed globally.
if ! "$ROOT/backend/.venv/bin/python" -c "import fastapi" 2>/dev/null; then
  echo "ABORT: backend/.venv is missing or broken. Run scripts/setup.sh first." >&2
  exit 1
fi
export PATH="$ROOT/backend/.venv/bin:$PATH"
[ -f "$ROOT/.env" ] || { echo "ABORT: no .env. Run scripts/setup.sh first." >&2; exit 1; }

AGENTS="coordinator-001:9001 kyc-001:9002 risk-001:9003 fraud-001:9004 decision-001:9005 risk-002:9006 risk-003:9007 payments-001:9008 docs-001:9009"

OCCUPIED=""
for port in $ALL_PORTS; do
  pid=$(port_pid "$port"); [ -n "$pid" ] && OCCUPIED="$OCCUPIED :$port(pid $pid)"
done
if [ -n "$OCCUPIED" ]; then
  echo "ABORT: ports already in use:$OCCUPIED" >&2
  echo "       Run scripts/stop_local.sh first." >&2
  exit 1
fi

echo "==> infrastructure"
# OPA (the PDP) and Keycloak (human identities, MCP OAuth) are hard
# dependencies of authorization and HITL, so they start here too. --wait blocks
# on each container's healthcheck; Keycloak's first boot imports the realm and
# can take a minute or two.
if ! docker compose up -d --wait --wait-timeout 300 postgres redis opa keycloak >/dev/null; then
  echo "    FAILED to bring up infrastructure:" >&2
  docker compose ps >&2
  exit 1
fi
echo "    postgres, redis, opa and keycloak healthy"

set -a; . "$ROOT/.env"; set +a
cd "$ROOT/backend"

echo "==> migrations"
.venv/bin/alembic upgrade head 2>&1 | grep -E "Running upgrade" || echo "    schema up to date"

echo "==> iam-api"
nohup .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port "${API_PORT:-8000}" \
  > "$RUN/iam-api.log" 2>&1 &
API_PID=$!
echo $API_PID > "$RUN/iam-api.pid"
if ! wait_http "http://localhost:${API_PORT:-8000}/health" 60; then
  echo "    FAILED to start iam-api. Last log lines:" >&2
  tail -20 "$RUN/iam-api.log" >&2
  exit 1
fi
echo "    iam-api on :${API_PORT:-8000} (pid $API_PID)"

echo "==> agent naming service"
nohup .venv/bin/python -m app.ans.service > "$RUN/ans.log" 2>&1 &
ANS_PID=$!
echo $ANS_PID > "$RUN/ans.pid"
if ! wait_http "http://localhost:${ANS_PORT:-8100}/health" 60; then
  echo "    FAILED to start the ANS. Last log lines:" >&2
  tail -20 "$RUN/ans.log" >&2
  exit 1
fi
echo "    ans on :${ANS_PORT:-8100} (pid $ANS_PID)"

# Phase 5 / S-7: an agent no longer creates its own identity. Provisioning is
# an authorized, audited administrative act, performed here by the
# `identity-authority` machine administrator before any agent starts.
echo "==> provisioning agent identities"
if ! python3 "$ROOT/scripts/provision_agents.py"; then
  echo "    FAILED to provision agent identities. Agents will not start." >&2
  exit 1
fi

echo "==> agents"
for entry in $AGENTS; do
  slug="${entry%%:*}"; port="${entry##*:}"
  AGENT_SLUG="$slug" AGENT_PORT="$port" AGENT_PUBLIC_URL="http://localhost:$port" \
    nohup .venv/bin/python -m app.agents.service > "$RUN/agent-$slug.log" 2>&1 &
  echo $! > "$RUN/agent-$slug.pid"
done

FAILED=0
for entry in $AGENTS; do
  slug="${entry%%:*}"; port="${entry##*:}"
  if wait_http "http://localhost:$port/health" 60; then
    status=$(curl -s "http://localhost:$port/health" | python3 -c \
      "import json,sys;d=json.load(sys.stdin);print(f\"{d['did']:<32} registered={d['registered_with_iam']} llm={d['llm']['available']}\")")
    echo "    :$port  $status"
  else
    echo "    :$port  FAILED - see $RUN/agent-$slug.log" >&2
    FAILED=1
  fi
done

echo
echo "IAM API      http://localhost:${API_PORT:-8000}/docs"
echo "ANS          http://localhost:${ANS_PORT:-8100}/docs"
echo "MCP          http://localhost:${API_PORT:-8000}/mcp  (OAuth 2.1)"
echo "Stop with    scripts/stop_local.sh"
echo
# NOT run automatically, deliberately. Seeding ISSUES credentials rather than
# replacing them, so doing it on every start would accumulate duplicates; and
# provisioning talks to Keycloak, which should not be a precondition for the
# API coming up. They are printed because without them an agent holds no
# credential (every call denies) and MCP has no OAuth client (every call is
# 401) -- both of which look like bugs rather than missing setup.
echo "Next, if you want agents to be able to DO anything:"
echo "  cd backend"
echo "  python3 ../scripts/seed_credentials.py       # capability credentials (1h TTL)"
echo "  python3 ../scripts/provision_mcp_clients.py  # Phase 8 OAuth clients"
exit $FAILED
