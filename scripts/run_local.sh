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

AGENTS="coordinator-001:9001 kyc-001:9002 risk-001:9003 fraud-001:9004 decision-001:9005 risk-002:9006 risk-003:9007 payments-001:9008"

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
docker compose up -d postgres redis >/dev/null
for _ in $(seq 1 60); do
  docker compose exec -T postgres pg_isready -U "${POSTGRES_USER:-iam}" >/dev/null 2>&1 && break
  sleep 1
done
echo "    postgres and redis ready"

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
echo "Stop with    scripts/stop_local.sh"
exit $FAILED
