#!/usr/bin/env bash
# Run every live security gate, deterministically, then the loan workflow E2E.
#
# WHY A HARNESS. The gates are ATTACK SIMULATIONS: Phases 4-9 deliberately send
# scope violations, replays and denial bursts as did:poc:agent:risk-001 and then
# expect risk-001 to keep working. Since the anomaly detector exists, that
# traffic is (correctly) read as hostile and risk-001 is auto-contained mid-
# sweep. So the gates run against an API started in the GATE PROFILE:
#
#     ANOMALY_DETECTOR_ENABLED=false     refused by the config validator in
#                                        production; a harness switch only
#     rate limiting                      ON -- the gates honour Retry-After
#                                        (scripts/cp_sign.py), they no longer
#                                        need the limiter switched off
#
# The detector and the kill switch are then exercised by the loan workflow
# E2E, which runs against the NORMAL profile with every control on.
#
# Usage: scripts/run_local.sh first, then  scripts/run_gates.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$ROOT/.run"
LOG="$RUN/gates"
mkdir -p "$LOG"
PY="$ROOT/backend/.venv/bin/python"

. "$ROOT/scripts/lib.sh"

start_api() {   # $1 = extra environment, e.g. ANOMALY_DETECTOR_ENABLED=false
  [ -f "$RUN/iam-api.pid" ] && kill "$(cat "$RUN/iam-api.pid")" 2>/dev/null
  # Phase 12 (harness defect): the pid file is not proof of who holds :8000.
  # Stop WHATEVER listens there and require the port free, or a stale API in
  # another profile keeps answering /health and the gates run against it.
  local stale; stale=$(port_pid 8000)
  [ -n "$stale" ] && kill "$stale" 2>/dev/null
  if ! wait_port_free 8000 30; then
    echo "IAM API port 8000 is still held by pid $(port_pid 8000); refusing to run" >&2; exit 2
  fi
  env -i HOME="$HOME" PATH=/usr/bin:/bin bash -c "
    cd '$ROOT' && set -a && . ./.env && set +a && cd backend &&
    $1 nohup .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port \${API_PORT:-8000} \
      > '$RUN/iam-api.log' 2>&1 & echo \$! > '$RUN/iam-api.pid'"
  for _ in $(seq 1 60); do
    if curl -sf localhost:8000/health >/dev/null; then
      # The listener must be the process just started, not a survivor.
      local listener started; listener=$(port_pid 8000); started=$(cat "$RUN/iam-api.pid")
      # `$!` may be the wrapper of an env-prefixed command; uvicorn is its child.
      if [ "$listener" = "$started" ] || [ "$(ps -o ppid= -p "$listener" | tr -d ' ')" = "$started" ]; then
        echo "$listener" > "$RUN/iam-api.pid"; return 0
      fi
      echo "port 8000 answered from pid $listener, not the API just started ($started)" >&2; exit 2
    fi
    sleep 1
  done
  echo "IAM API did not start; see $RUN/iam-api.log" >&2; exit 2
}

clean() { env -i HOME="$HOME" PATH=/usr/bin:/bin "$@"; }

echo "==> API in the GATE profile (detector off, rate limiting on)"
start_api "ANOMALY_DETECTOR_ENABLED=false"
(cd "$ROOT/backend" && clean "$PY" ../scripts/seed_credentials.py >/dev/null &&
 clean "$PY" ../scripts/provision_mcp_clients.py >/dev/null)
# risk-002's SOX credential is deliberately 30 s long; Phase 3 asserts it lapsed.
sleep 35

TOTAL_FAIL=0
gate() {
  local name=$1; shift
  # ONLY="phase6 phase7" scripts/run_gates.sh  reruns just those gates.
  if [ -n "${ONLY:-}" ] && [[ " $ONLY " != *" $name "* ]]; then return; fi
  printf "  %-16s " "$name"
  (cd "$ROOT/backend" && clean timeout 1800 "$@") > "$LOG/$name.log" 2>&1
  local code=$?
  local summary
  summary=$(grep -E 'PASSED:|RESULT:|passed, [0-9]+ failed' "$LOG/$name.log" | tail -1 | sed 's/^ *//')
  [ -z "$summary" ] && summary=$(tail -1 "$LOG/$name.log")
  echo "exit=$code  $summary"
  [ $code -ne 0 ] && TOTAL_FAIL=$((TOTAL_FAIL + 1))
}
gate phase1   bash ../scripts/phase1_gate.sh
gate phase2   "$PY" ../scripts/phase2_gate.py
gate phase3   "$PY" ../scripts/phase3_gate.py
gate phase4   "$PY" ../scripts/phase4_gate.py
gate phase45  "$PY" ../scripts/phase45_gate.py
gate phase5   "$PY" ../scripts/phase5_gate.py
gate phase55  "$PY" ../scripts/phase55_gate.py
gate phase6   "$PY" ../scripts/phase6_gate.py
gate phase7   "$PY" ../scripts/phase7_gate.py
gate phase8   "$PY" ../scripts/phase8_gate.py
gate phase9   "$PY" ../scripts/phase9_e2e.py

echo "==> open incidents after the gates (must be none in the gate profile)"
docker compose -f "$ROOT/docker-compose.yml" exec -T postgres psql -U iam -d agentic_iam -tAc \
  "select incident_id||' '||agent_did||' '||trigger from security_incidents where status='CONTAINED'" \
  | sed 's/^/    /'

echo "==> API back in the NORMAL profile (every control on)"
start_api ""
sleep 5
gate loan_e2e "$PY" ../scripts/loan_workflow_e2e.py

echo
echo "  logs: $LOG/"
[ $TOTAL_FAIL -eq 0 ] && echo "  ALL GATES PASSED" || echo "  $TOTAL_FAIL gate(s) FAILED"
exit $TOTAL_FAIL
