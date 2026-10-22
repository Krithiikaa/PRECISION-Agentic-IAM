#!/usr/bin/env bash
# Stop everything started by run_local.sh.
#
# Kills by recorded PID first (never by name pattern -- that can match the
# calling shell), then verifies the ports are actually free and clears any
# straggler still holding one. Without that second step a stale process can
# survive and quietly keep serving old code.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib.sh"
RUN="$ROOT/.run"
KEEP_INFRA="${1:-}"

if [ -d "$RUN" ]; then
  for pidfile in "$RUN"/*.pid; do
    [ -e "$pidfile" ] || continue
    pid=$(cat "$pidfile" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && echo "    stopped $(basename "$pidfile" .pid) (pid $pid)"
    fi
    rm -f "$pidfile"
  done
fi

for port in $ALL_PORTS; do
  wait_port_free "$port" 8 && continue
  pid=$(port_pid "$port")
  [ -z "$pid" ] && continue
  echo "    :$port still held by pid $pid (stale process) - terminating"
  kill "$pid" 2>/dev/null
  if ! wait_port_free "$port" 8; then
    echo "    :$port did not release after SIGTERM - sending SIGKILL"
    kill -9 "$pid" 2>/dev/null
    wait_port_free "$port" 5 || echo "    WARNING: :$port is still occupied by pid $(port_pid "$port")"
  fi
done

if [ "$KEEP_INFRA" != "--keep-infra" ]; then
  ( cd "$ROOT" && docker compose stop postgres redis >/dev/null 2>&1 ) \
    && echo "    stopped postgres and redis"
fi
