#!/usr/bin/env bash
# Shared helpers. Ports are the source of truth for "is it running?" -- a PID
# file can go stale, and a stale PID file once let an old build keep serving
# while a new one failed to bind and exited unnoticed.

port_pid() {  # port_pid <port> -> pid on stdout, empty if free
  # Always exits 0: "no process on this port" is a normal answer, not an
  # error. Under `set -e` with `pipefail`, a non-zero exit here would abort
  # the calling script the first time it looked at a free port.
  ss -lptn "sport = :$1" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1 || true
}

wait_port_free() {  # wait_port_free <port> <seconds>
  local port=$1 deadline=$(( SECONDS + ${2:-10} ))
  while [ $SECONDS -lt $deadline ]; do
    [ -z "$(port_pid "$port")" ] && return 0
    sleep 0.5
  done
  [ -z "$(port_pid "$port")" ]
}

wait_http() {  # wait_http <url> <seconds>
  local url=$1 deadline=$(( SECONDS + ${2:-60} ))
  while [ $SECONDS -lt $deadline ]; do
    curl -sf "$url" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

ALL_PORTS="8000 8100 9001 9002 9003 9004 9005 9006 9007 9008"
