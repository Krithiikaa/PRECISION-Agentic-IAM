#!/usr/bin/env bash
# One-time setup on a fresh machine (or after unzipping a package made by
# scripts/package.sh). Idempotent: safe to run again.
#
#   - checks the system prerequisites that CANNOT live in a venv
#     (Docker, Node, Ollama, a Python 3.11-3.13 interpreter)
#   - builds backend/.venv from the pinned requirements
#   - installs the frontend's node_modules from package-lock.json
#   - creates .env from .env.example if there is none
#   - pulls the Ollama model named in .env
#
# Why the venv is BUILT here rather than shipped in the zip: a venv hard-codes
# absolute paths and symlinks to the host's own interpreter, and its compiled
# extensions are specific to one Python version and CPU architecture. Copied to
# another machine it breaks -- often silently, as ModuleNotFoundError.
#
# Environment overrides:
#   PYTHON=/path/to/python3.12   use this interpreter for the venv
#   SKIP_OLLAMA_PULL=1           do not download the model (~4.7 GB)
#   SKIP_FRONTEND=1              do not install node_modules
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VENV="$ROOT/backend/.venv"
FAIL=0

ok()   { printf "    ok    %s\n" "$1"; }
warn() { printf "    WARN  %s\n" "$1"; }
bad()  { printf "    FAIL  %s\n" "$1" >&2; FAIL=1; }

echo "==> system prerequisites"
command -v curl >/dev/null && ok "curl" || bad "curl is required"
command -v ss   >/dev/null && ok "ss (iproute2)" || bad "ss is required (package: iproute2)"

if ! command -v docker >/dev/null; then
  bad "docker is required -- https://docs.docker.com/engine/install/"
elif ! docker compose version >/dev/null 2>&1; then
  bad "docker compose v2 plugin is required"
elif ! docker info >/dev/null 2>&1; then
  bad "docker is installed but the daemon is unreachable (is it running? is \$USER in the docker group?)"
else
  ok "docker + compose ($(docker compose version --short))"
fi

if [ "${SKIP_FRONTEND:-}" != 1 ]; then
  if command -v node >/dev/null && command -v npm >/dev/null; then
    NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]')
    [ "$NODE_MAJOR" -ge 20 ] && ok "node $(node -v)" || bad "node 20+ required (found $(node -v))"
  else
    bad "node 20+ and npm are required for the console (or set SKIP_FRONTEND=1)"
  fi
fi

if command -v ollama >/dev/null; then
  ok "ollama"
else
  warn "ollama not found -- agents start, but report llm=False and refuse LLM tasks. https://ollama.com/download"
fi

# The pinned dependencies (pydantic-core, cryptography, psycopg) are verified on
# 3.11-3.13. 3.14 has no wheels for some of them and would try to compile Rust.
py_ok() { "$1" -c 'import sys; sys.exit(0 if (3,11) <= sys.version_info[:2] <= (3,13) else 1)' 2>/dev/null; }
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for c in python3.13 python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null && py_ok "$(command -v "$c")"; then PY="$(command -v "$c")"; break; fi
  done
fi
if [ -z "$PY" ] && command -v uv >/dev/null; then
  echo "    no system Python 3.11-3.13; fetching 3.13 with uv"
  uv python install 3.13 >/dev/null && PY="$(uv python find 3.13)"
fi
if [ -n "$PY" ] && py_ok "$PY"; then
  ok "python $("$PY" -c 'import platform;print(platform.python_version())') ($PY)"
else
  bad "Python 3.11-3.13 is required. Install python3.13 (+ python3.13-venv on Debian/Ubuntu), or install uv (https://docs.astral.sh/uv/) and re-run, or set PYTHON=/path/to/python3.x"
fi

if [ $FAIL -ne 0 ]; then
  echo; echo "Fix the FAIL lines above and run scripts/setup.sh again." >&2
  exit 1
fi

echo "==> backend venv ($VENV)"
if [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c "import fastapi, uvicorn, sqlalchemy, cryptography" 2>/dev/null; then
  ok "existing venv works ($("$VENV/bin/python" -V)) -- syncing requirements"
elif [ -e "$VENV" ]; then
  # Never delete it automatically: on the dev host this has been a moved
  # interpreter symlink, fixable without a reinstall.
  bad "backend/.venv exists but is broken. Compare '$VENV/bin/python -V' with 'ls $VENV/lib/';"
  bad "if the interpreter simply moved, repoint the symlink; otherwise: rm -rf backend/.venv && scripts/setup.sh"
  exit 1
else
  "$PY" -m venv "$VENV" || { bad "venv creation failed (Debian/Ubuntu: apt install python3.x-venv)"; exit 1; }
  ok "created"
fi
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$ROOT/backend/requirements-dev.txt"
ok "requirements installed"

echo "==> configuration"
if [ -f "$ROOT/.env" ]; then
  ok ".env present (left untouched)"
else
  cp "$ROOT/.env.example" "$ROOT/.env"
  ok ".env created from .env.example (development defaults)"
fi
chmod +x "$ROOT"/scripts/*.sh

if [ "${SKIP_FRONTEND:-}" != 1 ]; then
  echo "==> frontend"
  if [ -d "$ROOT/frontend/node_modules" ]; then
    ok "node_modules present"
  else
    (cd "$ROOT/frontend" && npm ci --no-audit --no-fund --loglevel=error)
    ok "node_modules installed"
  fi
fi

echo "==> LLM model"
MODEL=$(grep -E '^OLLAMA_MODEL=' "$ROOT/.env" | tail -1 | cut -d= -f2-)
MODEL="${MODEL:-llama3:latest}"
if ! command -v ollama >/dev/null; then
  warn "skipped (ollama not installed)"
elif ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$MODEL"; then
  ok "$MODEL already pulled"
elif [ "${SKIP_OLLAMA_PULL:-}" = 1 ]; then
  warn "$MODEL not pulled (SKIP_OLLAMA_PULL=1). Later: ollama pull $MODEL"
else
  echo "    pulling $MODEL (several GB, one time)"
  ollama pull "$MODEL" && ok "$MODEL pulled" || warn "pull failed; run: ollama pull $MODEL"
fi

echo
echo "Setup complete. Next:"
echo "  scripts/run_local.sh      # start everything (first run pulls Docker images)"
echo "  see QUICKSTART.md         # what to open and run to see results"
