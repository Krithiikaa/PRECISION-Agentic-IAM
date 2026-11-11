#!/usr/bin/env bash
# Build a transferable zip of the project.
#
#   scripts/package.sh                      -> ../agentic-iam-poc-YYYYMMDD.zip
#   scripts/package.sh /path/to/out.zip
#
# Contents = every file git tracks plus untracked files that are NOT ignored,
# i.e. exactly what a fresh clone of the working tree would have. That means
# it EXCLUDES, by construction:
#
#   .env, .keystore/, .keystore-agents/   secrets -- the target machine gets
#                                         fresh keys and its own .env
#   backend/.venv, frontend/node_modules  machine-specific; setup.sh rebuilds
#   .run/, dist/, __pycache__/            runtime state and build output
#
# A second, explicit deny-list below refuses to package secrets even if
# .gitignore is ever loosened.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${1:-$(dirname "$ROOT")/agentic-iam-poc-$(date +%Y%m%d).zip}"
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac

command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
PY="$ROOT/backend/.venv/bin/python"; [ -x "$PY" ] || PY=python3

git ls-files -z --cached --others --exclude-standard | "$PY" -c '
import os, re, sys, zipfile
out, prefix = sys.argv[1], "agentic-iam-poc/"
DENY = re.compile(r"(^|/)(\.env|\.keystore[^/]*|\.venv|node_modules|\.run)(/|$)|\.key\.json$")
paths = [p for p in sys.stdin.buffer.read().decode().split("\0") if p]
kept, refused = [], []
for p in paths:
    if not os.path.isfile(p):          # tracked but deleted in the working tree
        continue
    (refused if DENY.search(p) else kept).append(p)
if refused:
    sys.exit("REFUSING to package secret/machine-specific files:\n  " + "\n  ".join(refused))
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for p in sorted(kept):
        z.write(p, prefix + p)       # ZipFile.write keeps the unix mode, so scripts stay executable
print(f"{len(kept)} files -> {out} ({os.path.getsize(out)/1e6:.1f} MB)")
' "$OUT"

echo
echo "On the target machine:"
echo "  unzip $(basename "$OUT") && cd agentic-iam-poc"
echo "  scripts/setup.sh && scripts/run_local.sh"
