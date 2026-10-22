#!/usr/bin/env bash
# Phase 1 gate TEST 6: agent identity survives a full restart of PostgreSQL,
# the IAM API and every agent process.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API=${IAM_API_URL:-http://localhost:8000}
DID="did:poc:agent:risk-001"
MESSAGE="I am the Risk Analysis Agent"

jqp() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }

echo "=== BEFORE restart ==="
BEFORE=$(curl -s "$API/api/v1/agents/did/$DID")
KEY_BEFORE=$(echo "$BEFORE" | jqp "d['active_key']['public_key_multibase']")
CREATED_BEFORE=$(echo "$BEFORE" | jqp "d['created_at']")
COUNT_BEFORE=$(curl -s "$API/api/v1/agents" | jqp "len(d)")
echo "  agents registered : $COUNT_BEFORE"
echo "  risk-001 public key: $KEY_BEFORE"
echo "  risk-001 created_at: $CREATED_BEFORE"

echo
echo "=== restarting everything ==="
"$ROOT/scripts/stop_local.sh" --keep-infra
( cd "$ROOT" && docker compose restart postgres >/dev/null 2>&1 )
echo "    restarted postgres container"
"$ROOT/scripts/run_local.sh" | sed 's/^/    /'

echo
echo "=== AFTER restart ==="
AFTER=$(curl -s "$API/api/v1/agents/did/$DID")
KEY_AFTER=$(echo "$AFTER" | jqp "d['active_key']['public_key_multibase']")
CREATED_AFTER=$(echo "$AFTER" | jqp "d['created_at']")
COUNT_AFTER=$(curl -s "$API/api/v1/agents" | jqp "len(d)")
echo "  agents registered : $COUNT_AFTER"
echo "  risk-001 public key: $KEY_AFTER"
echo "  risk-001 created_at: $CREATED_AFTER"

FAIL=0
pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAIL=1; }

echo
[ "$COUNT_BEFORE" = "$COUNT_AFTER" ] && pass "agent count unchanged" || fail "agent count changed"
[ "$KEY_BEFORE" = "$KEY_AFTER" ] && pass "public key unchanged" || fail "public key changed"
[ "$CREATED_BEFORE" = "$CREATED_AFTER" ] \
  && pass "created_at unchanged (the row persisted, it was not re-created)" \
  || fail "created_at changed: the identity was re-created, not restored"

# The restarted agent must still hold its private key, and its fresh signature
# must verify against the DID Document persisted before the restart.
SIG=$(curl -s -X POST http://localhost:9003/sign -H 'content-type: application/json' \
      -d "$(python3 -c "import json;print(json.dumps({'message':'$MESSAGE'}))")" | jqp "d['signature']")
VALID=$(curl -s -X POST "$API/api/v1/identity/verify" -H 'content-type: application/json' \
        -d "$(python3 -c "import json;print(json.dumps({'did':'$DID','message':'$MESSAGE','signature':'$SIG'}))")" \
        | jqp "str(d['valid'])")
[ "$VALID" = "True" ] \
  && pass "restarted agent signs with the same key and it still verifies" \
  || fail "signature from the restarted agent does not verify"

echo
[ "$FAIL" -eq 0 ] && echo "  TEST 6: PASSED" || echo "  TEST 6: FAILED"
exit $FAIL
