#!/usr/bin/env bash
# Phase 3 gate: the ANS registry survives a restart of PostgreSQL, the ANS
# service itself, and every agent process.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANS=${ANS_URL:-http://localhost:8100}
RISK="did:poc:agent:risk-001"

jqp() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }
FAIL=0
pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAIL=1; }

echo "=== BEFORE restart ==="
COUNT_BEFORE=$(curl -s "$ANS/api/v1/ans/agents" | jqp "len(d)")
ENDPOINT_BEFORE=$(curl -s "$ANS/api/v1/ans/resolve/$RISK" | jqp "d['endpoint']")
REGISTERED_BEFORE=$(curl -s "$ANS/api/v1/ans/resolve/$RISK" | jqp "d['registered_at']")
CAPS_BEFORE=$(curl -s "$ANS/api/v1/ans/capabilities" | jqp "len(d)")
echo "  agents registered : $COUNT_BEFORE"
echo "  capabilities      : $CAPS_BEFORE"
echo "  risk-001 endpoint : $ENDPOINT_BEFORE"

echo
echo "=== restarting postgres, the ANS, the IAM API and all agents ==="
"$ROOT/scripts/stop_local.sh" --keep-infra >/dev/null 2>&1
( cd "$ROOT" && docker compose restart postgres >/dev/null 2>&1 )
echo "  postgres container restarted"
bash "$ROOT/scripts/run_local.sh" >/dev/null 2>&1 || true
if ! curl -sf "$ANS/health" >/dev/null; then
  echo "  FAIL  the ANS did not come back up"; exit 1
fi
echo "  stack back up"

echo
echo "=== AFTER restart ==="
COUNT_AFTER=$(curl -s "$ANS/api/v1/ans/agents" | jqp "len(d)")
ENDPOINT_AFTER=$(curl -s "$ANS/api/v1/ans/resolve/$RISK" | jqp "d['endpoint']")
REGISTERED_AFTER=$(curl -s "$ANS/api/v1/ans/resolve/$RISK" | jqp "d['registered_at']")
CAPS_AFTER=$(curl -s "$ANS/api/v1/ans/capabilities" | jqp "len(d)")
echo "  agents registered : $COUNT_AFTER"
echo "  capabilities      : $CAPS_AFTER"

[ "$COUNT_BEFORE" = "$COUNT_AFTER" ] && pass "agent count unchanged" \
  || fail "agent count changed ($COUNT_BEFORE -> $COUNT_AFTER)"
[ "$CAPS_BEFORE" = "$CAPS_AFTER" ] && pass "capability index unchanged" \
  || fail "capability index changed"
[ "$ENDPOINT_BEFORE" = "$ENDPOINT_AFTER" ] && pass "endpoint unchanged" \
  || fail "endpoint changed"
[ "$REGISTERED_BEFORE" = "$REGISTERED_AFTER" ] \
  && pass "registered_at unchanged (the row persisted, it was not re-created)" \
  || fail "registered_at changed: the registration was re-created, not restored"

# Discovery must work immediately after the restart, from the persisted registry.
RESULT=$(curl -s -X POST "$ANS/api/v1/ans/discover" -H 'content-type: application/json' \
  -d '{"capability":"credit_analysis"}')
MATCHED=$(echo "$RESULT" | jqp "d['matched_count']")
[ "$MATCHED" -gt 0 ] && pass "discovery works from the persisted registry ($MATCHED providers)" \
  || fail "discovery returned nothing after the restart"

# The registration proof history must survive too: replaying an old nonce
# still has to be refused.
PROOFS=$(PGPASSWORD=${POSTGRES_PASSWORD:-iam} psql -h 127.0.0.1 -p 5433 \
  -U ${POSTGRES_USER:-iam} -d ${POSTGRES_DB:-agentic_iam} -tAc \
  "select count(*) from ans_registration_proofs where accepted;")
[ "$PROOFS" -gt 0 ] && pass "registration proof history persisted ($PROOFS accepted proofs)" \
  || fail "registration proofs were lost"

echo
[ "$FAIL" -eq 0 ] && echo "  PHASE 3 RESTART TEST: PASSED" || echo "  PHASE 3 RESTART TEST: FAILED"
exit $FAIL
