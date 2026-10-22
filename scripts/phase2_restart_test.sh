#!/usr/bin/env bash
# Phase 2 gate: credentials, their status and their proofs survive a full
# restart of PostgreSQL, the IAM API and every agent process.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API=${IAM_API_URL:-http://localhost:8000}
RISK="did:poc:agent:risk-001"

jqp() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }
FAIL=0
pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAIL=1; }

echo "=== BEFORE restart ==="
# A credential we revoke now: revocation must still be in force afterwards.
REVOKED_ID=$(curl -s -X POST "$API/api/v1/credentials/issue" -H 'content-type: application/json' \
  -d "{\"issuer\":\"did:poc:organization:bank-demo\",\"subject\":\"$RISK\",
       \"credential_type\":\"AgentRoleCredential\",
       \"claims\":{\"role\":\"restart_probe\",\"department\":\"qa\"},
       \"expires_in_seconds\":3600}" | jqp "d['credential_id']")
curl -s -X POST "$API/api/v1/credentials/$REVOKED_ID/revoke" \
  -H 'content-type: application/json' -d '{"reason":"RESTART_PROBE"}' >/dev/null

COUNT_BEFORE=$(curl -s "$API/api/v1/credentials?subject=$RISK" | jqp "len(d)")
CRED=$(curl -s "$API/api/v1/credentials?subject=$RISK" | jqp "[c['credential_id'] for c in d if c['status']=='ACTIVE'][0]")
PROOF_BEFORE=$(curl -s "$API/api/v1/credentials/$CRED" | jqp "d['credential']['proof']['proofValue']")
echo "  credentials held by risk-001 : $COUNT_BEFORE"
echo "  probe credential (revoked)   : $REVOKED_ID"
echo "  active credential proof      : ${PROOF_BEFORE:0:32}..."

echo
echo "=== restarting postgres, the IAM API and all agents ==="
"$ROOT/scripts/stop_local.sh" --keep-infra >/dev/null 2>&1
( cd "$ROOT" && docker compose restart postgres >/dev/null 2>&1 )
echo "  postgres container restarted"
bash "$ROOT/scripts/run_local.sh" >/dev/null 2>&1 || true
if ! curl -sf "$API/health" >/dev/null; then
  echo "  FAIL  stack did not come back up"; exit 1
fi
echo "  stack back up"

echo
echo "=== AFTER restart ==="
COUNT_AFTER=$(curl -s "$API/api/v1/credentials?subject=$RISK" | jqp "len(d)")
PROOF_AFTER=$(curl -s "$API/api/v1/credentials/$CRED" | jqp "d['credential']['proof']['proofValue']")
echo "  credentials held by risk-001 : $COUNT_AFTER"

[ "$COUNT_BEFORE" = "$COUNT_AFTER" ] && pass "credential count unchanged" \
  || fail "credential count changed ($COUNT_BEFORE -> $COUNT_AFTER)"
[ "$PROOF_BEFORE" = "$PROOF_AFTER" ] && pass "credential proof is byte-identical" \
  || fail "credential proof changed"

# The surviving credential must still verify -- the issuer key survived too.
VC=$(curl -s "$API/api/v1/credentials/$CRED" | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['credential']))")
VALID=$(curl -s -X POST "$API/api/v1/credentials/verify" -H 'content-type: application/json' \
  -d "{\"credential\":$VC,\"expected_subject\":\"$RISK\"}" | jqp "str(d['valid'])")
[ "$VALID" = "True" ] && pass "surviving credential still verifies against the issuer key" \
  || fail "surviving credential no longer verifies"

# Revocation is durable: the probe credential must still be rejected.
PROBE=$(curl -s "$API/api/v1/credentials/$REVOKED_ID" | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['credential']))")
REASON=$(curl -s -X POST "$API/api/v1/credentials/verify" -H 'content-type: application/json' \
  -d "{\"credential\":$PROBE}" | jqp "d['reason']")
[ "$REASON" = "CREDENTIAL_REVOKED" ] && pass "revocation survived the restart (still CREDENTIAL_REVOKED)" \
  || fail "revocation did not survive: reason is $REASON"

# The agent process must reload its wallet from the registry on boot.
ATTESTED=$(curl -s "http://localhost:9003/credentials" | jqp "','.join(d['attested_capabilities'])")
[ "$ATTESTED" = "credit_analysis" ] && pass "restarted agent reloaded its wallet ($ATTESTED)" \
  || fail "restarted agent wallet is wrong: '$ATTESTED'"

echo
[ "$FAIL" -eq 0 ] && echo "  PHASE 2 RESTART TEST: PASSED" || echo "  PHASE 2 RESTART TEST: FAILED"
exit $FAIL
