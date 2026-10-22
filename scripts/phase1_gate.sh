#!/usr/bin/env bash
# Phase 1 gate (spec section 48). Every check runs against the live system.
# Requires: iam-api on :8000, the risk agent on :9003.
set -uo pipefail

API=${IAM_API_URL:-http://localhost:8000}
RISK=${RISK_AGENT_URL:-http://localhost:9003}
DID="did:poc:agent:risk-001"
MESSAGE="I am the Risk Analysis Agent"
TAMPERED="I am the Payroll Agent"
PASS=0; FAIL=0

jqp() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }
check() { # check <name> <actual> <expected>
  if [ "$2" = "$3" ]; then echo "  PASS  $1"; PASS=$((PASS+1));
  else echo "  FAIL  $1 (got '$2', expected '$3')"; FAIL=$((FAIL+1)); fi
}

echo "=== TEST 1: agent identity exists with a DID and an Ed25519 key ==="
AGENT=$(curl -s "$API/api/v1/agents/did/$DID")
echo "$AGENT" | jqp "f\"  DID        {d['did']}\n  Name       {d['name']}\n  Status     {d['status']}\n  Algorithm  {d['active_key']['algorithm']}\n  Public key {d['active_key']['public_key_multibase']}\n  Custody    {d['active_key']['keystore_backend']}\""
check "DID assigned"      "$(echo "$AGENT" | jqp "d['did']")" "$DID"
check "status ACTIVE"     "$(echo "$AGENT" | jqp "d['status']")" "ACTIVE"
check "Ed25519 key bound" "$(echo "$AGENT" | jqp "d['active_key']['algorithm']")" "Ed25519"
check "no private key in response" "$(echo "$AGENT" | grep -ci private)" "0"

echo
echo "=== TEST 2: DID Document resolves ==="
DOC=$(curl -s "$API/api/v1/agents/did/$DID/did-document")
echo "$DOC" | python3 -m json.tool | sed 's/^/  /'
check "document id"      "$(echo "$DOC" | jqp "d['id']")" "$DID"
check "verification key" "$(echo "$DOC" | jqp "d['verificationMethod'][0]['type']")" "Ed25519VerificationKey2020"
check "service endpoint" "$(echo "$DOC" | jqp "'yes' if d['service'][0]['serviceEndpoint'] else 'no'")" "yes"

echo
echo "=== TEST 3: the running agent signs with its own private key ==="
SIGNED=$(curl -s -X POST "$RISK/sign" -H 'content-type: application/json' \
         -d "$(python3 -c "import json;print(json.dumps({'message':'$MESSAGE'}))")")
SIG=$(echo "$SIGNED" | jqp "d['signature']")
echo "  Message   $MESSAGE"
echo "  Signed by $(echo "$SIGNED" | jqp "d['verification_method']")"
echo "  Signature ${SIG:0:44}..."
check "signature produced" "$(python3 -c "import base64;print(len(base64.b64decode('$SIG')))")" "64"

echo
echo "=== TEST 4: IAM verifies that signature against the published DID Document ==="
V=$(curl -s -X POST "$API/api/v1/identity/verify" -H 'content-type: application/json' \
    -d "$(python3 -c "import json;print(json.dumps({'did':'$DID','message':'$MESSAGE','signature':'$SIG'}))")")
echo "$V" | jqp "f\"  valid={d['valid']}  reason={d['reason']}\""
check "original message VALID" "$(echo "$V" | jqp "str(d['valid'])")" "True"

echo
echo "=== TEST 5: tampered message, same signature ==="
V2=$(curl -s -X POST "$API/api/v1/identity/verify" -H 'content-type: application/json' \
     -d "$(python3 -c "import json;print(json.dumps({'did':'$DID','message':'$TAMPERED','signature':'$SIG'}))")")
echo "$V2" | jqp "f\"  valid={d['valid']}  reason={d['reason']}\""
check "tampered message INVALID" "$(echo "$V2" | jqp "str(d['valid'])")" "False"

echo
echo "=== TEST 7: a second agent has a different DID and a different key ==="
OTHER=$(curl -s "$API/api/v1/agents/did/did:poc:agent:fraud-001")
K1=$(echo "$AGENT" | jqp "d['active_key']['public_key_multibase']")
K2=$(echo "$OTHER" | jqp "d['active_key']['public_key_multibase']")
echo "  risk-001  $K1"
echo "  fraud-001 $K2"
check "distinct DIDs"     "$(echo "$OTHER" | jqp "d['did']")" "did:poc:agent:fraud-001"
check "distinct key pairs" "$([ "$K1" != "$K2" ] && echo different || echo same)" "different"

echo
echo "=============================================="
echo "  PASSED: $PASS   FAILED: $FAIL"
echo "  (TEST 6, restart persistence, is scripts/phase1_restart_test.sh)"
echo "=============================================="
[ "$FAIL" -eq 0 ]
