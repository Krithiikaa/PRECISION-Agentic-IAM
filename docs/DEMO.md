# Demonstration guide

What an evaluator can see working today: real agent processes, real identities,
real cryptography, real LLM calls, real persistence, and a real verifiable
credential layer.

The loan workflow, discovery, authorization and the kill switch are later
phases — see [PHASE_STATUS.md](PHASE_STATUS.md).

Phase 1 demos are steps 1–9; Phase 2 steps 10–17; Phase 3 steps 18–24.

## Start

```bash
cp .env.example .env          # first time only
scripts/run_local.sh
```

Expected tail:

```
    :9001  did:poc:agent:coordinator-001    registered=True llm=True
    :9002  did:poc:agent:kyc-001            registered=True llm=True
    :9003  did:poc:agent:risk-001           registered=True llm=True
    :9004  did:poc:agent:fraud-001          registered=True llm=True
    :9005  did:poc:agent:decision-001       registered=True llm=True
```

## 1. These are real processes

```bash
ps -o pid,cmd -p $(cat .run/agent-*.pid | tr '\n' ',' | sed 's/,$//')
curl -s localhost:9003/health | python3 -m json.tool
```

Five OS processes, five ports, five DIDs, independent runtime counters.

## 2. Each agent has its own identity

```bash
curl -s localhost:8000/api/v1/agents \
  | python3 -c "import json,sys;[print(a['did'], a['active_key']['public_key_multibase']) for a in json.load(sys.stdin)]"
```

Five distinct DIDs, five distinct Ed25519 public keys.

## 3. The DID Document is the trust anchor

```bash
curl -s localhost:8000/api/v1/agents/did/did:poc:agent:risk-001/did-document | python3 -m json.tool
```

`verificationMethod` carries `Ed25519VerificationKey2020` and the public key in
`did:key`-style multibase. `service` carries the agent's live endpoint.

## 4. Identity Lab — sign, verify, tamper

The agent signs in its own process; the IAM API verifies in a different process
using only the published DID Document.

```bash
SIG=$(curl -s -X POST localhost:9003/sign -H 'content-type: application/json' \
  -d '{"message":"I am the Risk Analysis Agent"}' \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['signature'])")

# original message -> VALID
curl -s -X POST localhost:8000/api/v1/identity/verify -H 'content-type: application/json' \
  -d "{\"did\":\"did:poc:agent:risk-001\",\"message\":\"I am the Risk Analysis Agent\",\"signature\":\"$SIG\"}"

# tampered message, same signature -> INVALID
curl -s -X POST localhost:8000/api/v1/identity/verify -H 'content-type: application/json' \
  -d "{\"did\":\"did:poc:agent:risk-001\",\"message\":\"I am the Payroll Agent\",\"signature\":\"$SIG\"}"
```

Both outcomes are written to the audit trail as `SIGNATURE_VERIFIED` and
`SIGNATURE_INVALID`.

The same flow through the CLI:

```bash
cd backend && set -a && . ../.env && set +a
.venv/bin/python -m app.cli create-agent demo-001 "Demo Agent" RISK --capability credit_analysis
.venv/bin/python -m app.cli sign did:poc:agent:demo-001 "I am the Risk Analysis Agent"
.venv/bin/python -m app.cli verify did:poc:agent:demo-001 "I am the Payroll Agent" "<signature>"
```

## 5. A real LLM call

```bash
curl -s -X POST localhost:9003/task -H 'content-type: application/json' -d '{
  "instruction": "Given credit_score=762, debt_to_income=31.2%, fraud_risk=LOW, explain in two sentences what this means for lending risk."
}' | python3 -m json.tool
```

The `llm` block reports provider, model, measured latency and token counts from
Ollama's own response. The result carries an Ed25519 signature over its
canonical payload.

To prove there is no fallback path, stop Ollama and repeat: the agent returns
503 with the reason. It never invents an answer.

## 6. An impostor cannot take an agent's DID

```bash
cd backend && set -a && . ../.env && set +a
AGENT_SLUG=risk-001 AGENT_PORT=9103 AGENT_KEYSTORE_DIR=/tmp/impostor \
  .venv/bin/python -m app.agents.service
```

The process generates a different key, sees that the registry publishes another
one for `did:poc:agent:risk-001`, and refuses to start:

```
AgentBootstrapError: IDENTITY CONFLICT for did:poc:agent:risk-001: the registry
publishes public key 'z6Mkuvsi...' but this process holds 'z6Mkp29o...'.
Refusing to start.
```

## 7. Termination destroys the key

```bash
ID=$(curl -s localhost:8000/api/v1/agents/did/did:poc:agent:demo-001 \
     | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")
curl -s -X POST localhost:8000/api/v1/agents/$ID/status -H 'content-type: application/json' \
  -d '{"status":"TERMINATED","reason":"COMPROMISED"}'
curl -s -X POST localhost:8000/api/v1/agents/$ID/sign -H 'content-type: application/json' \
  -d '{"message":"anything"}'
```

The second call fails: the key is revoked and gone from the keystore.

Note that a signature issued *before* termination still verifies — it is
mathematically valid. That is precisely why identity alone is not authorization,
and why credential status (Phase 2) and session revocation (Phase 9) exist.

## 8. The audit trail

```bash
curl -s "localhost:8000/api/v1/audit?limit=20" | python3 -m json.tool
```

Or live, while running the steps above in another terminal:

```bash
curl -N localhost:8000/api/v1/events/stream
```

Events appear only when something actually happens in the backend.

## 9. Everything survives a restart

```bash
scripts/phase1_restart_test.sh
```

Restarts PostgreSQL, the IAM API and all five agents, then asserts the DIDs,
public keys and `created_at` timestamps are unchanged and that a fresh signature
from the restarted agent still verifies.

---

# Phase 2 — verifiable credentials

```bash
python3 scripts/seed_credentials.py --replace
```

## 10. The trust roots

```bash
curl -s localhost:8000/api/v1/credentials/issuers | python3 -m json.tool
```

Two authorities, each with its own Ed25519 key. Compare their public keys with
any agent's: they are different keys, and no agent holds an issuer key. That is
why an agent cannot mint a credential about itself.

## 11. DEMO 1 — issue

```bash
curl -s -X POST localhost:8000/api/v1/credentials/issue \
  -H 'content-type: application/json' -d '{
    "issuer": "did:poc:organization:bank-demo",
    "subject": "did:poc:agent:risk-001",
    "credential_type": "AgentCapabilityCredential",
    "claims": {"capability": "credit_analysis",
               "allowed_actions": ["READ_CREDIT_PROFILE"],
               "allowed_resources": ["credit_records"],
               "purpose": "loan_assessment"},
    "expires_in_seconds": 3600}' | python3 -m json.tool
```

## 12. DEMO 2 — verify

```bash
CRED=$(curl -s "localhost:8000/api/v1/credentials?subject=did:poc:agent:risk-001" \
  | python3 -c "import json,sys;print([c['credential_id'] for c in json.load(sys.stdin) if c['status']=='ACTIVE'][0])")
VC=$(curl -s "localhost:8000/api/v1/credentials/$CRED" \
  | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['credential']))")

curl -s -X POST localhost:8000/api/v1/credentials/verify \
  -H 'content-type: application/json' \
  -d "{\"credential\":$VC,\"expected_subject\":\"did:poc:agent:risk-001\"}" \
  | python3 -m json.tool
```

Eight checks, each with a reason. Not a bare boolean.

## 13. DEMO 3 — tamper

Change one claim and reuse the proof:

```bash
FORGED=$(echo "$VC" | python3 -c "
import json,sys
vc=json.load(sys.stdin); vc['credentialSubject']['capability']='payroll_access'
print(json.dumps(vc))")

curl -s -X POST localhost:8000/api/v1/credentials/verify \
  -H 'content-type: application/json' -d "{\"credential\":$FORGED}" \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['valid'], d['reason'])"
```

→ `False SIGNATURE_INVALID`

## 14. DEMO 4 — revoke

```bash
curl -s -X POST "localhost:8000/api/v1/credentials/$CRED/revoke" \
  -H 'content-type: application/json' -d '{"reason":"COMPROMISED"}'

curl -s -X POST localhost:8000/api/v1/credentials/verify \
  -H 'content-type: application/json' -d "{\"credential\":$VC}" \
  | python3 -c "
import json,sys; d=json.load(sys.stdin)
print(d['valid'], d['reason'], '| signature check still:', d['checks']['signature'])"
```

→ `False CREDENTIAL_REVOKED | signature check still: True`

The signature is untouched and still verifies. Cryptographic validity and
current authority are different questions — which is exactly why a status
lookup exists.

## 15. DEMO 5 — expire

```bash
SHORT=$(curl -s -X POST localhost:8000/api/v1/credentials/issue \
  -H 'content-type: application/json' -d '{
    "issuer":"did:poc:organization:bank-demo","subject":"did:poc:agent:risk-001",
    "credential_type":"AgentRoleCredential",
    "claims":{"role":"demo","department":"qa"},"expires_in_seconds":15}')
DOC=$(echo "$SHORT" | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['credential']))")

curl -s -X POST localhost:8000/api/v1/credentials/verify -H 'content-type: application/json' \
  -d "{\"credential\":$DOC}" | python3 -c "import json,sys;print('now: ',json.load(sys.stdin)['reason'])"
sleep 16
curl -s -X POST localhost:8000/api/v1/credentials/verify -H 'content-type: application/json' \
  -d "{\"credential\":$DOC}" | python3 -c "import json,sys;print('after:',json.load(sys.stdin)['reason'])"
```

→ `now: CREDENTIAL_VALID`, `after: CREDENTIAL_EXPIRED`

The backend compares timestamps. No frontend timer is involved, and
`expirationDate` is inside the signature so it cannot be extended.

## 16. Holder proof — the agent presents its own credentials

```bash
CH=$(curl -s localhost:8000/api/v1/credentials/challenge \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['challenge'])")

VP=$(curl -s -X POST localhost:9003/present -H 'content-type: application/json' \
  -d "{\"capability\":\"credit_analysis\",\"challenge\":\"$CH\"}" \
  | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['presentation']))")

curl -s -X POST localhost:8000/api/v1/credentials/verify-presentation \
  -H 'content-type: application/json' \
  -d "{\"presentation\":$VP,\"expected_challenge\":\"$CH\"}" | python3 -m json.tool
```

The presentation is built and signed **inside the agent process**, because the
IAM API does not hold that agent's private key. The verifier then checks the
holder proof and every contained credential, with the proven holder as the
expected subject — so a copied credential belonging to another agent is
rejected.

## 17. The credentials console

```bash
cd frontend && npm install && npm run dev     # http://localhost:5173
```

- **Credentials** — trust roots, every credential with its live status, and a
  detail panel with claims, proof and JSON. `Verify` runs the real verifier and
  renders its eight checks; `Simulate tampering` edits a signed claim without
  re-signing and shows `SIGNATURE_INVALID`; `Revoke` changes backend state.
- **Agents** — DID, key custody, credentials held, and `Present & verify`,
  which asks the agent process for a holder-signed presentation.
- **Live trace** — every line arrives over `/api/v1/events/stream` from the
  real backend event bus. If the backend is idle, the panel stays empty.

---

# Phase 3 — agent discovery

## 18. Agents registered themselves, with proof

```bash
curl -s localhost:8100/api/v1/ans/agents | python3 -m json.tool
curl -s localhost:8100/api/v1/ans/capabilities | python3 -m json.tool
```

Seven agents, each of which signed its own registration at boot. Nothing was
seeded by hand.

## 19. DEMO 1 — normal discovery

```bash
curl -s -X POST localhost:8100/api/v1/ans/discover \
  -H 'content-type: application/json' \
  -d '{"capability":"credit_analysis","requester_did":"did:poc:agent:coordinator-001"}' \
  | python3 -m json.tool
```

Every candidate carries `match_reasons` — the checks the backend actually ran,
with its own detail strings.

## 20. DEMO 2 — the coordinator finds it, with no endpoint table

```bash
curl -s -X POST localhost:9001/coordinate -H 'content-type: application/json' \
  -d '{"task":"Analyze credit risk for USER-007."}' --max-time 300 | python3 -m json.tool
```

The coordinator asks the ANS what capabilities exist, has the LLM choose one
from that live list, discovers a provider, then cross-checks the endpoint
against the DID Document. Grep the source if you doubt it:

```bash
grep -rn "900[0-9]" backend/app/agents/coordinator.py    # no matches
```

## 21. DEMO 3 — multiple candidates, ranked on observed signals

Three agents provide `credit_analysis`. Ranking uses real in-flight load and
measured probe latency, not a hardcoded winner. Give one some load and re-run
the query — the order changes.

## 22. DEMO 4 — the compliance filter

```bash
curl -s -X POST localhost:8100/api/v1/ans/discover \
  -H 'content-type: application/json' \
  -d '{"capability":"credit_analysis","required_credentials":["ComplianceCredential"]}' \
  | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('eligible:', [r['did'] for r in d['results']])
for r in d['rejected']:
    print('filtered:', r['did'], r['reason_code'])"
```

The seed set gives risk-001 a valid SOX credential, risk-002 one with a 30
second TTL, and risk-003 none. Run the query twice a minute apart and risk-002
drops out on its own — the credential really expired.

## 23. DEMO 5 — an agent goes offline

```bash
kill $(cat .run/agent-risk-001.pid)          # a real process stops
curl -s localhost:8100/api/v1/ans/resolve/did:poc:agent:risk-001 \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['status'])"
```

It deregisters gracefully on SIGTERM, so it goes OFFLINE immediately rather
than after a heartbeat timeout. Re-run discovery: it is gone, and another
provider is selected. Ask for something only it could satisfy and the answer is
`NO_MATCHING_AGENT` — nothing is substituted.

## 24. DEMO 6 — a spoofed registration

```bash
python3 scripts/phase3_gate.py            # includes this test with output
```

Registering `did:poc:agent:risk-001` with a bogus signature is refused as
`INVALID_REGISTRATION_PROOF`, and so is a *validly signed* payload whose
endpoint was swapped afterwards. The real agent's endpoint is untouched.

## 25. The discovery console

```bash
cd frontend && npm run dev     # http://localhost:5173 -> Discovery
```

Pick a capability, optionally require a credential, hit Search. Matched and
filtered candidates both show why. "Ask coordinator" hands the whole job to the
coordinator agent. The live trace on the right shows the ANS events — which
come from a *different process*, which is why the stream tails the audit table
rather than an in-process bus.

---

## Gates

```bash
scripts/phase1_gate.sh              # Phase 1, spec section 48, tests 1-5 and 7
scripts/phase1_restart_test.sh      # Phase 1 test 6, restart persistence
python3 scripts/phase2_gate.py      # Phase 2 E2E + all seven failure cases
bash scripts/phase2_restart_test.sh # Phase 2 credential persistence
python3 scripts/phase3_gate.py      # Phase 3 E2E, spoofing, credentials, offline
bash scripts/phase3_restart_test.sh # Phase 3 registry persistence
cd backend && .venv/bin/python -m pytest tests -q    # 234 tests
```

## Stop

```bash
scripts/stop_local.sh
```
