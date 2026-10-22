#!/usr/bin/env python3
"""Phase 3 gate: the mandatory ANS acceptance tests, against the live system.

Covers specification sections 54 (end-to-end discovery), 55 (agent offline),
56 (credential revocation), 57 (spoofed registration), plus duplicate-DID and
endpoint-substitution protection.

Requires a running stack: scripts/run_local.sh
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

API = "http://localhost:8000"
ANS = "http://localhost:8100"
COORD = "http://localhost:9001"
RISK1 = "did:poc:agent:risk-001"
RISK3 = "did:poc:agent:risk-003"
BANK = "did:poc:organization:bank-demo"
COMPLIANCE_ISSUER = "did:poc:organization:compliance-authority"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cp_sign                                                  # noqa: E402

PASSED = 0
FAILED = 0


def call(method, url, body=None, timeout=120):
    # PHASE 5 / S-7: credential issuance and revocation are authorized now.
    # Signed as the machine identity administrator. ANS registration is
    # unchanged -- it has carried its own signed proof since Phase 3.
    path = url[url.index("/api/"):] if "/api/" in url else url
    if method == "POST" and (path.endswith("/credentials/issue")
                             or path.endswith("/revoke")
                             or path.endswith("/api/v1/agents")):
        data, headers = cp_sign.signed(cp_sign.IDENTITY_ADMIN, method, path, body)
    else:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"content-type": "application/json"}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}
    except urllib.error.URLError as e:
        raise SystemExit(f"Cannot reach {url}: {e}")


def check(label, actual, expected):
    global PASSED, FAILED
    if actual == expected:
        print(f"    PASS  {label}")
        PASSED += 1
    else:
        print(f"    FAIL  {label}: got {actual!r}, expected {expected!r}")
        FAILED += 1


def section(title):
    print(f"\n{'='*76}\n  {title}\n{'='*76}")


def discover(**query):
    _, body = call("POST", f"{ANS}/api/v1/ans/discover",
                   {"requester_did": "did:poc:agent:coordinator-001", **query})
    return body


def dids(result_list):
    return [r["did"] for r in result_list]


# ===========================================================================
section("SECTION 54 — MANDATORY END-TO-END DISCOVERY")

print("\n  The Coordinator source must contain no agent endpoint at all.")
sources = [ROOT / "backend/app/agents/coordinator.py",
           ROOT / "backend/app/agents/ans_client.py"]
url_pattern = re.compile(r"https?://[^\s\"']*:(9\d{3})")
found = []
for path in sources:
    for match in url_pattern.finditer(path.read_text()):
        found.append(f"{path.name}: {match.group(0)}")
check("no agent endpoint literal in coordinator code", found, [])

print("\n  Coordinator resolves the capability from the LIVE ANS catalogue")
status, outcome = call("POST", f"{COORD}/coordinate",
                       {"task": "Analyze credit risk for USER-007."}, timeout=300)
if status != 200:
    print(f"    (coordinate returned {status}: {str(outcome)[:200]})")
check("coordinate succeeded", status, 200)
capability = (outcome.get("capability") or {}).get("capability")
print(f"    capability resolved : {capability}")
print(f"    rationale           : {(outcome.get('capability') or {}).get('rationale','')[:64]}")
llm = (outcome.get("capability") or {}).get("llm") or {}
print(f"    decided by          : {llm.get('model')} in {llm.get('latency_ms')}ms")
check("capability is credit_analysis", capability, "credit_analysis")
check("capability came from the live catalogue",
      capability in (outcome.get("capability") or {}).get("catalogue", []), True)

selected = outcome.get("selected")
print(f"\n    selected agent      : {selected['did'] if selected else None}")
print(f"    resolved endpoint   : {selected['endpoint'] if selected else None}")
check("an agent was selected", bool(selected), True)
check("selected agent provides the capability",
      capability in (selected or {}).get("capabilities", []), True)

print("\n    Coordinator cross-checks ANS against the identity authority:")
for entry in outcome.get("verification", []):
    print(f"      {'PASS' if entry['passed'] else 'FAIL'}  {entry['name']:<18} "
          f"{entry['detail'][:52]}")
check("discovery result verified", outcome.get("verified"), True)
check("authorization explicitly NOT evaluated",
      outcome["authorization"]["evaluated"], False)

# ===========================================================================
section("SECTION 57 — MANDATORY SPOOFING TEST")

from app.ans.proof import RegistrationPayload  # noqa: E402

print("\n  Attacker registers an existing DID with a bogus signature")
payload = RegistrationPayload.build(
    did=RISK1, endpoint="http://attacker.invalid:9999",
    capabilities=["credit_analysis"], organization=BANK,
)
forged_signature = base64.b64encode(b"\x00" * 64).decode()
status, body = call("POST", f"{ANS}/api/v1/ans/register",
                    {**payload.to_dict(), "signature": forged_signature})
print(f"    HTTP {status}   reason={body.get('reason')}")
for entry in body.get("checks", []):
    mark = "PASS" if entry["passed"] else "FAIL"
    print(f"      {mark}  {entry['name']:<20} {entry['detail'][:50]}")
check("registration rejected", body.get("accepted"), False)
check("reason is INVALID_REGISTRATION_PROOF", body.get("reason"),
      "INVALID_REGISTRATION_PROOF")

print("\n  The real agent's endpoint is unchanged")
_, resolved = call("GET", f"{ANS}/api/v1/ans/resolve/{RISK1}")
print(f"    {RISK1} -> {resolved['endpoint']}")
check("endpoint not hijacked",
      resolved["endpoint"].startswith("http://localhost:9003"), True)

print("\n  Endpoint substitution: valid signature, but the endpoint is swapped")
from app.identity.keys import EncryptedFileKeyStore  # noqa: E402
from app.identity.signer import Signer  # noqa: E402

keystore_dir = ROOT / "backend/.keystore-agents/risk-001"
master = os.environ.get("KEYSTORE_MASTER_KEY") or next(
    line.split("=", 1)[1].strip()
    for line in (ROOT / ".env").read_text().splitlines()
    if line.startswith("KEYSTORE_MASTER_KEY=")
)
signer = Signer(EncryptedFileKeyStore(keystore_dir, master))
honest = RegistrationPayload.build(
    did=RISK1, endpoint="http://localhost:9003",
    capabilities=["credit_analysis", "financial_data_read", "risk_analysis"],
    organization=BANK,
)
signature = signer.sign(f"{RISK1}#key-1", honest.signing_bytes()).signature_b64
swapped = {**honest.to_dict(), "endpoint": "http://attacker.invalid:9999",
           "signature": signature}
status, body = call("POST", f"{ANS}/api/v1/ans/register", swapped)
print(f"    HTTP {status}   reason={body.get('reason')}")
check("endpoint substitution rejected", body.get("accepted"), False)
check("substitution reason is INVALID_REGISTRATION_PROOF",
      body.get("reason"), "INVALID_REGISTRATION_PROOF")

print("\n  Nonce replay: re-send a registration that already succeeded")
fresh = RegistrationPayload.build(
    did=RISK1, endpoint="http://localhost:9003",
    capabilities=["credit_analysis", "financial_data_read", "risk_analysis"],
    organization=BANK,
)
fresh_sig = signer.sign(f"{RISK1}#key-1", fresh.signing_bytes()).signature_b64
status, first = call("POST", f"{ANS}/api/v1/ans/register",
                     {**fresh.to_dict(), "signature": fresh_sig})
check("a genuine re-registration is accepted", first.get("accepted"), True)
status, replay = call("POST", f"{ANS}/api/v1/ans/register",
                      {**fresh.to_dict(), "signature": fresh_sig})
print(f"    replay -> HTTP {status}  reason={replay.get('reason')}")
check("replayed nonce rejected", replay.get("accepted"), False)
check("replay reason is REGISTRATION_NONCE_REPLAYED", replay.get("reason"),
      "REGISTRATION_NONCE_REPLAYED")

print("\n  Unknown DID cannot be registered at all")
ghost = RegistrationPayload.build(
    did="did:poc:agent:ghost-999", endpoint="http://localhost:9999",
    capabilities=["credit_analysis"],
)
status, body = call("POST", f"{ANS}/api/v1/ans/register",
                    {**ghost.to_dict(), "signature": forged_signature})
check("unknown DID rejected", body.get("reason"), "DID_UNKNOWN")

# ===========================================================================
section("SECTION 56 — MANDATORY CREDENTIAL TEST")

print("\n  Issue a SOX compliance credential to risk-003, which has none")
_, issued = call("POST", f"{API}/api/v1/credentials/issue", {
    "issuer": COMPLIANCE_ISSUER, "subject": RISK3,
    "credential_type": "ComplianceCredential",
    "claims": {"framework": "SOX", "status": "COMPLIANT",
               "scope": "financial_data_processing",
               "disclaimer": "DEMO / SYNTHETIC - not a real attestation"},
    "expires_in_seconds": 3600})
credential_id = issued["credential_id"]
print(f"    {credential_id}")

result = discover(capability="credit_analysis",
                  required_credentials=["ComplianceCredential"])
print(f"    eligible now: {dids(result['results'])}")
check("risk-003 is now eligible", RISK3 in dids(result["results"]), True)

print("\n  Revoke it through the Phase 2 endpoint, then run the same query")
call("POST", f"{API}/api/v1/credentials/{credential_id}/revoke",
     {"reason": "PHASE3_GATE"})
result = discover(capability="credit_analysis",
                  required_credentials=["ComplianceCredential"])
print(f"    eligible now: {dids(result['results'])}")
rejected = {r["did"]: r["reason_code"] for r in result["rejected"]}
print(f"    filtered    : {rejected}")
check("risk-003 excluded after revocation", RISK3 in dids(result["results"]), False)
check("exclusion reason is CREDENTIAL_INVALID",
      rejected.get(RISK3), "CREDENTIAL_INVALID")
detail = next(
    (m["detail"] for r in result["rejected"] if r["did"] == RISK3
     for m in r["match_reasons"] if m["name"].startswith("credential:")), "")
print(f"    detail      : {detail[:64]}")
check("detail names CREDENTIAL_REVOKED", "CREDENTIAL_REVOKED" in detail, True)

# ===========================================================================
section("SECTION 55 — MANDATORY OFFLINE TEST")

print("\n  Before: who provides credit_analysis?")
before = discover(capability="credit_analysis")
print(f"    {dids(before['results'])}")
check("risk-001 is currently discoverable", RISK1 in dids(before["results"]), True)

pid_file = ROOT / ".run/agent-risk-001.pid"
pid = int(pid_file.read_text().strip())
print(f"\n  Stopping the real risk-001 process (pid {pid})")
subprocess.run(["kill", str(pid)], check=False)
for _ in range(30):
    time.sleep(1)
    _, resolved = call("GET", f"{ANS}/api/v1/ans/resolve/{RISK1}")
    if resolved["status"] != "ACTIVE":
        break
print(f"    ANS status for risk-001: {resolved['status']}")
check("risk-001 left ACTIVE in the registry", resolved["status"] != "ACTIVE", True)

after = discover(capability="credit_analysis")
print(f"    still discoverable: {dids(after['results'])}")
check("risk-001 no longer returned", RISK1 in dids(after["results"]), False)
check("another suitable agent is still available",
      len(after["results"]) > 0, True)
print(f"    coordinator would now use: "
      f"{after['selected']['did'] if after['selected'] else None}")

print("\n  Honest failure: nothing satisfies a query only risk-001 could")
none = discover(capability="credit_analysis",
                required_credentials=["ComplianceCredential"])
print(f"    matched={none['matched_count']} reason={none['reason']}")
check("no match reported honestly", none["reason"], "NO_MATCHING_AGENT")
check("no fallback agent was invented", none["selected"], None)

print("\n  Restarting risk-001")
env = {**os.environ, "AGENT_SLUG": "risk-001", "AGENT_PORT": "9003",
       "AGENT_PUBLIC_URL": "http://localhost:9003"}
for line in (ROOT / ".env").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        key, _, value = line.partition("=")
        env.setdefault(key.strip(), value.strip())
        env[key.strip()] = value.strip()
env.update({"AGENT_SLUG": "risk-001", "AGENT_PORT": "9003",
            "AGENT_PUBLIC_URL": "http://localhost:9003"})
process = subprocess.Popen(
    [str(ROOT / "backend/.venv/bin/python"), "-m", "app.agents.service"],
    cwd=str(ROOT / "backend"), env=env,
    stdout=open(ROOT / ".run/agent-risk-001.log", "w"), stderr=subprocess.STDOUT)
pid_file.write_text(str(process.pid))
for _ in range(40):
    time.sleep(1)
    try:
        status, _ = call("GET", "http://localhost:9003/health", timeout=3)
        if status == 200:
            break
    except SystemExit:
        continue
back = discover(capability="credit_analysis")
print(f"    discoverable again: {dids(back['results'])}")
check("risk-001 re-registered itself and is discoverable",
      RISK1 in dids(back["results"]), True)

# ===========================================================================
section("AUDIT AND EVENTS")

# Query per event type rather than scanning a bounded window: the trail is
# shared by every process, so a window can be dominated by whatever was
# chattiest most recently.
REQUIRED_EVENTS = (
    "ANS_AGENT_REGISTERED", "ANS_DISCOVERY_STARTED", "ANS_DISCOVERY_MATCH",
    "ANS_DISCOVERY_REJECTED", "ANS_DISCOVERY_NO_MATCH", "ANS_AGENT_SELECTED",
    "ANS_REGISTRATION_REJECTED", "ANS_SIGNATURE_INVALID", "ANS_AGENT_OFFLINE",
    "ANS_AGENT_RESOLVED", "COORDINATOR_CAPABILITY_RESOLVED",
)
for required in REQUIRED_EVENTS:
    _, rows = call("GET", f"{API}/api/v1/audit?event_type={required}&limit=5")
    print(f"    {required:<38} {len(rows)} recorded")
    check(f"{required} recorded", len(rows) > 0, True)

# Heartbeats are deliberately NOT audited unless they carry information: a
# routine "still alive" every 15s from every agent would bury everything else.
_, beats = call("GET", f"{API}/api/v1/audit?event_type=ANS_HEARTBEAT_RECEIVED&limit=50")
print(f"    ANS_HEARTBEAT_RECEIVED (status changes only)  {len(beats)} recorded")
check("routine heartbeats are not audited as events",
      all(e.get("reason") == "STATUS_CHANGED" for e in beats), True)

print(f"\n{'='*76}")
print(f"  PASSED: {PASSED}   FAILED: {FAILED}")
print(f"{'='*76}")
sys.exit(1 if FAILED else 0)
