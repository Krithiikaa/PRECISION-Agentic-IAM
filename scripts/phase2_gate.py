#!/usr/bin/env python3
"""Phase 2 gate: the mandatory end-to-end and failure demonstrations.

Runs against the LIVE system: the IAM API on :8000 and the real risk agent
process on :9003, which holds its own private key and signs its own
presentations.

Covers specification sections 37-41 and the seven failure cases in section 19.
"""
from __future__ import annotations

import base64
import copy
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

API = "http://localhost:8000"
RISK_AGENT = "http://localhost:9003"
RISK = "did:poc:agent:risk-001"
FRAUD = "did:poc:agent:fraud-001"
BANK = "did:poc:organization:bank-demo"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cp_sign                                                  # noqa: E402

PASSED = 0
FAILED = 0


def call(method, url, body=None):
    # PHASE 5 / S-7: credential issuance and revocation are authorized
    # operations now. The gate signs as the machine identity administrator --
    # the supported path for automation, which has no browser.
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
        with urllib.request.urlopen(req) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode())
        except Exception:
            return exc.code, {}
    except urllib.error.URLError as exc:
        raise SystemExit(f"Cannot reach {url}: {exc}")


def check(label, actual, expected):
    global PASSED, FAILED
    if actual == expected:
        print(f"    PASS  {label}")
        PASSED += 1
    else:
        print(f"    FAIL  {label}: got {actual!r}, expected {expected!r}")
        FAILED += 1


def show_checks(report):
    for entry in report.get("check_details", []):
        mark = "PASS" if entry["passed"] else "FAIL"
        print(f"          {mark}  {entry['name']:<12} {entry['detail'][:64]}")


def issue(claims=None, ttl=3600, subject=RISK, ctype="AgentCapabilityCredential"):
    claims = claims or {
        "capability": "credit_analysis",
        "allowed_actions": ["READ_CREDIT_PROFILE"],
        "allowed_resources": ["credit_records"],
        "purpose": "loan_assessment",
    }
    status, body = call("POST", f"{API}/api/v1/credentials/issue", {
        "issuer": BANK, "subject": subject, "credential_type": ctype,
        "claims": claims, "expires_in_seconds": ttl,
    })
    if status != 201:
        raise SystemExit(f"Issuance failed: {status} {body}")
    return body


def verify(credential, **kwargs):
    _, report = call("POST", f"{API}/api/v1/credentials/verify",
                     {"credential": credential, **kwargs})
    return report


# ===========================================================================
print("=" * 74)
print("  MANDATORY END-TO-END TEST (spec section 37)")
print("=" * 74)

print("\n  STEP 1  Phase 1 agent identity is reused, not re-created")
_, agent = call("GET", f"{API}/api/v1/agents/did/{RISK}")
print(f"          DID        {agent['did']}")
print(f"          Public key {agent['active_key']['public_key_multibase']}")
print(f"          Custody    {agent['active_key']['keystore_backend']} (agent holds its own key)")
check("subject DID is the Phase 1 identity", agent["did"], RISK)

print("\n  STEP 2/3  Demo Bank Identity Authority issues and signs the credential")
issued = issue()
vc = issued["credential"]
print(f"          Credential {vc['id']}")
print(f"          Issuer     {vc['issuer']}")
print(f"          Proof      {vc['proof']['type']} by {vc['proof']['verificationMethod']}")
check("issuer key differs from the agent key",
      vc["proof"]["verificationMethod"] != agent["active_key"]["kid"], True)
check("proof is a 64-byte Ed25519 signature",
      len(base64.b64decode(vc["proof"]["proofValue"])), 64)

print("\n  STEP 4  The agent receives it (wallet loaded from the registry)")
_, wallet = call("GET", f"{RISK_AGENT}/credentials")
print(f"          Holds {wallet['count']} credential(s); "
      f"attested capabilities: {wallet['attested_capabilities']}")
check("credit_analysis is attested by a credential",
      "credit_analysis" in wallet["attested_capabilities"], True)

print("\n  STEP 5  The agent presents it, signing with ITS OWN private key")
_, ch = call("GET", f"{API}/api/v1/credentials/challenge")
challenge = ch["challenge"]
status, presented = call("POST", f"{RISK_AGENT}/present",
                         {"capability": "credit_analysis", "challenge": challenge,
                          "domain": "loan-service"})
if status != 200:
    raise SystemExit(f"Presentation failed: {status} {presented}")
vp = presented["presentation"]
print(f"          Presentation {vp['id']}")
print(f"          Holder proof {vp['proof']['verificationMethod']} "
      f"(purpose={vp['proof']['proofPurpose']})")
check("holder proof is made by the agent's own key",
      vp["proof"]["verificationMethod"], agent["active_key"]["kid"])
check("issuer proof and holder proof are different signatures",
      vp["proof"]["proofValue"] != vp["verifiableCredential"][0]["proof"]["proofValue"], True)

print("\n  STEPS 6-11  Verifier resolves the issuer key and checks everything")
_, report = call("POST", f"{API}/api/v1/credentials/verify-presentation",
                 {"presentation": vp, "expected_challenge": challenge,
                  "required_claims": {"capability": "credit_analysis"}})
for entry in report["check_details"]:
    print(f"          {'PASS' if entry['passed'] else 'FAIL'}  {entry['name']:<12} "
          f"{entry['detail'][:60]}")
print("          -- contained credential --")
show_checks(report["credentials"][0])
check("presentation VERIFIED", report["valid"], True)
check("contained credential VERIFIED", report["credentials"][0]["valid"], True)

# ===========================================================================
print("\n" + "=" * 74)
print("  MANDATORY FAILURE TESTS (spec sections 38-41 and 19)")
print("=" * 74)

print("\n  CASE 1/6  Tampered claim, original proof reused (section 38)")
forged = copy.deepcopy(vc)
forged["credentialSubject"]["capability"] = "payroll_access"
report = verify(forged, expected_subject=RISK)
show_checks(report)
check("tampered credential INVALID", report["valid"], False)
check("reason is SIGNATURE_INVALID", report["reason"], "SIGNATURE_INVALID")

print("\n  CASE 3  Revoked credential (section 39)")
revocable = issue()
check("valid before revocation", verify(revocable["credential"])["valid"], True)
call("POST", f"{API}/api/v1/credentials/{revocable['credential_id']}/revoke",
     {"reason": "COMPROMISED"})
report = verify(revocable["credential"])
show_checks(report)
check("revoked credential INVALID", report["valid"], False)
check("reason is CREDENTIAL_REVOKED", report["reason"], "CREDENTIAL_REVOKED")
check("signature itself is still mathematically valid",
      report["checks"]["signature"], True)

print("\n  CASE 2  Expired credential, real elapsed time (section 40)")
short = issue(ttl=5)
check("valid before expiry", verify(short["credential"])["valid"], True)
print("          waiting 6s for the credential to actually expire ...")
time.sleep(6)
report = verify(short["credential"])
show_checks(report)
check("expired credential INVALID", report["valid"], False)
check("reason is CREDENTIAL_EXPIRED", report["reason"], "CREDENTIAL_EXPIRED")

print("\n  CASE 4  Wrong subject: risk agent's credential in the fraud agent's context")
report = verify(vc, expected_subject=FRAUD)
show_checks(report)
check("wrong subject INVALID", report["valid"], False)
check("reason is SUBJECT_MISMATCH", report["reason"], "SUBJECT_MISMATCH")

print("\n  CASE 5  Unknown issuer")
forged = copy.deepcopy(vc)
forged["issuer"] = "did:poc:organization:totally-made-up"
forged["proof"]["verificationMethod"] = "did:poc:organization:totally-made-up#key-1"
report = verify(forged)
show_checks(report)
check("unknown issuer INVALID", report["valid"], False)
check("reason is ISSUER_UNKNOWN", report["reason"], "ISSUER_UNKNOWN")

print("\n  CASE 7  Missing required claim")
report = verify(vc, required_claims=["fraudClearance"])
check("missing claim INVALID", report["valid"], False)
check("reason is MISSING_REQUIRED_CLAIM", report["reason"], "MISSING_REQUIRED_CLAIM")

# ===========================================================================
print("\n" + "=" * 74)
print("  AUDIT TRAIL (spec section 42)")
print("=" * 74)
_, events = call("GET", f"{API}/api/v1/audit?agent_did={RISK}&limit=200")
seen = {}
for event in events:
    seen[event["event_type"]] = seen.get(event["event_type"], 0) + 1
for name in sorted(seen):
    if name.startswith(("CREDENTIAL", "PRESENTATION")):
        print(f"    {name:<36} x{seen[name]}")
for required in ("CREDENTIAL_ISSUED", "CREDENTIAL_VERIFIED", "CREDENTIAL_SIGNATURE_INVALID",
                 "CREDENTIAL_REVOKED", "CREDENTIAL_SUBJECT_MISMATCH",
                 "CREDENTIAL_ISSUER_UNKNOWN", "PRESENTATION_VERIFIED"):
    check(f"{required} recorded", required in seen, True)

print("\n" + "=" * 74)
print(f"  PASSED: {PASSED}   FAILED: {FAILED}")
print("=" * 74)
sys.exit(1 if FAILED else 0)
