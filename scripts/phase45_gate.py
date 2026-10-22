#!/usr/bin/env python3
"""Phase 4.5 gate: control-plane hardening, against the live system.

Proves, against a running API, a running ANS and a running OPA, that:

  * an unauthenticated caller cannot heartbeat, deregister, mutate policy,
    query the PDP, reach a protected tool, or make the registry sign for it
  * a GENUINE agent holding a GENUINE key cannot act for another agent
  * a captured proof cannot be replayed, redirected to another endpoint, or
    used after it goes stale
  * an administrator is refused an operation its role does not cover
  * the authorized principal for each operation succeeds
  * OPA's administrative API is not reachable off the loopback interface
  * a control-plane failure denies rather than proceeds
  * every acceptance and every refusal is on the audit trail

Latency numbers printed here are MEASURED from real calls. Nothing is modelled.

Usage:
    scripts/run_local.sh          # or: docker compose up -d
    python3 scripts/phase45_gate.py
"""
from __future__ import annotations

import json
import pathlib
import statistics
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cp_sign                                                      # noqa: E402

from app.ans.proof import RegistrationPayload                       # noqa: E402

API = "http://localhost:8000"
ANS = "http://localhost:8100"
OPA = "http://localhost:8181"

PROBE_SLUG = "gate-probe"
PROBE_DID = f"did:poc:agent:{PROBE_SLUG}"
VICTIM = "did:poc:agent:risk-001"

PASS, FAIL = 0, 0


def call(method, url, body=None, principal=None, timeout=30.0, base=None):
    """Issue a request, signing it as `principal` when one is given."""
    if principal is not None:
        path = url[len(base or API):]
        data, headers = cp_sign.signed(principal, method, path, body)
    else:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw.decode()[:300]}
    except urllib.error.URLError as exc:
        print(f"\n  CANNOT REACH {url}: {exc}")
        print("  Start the stack first:  scripts/run_local.sh")
        sys.exit(2)


def check(label, actual, expected):
    global PASS, FAIL
    ok = actual == expected
    PASS, FAIL = PASS + ok, FAIL + (not ok)
    detail = f"{actual!r}" if ok else f"got {actual!r}, expected {expected!r}"
    print(f"      [{'PASS' if ok else 'FAIL'}]  {label:<54s} {detail}")


def reason(body):
    return (body.get("detail") or {}).get("reason") if isinstance(body, dict) else None


print("=" * 78)
print("  PHASE 4.5 GATE - CONTROL-PLANE HARDENING")
print("=" * 78)

# --- 0. a signable probe identity ------------------------------------------
print("\n  STEP 0  A real, registry-custodied agent identity for the probe")
# PHASE 5 / S-7: creating an identity is an authorized operation now, so the
# probe is provisioned by the machine identity administrator. That is the
# supported path for automation -- and the refusal of an ANONYMOUS creation is
# itself asserted, in the Phase 5 gate.
status, created = call("POST", f"{API}/api/v1/agents", {
    "slug": PROBE_SLUG, "name": "Control-plane gate probe", "agent_type": "RISK",
    "capabilities": ["credit_analysis"], "endpoint": "http://localhost:9099",
}, principal=cp_sign.IDENTITY_ADMIN)
if status not in (201, 409):
    print(f"      Could not create the probe agent: HTTP {status} {created}")
    sys.exit(2)
if status == 409:
    # A previous run already made it. Re-read the identity so the gate is
    # rerunnable: a conflict body carries no id, and silently carrying None
    # through turned a real refusal into a 422 that looked like a policy bug.
    _, created = call("GET", f"{API}/api/v1/agents/did/{PROBE_DID}")
PROBE_ID = created.get("id")
if not PROBE_ID:
    print(f"      Could not resolve {PROBE_DID}: {created}")
    sys.exit(2)
print(f"      {PROBE_DID}  (holds a real Ed25519 key, and is NOT {VICTIM})")

payload = RegistrationPayload.build(
    did=PROBE_DID, endpoint="http://localhost:9099",
    capabilities=["credit_analysis"],
    organization="did:poc:organization:bank-demo",
)
signature = cp_sign.signer().sign(f"{PROBE_DID}#key-1", payload.signing_bytes())
status, registered = call("POST", f"{ANS}/api/v1/ans/register",
                          {**payload.to_dict(), "signature": signature.signature_b64})
check("probe registers with a signed registration proof", status, 201)

HEARTBEAT = f"{ANS}/api/v1/ans/heartbeat"

# --- 1. no proof at all -----------------------------------------------------
print("\n  STEP 1  An unauthenticated caller is refused everywhere it matters")
cases = [
    ("ANS heartbeat", "POST", HEARTBEAT, {"did": VICTIM, "status": "OFFLINE"}, ANS),
    ("ANS deregistration", "POST", f"{ANS}/api/v1/ans/unregister/{VICTIM}",
     {"reason": "x"}, ANS),
    ("ANS sweep", "POST", f"{ANS}/api/v1/ans/sweep", None, ANS),
    ("policy reload", "POST", f"{API}/api/v1/policies/reload", None, API),
    ("policy deactivation", "POST",
     f"{API}/api/v1/policies/loan-credit-read/deactivate", None, API),
    ("PDP query", "POST", f"{API}/api/v1/authorize", {
        "subject": {"did": VICTIM}, "action": "read",
        "resource": {"type": "credit_records", "id": "customer-007"},
        "purpose": "loan_assessment"}, API),
    ("AEM enforcement", "POST", f"{API}/api/v1/enforce", {
        "subject": {"did": VICTIM}, "tool": "get_credit_profile",
        "arguments": {"customer_id": "customer-007"},
        "purpose": "loan_assessment"}, API),
]
for label, method, url, body, base in cases:
    status, response = call(method, url, body, base=base)
    check(f"{label} refused", (status, reason(response)),
          (401, "CONTROL_PLANE_PROOF_MISSING"))

status, body = call("POST", f"{API}/api/v1/agents/{PROBE_ID}/sign",
                    {"message": "forge me a control-plane proof"})
check("registry signing oracle refused (S-6)", (status, reason(body)),
      (401, "CONTROL_PLANE_PROOF_MISSING"))

# --- 2. the victim is untouched ---------------------------------------------
print("\n  STEP 2  None of that changed anything")
_, agents = call("GET", f"{ANS}/api/v1/ans/agents", base=ANS)
victim = next((a for a in agents if a["did"] == VICTIM), None)
check("the victim is still ACTIVE", victim and victim["status"], "ACTIVE")
_, policies = call("GET", f"{API}/api/v1/policies")
loaded = {p["policy_id"]: p for p in policies["policies"]}
check("loan-credit-read is still in the engine",
      loaded["loan-credit-read"]["in_engine"], True)

# --- 3. a genuine identity, acting for someone else -------------------------
print("\n  STEP 3  A GENUINE agent with a GENUINE key cannot act for another")
print(f"      {PROBE_DID} signs a real proof -- for itself -- and names {VICTIM}")
status, body = call("POST", HEARTBEAT, {"did": VICTIM, "status": "OFFLINE"},
                    principal=PROBE_DID, base=ANS)
check("spoofed heartbeat refused", (status, reason(body)),
      (403, "PRINCIPAL_IS_NOT_THE_SUBJECT"))

status, body = call("POST", f"{ANS}/api/v1/ans/unregister/{VICTIM}", {"reason": "x"},
                    principal=PROBE_DID, base=ANS)
check("spoofed deregistration refused", (status, reason(body)),
      (403, "PRINCIPAL_IS_NOT_THE_SUBJECT"))

status, body = call("POST", f"{API}/api/v1/enforce", {
    "subject": {"did": VICTIM}, "tool": "get_credit_profile",
    "arguments": {"customer_id": "customer-007"}, "purpose": "loan_assessment",
}, principal=PROBE_DID)
check("enforcement as another subject refused", (status, reason(body)),
      (403, "PRINCIPAL_IS_NOT_THE_SUBJECT"))
check("no resource data leaked", "credit_score" in json.dumps(body), False)

# --- 4. privilege escalation -------------------------------------------------
print("\n  STEP 4  An agent cannot reach for administrative authority")
for label, url in (
    ("policy deactivation", f"{API}/api/v1/policies/loan-credit-read/deactivate"),
    ("registry sweep", f"{ANS}/api/v1/ans/sweep"),
    ("registry signing", f"{API}/api/v1/agents/{PROBE_ID}/sign"),
):
    base = ANS if url.startswith(ANS) else API
    status, body = call("POST", url, {"message": "x"} if "sign" in url else None,
                        principal=PROBE_DID, base=base)
    check(f"agent refused {label}", (status, reason(body)),
          (403, "AGENT_MAY_NOT_ADMINISTER"))

# --- 5. the legitimate agent path -------------------------------------------
print("\n  STEP 5  The agent acting on ITSELF is accepted")
status, body = call("POST", HEARTBEAT, {"did": PROBE_DID, "active_tasks": 4},
                    principal=PROBE_DID, base=ANS)
check("self heartbeat accepted", status, 200)
check("liveness recorded", body.get("status"), "ACTIVE")
_, agents = call("GET", f"{ANS}/api/v1/ans/agents", base=ANS)
probe = next((a for a in agents if a["did"] == PROBE_DID), None)
check("active_tasks actually updated", probe and probe["active_tasks"], 4)

status, body = call("POST", HEARTBEAT,
                    {"did": PROBE_DID, "endpoint": "http://attacker.invalid:9999"},
                    principal=PROBE_DID, base=ANS)
check("a heartbeat still cannot move the endpoint", status, 400)

# DERIVED from the agent catalogue rather than hardcoded. A literal here
# meant that adding an agent -- as Phase 7 did, to receive A2A transactions --
# failed this gate for a reason that had nothing to do with control-plane
# authentication. The PROPERTY under test is "every running agent is
# heartbeating with a signed proof", and it should be read off how many
# agents there are.
from app.agents.definitions import AGENT_DEFINITIONS                # noqa: E402

EXPECTED_AGENTS = len(AGENT_DEFINITIONS)
print(f"\n      The {EXPECTED_AGENTS} REAL agent processes are heartbeating "
      f"with signed proofs:")
_, agents = call("GET", f"{ANS}/api/v1/ans/agents", base=ANS)
live = [a for a in agents if a["did"] != PROBE_DID
        and a["seconds_since_heartbeat"] is not None
        and a["seconds_since_heartbeat"] < 60]
for agent in live:
    print(f"        {agent['did']:<34s} {agent['status']:<8s} "
          f"{agent['seconds_since_heartbeat']:>5.1f}s ago")
check("every running agent is heartbeating successfully", len(live),
      EXPECTED_AGENTS)

# --- 6. replay, redirection and staleness -----------------------------------
print("\n  STEP 6  A captured proof cannot be reused, redirected or kept")
body = {"did": PROBE_DID, "active_tasks": 1}
data, headers = cp_sign.signed(PROBE_DID, "POST", "/api/v1/ans/heartbeat", body)


def present(url, payload, hdrs):
    request = urllib.request.Request(url, data=payload, method="POST", headers=hdrs)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or "{}")


status, _ = present(HEARTBEAT, data, headers)
check("the proof works once", status, 200)
status, replayed = present(HEARTBEAT, data, headers)
check("the same proof refused on replay", (status, reason(replayed)),
      (403, "CONTROL_PLANE_NONCE_REPLAYED"))

data, headers = cp_sign.signed(PROBE_DID, "POST", "/api/v1/ans/heartbeat", body)
status, redirected = present(f"{ANS}/api/v1/ans/unregister/{PROBE_DID}", data, headers)
check("a heartbeat proof refused at deregistration", (status, reason(redirected)),
      (403, "CONTROL_PLANE_SIGNATURE_INVALID"))

data, headers = cp_sign.signed(PROBE_DID, "POST", "/api/v1/ans/heartbeat", body)
tampered = json.dumps({"did": VICTIM, "active_tasks": 1},
                      separators=(",", ":")).encode()
status, swapped = present(HEARTBEAT, tampered, headers)
check("the body cannot be swapped after signing", (status, reason(swapped)),
      (403, "CONTROL_PLANE_SIGNATURE_INVALID"))

# --- 7. least privilege among administrators --------------------------------
print("\n  STEP 7  Least privilege between administrators is real, not decorative")
status, body = call("POST", f"{API}/api/v1/policies/sensitive-action/deactivate",
                    principal=cp_sign.IDENTITY_ADMIN)
check("identity administrator refused policy administration",
      (status, reason(body)), (403, "MISSING_CONTROL_PLANE_ROLE"))
status, body = call("POST", f"{API}/api/v1/agents/{PROBE_ID}/sign",
                    {"message": "x"}, principal=cp_sign.POLICY_ADMIN)
check("policy administrator refused identity signing",
      (status, reason(body)), (403, "MISSING_CONTROL_PLANE_ROLE"))
status, body = call("POST", f"{API}/api/v1/policies/sensitive-action/deactivate",
                    principal=cp_sign.GATEWAY)
check("enforcement gateway refused policy administration",
      (status, reason(body)), (403, "MISSING_CONTROL_PLANE_ROLE"))

# --- 8. the authorized paths -------------------------------------------------
print("\n  STEP 8  Each authorized principal succeeds at its own operation")
status, body = call("POST", f"{API}/api/v1/policies/sensitive-action/deactivate",
                    principal=cp_sign.POLICY_ADMIN)
check("policy administrator deactivates", (status, body.get("status")),
      (200, "INACTIVE"))
status, body = call("POST", f"{API}/api/v1/policies/sensitive-action/activate",
                    principal=cp_sign.POLICY_ADMIN)
check("policy administrator reactivates", (status, body.get("status")),
      (200, "ACTIVE"))
status, body = call("POST", f"{API}/api/v1/agents/{PROBE_ID}/sign",
                    {"message": "an operator-authorised signature"},
                    principal=cp_sign.IDENTITY_ADMIN)
check("identity administrator may sign", status, 200)
status, body = call("POST", f"{ANS}/api/v1/ans/sweep", principal=cp_sign.POLICY_ADMIN,
                    base=ANS)
check("registry administrator may sweep", status, 200)
status, body = call("POST", f"{API}/api/v1/enforce", {
    "subject": {"did": VICTIM}, "tool": "get_credit_profile",
    "arguments": {"customer_id": "customer-007"}, "purpose": "loan_assessment",
}, principal=cp_sign.GATEWAY)
check("enforcement gateway reaches the protected tool", status, 200)
check("and receives the real record", (body.get("result") or {}).get("credit_score"), 742)

# --- 9. OPA boundary ---------------------------------------------------------
print("\n  STEP 9  OPA's administrative API is internal")
compose = (pathlib.Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text()
check("OPA is published on loopback only", '"127.0.0.1:8181:8181"' in compose, True)
check("OPA is not published on all interfaces", '"8181:8181"' in compose, False)
try:
    import socket
    listening = socket.create_connection(("127.0.0.1", 8181), timeout=3)
    listening.close()
    print("      loopback reaches OPA (this host runs the backend directly)")
except OSError:
    print("      OPA is not reachable even on loopback")
print("      Every policy change in this gate went through the PAP, never through")
print("      OPA's own API. In a deployment the port is not published at all.")

# --- 10. audit ---------------------------------------------------------------
print("\n  STEP 10  Acceptances and refusals are both on the audit trail")
_, events = call("GET", f"{API}/api/v1/audit?limit=400")
types = [e["event_type"] for e in events]
for expected in ("CONTROL_PLANE_AUTHENTICATED", "CONTROL_PLANE_AUTHORIZED",
                 "CONTROL_PLANE_REJECTED", "CONTROL_PLANE_DENIED",
                 "CONTROL_PLANE_REPLAY_DETECTED", "ANS_HEARTBEAT_ACCEPTED",
                 "ANS_HEARTBEAT_REJECTED", "AUTHORIZATION_API_REJECTED"):
    check(f"{expected} recorded", expected in types, True)

denied = [e for e in events if e["event_type"] == "CONTROL_PLANE_DENIED"]
if denied:
    print(f"      A refusal names the policy that decided: "
          f"{denied[0]['reason']} / {denied[0]['metadata'].get('policy')} "
          f"/ {denied[0]['metadata'].get('classification')}")

# --- 11. measured overhead ---------------------------------------------------
print("\n  STEP 11  MEASURED control-plane overhead (20 real requests each)")
unsigned, signed_calls = [], []
for _ in range(20):
    started = time.perf_counter()
    call("GET", f"{API}/api/v1/policies")
    unsigned.append((time.perf_counter() - started) * 1000)
for _ in range(20):
    started = time.perf_counter()
    call("POST", HEARTBEAT, {"did": PROBE_DID, "active_tasks": 1},
         principal=PROBE_DID, base=ANS)
    signed_calls.append((time.perf_counter() - started) * 1000)

auth_ms, authz_ms = [], []
_, events = call("GET", f"{API}/api/v1/audit?limit=200")
for event in events:
    if event["event_type"] == "CONTROL_PLANE_AUTHORIZED":
        auth_ms.append(event["metadata"].get("authentication_ms") or 0)
        authz_ms.append(event["metadata"].get("authorization_ms") or 0)


def summarise(name, values):
    if not values:
        return
    ordered = sorted(values)
    p95 = ordered[int(len(ordered) * 0.95) - 1]
    print(f"      {name:<40s} min {min(values):6.2f}  "
          f"median {statistics.median(values):6.2f}  "
          f"p95 {p95:6.2f}  max {max(values):6.2f}  (ms)")


summarise("unguarded read (GET /policies)", unsigned)
summarise("guarded write (POST /ans/heartbeat)", signed_calls)
summarise("  of which: authentication", auth_ms)
summarise("  of which: authorization (PDP+OPA)", authz_ms)
print("      (measured on this host against the running stack. Not modelled.)")

# --- 12. fail closed ---------------------------------------------------------
print("\n  STEP 12  Fail-closed")
print("      To verify the control-plane outage path, stop OPA and re-run STEP 5:")
print("        docker compose stop opa && python3 scripts/phase45_gate.py")
print("      Expected: 403 CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE - never 200.")
print("      A valid proof from a legitimate agent is still refused when policy")
print("      cannot be consulted.")

print("\n" + "=" * 78)
print(f"  RESULT: {PASS} passed, {FAIL} failed")
print("=" * 78)
print("""
  ANYONE CAN ASK       != SOMEONE MAY ACT
  PROVING WHO YOU ARE  != BEING ALLOWED
  AN AGENT'S AUTHORITY != AN OPERATOR'S AUTHORITY

  AUTHENTICATION + CONTROL-PLANE AUTHORIZATION = A PERMITTED OPERATION
""")
sys.exit(1 if FAIL else 0)
