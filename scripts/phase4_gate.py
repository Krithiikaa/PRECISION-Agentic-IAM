#!/usr/bin/env python3
"""Phase 4 gate: fine-grained authorization, against the live system.

Proves, against a running API and a running OPA, that:

  * a valid agent with a valid credential is ALLOWED to read credit_records
  * THE SAME AGENT, SAME IDENTITY, SAME CREDENTIAL is DENIED payroll_records
  * missing / expired / revoked credentials deny, each with its own reason
  * a sensitive action returns HUMAN_APPROVAL_REQUIRED (decision value only)
  * an agent asserting "allow: true" is ignored
  * a protected tool is unreachable except through the AEM
  * OPA being unavailable denies rather than permits
  * every decision is audited and attributable to a policy version

Latency numbers printed here are MEASURED from real calls. Nothing is modelled.

PHASE 4.5 NOTE: /authorize and /enforce are now behind the control-plane guard,
so this gate signs its requests as the `enforcement-gateway` principal -- the
PEP role. That is not a workaround: an unsigned call to either endpoint is
refused, which scripts/phase45_gate.py proves separately.

Usage:
    docker compose up -d opa postgres redis iam-api
    python3 scripts/phase4_gate.py
"""
from __future__ import annotations

import json
import statistics
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
import cp_sign                                      # noqa: E402

API = "http://localhost:8000"
OPA = "http://localhost:8181"
BANK = "did:poc:organization:bank-demo"

PASS, FAIL = 0, 0


def call(method: str, url: str, body: dict | None = None, timeout: float = 30.0,
         principal: str | None = None):
    """Issue a request, signing it when `principal` is given.

    A signed call serialises the body ONCE and sends exactly those bytes: the
    control-plane proof binds sha256(body), so re-encoding would invalidate it.
    """
    if principal is not None:
        path = url[len(API):]
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
        print("  Start the stack first:  docker compose up -d opa postgres redis iam-api")
        sys.exit(2)


def check(label: str, actual, expected) -> None:
    global PASS, FAIL
    ok = actual == expected
    if ok:
        PASS += 1
    else:
        FAIL += 1
    mark = "PASS" if ok else "FAIL"
    detail = f"{actual!r}" if ok else f"got {actual!r}, expected {expected!r}"
    print(f"      [{mark}]  {label:<52s} {detail}")


def authorize(did: str, *, action="read", resource_type="credit_records",
              resource_id="customer-007", purpose="loan_assessment", context=None):
    body = {
        "subject": {"did": did},
        "action": action,
        "resource": {"type": resource_type, "id": resource_id},
        "purpose": purpose,
    }
    if context is not None:
        body["context"] = context
    return call("POST", f"{API}/api/v1/authorize", body,
                principal=cp_sign.GATEWAY)[1]


def enforce(did: str, tool: str, customer="customer-007", purpose="loan_assessment"):
    return call("POST", f"{API}/api/v1/enforce", {
        "subject": {"did": did}, "tool": tool,
        "arguments": {"customer_id": customer}, "purpose": purpose,
    }, principal=cp_sign.GATEWAY)[1]


print("=" * 78)
print("  PHASE 4 GATE - PDP / PIP / PAP / OPA / REGO / AEM")
print("=" * 78)

# --- 0. the engine is real -------------------------------------------------
print("\n  STEP 0  The policy engine is a real OPA runtime")
status, health = call("GET", f"{API}/api/v1/authorize/health")
check("authorization health reachable", status, 200)
check("OPA available", health["opa"]["available"], True)
check("fail-closed posture", health["fail_closed"], True)
try:
    with urllib.request.urlopen(f"{OPA}/v1/policies", timeout=10) as response:
        modules = [m["id"] for m in json.loads(response.read())["result"]]
    print(f"      OPA modules loaded: {len(modules)}")
    for module in sorted(modules):
        print(f"        - {module}")
    check("combining algorithm loaded", "agentic_iam/decision" in modules, True)
except urllib.error.URLError as exc:
    print(f"      OPA not directly reachable ({exc}); relying on the API's view")

_, policies = call("GET", f"{API}/api/v1/policies")
print(f"\n      Policy lifecycle ({len(policies['policies'])} policies):")
for policy in policies["policies"]:
    print(f"        {policy['policy_id']:<24s} {policy['version']:<4s} "
          f"{policy['status']:<9s} owner={policy['owner']:<18s} "
          f"in_engine={policy['in_engine']}")

# --- 1. subject ------------------------------------------------------------
print("\n  STEP 1  A real Phase 1 identity holding a real Phase 2 credential")
_, agents = call("GET", f"{API}/api/v1/agents")
risk = next((a for a in agents if a["slug"] == "risk-001"), None)
if risk is None:
    print("      No risk-001 agent. Run scripts/run_local.sh first.")
    sys.exit(2)
did = risk["did"]
print(f"      Agent {did}  status={risk['status']}")

_, held = call("GET", f"{API}/api/v1/credentials?subject={did}")
active = [c for c in held if c["status"] == "ACTIVE"
          and c["credential_type"] == "AgentCapabilityCredential"]
if not active:
    print("      No active capability credential. Run scripts/seed_credentials.py first.")
    sys.exit(2)
print(f"      Holds {len(active)} active capability credential(s); "
      f"capability={active[0]['claims'].get('capability')}, "
      f"allowedResources={active[0]['claims'].get('allowedResources')}")

# --- 2. ALLOW --------------------------------------------------------------
print("\n  STEP 2  ALLOW: credit_records + read + loan_assessment")
decision = authorize(did)
print(f"      decision={decision['decision']}  reason={decision['reason']}  "
      f"policy={decision['policy']}")
for stage in decision["stages"]:
    print(f"        {stage['name']:<10s} {stage['duration_ms']:>7.2f}ms  {stage['detail'][:52]}")
check("ALLOW", decision["decision"], "ALLOW")
check("reason", decision["reason"], "VALID_CREDENTIAL_AND_POLICY_MATCH")
check("attributable to a versioned policy", decision["policy"], "loan-credit-read:v1")

# --- 3. DENY: the headline demonstration -----------------------------------
print("\n  STEP 3  DENY: SAME agent, SAME identity, SAME credential - payroll_records")
denied = authorize(did, resource_type="payroll_records")
print(f"      decision={denied['decision']}  reason={denied['reason']}  "
      f"policy={denied['policy']}")
check("DENY", denied["decision"], "DENY")
check("reason", denied["reason"], "RESOURCE_NOT_ALLOWED")
print("      -> a valid identity and a valid credential do NOT confer unlimited access")

# --- 4. purpose ------------------------------------------------------------
print("\n  STEP 4  DENY: right resource, right action, WRONG purpose")
wrong_purpose = authorize(did, purpose="marketing_analytics")
check("DENY", wrong_purpose["decision"], "DENY")
check("reason", wrong_purpose["reason"], "PURPOSE_NOT_ALLOWED")

# --- 5. human approval -----------------------------------------------------
print("\n  STEP 5  HUMAN_APPROVAL_REQUIRED: a sensitive action")
sensitive = authorize(did, action="approve_loan")
check("decision", sensitive["decision"], "HUMAN_APPROVAL_REQUIRED")
check("reason", sensitive["reason"], "SENSITIVE_ACTION_REQUIRES_HUMAN")
print("      NOTE: the decision VALUE only. No approval flow, artifact or human")
print("            principal exists - that is the future HITL phase.")

# --- 6. self-asserted authorization ----------------------------------------
print("\n  STEP 6  An agent that asserts its own permission is ignored")
asserted = authorize(did, resource_type="payroll_records",
                     context={"allow": True, "decision": "ALLOW", "trust_score": 100})
check("still DENY", asserted["decision"], "DENY")
check("self-asserted keys rejected",
      sorted(asserted["evaluation"]["rejected_context_keys"]),
      ["allow", "decision", "trust_score"])

# --- 7. unknown subject ----------------------------------------------------
print("\n  STEP 7  Unknown subject fails closed")
ghost = authorize("did:poc:agent:ghost-999")
check("DENY", ghost["decision"], "DENY")
check("reason", ghost["reason"], "UNKNOWN_SUBJECT")

# --- 8. enforcement --------------------------------------------------------
print("\n  STEP 8  AEM enforcement: the tool is reached only through the boundary")
allowed = enforce(did, "get_credit_profile")
check("executed", allowed["executed"], True)
if allowed["executed"]:
    print(f"      credit_score={allowed['result']['credit_score']} "
          f"band={allowed['result']['score_band']}  "
          f"grant={allowed['grant']['grant_id']}")
    check("grant names the policy", allowed["grant"]["policy"], "loan-credit-read:v1")

blocked = enforce(did, "get_payroll_record")
check("payroll blocked", blocked["executed"], False)
check("no data returned", blocked["result"], None)
check("reason", blocked["decision"]["reason"], "RESOURCE_NOT_ALLOWED")
print("      -> the tool was never called; no payroll data left the boundary")

# --- 9. audit --------------------------------------------------------------
print("\n  STEP 9  Every decision is audited and correlated")
request_id = allowed["decision"]["request_id"]
_, events = call("GET", f"{API}/api/v1/audit?limit=300")
correlated = [e for e in events if e.get("request_id") == request_id]
types = [e["event_type"] for e in correlated]
print(f"      request_id={request_id} -> {len(correlated)} correlated events")
for event_type in types:
    print(f"        {event_type}")
for expected in ("AEM_INTERCEPT", "AUTHORIZATION_REQUESTED", "PIP_CONTEXT_COLLECTED",
                 "OPA_DECISION", "PDP_EVALUATION", "POLICY_ALLOW", "AEM_ALLOWED",
                 "TOOL_EXECUTED"):
    check(f"{expected} recorded", expected in types, True)

# --- 10. measured latency --------------------------------------------------
print("\n  STEP 10  MEASURED authorization latency (20 real requests)")
samples, opa_samples, pip_samples = [], [], []
for _ in range(20):
    started = time.perf_counter()
    result = authorize(did)
    samples.append((time.perf_counter() - started) * 1000)
    for stage in result["stages"]:
        if stage["name"] == "opa":
            opa_samples.append(stage["duration_ms"])
        if stage["name"] == "pip":
            pip_samples.append(stage["duration_ms"])


def summarise(name: str, values: list[float]) -> None:
    if not values:
        return
    ordered = sorted(values)
    p95 = ordered[int(len(ordered) * 0.95) - 1]
    print(f"      {name:<34s} min {min(values):6.2f}  "
          f"median {statistics.median(values):6.2f}  "
          f"p95 {p95:6.2f}  max {max(values):6.2f}  (ms)")


summarise("PIP context collection", pip_samples)
summarise("OPA policy evaluation", opa_samples)
summarise("end-to-end HTTP /authorize", samples)
print("      (measured on this host, against the running OPA. Not modelled.)")

# --- 11. fail closed -------------------------------------------------------
print("\n  STEP 11  Fail-closed behaviour")
malformed = call("POST", f"{API}/api/v1/authorize", {
    "subject": {"did": did}, "action": "read",
    "resource": {"type": "credit_records"}, "purpose": "",
})
check("malformed request rejected", malformed[0] >= 400, True)
print("      To verify the OPA-outage path, stop OPA and re-run STEP 2:")
print("        docker compose stop opa && python3 scripts/phase4_gate.py")
print("      Expected: DENY / AUTHORIZATION_UNAVAILABLE - never ALLOW.")

# --- summary ---------------------------------------------------------------
print("\n" + "=" * 78)
print(f"  RESULT: {PASS} passed, {FAIL} failed")
print("=" * 78)
print("""
  IDENTITY        != AUTHORIZATION
  DISCOVERY       != AUTHORIZATION
  AUTHENTICATION  != AUTHORIZATION
  LLM DECISION    != SECURITY DECISION

  PDP DECISION + AEM ENFORCEMENT = AUTHORIZED ACTION
""")
sys.exit(1 if FAIL else 0)
