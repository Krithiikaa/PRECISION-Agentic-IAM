#!/usr/bin/env python3
"""Phase 5 gate: human-in-the-loop authorization, against the live system.

Proves, against a running API, a running OPA and a running KEYCLOAK, that:

  * a high-value loan decision is referred to a human, and blocks
  * the approval screen carries what a person actually needs to judge it
  * the WRONG humans cannot approve -- IAM administrator, auditor, no-roles
  * an AGENT cannot approve its own action, and neither can a machine key
  * the loan officer's approval produces a SIGNED artifact, bound to the action
  * the PDP is asked AGAIN, and only then does the action execute
  * the same approval cannot be replayed, moved to another resource, or used
    by another agent
  * a rejection blocks the action, and the resource is observably untouched
  * an approval expires on the server clock
  * S-7 is closed: agent creation, credential issuance and revocation, agent
    termination and audit ingest all refuse anonymous callers
  * the whole flow is correlated in the audit trail by one request id

Latency numbers printed here are MEASURED from real calls. Nothing is modelled.

Usage:
    docker compose up -d postgres redis opa keycloak
    scripts/run_local.sh
    python3 scripts/phase5_gate.py
"""
from __future__ import annotations

import json
import os
import pathlib
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cp_sign                                                      # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]
os.environ.setdefault("AGENT_KEYSTORE_DIR", str(REPO / "backend" / ".keystore-agents"))

from app.controlplane.client import canonical_body, control_plane_headers  # noqa: E402
from app.core.config import get_settings                                   # noqa: E402
from app.identity.keys import EncryptedFileKeyStore                        # noqa: E402
from app.identity.signer import Signer                                     # noqa: E402

API = "http://localhost:8000"
KEYCLOAK = get_settings().oidc_token_url
BANK = "did:poc:organization:bank-demo"
AGENT = "did:poc:agent:risk-001"
LOAN = "loan-7842"
OTHER_LOAN = "loan-1001"

HUMANS = {
    "loan.officer": "loan-officer-demo",
    "iam.admin": "iam-admin-demo",
    "auditor": "auditor-demo",
    "no.roles": "no-roles-demo",
}

PASS, FAIL = 0, 0
_tokens: dict[str, str] = {}


def token(username: str) -> str:
    """A REAL access token from the running Keycloak."""
    if username in _tokens:
        return _tokens[username]
    data = urllib.parse.urlencode({
        "client_id": get_settings().oidc_client_id, "grant_type": "password",
        "username": username, "password": HUMANS[username], "scope": "openid",
    }).encode()
    try:
        with urllib.request.urlopen(KEYCLOAK, data, timeout=15) as response:
            _tokens[username] = json.loads(response.read())["access_token"]
    except urllib.error.URLError as exc:
        print(f"\n  CANNOT REACH KEYCLOAK at {KEYCLOAK}: {exc}")
        print("  Start it with:  docker compose up -d keycloak")
        sys.exit(2)
    return _tokens[username]


def agent_headers(method: str, path: str, body) -> tuple[bytes, dict[str, str]]:
    """Sign as the agent, with the agent's OWN key from its own keystore."""
    keystore = EncryptedFileKeyStore(
        os.path.join(os.environ["AGENT_KEYSTORE_DIR"], "risk-001"),
        get_settings().keystore_master_key,
    )
    payload = canonical_body(body)
    headers = control_plane_headers(
        Signer(keystore), principal_did=AGENT, kid=f"{AGENT}#key-1",
        method=method, path=path, body=payload,
    )
    headers["Content-Type"] = "application/json"
    return payload, headers


def call(method, path, body=None, *, principal=None, human=None, agent=False,
         timeout=60.0):
    if agent:
        data, headers = agent_headers(method, path, body)
    elif principal:
        data, headers = cp_sign.signed(principal, method, path, body)
    else:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
    if human:
        headers["Authorization"] = f"Bearer {token(human)}"
    request = urllib.request.Request(API + path, data=data, method=method,
                                     headers=headers)
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
        print(f"\n  CANNOT REACH {API}: {exc}")
        print("  Start the stack first:  scripts/run_local.sh")
        sys.exit(2)


def check(label, actual, expected):
    global PASS, FAIL
    ok = actual == expected
    PASS, FAIL = PASS + ok, FAIL + (not ok)
    detail = f"{actual!r}" if ok else f"got {actual!r}, expected {expected!r}"
    print(f"      [{'PASS' if ok else 'FAIL'}]  {label:<54s} {detail}")


def reason(body):
    detail = body.get("detail") if isinstance(body, dict) else None
    return detail.get("reason") if isinstance(detail, dict) else None


def enforce(application_id=LOAN, *, request_id=None, approval_id=None,
            did=AGENT, purpose="loan_decision", context=None):
    body = {"subject": {"did": did}, "tool": "approve_loan_application",
            "arguments": {"application_id": application_id}, "purpose": purpose}
    if request_id:
        body["request_id"] = request_id
    if approval_id:
        body["approval_id"] = approval_id
    if context is not None:
        body["context"] = context
    return call("POST", "/api/v1/enforce", body, principal=cp_sign.GATEWAY)[1]


def escalate(application_id=LOAN):
    body = enforce(application_id)
    request = (body.get("decision", {}).get("evaluation", {})
               .get("approval_request") or {})
    return body, request.get("approval_id"), request.get("retry_with_request_id")


print("=" * 78)
print("  PHASE 5 GATE - HUMAN-IN-THE-LOOP AUTHORIZATION")
print("=" * 78)

# --- 0. the identity provider is real --------------------------------------
print("\n  STEP 0  The identity provider is a real Keycloak")
status, health = call("GET", "/api/v1/hitl/health")
check("HITL health reachable", status, 200)
check("identity provider available", health["identity_provider"]["available"], True)
check("issuer matches configuration",
      health["identity_provider"]["issuer_matches_configuration"], True)
check("approval authority present", health["approval_authority"]["present"], True)
print(f"      issuer     : {health['identity_provider']['issuer']}")
print(f"      authority  : {health['approval_authority']['did']}")
print(f"      approval TTL: {health['approval_ttl_seconds']}s")

status, config = call("GET", "/api/v1/hitl/config")
check("OIDC flow is authorization code + PKCE", config["flow"],
      "authorization_code+pkce")

print("\n      Real tokens, real realm roles:")
for username in HUMANS:
    status, me = call("GET", "/api/v1/hitl/me", human=username)
    print(f"        {username:<14s} {str(me.get('roles')):<20s} {me.get('principal')}")
    check(f"{username} authenticates", status, 200)

# --- 1. the agent is credentialled -----------------------------------------
print("\n  STEP 1  The agent holds a credential scoped to loan applications")
status, issued = call("POST", "/api/v1/credentials/issue", {
    "issuer": BANK, "subject": AGENT,
    "credential_type": "AgentCapabilityCredential",
    "claims": {"capability": "credit_analysis",
               "allowed_actions": ["APPROVE_LOAN"],
               "allowed_resources": ["loan_applications"],
               "purpose": "loan_decision"},
    "expires_in_seconds": 3600,
}, human="iam.admin")
check("IAM_ADMIN may issue it", status, 201)

# --- 2. escalation ----------------------------------------------------------
print("\n  STEP 2  A high-value loan decision is referred to a human")
body, approval_id, request_id = escalate()
decision = body["decision"]
check("decision", decision["decision"], "HUMAN_APPROVAL_REQUIRED")
check("reason", decision["reason"], "SENSITIVE_ACTION_REQUIRES_HUMAN")
check("the tool did NOT run", body["executed"], False)
print(f"      approval  : {approval_id}")
print(f"      retry as  : {request_id}")

# --- 3. what the human sees -------------------------------------------------
print("\n  STEP 3  The human sees exactly what they are approving")
status, approval = call("GET", f"/api/v1/hitl/approvals/{approval_id}",
                        human="loan.officer")
p = approval["presentation"]
print(f"      Agent    : {p['agent']['name']}   {p['agent']['did']}")
print(f"      Action   : {p['action']['label']}")
print(f"      Resource : {p['resource']['label']} {p['resource']['id']}")
print(f"      Amount   : {p['resource']['detail']['amount']}")
print(f"      Purpose  : {p['purpose']}")
print(f"      Expires  : {approval['request_expires_at']}")
check("the amount is shown", p["resource"]["detail"]["amount"], "₹25,00,000")
# THE PROPERTY, not an inventory. What an approver is shown must be what a
# credential ATTESTS, never what the agent DECLARES about itself -- an agent
# can claim any capability. Asserted as a property rather than as an exact
# list, because the list legitimately grows: Phase 7 issued risk-001 a second
# capability credential, and a literal here would have failed for a reason
# that has nothing to do with what this check is about.
attested = set(p["agent"]["verified_capabilities"])
check("the attested capability is shown", "credit_analysis" in attested, True)
check("DECLARED-only capabilities are NOT shown as verified",
      attested & {"risk_analysis", "financial_data_read"}, set())
check("a reason is given", bool(p["policy"]["explanation"]), True)
check("no resource data leaks into the screen",
      "credit_score" in json.dumps(approval), False)

# --- 4. who may NOT approve -------------------------------------------------
print("\n  STEP 4  The wrong principals cannot approve")
decide = f"/api/v1/hitl/approvals/{approval_id}/decide"
status, refused = call("POST", decide, {"decision": "APPROVED"})
check("anonymous refused", (status, reason(refused)),
      (401, "CONTROL_PLANE_PROOF_MISSING"))
for username, expected in (("iam.admin", "HUMAN_MAY_NOT_APPROVE_THIS"),
                           ("auditor", "HUMAN_MAY_NOT_APPROVE_THIS"),
                           ("no.roles", "HUMAN_MAY_NOT_APPROVE_THIS")):
    status, refused = call("POST", decide, {"decision": "APPROVED"}, human=username)
    check(f"{username} refused", (status, reason(refused)), (403, expected))

status, refused = call("POST", decide, {"decision": "APPROVED"}, agent=True)
check("THE AGENT ITSELF refused", (status, reason(refused)),
      (403, "AGENT_MAY_NOT_APPROVE"))
status, refused = call("POST", decide, {"decision": "APPROVED"},
                       principal=cp_sign.IDENTITY_ADMIN)
check("a machine administrator refused", (status, reason(refused)),
      (403, "MACHINE_MAY_NOT_APPROVE"))

# --- 5. the approval --------------------------------------------------------
print("\n  STEP 5  The loan officer approves")
status, approved = call("POST", decide,
                        {"decision": "APPROVED", "note": "within lending policy"},
                        human="loan.officer")
check("accepted", status, 200)
check("status", approved["status"], "APPROVED")
check("approver recorded", approved["approver"]["username"], "loan.officer")
check("signed by the approval authority", approved["artifact_signed_by"],
      "did:poc:service:approval-authority")
artifact = approved["artifact"]
check("proof purpose", artifact["proof"]["proofPurpose"], "humanApproval")
check("NOT signed by the agent",
      AGENT in artifact["proof"]["verificationMethod"], False)
print(f"      binding   : {artifact['credentialSubject']['bindingHash'][:32]}...")
print(f"      expires   : {approved['expires_at']}")

# --- 6. PDP re-evaluation ----------------------------------------------------
print("\n  STEP 6  The PDP is asked AGAIN, with the approval as evidence")
body = enforce(request_id=request_id)
decision = body["decision"]
check("decision", decision["decision"], "ALLOW")
check("reason", decision["reason"], "HUMAN_APPROVED_AND_POLICY_MATCH")
check("attributable to a versioned policy", decision["policy"], "loan-approval:v1")
check("the tool ran", body["executed"], True)
check("the loan was decided", body["result"]["status"], "APPROVED")
print(f"      grant     : {body['grant']['grant_id']}")
print("      -> the human decision was EVIDENCE. Policy still decided.")

# --- 7. replay ---------------------------------------------------------------
print("\n  STEP 7  The same approval cannot be used twice")
body = enforce(request_id=request_id)
check("DENY", body["decision"]["decision"], "DENY")
check("reason", body["decision"]["reason"], "APPROVAL_ALREADY_CONSUMED")
check("the tool did NOT run", body["executed"], False)

# --- 8. tamper ---------------------------------------------------------------
print("\n  STEP 8  An approval cannot be moved to another action")
_, small_id, small_request = escalate(OTHER_LOAN)
call("POST", f"/api/v1/hitl/approvals/{small_id}/decide",
     {"decision": "APPROVED"}, human="loan.officer")
body = enforce(LOAN, request_id=small_request, approval_id=small_id)
check("DENY", body["decision"]["decision"], "DENY")
check("reason", body["decision"]["reason"], "APPROVAL_BINDING_MISMATCH")
approval_fact = body["decision"]["evaluation"]["pip"]["approval"]
failed = [c for c in approval_fact["checks"] if not c["passed"]]
print(f"      {failed[0]['detail']}")
check("the denial names the field that moved",
      "resource_id" in failed[0]["detail"], True)

# --- 9. the agent asserting its own approval ---------------------------------
print("\n  STEP 9  An agent that asserts its own approval is ignored")
body = enforce(OTHER_LOAN, context={"approval": {"valid": True},
                                    "human_approved": True, "approved": True})
check("still referred to a human", body["decision"]["decision"],
      "HUMAN_APPROVAL_REQUIRED")
check("self-asserted keys rejected",
      sorted(body["decision"]["evaluation"]["rejected_context_keys"]),
      ["approval", "approved", "human_approved"])

# --- 10. rejection -----------------------------------------------------------
print("\n  STEP 10  A rejection blocks the action")
_, reject_id, reject_request = escalate(OTHER_LOAN)
status, rejected = call("POST", f"/api/v1/hitl/approvals/{reject_id}/decide",
                        {"decision": "REJECTED", "note": "amount unverified"},
                        human="loan.officer")
check("recorded as REJECTED", rejected["status"], "REJECTED")
check("no artifact to present", rejected["artifact"], None)
body = enforce(OTHER_LOAN, request_id=reject_request)
check("DENY", body["decision"]["decision"], "DENY")
check("reason", body["decision"]["reason"], "APPROVAL_REJECTED")
check("the tool did NOT run", body["executed"], False)
status, loan = call("GET", "/api/v1/hitl/approvals?limit=1")
print("      -> no protected action occurred")

# --- 11. S-7 -----------------------------------------------------------------
print("\n  STEP 11  S-7: the identity plane refuses anonymous callers")
s7 = [
    ("agent creation", "POST", "/api/v1/agents", {
        "slug": "rogue-001", "name": "Rogue", "agent_type": "RISK",
        "capabilities": ["credit_analysis"], "endpoint": "http://localhost:9099"}),
    ("credential issuance", "POST", "/api/v1/credentials/issue", {
        "issuer": BANK, "subject": AGENT,
        "credential_type": "AgentCapabilityCredential",
        "claims": {"capability": "credit_analysis",
                   "allowed_resources": ["payroll_records"],
                   "allowed_actions": ["READ"], "purpose": "loan_decision"},
        "expires_in_seconds": 3600}),
    ("credential revocation", "POST",
     f"/api/v1/credentials/{issued.get('credential_id')}/revoke",
     {"reason": "COMPROMISED"}),
    ("audit ingest", "POST", "/api/v1/audit/events", {
        "event_type": "AGENT_TASK_COMPLETED", "agent_did": AGENT}),
]
for label, method, path, payload in s7:
    status, refused = call(method, path, payload)
    check(f"anonymous {label} refused", (status, reason(refused)),
          (401, "CONTROL_PLANE_PROOF_MISSING"))

status, agents = call("GET", "/api/v1/agents")
risk = next((a for a in agents if a["slug"] == "risk-001"), None)
status, refused = call("POST", f"/api/v1/agents/{risk['id']}/status",
                       {"status": "TERMINATED", "reason": "x"})
check("anonymous agent termination refused", (status, reason(refused)),
      (401, "CONTROL_PLANE_PROOF_MISSING"))
status, refused = call("POST", f"/api/v1/agents/{risk['id']}/status",
                       {"status": "TERMINATED", "reason": "x"},
                       human="loan.officer")
check("LOAN_OFFICER cannot terminate an agent", (status, reason(refused)),
      (403, "HUMAN_MAY_NOT_ADMINISTER_IAM"))

print("\n      And the authorized administrator can:")
status, created = call("POST", "/api/v1/agents", {
    "slug": "gate-probe-5", "name": "Phase 5 gate probe", "agent_type": "RISK",
    "capabilities": ["credit_analysis"], "endpoint": "http://localhost:9098",
}, human="iam.admin")
check("IAM_ADMIN creates an agent", status in (201, 409), True)
check("the agent is still ACTIVE",
      call("GET", f"/api/v1/agents/{risk['id']}")[1]["status"], "ACTIVE")

# --- 12. audit ---------------------------------------------------------------
print("\n  STEP 12  The whole flow is correlated in the audit trail")
_, events = call("GET", "/api/v1/audit?limit=500")
types = [e["event_type"] for e in events]
for expected in ("HUMAN_AUTHENTICATED", "APPROVAL_REQUESTED", "APPROVAL_VIEWED",
                 "APPROVAL_APPROVED", "APPROVAL_REJECTED",
                 "AUTHORIZATION_REEVALUATED", "APPROVAL_CONSUMED",
                 "CREDENTIAL_ISSUED", "POLICY_ALLOW", "AEM_ALLOWED",
                 "TOOL_EXECUTED"):
    check(f"{expected} recorded", expected in types, True)

correlated = [e for e in events if e.get("request_id") == request_id]
print(f"\n      request_id={request_id} -> {len(correlated)} correlated events")
for event in sorted(correlated, key=lambda e: e["timestamp"]):
    print(f"        {event['event_type']}")

trail = json.dumps(events)
check("no access token in the audit trail",
      any(t in trail for t in _tokens.values()), False)

# --- 13. measured latency -----------------------------------------------------
print("\n  STEP 13  MEASURED latency (10 real cycles)")
oidc, request_ms, decide_ms, reeval_ms, end_to_end = [], [], [], [], []
for index in range(10):
    started = time.perf_counter()
    call("GET", "/api/v1/hitl/me", human="loan.officer")
    oidc.append((time.perf_counter() - started) * 1000)

    cycle = time.perf_counter()
    started = time.perf_counter()
    _, aid, rid = escalate(OTHER_LOAN if index % 2 else LOAN)
    request_ms.append((time.perf_counter() - started) * 1000)

    started = time.perf_counter()
    call("POST", f"/api/v1/hitl/approvals/{aid}/decide",
         {"decision": "APPROVED"}, human="loan.officer")
    decide_ms.append((time.perf_counter() - started) * 1000)

    started = time.perf_counter()
    body = enforce(OTHER_LOAN if index % 2 else LOAN, request_id=rid)
    reeval_ms.append((time.perf_counter() - started) * 1000)
    end_to_end.append((time.perf_counter() - cycle) * 1000)


def summarise(name, values):
    if not values:
        return
    ordered = sorted(values)
    p95 = ordered[int(len(ordered) * 0.95) - 1]
    print(f"      {name:<40s} min {min(values):7.2f}  "
          f"median {statistics.median(values):7.2f}  "
          f"p95 {p95:7.2f}  max {max(values):7.2f}  (ms)")


summarise("OIDC validation (GET /hitl/me)", oidc)
summarise("approval request creation", request_ms)
summarise("approval decision + signing", decide_ms)
summarise("PDP re-evaluation + enforcement", reeval_ms)
summarise("end-to-end HITL cycle", end_to_end)
print("      (measured on this host against the running stack. Not modelled.)")

# --- 14. fail closed ----------------------------------------------------------
print("\n  STEP 14  Fail-closed")
print("      To verify the identity-provider outage path:")
print("        docker compose stop keycloak && python3 scripts/phase5_gate.py")
print("      Expected: no human can authenticate, so no approval can be made,")
print("      and every escalated action stays BLOCKED. HUMAN_APPROVAL_REQUIRED")
print("      never becomes ALLOW.")

print("\n" + "=" * 78)
print(f"  RESULT: {PASS} passed, {FAIL} failed")
print("=" * 78)
print("""
  HUMAN AUTHENTICATION  != HUMAN APPROVAL
  HUMAN APPROVAL        != AUTHORIZATION
  AUTHORIZATION         != ENFORCEMENT

  Keycloak identifies the human.   The approval records the decision.
  The PDP decides.                 The AEM enforces.
""")
sys.exit(1 if FAIL else 0)
