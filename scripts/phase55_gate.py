#!/usr/bin/env python3
"""Phase 5.5 gate: HITL security hardening, against the live system.

Proves, against a running API, a running OPA and a running KEYCLOAK, that:

  * the AMOUNT is an authorization input, read server-side, and POLICY decides
    what it means -- three amounts, three different outcomes, one credential
  * a small loan proceeds on the agent's own authority     (scenario A)
  * a mid-value loan needs ONE authorized loan officer     (scenario B)
  * a high-value loan needs TWO DISTINCT humans            (scenario C)
  * an amount changed after a person approved it INVALIDATES the approval
  * the same human cannot satisfy both halves of dual control
  * the officer who submitted an application cannot sign it off
  * the approval-signing key ROTATES without invalidating history, and a
    retired key cannot issue anything new
  * every negative in spec section 25 is refused, by name
  * the thresholds are POLICY CONFIGURATION, and removing them fails CLOSED

Latency numbers printed here are MEASURED from real calls. Nothing is modelled.

Usage:
    docker compose up -d postgres redis opa keycloak
    scripts/run_local.sh
    python3 scripts/phase55_gate.py
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
AGENT = "did:poc:agent:risk-001"

# The three scenarios. The AMOUNTS live in the resource records and the
# THRESHOLDS live in policy configuration, so nothing here names a limit --
# these are applications, and the outcome is whatever policy reaches.
AUTONOMOUS = "loan-2201"      # Rs 5,00,000
SINGLE = "loan-7842"          # Rs 25,00,000
DUAL = "loan-9001"            # Rs 2,00,00,000
SELF_SUBMITTED = "loan-5150"  # submitted_by: loan.officer

HUMANS = {
    "loan.officer": "loan-officer-demo",
    "loan.officer.2": "loan-officer-2-demo",
    "iam.admin": "iam-admin-demo",
    "auditor": "auditor-demo",
    "no.roles": "no-roles-demo",
}

PASS, FAIL = 0, 0
_tokens: dict[str, str] = {}


def token(username: str) -> str:
    if username in _tokens:
        return _tokens[username]
    data = urllib.parse.urlencode({
        "client_id": get_settings().oidc_client_id, "grant_type": "password",
        "username": username, "password": HUMANS[username], "scope": "openid",
    }).encode()
    try:
        with urllib.request.urlopen(KEYCLOAK, data, timeout=15) as response:
            _tokens[username] = json.loads(response.read())["access_token"]
    except urllib.error.HTTPError as exc:
        print(f"\n  KEYCLOAK REFUSED a token for {username!r}: HTTP {exc.code}")
        if username == "loan.officer.2":
            print("  Phase 5.5 adds a SECOND loan officer, because dual control")
            print("  cannot be demonstrated with one account. Re-import the realm:")
            print("    docker compose down keycloak && docker compose up -d keycloak")
        sys.exit(2)
    except urllib.error.URLError as exc:
        print(f"\n  CANNOT REACH KEYCLOAK at {KEYCLOAK}: {exc}")
        print("  Start it with:  docker compose up -d keycloak")
        sys.exit(2)
    return _tokens[username]


def agent_headers(method: str, path: str, body):
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
    print(f"      [{'PASS' if ok else 'FAIL'}]  {label:<56s} {detail}")


def reason(body):
    detail = body.get("detail") if isinstance(body, dict) else None
    return detail.get("reason") if isinstance(detail, dict) else None


def enforce(application_id, *, request_id=None, approval_id=None, did=AGENT,
            context=None):
    body = {"subject": {"did": did}, "tool": "approve_loan_application",
            "arguments": {"application_id": application_id},
            "purpose": "loan_decision"}
    if request_id:
        body["request_id"] = request_id
    if approval_id:
        body["approval_id"] = approval_id
    if context is not None:
        body["context"] = context
    return call("POST", "/api/v1/enforce", body, principal=cp_sign.GATEWAY)[1]


def escalate(application_id):
    body = enforce(application_id)
    request = (body.get("decision", {}).get("evaluation", {})
               .get("approval_request") or {})
    return body, request.get("approval_id"), request.get("retry_with_request_id")


def decide(approval_id, username, decision="APPROVED"):
    return call("POST", f"/api/v1/hitl/approvals/{approval_id}/decide",
                {"decision": decision}, human=username)


def set_amount(application_id, amount, *, principal=None, human=None):
    """Restate the amount on a loan, the way an upstream system would.

    Over HTTP, through the SAME control-plane guard as every other mutation.
    Doing it in this process instead would have changed nothing in the running
    API -- and a tamper the server never saw proves nothing about the server.

    `loan_amend` is held by exactly one machine principal and by no human role,
    so this is also the negative test: a loan officer who could restate an
    amount and then approve it would have defeated the amount policy and
    maker-checker in one move.
    """
    return call("POST", f"/api/v1/loans/{application_id}/amount",
                {"amount_inr": amount, "reason": "phase 5.5 gate"},
                principal=principal if human is None else None, human=human)


print("=" * 78)
print("  PHASE 5.5 GATE - HITL SECURITY HARDENING")
print("=" * 78)

# --- 0. environment ---------------------------------------------------------
print("\n  STEP 0  The live system, and the two people dual control needs")
status, health = call("GET", "/api/v1/hitl/health")
check("HITL health reachable", status, 200)
check("identity provider available", health["identity_provider"]["available"], True)
check("approval authority present", health["approval_authority"]["present"], True)

for username in HUMANS:
    status, me = call("GET", "/api/v1/hitl/me", human=username)
    check(f"{username} authenticates", status, 200)
    print(f"        {username:<16s} {str(me.get('roles')):<24s} {me.get('subject')}")

officers = [call("GET", "/api/v1/hitl/me", human=u)[1]["subject"]
            for u in ("loan.officer", "loan.officer.2")]
check("the two loan officers are DIFFERENT people",
      officers[0] != officers[1], True)

# --- 1. the amount is policy configuration ----------------------------------
print("\n  STEP 1  The thresholds are policy CONFIGURATION, loaded into OPA")
status, policy_health = call("GET", "/api/v1/policies")
loaded = {p["policy_id"] for p in policy_health.get("policies", [])}
check("loan-amount policy is loaded", "loan-amount" in loaded, True)
data_rows = {d["data_id"]: d for d in policy_health.get("data", [])}
check("threshold configuration is in the engine",
      data_rows.get("loan-amount-policy", {}).get("in_engine"), True)
check("configuration matches the repository",
      data_rows.get("loan-amount-policy", {}).get("source_drift"), False)
config = json.loads(
    (REPO / "policies" / "data" / "loan_amount_policy.json").read_text())
thresholds = config["thresholds"]
print(f"      agent autonomous limit : Rs {thresholds['agent_autonomous_limit_inr']:,}")
print(f"      single approver limit  : Rs {thresholds['single_approver_limit_inr']:,}")
print("      (no threshold appears anywhere in Python; the PIP supplies the")
print("       amount and Rego decides what it means)")

# --- 2. the agent is credentialled ------------------------------------------
print("\n  STEP 2  The agent holds a credential scoped to loan applications")
status, issued = call("POST", "/api/v1/credentials/issue", {
    "issuer": "did:poc:organization:bank-demo", "subject": AGENT,
    "credential_type": "AgentCapabilityCredential",
    "claims": {"capability": "credit_analysis",
               "allowed_actions": ["APPROVE_LOAN"],
               "allowed_resources": ["loan_applications"],
               "purpose": "loan_decision"},
    "expires_in_seconds": 3600,
}, principal=cp_sign.IDENTITY_ADMIN)
check("credential issued to the agent", status, 201)

# --- 3. SCENARIO A ----------------------------------------------------------
print("\n  SCENARIO A  Rs 5,00,000 -- below the autonomous limit")
print("      Risk Agent -> PDP -> ALLOW.  No human is asked.")
body = enforce(AUTONOMOUS)
check("decision", body["decision"]["decision"], "ALLOW")
check("reason", body["decision"]["reason"], "WITHIN_AGENT_APPROVAL_AUTHORITY")
check("policy", body["decision"]["policy"], "loan-amount:v1")
check("the tool executed", body["executed"], True)
check("no approval was opened",
      body["decision"]["evaluation"].get("approval_request"), None)
amount = (body["decision"]["evaluation"]["pip"]["resource"]["attributes"])
check("the amount reached policy from the server", amount["amount_inr"], 500_000)

# --- 4. SCENARIO B ----------------------------------------------------------
print("\n  SCENARIO B  Rs 25,00,000 -- one authorized loan officer")
print("      Risk Agent -> PDP -> HUMAN_APPROVAL_REQUIRED -> Keycloak")
print("      -> Loan Officer -> Approve -> PDP -> ALLOW")
body, approval_b, request_b = escalate(SINGLE)
check("decision", body["decision"]["decision"], "HUMAN_APPROVAL_REQUIRED")
check("reason", body["decision"]["reason"], "SENSITIVE_ACTION_REQUIRES_HUMAN")
check("one approver required",
      body["decision"]["evaluation"]["approval_request"]["required_approvals"], 1)
check("blocked", body["executed"], False)

status, screen = call("GET", f"/api/v1/hitl/approvals/{approval_b}",
                      human="loan.officer")
detail = screen["presentation"]["resource"]["detail"]
print(f"      the human is shown  : {detail['amount']}  ({detail['applicant']})")
check("the screen states how many approvers",
      screen["presentation"]["approval"]["required_approvals"], 1)

status, decided = decide(approval_b, "loan.officer")
check("loan officer may approve", status, 200)
check("approval completes with one sign-off", decided["status"], "APPROVED")
check("the artifact binds the amount",
      decided["binding"]["amount_inr"], 2_500_000)

body = enforce(SINGLE, request_id=request_b)
check("PDP re-evaluated to ALLOW", body["decision"]["decision"], "ALLOW")
check("the tool executed", body["executed"], True)

# --- 5. SCENARIO C ----------------------------------------------------------
print("\n  SCENARIO C  Rs 2,00,00,000 -- two distinct humans")
print("      Risk Agent -> PDP -> DUAL_APPROVAL_REQUIRED")
print("      -> Officer A -> Officer B -> PDP -> ALLOW")
body, approval_c, request_c = escalate(DUAL)
check("decision", body["decision"]["decision"], "HUMAN_APPROVAL_REQUIRED")
check("reason", body["decision"]["reason"], "DUAL_APPROVAL_REQUIRED")
check("two approvers required",
      body["decision"]["evaluation"]["approval_request"]["required_approvals"], 2)

status, first = decide(approval_c, "loan.officer")
check("officer A signs off", status, 200)
check("still PENDING after one of two", first["status"], "PENDING")
check("one of two recorded", first["approvals_recorded"], 1)
check("nothing is signed yet", first["artifact"], None)

body = enforce(DUAL, request_id=request_c)
check("one approval does not release the action", body["executed"], False)
check("still escalated", body["decision"]["reason"], "DUAL_APPROVAL_REQUIRED")

status, second = decide(approval_c, "loan.officer.2")
check("officer B signs off", status, 200)
check("approval completes", second["status"], "APPROVED")
check("two sign-offs recorded", second["approvals_recorded"], 2)
signers = [s["username"] for s in second["signoffs"]]
check("both officers named in order", signers, ["loan.officer", "loan.officer.2"])
artifact_approvers = second["artifact"]["credentialSubject"]["approvers"]
check("the SIGNED artifact names both", len(artifact_approvers), 2)
check("the artifact records the requirement",
      second["artifact"]["credentialSubject"]["requiredApprovals"], 2)

body = enforce(DUAL, request_id=request_c)
check("PDP re-evaluated to ALLOW", body["decision"]["decision"], "ALLOW")
check("the tool executed", body["executed"], True)

# ===========================================================================
#  NEGATIVE DEMONSTRATIONS (spec section 25)
# ===========================================================================
print("\n  NEGATIVES  Every one of these must be refused, by name")

# 1 -- wrong role
body, approval_n, request_n = escalate(SINGLE)
for username in ("iam.admin", "auditor", "no.roles"):
    status, refusal = decide(approval_n, username)
    check(f"wrong role: {username} may not approve", reason(refusal),
          "HUMAN_MAY_NOT_APPROVE_THIS")

# 2 -- an agent, and a machine administrator
status, refusal = call("POST", f"/api/v1/hitl/approvals/{approval_n}/decide",
                       {"decision": "APPROVED"}, agent=True)
check("the agent may not approve its own action", reason(refusal),
      "AGENT_MAY_NOT_APPROVE")
status, refusal = call("POST", f"/api/v1/hitl/approvals/{approval_n}/decide",
                       {"decision": "APPROVED"}, principal=cp_sign.IDENTITY_ADMIN)
check("a machine administrator may not approve", reason(refusal),
      "MACHINE_MAY_NOT_APPROVE")

# 3 -- self approval
_, approval_self, _ = escalate(SELF_SUBMITTED)
status, refusal = decide(approval_self, "loan.officer")
check("self-approval by the submitting officer", reason(refusal),
      "SELF_APPROVAL_PROHIBITED")
status, allowed = decide(approval_self, "loan.officer.2")
check("...but a DIFFERENT officer may sign it off", allowed.get("status"),
      "APPROVED")

# 4 -- the same human twice
_, approval_same, _ = escalate(DUAL)
decide(approval_same, "loan.officer")
status, refusal = decide(approval_same, "loan.officer")
check("the same human cannot satisfy both approvals", reason(refusal),
      "APPROVER_ALREADY_SIGNED")

# 5 -- tampered amount
_, approval_t, request_t = escalate(SINGLE)
status, decided = decide(approval_t, "loan.officer")
approved_amount = decided["binding"]["amount_inr"]
status, amended = set_amount(SINGLE, 25_000_000, principal=cp_sign.CORE_BANKING)
check("the amendment is authorized and audited", status, 200)
body = enforce(SINGLE, request_id=request_t)
check("tampered amount denies", body["decision"]["decision"], "DENY")
check("...by name", body["decision"]["reason"], "APPROVAL_BINDING_MISMATCH")
check("...and the resource was NOT touched", body["executed"], False)
checks = body["decision"]["evaluation"]["pip"]["approval"]["checks"]
binding_check = next(c for c in checks if c["name"] == "binding")
check("...naming the field that moved", "amount_inr" in binding_check["detail"], True)
print(f"      approved at Rs {approved_amount:,}, presented at Rs 25,000,000")

# ...and no human, and no other machine principal, may restate an amount.
for username in ("loan.officer", "iam.admin"):
    status, refusal = set_amount(SINGLE, 1, human=username)
    check(f"{username} may not restate a loan amount", reason(refusal),
          "HUMAN_MAY_NOT_PERFORM_MACHINE_OPERATION")
status, refusal = set_amount(SINGLE, 1, principal=cp_sign.IDENTITY_ADMIN)
check("the identity administrator may not either", reason(refusal),
      "MISSING_CONTROL_PLANE_ROLE")
status, refusal = call("POST", f"/api/v1/loans/{SINGLE}/amount",
                       {"amount_inr": 1})
check("an anonymous caller may not either", status, 401)

set_amount(SINGLE, 2_500_000, principal=cp_sign.CORE_BANKING)

# 6 -- tampered resource
_, approval_r, request_r = escalate(SINGLE)
decide(approval_r, "loan.officer")
body = enforce("loan-1001", request_id=request_r, approval_id=approval_r)
check("an approval moved to another loan", body["decision"]["decision"], "DENY")
check("...and nothing executed", body["executed"], False)

# 7 -- wrong agent
body = enforce(SINGLE, request_id=request_r, approval_id=approval_r,
               did="did:poc:agent:fraud-001")
check("another agent cannot use it", body["executed"], False)

# 8 -- replay
_, approval_p, request_p = escalate(SINGLE)
decide(approval_p, "loan.officer")
first_use = enforce(SINGLE, request_id=request_p)
check("the approval is spent once", first_use["executed"], True)
replay = enforce(SINGLE, request_id=request_p, approval_id=approval_p)
check("replayed approval denies", replay["decision"]["reason"],
      "APPROVAL_ALREADY_CONSUMED")

# 9 -- a rejection
_, approval_x, request_x = escalate(SINGLE)
decide(approval_x, "loan.officer", "REJECTED")
body = enforce(SINGLE, request_id=request_x)
check("a rejection blocks", body["decision"]["reason"], "APPROVAL_REJECTED")
check("...and the resource was NOT touched", body["executed"], False)

# 10 -- a self-asserted amount
_, approval_c2, request_c2 = escalate(DUAL)
body = enforce(DUAL, request_id=request_c2,
               context={"amount_inr": 1, "approved": True, "allow": True})
check("a caller cannot talk its own amount down",
      body["decision"]["reason"], "DUAL_APPROVAL_REQUIRED")
rejected = body["decision"]["evaluation"]["rejected_context_keys"]
check("self-asserted decision keys are stripped and recorded",
      sorted(rejected), ["allow", "approved"])

# ===========================================================================
#  KEY ROTATION (spec sections 8-10)
# ===========================================================================
print("\n  KEY ROTATION  History stays verifiable; a retired key issues nothing")

status, register = call("GET", "/api/v1/hitl/authority/keys")
check("the key register is readable", status, 200)
before_generation = register["active"]["generation"]
check("no private key is exposed", register["active"]["private_key"],
      "NEVER EXPOSED - held by the KeyStore")

# An artifact signed by the CURRENT key.
_, approval_k, request_k = escalate(SINGLE)
status, before = decide(approval_k, "loan.officer")
key_before = before["artifact"]["proof"]["verificationMethod"]
check("artifact A signed by the active key",
      key_before.endswith(f"#key-{before_generation}"), True)

# No human may rotate it.
for username in ("iam.admin", "loan.officer"):
    status, refusal = call("POST", "/api/v1/hitl/authority/keys/rotate",
                           {"reason": "attempt"}, human=username)
    check(f"{username} may not rotate the signing key", reason(refusal),
          "HUMAN_MAY_NOT_PERFORM_MACHINE_OPERATION")
status, refusal = call("POST", "/api/v1/hitl/authority/keys/rotate",
                       {"reason": "anonymous"})
check("an anonymous caller may not rotate it", status, 401)

status, rotated = call("POST", "/api/v1/hitl/authority/keys/rotate",
                       {"reason": "phase 5.5 gate"}, principal=cp_sign.IDENTITY_ADMIN)
check("the identity administrator may rotate", status, 200)
check("a new generation is active",
      rotated["active"]["generation"], before_generation + 1)
check("the outgoing key is RETIRED", rotated["retired"]["status"], "RETIRED")
print(f"      retired {rotated['retired']['kid']}")
print(f"      active  {rotated['active']['kid']}")

# Artifact A must STILL verify, and be usable.
body = enforce(SINGLE, request_id=request_k)
check("artifact A still verifies after rotation",
      body["decision"]["decision"], "ALLOW")
check("...and the action executed", body["executed"], True)

# A new artifact is signed by the NEW key.
_, approval_k2, request_k2 = escalate("loan-1001")
status, after = decide(approval_k2, "loan.officer")
key_after = after["artifact"]["proof"]["verificationMethod"]
check("artifact B signed by the NEW key", key_after != key_before, True)
body = enforce("loan-1001", request_id=request_k2)
check("artifact B verifies", body["decision"]["decision"], "ALLOW")

status, register = call("GET", "/api/v1/hitl/authority/keys")
check("both generations are published", len(register["keys"]),
      before_generation + 1)
check("exactly one key is ACTIVE",
      len([k for k in register["keys"] if k["status"] == "ACTIVE"]), 1)

# ===========================================================================
#  AUDIT
# ===========================================================================
print("\n  AUDIT  The dual-control cycle, correlated by one request id")
status, events = call("GET", f"/api/v1/audit?limit=800")
types = {e["event_type"] for e in events}
for required in ("APPROVAL_REQUESTED", "POLICY_ESCALATED", "APPROVAL_VIEWED",
                 "APPROVAL_SIGNOFF_RECORDED", "APPROVAL_APPROVED",
                 "APPROVAL_REJECTED", "APPROVAL_DUAL_CONTROL_SATISFIED",
                 "APPROVAL_CONSUMED", "APPROVAL_REPLAY_REJECTED",
                 "AUTHORIZATION_REEVALUATED", "APPROVAL_KEY_ROTATED",
                 "LOAN_AMOUNT_AMENDED", "AEM_ALLOWED", "TOOL_EXECUTED"):
    check(f"audited: {required}", required in types, True)

# The separation-of-duties refusals are audited by the CONTROL PLANE, because
# policy refuses them before the approval service is ever reached. That is the
# right place: the request never became a decision.
denials = {e["reason"] for e in events if e["event_type"] == "CONTROL_PLANE_DENIED"}
for required in ("SELF_APPROVAL_PROHIBITED", "APPROVER_ALREADY_SIGNED",
                 "HUMAN_MAY_NOT_APPROVE_THIS", "AGENT_MAY_NOT_APPROVE",
                 "MACHINE_MAY_NOT_APPROVE"):
    check(f"audited refusal: {required}", required in denials, True)

correlated = [e for e in events if e.get("request_id") == request_c]
check("the scenario C cycle is correlated by one request id",
      len(correlated) >= 8, True)
print(f"      {len(correlated)} events share request_id {request_c}")

escalations = [e for e in events if e["event_type"] == "POLICY_ESCALATED"]
dual = [e for e in escalations if e["metadata"].get("required_approvals") == 2]
check("the escalation records WHY two people were needed", bool(dual), True)
if dual:
    print(f"      tier={dual[0]['metadata']['tier']} "
          f"amount={dual[0]['metadata']['amount_inr']}")

rotations = [e for e in events if e["event_type"] == "APPROVAL_KEY_ROTATED"]
check("rotation is audited without exposing the key",
      rotations[0]["metadata"]["private_key_exposed"] if rotations else None, False)

raw = json.dumps(events)
check("no bearer token appears in the trail",
      token("loan.officer") not in raw, True)

# ===========================================================================
#  LIVE TRACE
# ===========================================================================
print("\n  LIVE TRACE  The dual-control cycle, in order")
# Ordered by the audit trail's MONOTONIC cursor. Sorting on the timestamp is
# not enough: `occurred_at` defaults to the database clock, which is
# transaction-start, so several events written in one transaction share a
# timestamp exactly -- and a trace whose steps are out of order is worse than
# no trace at all.
trace = sorted(
    (e for e in events if e.get("request_id") == request_c),
    key=lambda e: e["seq"],
)
LABEL = {
    "AEM_INTERCEPT":            ("ENFORCEMENT",   "-> intercepted"),
    "AUTHORIZATION_REQUESTED":  ("AGENT",         "-> identity presented"),
    "PIP_CONTEXT_COLLECTED":    ("CREDENTIAL",    "credential verified"),
    "OPA_DECISION":             ("AUTHORIZATION", "-> policy evaluated"),
    "POLICY_HUMAN_APPROVAL_REQUIRED": ("AUTHORIZATION", "!! HUMAN APPROVAL REQUIRED"),
    "POLICY_ESCALATED":         ("AUTHORIZATION", "!! escalated"),
    "APPROVAL_REQUESTED":       ("HUMAN",         "-> approval opened"),
    "APPROVAL_VIEWED":          ("HUMAN",         "-> approval viewed"),
    "APPROVAL_SIGNOFF_RECORDED": ("HUMAN",        "ok sign-off"),
    "APPROVAL_APPROVED":        ("HUMAN",         "ok approved"),
    "APPROVAL_DUAL_CONTROL_SATISFIED": ("AUTHORIZATION", "ok dual approval satisfied"),
    "AUTHORIZATION_REEVALUATED": ("AUTHORIZATION", "-> PDP re-evaluation"),
    "POLICY_ALLOW":             ("AUTHORIZATION", "ok ALLOW"),
    "APPROVAL_CONSUMED":        ("HUMAN",         "ok approval spent"),
    "AEM_ALLOWED":              ("ENFORCEMENT",   "ok action permitted"),
    "TOOL_EXECUTED":            ("ENFORCEMENT",   "ok action executed"),
}
for event in trace:
    stage, note = LABEL.get(event["event_type"], ("", event["event_type"]))
    who = (event["metadata"].get("approver_username")
           or event["metadata"].get("viewer_username") or "")
    print(f"      {stage:<14s} {note:<32s} {who}")

# ===========================================================================
#  PERFORMANCE -- measured, not modelled
# ===========================================================================
print("\n  PERFORMANCE  10 real cycles on this host")
oidc, request_ms, decide_ms, reeval_ms, end_to_end = [], [], [], [], []
dual_ms = []

for index in range(10):
    started = time.perf_counter()
    call("GET", "/api/v1/hitl/me", human="loan.officer")
    oidc.append((time.perf_counter() - started) * 1000)

    cycle = time.perf_counter()
    started = time.perf_counter()
    _, approval_id, request_id = escalate(SINGLE)
    request_ms.append((time.perf_counter() - started) * 1000)

    started = time.perf_counter()
    decide(approval_id, "loan.officer")
    decide_ms.append((time.perf_counter() - started) * 1000)

    started = time.perf_counter()
    enforce(SINGLE, request_id=request_id)
    reeval_ms.append((time.perf_counter() - started) * 1000)
    end_to_end.append((time.perf_counter() - cycle) * 1000)

for index in range(5):
    cycle = time.perf_counter()
    _, approval_id, request_id = escalate(DUAL)
    decide(approval_id, "loan.officer")
    decide(approval_id, "loan.officer.2")
    enforce(DUAL, request_id=request_id)
    dual_ms.append((time.perf_counter() - cycle) * 1000)


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
summarise("end-to-end single-approval cycle", end_to_end)
summarise("end-to-end DUAL-control cycle", dual_ms)
print("      (measured on this host against the running stack. Not modelled.)")

# ===========================================================================
#  FAIL CLOSED
# ===========================================================================
print("\n  FAIL-CLOSED  Verified paths, and how to reproduce the rest")
print("      Removing the threshold configuration from the engine makes every")
print("      loan decision DENY with LOAN_POLICY_UNCONFIGURED. An unconfigured")
print("      limit is never 'no limit'. Covered by")
print("      tests/test_loan_amount_policy.py, which genuinely removes it from")
print("      the running OPA and restores it.")
print("      Identity-provider outage:  docker compose stop keycloak")
print("      Expected: no human can authenticate, no approval can be made, and")
print("      every escalated action stays BLOCKED.")

print("\n" + "=" * 78)
print(f"  RESULT: {PASS} passed, {FAIL} failed")
print("=" * 78)
print("""
  THE AMOUNT IS AN AUTHORIZATION INPUT, not a display value.
  TWO PEOPLE MEANS TWO PEOPLE -- one human signing twice is not dual control.
  MAKER != CHECKER.
  A KEY CAN ROTATE without invalidating what it already signed.

  Policy decides.  The database arbitrates.  The AEM enforces.
""")
sys.exit(1 if FAIL else 0)
