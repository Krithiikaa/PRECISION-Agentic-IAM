"""End-to-end loan workflow against the RUNNING multi-process system.

The blueprint journey, with every hop real:

    loan officer --Keycloak--> IAM API (Rego: LOAN_OFFICER may submit)
    coordinator agent (own key) --AEM--> claims the workflow
    coordinator --ANS--> discovers each specialist by capability
    coordinator --signed instruction--> specialist process
    specialist (own key) --AEM/PDP--> SIMULATED adapter
    decision agent --AEM--> policy escalates by amount --> human approval
    coordinator --AEM--> records the outcome and the customer message

Scenarios:
    A  small clean loan                  approved by the agent within its band
    B  adverse findings                  declined; no approval is even sought
    C  large loan                        paused for a human; the SUBMITTING officer
                                         is refused (maker-checker); a second
                                         officer approves; the workflow resumes
    D  large loan, human rejects         declined
    E  specialist contained mid-service  workflow FAILS at that step; reinstated
                                         by a DIFFERENT principal; recovers
    F  negative access                   anonymous and agent submissions refused
    G  audit                             every step is in the trail under the
                                         workflow's request ids

Requires: scripts/run_local.sh, scripts/seed_credentials.py, Keycloak.
Usage:    python3 scripts/loan_workflow_e2e.py
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cp_sign                                                      # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))
os.environ.setdefault("AGENT_KEYSTORE_DIR", str(REPO / "backend" / ".keystore-agents"))

from app.controlplane.client import canonical_body, control_plane_headers  # noqa: E402
from app.core.config import get_settings                                   # noqa: E402
from app.identity.keys import EncryptedFileKeyStore                        # noqa: E402
from app.identity.signer import Signer                                     # noqa: E402

API = "http://localhost:8000"
KEYCLOAK = get_settings().oidc_token_url
HUMANS = {"loan.officer": "loan-officer-demo", "loan.officer.2": "loan-officer-2-demo",
          "iam.admin": "iam-admin-demo", "auditor": "auditor-demo"}
DOCS = [{"type": t, "content": f"{t} scan"} for t in
        ("IDENTITY_PROOF", "INCOME_PROOF", "ADDRESS_PROOF")]
PASS, FAIL = 0, 0
_tokens: dict[str, str] = {}


def token(username):
    if username not in _tokens:
        data = urllib.parse.urlencode({
            "client_id": get_settings().oidc_client_id, "grant_type": "password",
            "username": username, "password": HUMANS[username], "scope": "openid"}).encode()
        try:
            with urllib.request.urlopen(KEYCLOAK, data, timeout=15) as response:
                _tokens[username] = json.loads(response.read())["access_token"]
        except (urllib.error.URLError, OSError) as exc:
            print(f"  CANNOT GET A KEYCLOAK TOKEN for {username}: {exc}")
            sys.exit(2)
    return _tokens[username]


def call(method, path, body=None, *, human=None, principal=None, agent=None):
    if principal:
        data, headers = cp_sign.signed(principal, method, path.split("?", 1)[0], body)
    elif agent:
        slug = agent.split(":")[-1]
        keystore = EncryptedFileKeyStore(os.path.join(os.environ["AGENT_KEYSTORE_DIR"], slug),
                                         get_settings().keystore_master_key)
        data = canonical_body(body)
        headers = control_plane_headers(Signer(keystore), principal_did=agent,
                                        kid=f"{agent}#key-1", method=method,
                                        path=path, body=data)
        headers["Content-Type"] = "application/json"
    else:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
    if human:
        headers["Authorization"] = f"Bearer {token(human)}"
    request = urllib.request.Request(API + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.loads(response.read() or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw.decode()[:300]}


def check(label, actual, expected):
    global PASS, FAIL
    ok = actual == expected
    PASS += ok
    FAIL += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + ("" if ok else
          f"\n         expected {expected!r}, got {actual!r}"))
    return ok


def submit(officer="loan.officer", **overrides):
    body = {"customer_id": "customer-007", "applicant_name": "E2E Applicant",
            "amount_inr": 400_000, "term_months": 36, "declared_monthly_income_inr": 150_000,
            "documents": DOCS, **overrides}
    status, created = call("POST", "/api/v1/loan-workflows", body, human=officer)
    if status != 201:
        print(f"  submission failed: HTTP {status} {created}")
        sys.exit(1)
    return created


def wait_for(workflow_id, statuses, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, workflow = call("GET", f"/api/v1/loan-workflows/{workflow_id}", human="auditor")
        if workflow.get("status") in statuses:
            return workflow
        time.sleep(1.5)
    return workflow


def specialist_dids(workflow):
    return {s["step"]: s.get("agent_did") for s in workflow.get("steps", [])}


print("\nA. Small clean loan: approved by the decision agent within its own band")
started = time.time()
a = submit()
done = wait_for(a["workflow_id"], {"APPROVED", "DECLINED", "FAILED"})
elapsed = time.time() - started
check("workflow APPROVED", done.get("status"), "APPROVED")
dids = specialist_dids(done)
check("KYC done by kyc-001", dids.get("kyc"), "did:poc:agent:kyc-001")
check("risk assessment by risk-002", dids.get("risk_assessment"), "did:poc:agent:risk-002")
check("documents by docs-001", dids.get("document_verification"), "did:poc:agent:docs-001")
check("fraud by fraud-001", dids.get("fraud_detection"), "did:poc:agent:fraud-001")
check("decision by decision-001", dids.get("decision"), "did:poc:agent:decision-001")
check("credit analysis by a credit_analysis agent",
      (dids.get("credit_analysis") or "").startswith("did:poc:agent:risk-00"), True)
check("every step executed through the AEM",
      all(s.get("executed") for s in done.get("steps", [])), True)
check("coordinator received findings, not records (no balance field)",
      "total_balance_gbp" in json.dumps(done.get("steps")), False)
check("application status APPROVED", (done.get("application") or {}).get("status"), "APPROVED")
check("customer told", "approved" in done.get("customer_message", ""), True)
print(f"        end-to-end: {elapsed:.1f}s across 7 agent processes")

print("\nB. Adverse findings (sanctions hit, HIGH fraud): declined, no approval sought")
b = wait_for(submit(customer_id="customer-666")["workflow_id"], {"APPROVED", "DECLINED", "FAILED"})
check("workflow DECLINED", b.get("status"), "DECLINED")
check("decision agent never asked", "decision" in specialist_dids(b), False)

print("\nC. Large loan: paused for a human; maker-checker; second officer approves")
c = submit(amount_inr=2_500_000, declared_monthly_income_inr=900_000)
paused = wait_for(c["workflow_id"], {"AWAITING_APPROVAL", "APPROVED", "DECLINED", "FAILED"})
check("workflow AWAITING_APPROVAL", paused.get("status"), "AWAITING_APPROVAL")
approval_id = (paused.get("approval") or {}).get("approval_id")
check("an approval request exists", bool(approval_id), True)
status, refusal = call("POST", f"/api/v1/hitl/approvals/{approval_id}/decide",
                       {"decision": "APPROVED"}, human="loan.officer")
check("submitting officer may NOT approve (maker-checker)", status, 403)
status, _ = call("POST", f"/api/v1/hitl/approvals/{approval_id}/decide",
                 {"decision": "APPROVED"}, human="loan.officer.2")
check("second officer approves", status, 200)
resumed = wait_for(c["workflow_id"], {"APPROVED", "DECLINED", "FAILED"}, timeout=60)
check("workflow resumes and is APPROVED", resumed.get("status"), "APPROVED")

print("\nD. Large loan, human rejects: declined")
d = submit(amount_inr=2_600_000, declared_monthly_income_inr=900_000)
paused = wait_for(d["workflow_id"], {"AWAITING_APPROVAL", "APPROVED", "DECLINED", "FAILED"})
rid = (paused.get("approval") or {}).get("approval_id")
call("POST", f"/api/v1/hitl/approvals/{rid}/decide", {"decision": "REJECTED"},
     human="loan.officer.2")
rejected = wait_for(d["workflow_id"], {"APPROVED", "DECLINED", "FAILED"}, timeout=60)
check("workflow DECLINED after rejection", rejected.get("status"), "DECLINED")

print("\nE. Fraud specialist contained: the workflow fails at that step, then recovers")
status, incident = call("POST", "/api/v1/security/incidents", {
    "agent_did": "did:poc:agent:fraud-001",
    "justification": "E2E: simulated compromise of the fraud specialist"},
    principal=cp_sign.IDENTITY_ADMIN)
check("contained", status, 201)
check("containment did not touch other agents",
      (incident.get("unaffected_active_agents") or 0) >= 8, True)
print(f"        containment took {incident.get('containment_ms')} ms; "
      f"SSS push: {incident.get('sss_push')}")
push = (incident.get("sss_push") or [{}])[0]
check("SSS push delivered to every agent runtime", (push.get("subscribers") or 0) >= 9, True)
time.sleep(1)
with urllib.request.urlopen("http://localhost:9004/health", timeout=5) as response:
    fraud_health = json.loads(response.read())
check("the contained agent knows it is locked out (local fast-fail)",
      (fraud_health.get("sessions") or {}).get("self_locked_out"), True)
e = wait_for(submit()["workflow_id"], {"APPROVED", "DECLINED", "FAILED"})
check("workflow FAILED", e.get("status"), "FAILED")
check("...at fraud_detection", (e.get("decision") or {}).get("failed_step"), "fraud_detection")
status, _ = call("POST", f"/api/v1/security/incidents/{incident.get('incident_id')}/reinstate",
                 {"review": "E2E: compromise was simulated; agent verified clean."},
                 principal=cp_sign.IDENTITY_ADMIN)
check("the containing principal may NOT reinstate (separation of duties)", status, 409)
status, _ = call("POST", f"/api/v1/security/incidents/{incident.get('incident_id')}/reinstate",
                 {"review": "E2E: compromise was simulated; agent verified clean."},
                 human="iam.admin")
check("a different principal reinstates", status, 200)
deadline, recovered = time.time() + 60, None
while time.time() < deadline:
    recovered = wait_for(submit()["workflow_id"], {"APPROVED", "DECLINED", "FAILED"})
    if recovered.get("status") == "APPROVED":
        break
    time.sleep(5)
check("after the agent re-registers, workflows succeed again",
      (recovered or {}).get("status"), "APPROVED")

print("\nF. Negative access")
status, _ = call("POST", "/api/v1/loan-workflows", {"customer_id": "customer-007"})
check("anonymous submission refused", status, 401)
status, _ = call("POST", "/api/v1/loan-workflows", {
    "customer_id": "customer-007", "applicant_name": "X", "amount_inr": 1, "term_months": 12,
    "declared_monthly_income_inr": 1}, agent="did:poc:agent:risk-001")
check("an agent may not submit", status, 403)
status, _ = call("POST", "/api/v1/loan-workflows", {
    "customer_id": "customer-007", "applicant_name": "X", "amount_inr": 1, "term_months": 12,
    "declared_monthly_income_inr": 1}, human="auditor")
check("an auditor may not submit", status, 403)

print("\nG. Audit trail")
status, events = call("GET", f"/api/v1/audit?request_id={a['workflow_id']}-kyc&limit=50",
                      human="auditor")
types = {e["event_type"] for e in (events if isinstance(events, list) else [])}
check("KYC step intercepted by the AEM", "AEM_INTERCEPT" in types, True)
check("KYC step executed", "TOOL_EXECUTED" in types, True)

print(f"\n  {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
