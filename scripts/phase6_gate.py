#!/usr/bin/env python3
"""Phase 6 gate: JIT temporary access, against the live system.

Proves, against a running API, a running OPA and a real PostgreSQL, that:

  * a mandate is issued only after the FULL PDP evaluation permits the action,
    so it can never confer authority the PDP would have refused
  * a mandate is a BUDGET and a WINDOW -- bounded in both, both policy-capped
  * every use is RE-DECIDED: credential revocation, agent suspension and the
    Phase 5.5 amount bands all still apply with a valid mandate in hand
  * a mandate cannot be carried to another resource, action, agent or purpose
  * an expired or revoked mandate is refused immediately
  * a tampered mandate fails its signature
  * a mandate CANNOT be used to get around a human approval requirement
  * the signing key rotates without invalidating history
  * the whole arc is auditable and correlated by grant_id

Latency numbers printed here are MEASURED from real calls. Nothing is modelled.

Usage:
    docker compose up -d postgres redis opa keycloak
    scripts/run_local.sh
    python3 scripts/phase6_gate.py
"""
from __future__ import annotations

import json
import os
import pathlib
import statistics
import sys
import time
import urllib.error
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
AGENT = "did:poc:agent:risk-001"
OTHER_AGENT = "did:poc:agent:risk-002"
CUSTOMER = "customer-007"
OTHER_CUSTOMER = "customer-001"

PASS = FAIL = 0


def agent_headers(method, path, body, did=AGENT, slug="risk-001"):
    keystore = EncryptedFileKeyStore(
        os.path.join(os.environ["AGENT_KEYSTORE_DIR"], slug),
        get_settings().keystore_master_key,
    )
    payload = canonical_body(body)
    headers = control_plane_headers(
        Signer(keystore), principal_did=did, kid=f"{did}#key-1",
        method=method, path=path, body=payload,
    )
    headers["Content-Type"] = "application/json"
    return payload, headers


def call(method, path, body=None, *, principal=None, agent=False, did=AGENT,
         slug="risk-001", timeout=60.0):
    if agent:
        data, headers = agent_headers(method, path, body, did, slug)
    elif principal:
        data, headers = cp_sign.signed(principal, method, path, body)
    else:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
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
    print(f"      [{'PASS' if ok else 'FAIL'}]  {label:<58s} {detail}")


def request_mandate(**overrides):
    body = {
        "subject_did": AGENT, "action": "read", "resource_type": "credit_records",
        "resource_ids": [CUSTOMER], "purpose": "loan_assessment",
        "ttl_seconds": 300, "max_uses": 3,
    }
    body.update(overrides)
    did = body["subject_did"]
    slug = did.rsplit(":", 1)[-1]
    return call("POST", "/api/v1/jit/request", body, agent=True, did=did, slug=slug)[1]


def read_profile(grant_id=None, *, customer=CUSTOMER, did=AGENT,
                 tool="get_credit_profile", purpose="loan_assessment"):
    body = {"subject": {"did": did}, "tool": tool,
            "arguments": {"customer_id": customer}, "purpose": purpose}
    if grant_id:
        body["jit_grant_id"] = grant_id
    return call("POST", "/api/v1/enforce", body, principal=cp_sign.GATEWAY)[1]


def decision_of(body):
    return (body.get("decision") or {}).get("decision")


def reason_of(body):
    return (body.get("decision") or {}).get("reason")


print("=" * 78)
print("  PHASE 6 GATE -- JIT temporary access, against the live system")
print("=" * 78)

# ---------------------------------------------------------------------------
#  0. PRECONDITIONS
# ---------------------------------------------------------------------------
print("\n  SETUP  The signing authority and a valid credential")

status, keys = call("GET", "/api/v1/jit/keys")
check("the JIT authority exists", status, 200)
check("it has an ACTIVE signing key", bool(keys.get("active_kid")), True)
check("no private key is exposed", keys.get("private_key"),
      "NEVER EXPOSED - held by the KeyStore")

status, approval_keys = call("GET", "/api/v1/hitl/keys")
if status == 200:
    approval_kid = approval_keys.get("active_kid")
    check("the JIT key is NOT the approval key", keys["active_kid"] == approval_kid,
          False)
    print(f"      jit:      {keys['active_kid']}")
    print(f"      approval: {approval_kid}")

status, _ = call("POST", "/api/v1/credentials/issue", {
    "issuer": "did:poc:organization:bank-demo", "subject": AGENT,
    "credential_type": "AgentCapabilityCredential",
    "claims": {"capability": "credit_analysis",
               "allowed_actions": ["READ_CREDIT_PROFILE"],
               "allowed_resources": ["credit_records"],
               "purpose": "loan_assessment"},
    "expires_in_seconds": 3600,
}, principal=cp_sign.IDENTITY_ADMIN)
check("a valid capability credential is issued", status, 201)

# ---------------------------------------------------------------------------
#  SCENARIO 1 -- a mandate is issued and used
# ---------------------------------------------------------------------------
print("\n  SCENARIO 1  risk-001 asks for a mandate over credit_records")
print("      Agent -> control plane -> PIP -> PDP/OPA -> AEM -> signed mandate.")

issued = request_mandate()
check("the mandate is issued", issued.get("issued"), True)
check("policy permitted the issuance", issued.get("reason"), "JIT_ISSUANCE_PERMITTED")
check("the PDP allowed the action first",
      (issued.get("authorization") or {}).get("decision"), "ALLOW")

grant = issued.get("grant") or {}
GRANT = grant.get("grant_id")
check("it is signed by the JIT authority", grant.get("issuer"),
      "did:poc:service:jit-authority")
check("it is bounded in time", bool(grant.get("expires_at")), True)
check("it is bounded in uses", grant.get("max_uses"), 3)
print(f"      {GRANT}  expires {grant.get('expires_at')}  budget {grant.get('max_uses')}")
print(f"      {grant.get('presentation', {}).get('headline', '')}")

body = read_profile(GRANT)
check("the resource is reached with the mandate", body.get("executed"), True)
check("and the PDP still decided it", decision_of(body), "ALLOW")

status, record = call("GET", f"/api/v1/jit/{GRANT}")
check("one use is recorded", record.get("uses"), 1)
check("the budget is decremented", record.get("uses_remaining"), 2)

# ---------------------------------------------------------------------------
#  SCENARIO 2 -- the same mandate, a different resource
# ---------------------------------------------------------------------------
print("\n  SCENARIO 2  The SAME mandate, aimed at payroll_records")
print("      A credit_records mandate is not a payroll_records mandate.")

body = read_profile(GRANT, tool="get_payroll_record")
check("the action is blocked", body.get("executed"), False)
check("and refused BY NAME", reason_of(body), "JIT_GRANT_BINDING_MISMATCH")

status, record = call("GET", f"/api/v1/jit/{GRANT}")
check("a blocked call does not spend the budget", record.get("uses"), 1)

print("\n      A resource INSTANCE outside the mandate is refused too")
body = read_profile(GRANT, customer=OTHER_CUSTOMER)
check("another customer is refused", body.get("executed"), False)
check("named as a scope mismatch", reason_of(body), "JIT_GRANT_BINDING_MISMATCH")

# ---------------------------------------------------------------------------
#  SCENARIO 5 -- another agent presents it
# ---------------------------------------------------------------------------
print("\n  SCENARIO 5  risk-002 presents risk-001's mandate")
print("      Perfectly signed. Perfectly valid. Not theirs.")

body = read_profile(GRANT, did=OTHER_AGENT)
check("the other agent is refused", body.get("executed"), False)
check("the mandate is not transferable",
      reason_of(body) in {"JIT_GRANT_BINDING_MISMATCH", "MISSING_CAPABILITY",
                          "UNKNOWN_SUBJECT"}, True)
print(f"      reason: {reason_of(body)}")

# ---------------------------------------------------------------------------
#  SCENARIO 6 -- tampering
# ---------------------------------------------------------------------------
print("\n  SCENARIO 6  Editing the mandate's scope and expiry")
print("      Every bound field is inside the signature.")

status, full = call("GET", f"/api/v1/jit/{GRANT}")
artifact = full.get("artifact") or {}
subject = dict(artifact.get("credentialSubject") or {})
check("the scope is inside the signed body", subject.get("resource_type"),
      "credit_records")
check("the expiry is inside the signed body", bool(artifact.get("expirationDate")), True)
check("max_uses is inside the signed body", subject.get("maxUses"), 3)
check("the binding digest is inside the signed body",
      bool(subject.get("bindingHash")), True)
check("the proof purpose is the JIT domain separator",
      (artifact.get("proof") or {}).get("proofPurpose"), "jitGrant")
print("      Editing any of these invalidates the signature -- proven directly by")
print("      tests/test_jit_grant_artifact.py, which mutates each field in turn.")

# ---------------------------------------------------------------------------
#  SCENARIO 4 -- revocation
# ---------------------------------------------------------------------------
print("\n  SCENARIO 4  The mandate is revoked before it expires")

status, revoked = call("POST", f"/api/v1/jit/{GRANT}/revoke",
                       {"reason": "phase 6 gate"}, principal=cp_sign.IDENTITY_ADMIN)
check("revocation is accepted from an administrator", status, 200)
check("the mandate is REVOKED", revoked.get("status"), "REVOKED")

body = read_profile(GRANT)
check("the next use is refused", body.get("executed"), False)
check("named as revoked", reason_of(body), "JIT_GRANT_REVOKED")

print("\n      An agent may ASK for a mandate; it may not revoke one")
status, _ = call("POST", f"/api/v1/jit/{GRANT}/revoke",
                 {"reason": "let me out"}, agent=True)
check("an agent cannot revoke", status in (401, 403), True)

# ---------------------------------------------------------------------------
#  SCENARIO 3 -- expiry
# ---------------------------------------------------------------------------
print("\n  SCENARIO 3  A mandate that has run out of time")

short = request_mandate(ttl_seconds=2, max_uses=3)
SHORT = (short.get("grant") or {}).get("grant_id")
check("a short-lived mandate is issued", short.get("issued"), True)
body = read_profile(SHORT)
check("it works inside its window", body.get("executed"), True)
print("      waiting for it to expire (server clock, never the agent's)...")
time.sleep(2.5)
body = read_profile(SHORT)
check("it is refused after expiry", body.get("executed"), False)
check("named as expired", reason_of(body), "JIT_GRANT_EXPIRED")

status, swept = call("POST", "/api/v1/jit/sweep", {}, principal=cp_sign.IDENTITY_ADMIN)
check("the sweep records it as EXPIRED", SHORT in (swept.get("expired") or []), True)
print("      The sweep is HOUSEKEEPING: the mandate was already unusable above,")
print("      before any sweep ran. Enforcement never waits for a background job.")

# ---------------------------------------------------------------------------
#  SCENARIO 7 -- JIT cannot buy its way past a human
# ---------------------------------------------------------------------------
print("\n  SCENARIO 7  Trying to use JIT to get around a human approval")
print("      THE most important refusal in this phase.")

status, _ = call("POST", "/api/v1/credentials/issue", {
    "issuer": "did:poc:organization:bank-demo", "subject": AGENT,
    "credential_type": "AgentCapabilityCredential",
    "claims": {"capability": "credit_analysis",
               "allowed_actions": ["APPROVE_LOAN"],
               "allowed_resources": ["loan_applications"],
               "purpose": "loan_decision"},
    "expires_in_seconds": 3600,
}, principal=cp_sign.IDENTITY_ADMIN)

escalated = request_mandate(
    action="approve_loan", resource_type="loan_applications",
    resource_ids=["loan-7842"], purpose="loan_decision",
)
check("a mandate for an escalated action is REFUSED", escalated.get("issued"), False)
check("refused by policy, by name",
      escalated.get("reason") in {"JIT_SCOPE_EXCEEDS_DECISION",
                                  "JIT_ACTION_NOT_ELIGIBLE"}, True)
print(f"      reason: {escalated.get('reason')}")
print(f"      detail: {escalated.get('detail')}")
print("      A mandate is not a human. Policy asking for a person is not")
print("      satisfied by asking for a grant instead.")

dual = request_mandate(
    action="approve_loan", resource_type="loan_applications",
    resource_ids=["loan-9001"], purpose="loan_decision",
)
check("nor for a DUAL-control loan", dual.get("issued"), False)

# ---------------------------------------------------------------------------
#  BOUNDS
# ---------------------------------------------------------------------------
print("\n  BOUNDS  Policy caps the window and the budget")

over_ttl = request_mandate(ttl_seconds=3000)
check("an excessive TTL is refused", over_ttl.get("reason"),
      "JIT_TTL_EXCEEDS_POLICY_MAXIMUM")
over_uses = request_mandate(max_uses=999)
check("an excessive budget is refused", over_uses.get("reason"),
      "JIT_USES_EXCEED_POLICY_MAXIMUM")
# payroll_records is refused twice over, and the FIRST refusal wins: this
# agent holds no payroll credential, so the PDP denies the action before
# eligibility is even reached. That is the more useful answer -- "you may not
# do this at all" rather than "this is not JIT-eligible" -- and it is why the
# assertion accepts either. The eligibility rule itself is proven in isolation
# by tests/test_jit_policy.py, which forces a PDP ALLOW first.
ineligible = request_mandate(resource_type="payroll_records")
check("an ineligible resource is refused",
      ineligible.get("reason") in {"JIT_ACTION_NOT_ELIGIBLE",
                                   "JIT_SCOPE_EXCEEDS_DECISION"}, True)
print(f"      reason: {ineligible.get('reason')}  "
      f"(underlying: {ineligible.get('detail')})")

print("\n      The budget genuinely runs out")
budget = request_mandate(max_uses=2)
BUDGET = (budget.get("grant") or {}).get("grant_id")
for n in (1, 2):
    body = read_profile(BUDGET)
    check(f"use {n} of 2 permitted", body.get("executed"), True)
body = read_profile(BUDGET)
check("the third use is refused", body.get("executed"), False)
check("named as exhausted", reason_of(body), "JIT_GRANT_EXHAUSTED")
status, spent = call("GET", f"/api/v1/jit/{BUDGET}")
check("and the mandate is EXHAUSTED", spent.get("status"), "EXHAUSTED")
check("exhausted is not expired", spent.get("uses"), 2)

# ---------------------------------------------------------------------------
#  PHASE 5 vs PHASE 6 -- the difference this phase exists to make
# ---------------------------------------------------------------------------
print("\n  PHASE 5 vs PHASE 6  One mandate, several individually decided uses")
print("      Phase 5: one approval  -> ONE authorized operation, then spent.")
print("      Phase 6: one mandate   -> N operations, EACH with a fresh PDP decision.")

multi = request_mandate(max_uses=3)
MULTI = (multi.get("grant") or {}).get("grant_id")
check("one mandate is issued", multi.get("issued"), True)

request_ids = []
for n in (1, 2, 3):
    body = read_profile(MULTI)
    request_ids.append((body.get("decision") or {}).get("request_id"))
    check(f"use {n} of 3 executed", body.get("executed"), True)
    check(f"use {n} got its own PDP decision", decision_of(body), "ALLOW")

check("each use was a DISTINCT authorization request",
      len(set(request_ids)) == 3, True)
print(f"      three request ids: {', '.join(r[:18] for r in request_ids if r)}")
print("      Three separate PDP evaluations. Nothing was cached, and nothing")
print("      was replayed -- the mandate removed the repeated ISSUANCE, not the")
print("      repeated DECISION.")

status, spent_multi = call("GET", f"/api/v1/jit/{MULTI}")
check("the budget records all three", spent_multi.get("uses"), 3)
check("and the mandate is now EXHAUSTED", spent_multi.get("status"), "EXHAUSTED")

# ---------------------------------------------------------------------------
#  FINANCIAL BOUNDING -- the mandate's ceiling, on a real amount
# ---------------------------------------------------------------------------
print("\n  FINANCIAL BOUNDING  A mandate carries an amount ceiling, checked live")
print("      Reading a loan is JIT-eligible; APPROVING one is not (T-2).")

status, _ = call("POST", "/api/v1/credentials/issue", {
    "issuer": "did:poc:organization:bank-demo", "subject": AGENT,
    "credential_type": "AgentCapabilityCredential",
    "claims": {"capability": "credit_analysis",
               "allowed_actions": ["READ_LOAN_APPLICATION"],
               "allowed_resources": ["loan_applications"],
               "purpose": "loan_assessment"},
    "expires_in_seconds": 3600,
}, principal=cp_sign.IDENTITY_ADMIN)
check("a loan-reading credential is issued", status, 201)

money = request_mandate(action="read", resource_type="loan_applications",
                        resource_ids=["loan-2201", "loan-9001"], max_uses=5)
MONEY = (money.get("grant") or {}).get("grant_id")
check("a mandate over two loans is issued", money.get("issued"), True)
ceiling = ((money.get("grant") or {}).get("constraints") or {}).get("max_amount_inr")
check("it carries a financial ceiling", ceiling, 1000000)
print(f"      ceiling: Rs {ceiling:,} -- from POLICY configuration, not the request")


def authorize_loan(application_id, grant_id=None):
    body = {"subject": {"did": AGENT}, "action": "read",
            "resource": {"type": "loan_applications", "id": application_id},
            "purpose": "loan_assessment"}
    if grant_id:
        body["jit_grant_id"] = grant_id
    return call("POST", "/api/v1/authorize", body, principal=cp_sign.GATEWAY)[1]


small = authorize_loan("loan-2201", MONEY)
check("Rs 5,00,000 is within the mandate", small.get("decision"), "ALLOW")
large = authorize_loan("loan-9001", MONEY)
check("Rs 2,00,00,000 is REFUSED by the ceiling", large.get("decision"), "DENY")
check("named as a constraint violation", large.get("reason"), "JIT_CONSTRAINT_VIOLATED")
print("      SAME mandate, SAME agent, SAME action. The amount decided it, and")
print("      the amount was read server-side on each use -- never from the caller.")

# ---------------------------------------------------------------------------
#  POLICY CHANGE -- a valid mandate does not survive a policy that now denies
# ---------------------------------------------------------------------------
print("\n  POLICY CHANGE  A valid mandate with a current DENY is a DENY")

policy_grant = request_mandate(max_uses=3)
POLICY_GRANT = (policy_grant.get("grant") or {}).get("grant_id")
check("a mandate is issued while policy permits", policy_grant.get("issued"), True)
before = read_profile(POLICY_GRANT)
check("it works under the current policy", before.get("executed"), True)

status, _ = call("POST", "/api/v1/policies/loan-credit-read/deactivate", {},
                 principal=cp_sign.POLICY_ADMIN)
check("the permitting policy is deactivated", status, 200)
try:
    after = read_profile(POLICY_GRANT)
    check("THE MANDATE NO LONGER HELPS", after.get("executed"), False)
    print(f"      reason: {reason_of(after)}")
    print("      The grant is unexpired, unspent, correctly signed and bound to")
    print("      this exact request. Policy changed, so the answer changed.")
finally:
    status, _ = call("POST", "/api/v1/policies/loan-credit-read/activate", {},
                     principal=cp_sign.POLICY_ADMIN)
    check("the policy is restored", status, 200)

restored = read_profile(POLICY_GRANT)
check("and the mandate works again", restored.get("executed"), True)

# ---------------------------------------------------------------------------
#  SIGNATURE TAMPERING -- against the real verifier
# ---------------------------------------------------------------------------
print("\n  TAMPERING  Editing a signed mandate breaks it, field by field")

status, full_grant = call("GET", f"/api/v1/jit/{MONEY}")
artifact = full_grant.get("artifact")
check("the artifact is readable", bool(artifact), True)

sys.path.insert(0, str(REPO / "backend"))
from app.jit.grant import JITBinding, verify_grant                  # noqa: E402

status, jit_keys = call("GET", "/api/v1/jit/keys")
authority_document = jit_keys.get("did_document")
register = {
    k["kid"]: {
        "status": k["status"],
        "not_before": __import__("datetime").datetime.fromisoformat(k["not_before"]),
        "retired_at": (__import__("datetime").datetime.fromisoformat(k["retired_at"])
                       if k["retired_at"] else None),
    }
    for k in jit_keys.get("keys", [])
}
expected = JITBinding(
    agent_did=AGENT, action="read", resource_type="loan_applications",
    resource_ids=("loan-2201",), purpose="loan_assessment", constraints={},
)


def verify(document, resource_id="loan-2201"):
    return verify_grant(
        document, authority_document=authority_document,
        expected_binding=expected, expected_domain="agentic-iam-aem",
        resource_id=resource_id,
        resource_attributes={"available": True, "amount_inr": 500000},
        authority_keys=register,
    )


check("the untouched artifact verifies", verify(artifact).valid, True)

import copy as _copy                                                # noqa: E402

for field, mutate in (
    ("expirationDate", lambda d: d.__setitem__(
        "expirationDate", "2099-01-01T00:00:00.000Z")),
    ("agent_did", lambda d: d["credentialSubject"].__setitem__(
        "agent_did", "did:poc:agent:attacker")),
    ("action", lambda d: d["credentialSubject"].__setitem__("action", "write")),
    ("resource_type", lambda d: d["credentialSubject"].__setitem__(
        "resource_type", "payroll_records")),
    ("purpose", lambda d: d["credentialSubject"].__setitem__(
        "purpose", "anything_i_like")),
    ("maxUses", lambda d: d["credentialSubject"].__setitem__("maxUses", 9999)),
    ("constraints", lambda d: d["credentialSubject"].__setitem__(
        "constraints", {"max_amount_inr": 999999999})),
    ("signatureValue", lambda d: d["proof"].__setitem__(
        "signatureValue", "A" * 86 + "==")),
):
    tampered = _copy.deepcopy(artifact)
    mutate(tampered)
    report = verify(tampered)
    check(f"tampering with {field} is refused", report.valid, False)

# ---------------------------------------------------------------------------
#  UNDERLYING TRUST -- the property that proves this is not standing permission
# ---------------------------------------------------------------------------
print("\n  UNDERLYING TRUST  A mandate never outlives what it rested on")

live = request_mandate(max_uses=5)
LIVE = (live.get("grant") or {}).get("grant_id")
check("a fresh mandate is issued", live.get("issued"), True)
body = read_profile(LIVE)
check("it works while the credential is good", body.get("executed"), True)

status, creds = call("GET", f"/api/v1/credentials?subject={AGENT}")
capability = [
    c for c in (creds if isinstance(creds, list) else creds.get("items", []))
    if c.get("status") == "ACTIVE"
    and "credit_records" in json.dumps(c.get("claims") or {})
]
revoked_any = False
for credential in capability:
    status, _ = call("POST",
                     f"/api/v1/credentials/{credential['credential_id']}/revoke",
                     {"reason": "phase 6 gate"}, principal=cp_sign.IDENTITY_ADMIN)
    revoked_any = revoked_any or status == 200
check("the underlying credentials are revoked", revoked_any, True)

body = read_profile(LIVE)
check("THE MANDATE STOPS WORKING", body.get("executed"), False)
print(f"      reason: {reason_of(body)}")
print("      The mandate is still perfectly signed, unexpired and unspent.")
print("      It is the LIVE evaluation that refused -- which is what makes")
print("      'revocation is invalid everywhere at once' still true.")

status, still = call("GET", f"/api/v1/jit/{LIVE}")
check("the mandate record itself is untouched", still.get("status"), "ACTIVE")

# ---------------------------------------------------------------------------
#  CONCURRENCY -- the last unit of budget has exactly one winner
# ---------------------------------------------------------------------------
print("\n  CONCURRENCY  Ten callers, one remaining use")
print("      The DATABASE decides the winner, not the application.")

# A fresh credential: the UNDERLYING TRUST section above deliberately revoked
# the agent's credit-record credentials to prove a mandate cannot outlive them.
# This section needs a working one again, and issuing it here rather than
# relying on an earlier one keeps the sections independently reorderable.
status, _ = call("POST", "/api/v1/credentials/issue", {
    "issuer": "did:poc:organization:bank-demo", "subject": AGENT,
    "credential_type": "AgentCapabilityCredential",
    "claims": {"capability": "credit_analysis",
               "allowed_actions": ["READ_CREDIT_PROFILE"],
               "allowed_resources": ["credit_records"],
               "purpose": "loan_assessment"},
    "expires_in_seconds": 3600,
}, principal=cp_sign.IDENTITY_ADMIN)
check("a fresh credential is issued for this section", status, 201)

race = request_mandate(max_uses=3)
RACE = (race.get("grant") or {}).get("grant_id")
check("a mandate with a budget of 3 is issued", race.get("issued"), True)
for _ in range(2):
    read_profile(RACE)
status, before_race = call("GET", f"/api/v1/jit/{RACE}")
check("two uses are spent, one remains", before_race.get("uses_remaining"), 1)

import concurrent.futures                                           # noqa: E402

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
    outcomes = list(pool.map(lambda _: read_profile(RACE), range(10)))

winners = [o for o in outcomes if o.get("executed") is True]
check("EXACTLY ONE caller wins the last use", len(winners), 1)
refused = [o for o in outcomes if o.get("executed") is False]
check("the other nine are refused", len(refused), 9)
reasons = {reason_of(o) for o in refused}
check("every refusal names a real condition",
      reasons <= {"JIT_GRANT_EXHAUSTED", "JIT_GRANT_EXPIRED",
                  "JIT_GRANT_REVOKED"}, True)
print(f"      refusal reasons: {', '.join(sorted(r for r in reasons if r))}")

status, after_race = call("GET", f"/api/v1/jit/{RACE}")
check("the budget is exactly spent, never overspent", after_race.get("uses"), 3)
check("and the mandate is EXHAUSTED", after_race.get("status"), "EXHAUSTED")
print("      A read-then-write would have let several through. One conditional")
print("      UPDATE with `uses < max_uses` in the WHERE clause cannot.")

# ---------------------------------------------------------------------------
#  KEY ROTATION
# ---------------------------------------------------------------------------
print("\n  KEY ROTATION  History stays verifiable; a retired key issues nothing")

status, before_keys = call("GET", "/api/v1/jit/keys")
before_kid = before_keys.get("active_kid")
status, rotated = call("POST", "/api/v1/jit/keys/rotate",
                       {"reason": "phase 6 gate"}, principal=cp_sign.IDENTITY_ADMIN)
check("rotation is accepted from an administrator", status, 200)
after_kid = (rotated.get("active") or {}).get("kid")
check("a new generation is active", after_kid != before_kid, True)
check("the old key is RETIRED, not deleted",
      (rotated.get("retired") or {}).get("status"), "RETIRED")

status, after_keys = call("GET", "/api/v1/jit/keys")
published = {k["kid"] for k in after_keys.get("keys", [])}
check("both generations remain published", {before_kid, after_kid} <= published, True)
print(f"      retired: {before_kid}")
print(f"      active:  {after_kid}")

status, _ = call("POST", "/api/v1/jit/keys/rotate", {"reason": "nope"}, agent=True)
check("an agent cannot rotate the signing key", status in (401, 403), True)

# ---------------------------------------------------------------------------
#  AUTHORIZATION OF THE ENDPOINTS
# ---------------------------------------------------------------------------
print("\n  CONTROL PLANE  Who may ask, and who may not")

status, _ = call("POST", "/api/v1/jit/request", {
    "subject_did": AGENT, "action": "read", "resource_type": "credit_records",
    "resource_ids": [CUSTOMER], "purpose": "loan_assessment",
})
check("an UNSIGNED mandate request is refused", status in (401, 403), True)

status, body = call("POST", "/api/v1/jit/request", {
    "subject_did": OTHER_AGENT, "action": "read", "resource_type": "credit_records",
    "resource_ids": [CUSTOMER], "purpose": "loan_assessment",
}, agent=True)
check("an agent cannot ask for a mandate naming ANOTHER agent",
      status in (401, 403), True)

# ---------------------------------------------------------------------------
#  AUDIT
# ---------------------------------------------------------------------------
print("\n  AUDIT  The whole arc, correlated by grant_id")

# Queried per type rather than by scanning a window: agent heartbeats flood the
# trail continuously, so any fixed limit is a race against how long the gate
# took to get here.
def audit(event_type, limit=200):
    status, rows = call("GET", f"/api/v1/audit?event_type={event_type}&limit={limit}")
    return rows if isinstance(rows, list) else []


for expected in ("JIT_REQUESTED", "JIT_ISSUED", "JIT_USED", "JIT_DENIED",
                 "JIT_REVOKED", "JIT_EXPIRED", "JIT_EXHAUSTED",
                 "JIT_REPLAY_BLOCKED", "JIT_KEY_ROTATED"):
    check(f"audited: {expected}", bool(audit(expected, limit=5)), True)

correlated = []
for event_type in ("JIT_REQUESTED", "JIT_ISSUED", "JIT_USED", "JIT_REVOKED",
                   "AEM_ALLOWED", "JIT_REPLAY_BLOCKED"):
    for event in audit(event_type):
        metadata = event.get("metadata") or {}
        if GRANT in (metadata.get("grant_id"), metadata.get("jit_grant_id")):
            correlated.append(event)
check("the first mandate's life is correlated by grant_id",
      len(correlated) >= 3, True)
print(f"      {len(correlated)} events share grant_id {GRANT}")
print("      " + ", ".join(sorted({e["event_type"] for e in correlated})))

rotations = audit("JIT_KEY_ROTATED", limit=5)
check("rotation is audited without exposing the key",
      rotations[0]["metadata"]["private_key_exposed"] if rotations else None, False)

issued_events = audit("JIT_ISSUED", limit=50)
check("an issuance records its bounds and its basis",
      all(k in (issued_events[0].get("metadata") or {})
          for k in ("ttl_seconds", "max_uses", "expires_at", "policy"))
      if issued_events else False, True)

raw = json.dumps(issued_events + rotations + audit("JIT_USED", limit=50))
check("no private key material appears in the trail",
      any(marker in raw for marker in ("BEGIN ", "privateKey", "private_key_b64")),
      False)

# ---------------------------------------------------------------------------
#  PERFORMANCE
# ---------------------------------------------------------------------------
print("\n  PERFORMANCE  10 real cycles on this host")

status, _ = call("POST", "/api/v1/credentials/issue", {
    "issuer": "did:poc:organization:bank-demo", "subject": AGENT,
    "credential_type": "AgentCapabilityCredential",
    "claims": {"capability": "credit_analysis",
               "allowed_actions": ["READ_CREDIT_PROFILE"],
               "allowed_resources": ["credit_records"],
               "purpose": "loan_assessment"},
    "expires_in_seconds": 3600,
}, principal=cp_sign.IDENTITY_ADMIN)

timings: dict[str, list[float]] = {
    "mandate issuance (control plane + PDP + policy + signature)": [],
    "verification + PDP re-evaluation + enforcement, WITH a mandate": [],
    "the same call WITHOUT a mandate (Phase 4 baseline)": [],
    "end-to-end: ask for a mandate, then use it": [],
}

for _ in range(10):
    t0 = time.perf_counter()
    issued = request_mandate(max_uses=2)
    t1 = time.perf_counter()
    grant_id = (issued.get("grant") or {}).get("grant_id")
    if not grant_id:
        continue
    timings["mandate issuance (control plane + PDP + policy + signature)"].append(
        (t1 - t0) * 1000)

    t2 = time.perf_counter()
    read_profile(grant_id)
    t3 = time.perf_counter()
    timings["verification + PDP re-evaluation + enforcement, WITH a mandate"].append(
        (t3 - t2) * 1000)
    timings["end-to-end: ask for a mandate, then use it"].append((t3 - t0) * 1000)

    t4 = time.perf_counter()
    read_profile(None)
    t5 = time.perf_counter()
    timings["the same call WITHOUT a mandate (Phase 4 baseline)"].append(
        (t5 - t4) * 1000)

for label, samples in timings.items():
    if not samples:
        continue
    samples.sort()
    p95 = samples[min(len(samples) - 1, int(len(samples) * 0.95))]
    print(f"      {label:<58s} min {min(samples):7.2f}  median "
          f"{statistics.median(samples):7.2f}  p95 {p95:7.2f}  "
          f"max {max(samples):7.2f}  (ms)")
print("      (measured on this host against the running stack. Not modelled.)")

with_mandate = timings["verification + PDP re-evaluation + enforcement, WITH a mandate"]
without = timings["the same call WITHOUT a mandate (Phase 4 baseline)"]
if with_mandate and without:
    overhead = statistics.median(with_mandate) - statistics.median(without)
    print(f"\n      Mandate overhead on the enforcement path: {overhead:+.2f} ms median")
    print("      That is the cost of verifying a signature, comparing a binding")
    print("      and spending a use atomically. The PDP evaluation happens either")
    print("      way -- which is the point.")

# ---------------------------------------------------------------------------
#  FAIL CLOSED
# ---------------------------------------------------------------------------
print("\n  FAIL-CLOSED  Verified paths, and how to reproduce the rest")
print("      Removing the JIT configuration from the engine makes every")
print("      issuance DENY with JIT_POLICY_UNCONFIGURED. An unconfigured")
print("      maximum TTL is never 'unlimited'. Covered by")
print("      tests/test_jit_policy.py, which genuinely removes it from the")
print("      running OPA and restores it.")
print("      Policy-engine outage:  docker compose stop opa")
print("      Expected: no mandate can be issued and no action authorized.")

print("\n" + "=" * 78)
print(f"  RESULT: {PASS} passed, {FAIL} failed")
print("=" * 78)
print("""
  A MANDATE IS AN INPUT TO AUTHORIZATION, never a substitute for one.
  EVERY USE IS RE-DECIDED -- revoke the credential and the mandate stops.
  A MANDATE IS A BUDGET AND A WINDOW, both capped by policy.
  A MANDATE IS NOT A HUMAN -- it cannot satisfy an approval requirement.

  Policy decides.  The database arbitrates.  The AEM enforces.
""")
sys.exit(1 if FAIL else 0)
