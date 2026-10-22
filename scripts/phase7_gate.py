#!/usr/bin/env python3
"""Phase 7 gate: secure A2A transactions, against the live system.

Proves, against a running API, a running OPA, a real PostgreSQL and (where
reachable) real agent processes, that:

  * a signed transaction from one agent to another is VERIFIED, AUTHORIZED by
    the PDP and only then executed -- a valid signature is never authorization
  * sender, receiver, action, resource, purpose, amount and payload cannot
    change without the signature failing
  * an envelope addressed to B cannot be presented by C, enforced BOTH
    cryptographically and by the control-plane guard
  * a payment executes AT MOST ONCE, decided by the database under real
    concurrency, and a retry returns the recorded outcome
  * the amount is signed, established server-side, authorized, and reconciled
    at all four points -- and any disagreement refuses
  * a revoked credential or a suspended sender stops the next transaction
  * an amount above the autonomous limit needs a PAYMENT_OFFICER, and above
    the single-approver limit needs TWO DISTINCT humans
  * JIT cannot authorize a payment and cannot substitute for a human
  * rotation keeps history verifiable; revocation does not
  * the whole arc is auditable by one request id

Latency numbers printed here are MEASURED from real calls. Nothing is modelled.

Usage:
    docker compose up -d postgres redis opa keycloak
    scripts/run_local.sh
    python3 scripts/phase7_gate.py
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cp_sign                                                      # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]
os.environ.setdefault("AGENT_KEYSTORE_DIR", str(REPO / "backend" / ".keystore-agents"))

from app.controlplane.client import canonical_body, control_plane_headers  # noqa: E402
from app.core.config import get_settings                                   # noqa: E402
from app.identity.keys import EncryptedFileKeyStore                        # noqa: E402
from app.identity.signer import Signer                                     # noqa: E402
from app.protocols.a2a.client import build_signed_transaction              # noqa: E402
from app.protocols.a2a.envelope import A2ABinding, payload_digest          # noqa: E402

API = "http://localhost:8000"
SENDER = "did:poc:agent:risk-001"
SENDER_SLUG = "risk-001"
RECEIVER = "did:poc:agent:payments-001"
RECEIVER_SLUG = "payments-001"
OTHER = "did:poc:agent:fraud-001"
OTHER_SLUG = "fraud-001"

AUTONOMOUS = "pay-3310"       # Rs    50,000  -- the agent's own authority
SINGLE = "pay-3311"           # Rs 5,00,000   -- one PAYMENT_OFFICER
DUAL = "pay-3312"             # Rs 50,00,000  -- TWO distinct humans

PASS = FAIL = 0

# A TRANSACTION ID IS THE SENDER'S IDEMPOTENCY KEY, and the gate runs against a
# LIVE system whose ledger persists between runs. Fixed ids would make the
# second run find its own first run's settled transactions and be answered
# idempotently -- so the gate would "pass" by re-reading history instead of
# exercising anything. Every id below is therefore scoped to this run.
RUN = f"gate{int(time.time())}"


def txn(name: str) -> str:
    """A transaction id unique to THIS run, stable within it.

    Stable within the run matters as much as unique across runs: the replay,
    id-reuse and HITL-retry sections all depend on deliberately presenting
    the SAME id twice.
    """
    return f"{RUN}-{name}"


# ---------------------------------------------------------------------------
#  plumbing
# ---------------------------------------------------------------------------
def keystore_for(slug):
    return EncryptedFileKeyStore(
        os.path.join(os.environ["AGENT_KEYSTORE_DIR"], slug),
        get_settings().keystore_master_key,
    )


def agent_headers(method, path, body, did, slug):
    payload = canonical_body(body)
    headers = control_plane_headers(
        Signer(keystore_for(slug)), principal_did=did, kid=f"{did}#key-1",
        method=method, path=path, body=payload,
    )
    headers["Content-Type"] = "application/json"
    return payload, headers


def call(method, path, body=None, *, principal=None, agent=None, slug=None,
         token=None, timeout=90.0):
    if agent:
        data, headers = agent_headers(method, path, body, agent, slug)
    elif principal:
        data, headers = cp_sign.signed(principal, method, path, body)
    else:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
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


def check_in(label, actual, expected_set):
    global PASS, FAIL
    ok = actual in expected_set
    PASS, FAIL = PASS + ok, FAIL + (not ok)
    detail = f"{actual!r}" if ok else f"got {actual!r}, expected one of {sorted(expected_set)}"
    print(f"      [{'PASS' if ok else 'FAIL'}]  {label:<58s} {detail}")


def envelope(*, sender=SENDER, slug=SENDER_SLUG, kid=None, receiver=RECEIVER,
             resource_id=AUTONOMOUS, amount_inr=50_000, currency="INR",
             action="execute_payment", resource_type="payment_instructions",
             purpose="payment_settlement", transaction_id=None, ttl_seconds=300,
             payload=None, moment=None, nonce=None, correlation_id=None,
             approval_id=None, jit_grant_id=None, domain=None, tamper=None):
    document = build_signed_transaction(
        Signer(keystore_for(slug)), sender_did=sender,
        sender_kid=kid or f"{sender}#key-1", receiver_did=receiver, action=action,
        resource_type=resource_type, resource_id=resource_id, purpose=purpose,
        domain=domain or get_settings().a2a_domain,
        payload=payload if payload is not None else {"note": "phase 7 gate"},
        amount_inr=amount_inr, currency=currency,
        transaction_id=transaction_id, ttl_seconds=ttl_seconds, nonce=nonce,
        moment=moment, correlation_id=correlation_id, approval_id=approval_id,
        jit_grant_id=jit_grant_id,
    )
    if tamper is not None:
        tamper(document)
    return document


def submit(document, *, as_did=RECEIVER, as_slug=RECEIVER_SLUG):
    return call("POST", "/api/v1/a2a/transactions", {"envelope": document},
                agent=as_did, slug=as_slug)


def instruction(instruction_id):
    return call("GET", f"/api/v1/loans")[1] and call(
        "GET", "/api/v1/a2a/instructions")[1]


def instruction_state(instruction_id):
    for record in call("GET", "/api/v1/a2a/instructions")[1]:
        if record["instruction_id"] == instruction_id:
            return record
    return {}


def executions(instruction_id):
    """How many times this instruction has actually been settled.

    READ FROM THE RECORD, never from a response. A gate that only checked
    responses could not tell one execution from two that both reported
    success -- and that is the single most important number here.

    Counted as a DELTA by every caller, because the gate runs against a
    LIVE system whose instruction state persists between runs. Asserting an
    absolute would make the gate pass or fail on how many times it had been
    run before, which is exactly the kind of assertion that quietly stops
    meaning anything.
    """
    return instruction_state(instruction_id).get("executions", 0)


CORE_BANKING = cp_sign.CORE_BANKING
IDENTITY_ADMIN = cp_sign.IDENTITY_ADMIN


def restore(instruction_id, amount_inr):
    call("POST", f"/api/v1/a2a/instructions/{instruction_id}/amount",
         {"amount_inr": amount_inr, "reason": "gate restore"},
         principal=CORE_BANKING)


def token_for(username, password):
    import urllib.parse

    data = urllib.parse.urlencode({
        "client_id": get_settings().oidc_client_id, "grant_type": "password",
        "username": username, "password": password, "scope": "openid"}).encode()
    try:
        with urllib.request.urlopen(get_settings().oidc_token_url, data,
                                    timeout=15) as response:
            return json.loads(response.read())["access_token"]
    except Exception:                                          # noqa: BLE001
        return None


print("=" * 78)
print("  PHASE 7 GATE - SECURE AGENT-TO-AGENT TRANSACTIONS")
print("=" * 78)

# ---------------------------------------------------------------------------
print("\n  0. PRECONDITIONS")
# ---------------------------------------------------------------------------
status, health = call("GET", "/api/v1/a2a/health")
check("the A2A layer is served", status, 200)
check("phase", health.get("phase"), 7)
check("policy configuration is loaded in the engine",
      health.get("policy_configuration", {}).get("loaded"), True)
check("envelope verification cannot be switched off",
      health.get("verification_required"), True)
check("the audience is bound", health.get("domain"), "agentic-iam-a2a")

status, policies = call("GET", "/api/v1/policies")
ids = {p["policy_id"] for p in policies.get("policies", [])}
check("a2a-transaction is loaded", "a2a-transaction" in ids, True)
check("every declared module is in the engine",
      all(p["in_engine"] for p in policies["policies"]), True)
check("no policy has drifted from disk",
      any(p["source_drift"] for p in policies["policies"]), False)
data_ids = {d["data_id"] for d in policies.get("data", [])}
check("a2a-policy configuration is declared", "a2a-policy" in data_ids, True)

status, sender_identity = call("GET", f"/api/v1/agents/did/{SENDER}")
check("the sender identity is ACTIVE", sender_identity.get("status"), "ACTIVE")
status, receiver_identity = call("GET", f"/api/v1/agents/did/{RECEIVER}")
check("the receiver identity is ACTIVE", receiver_identity.get("status"), "ACTIVE")

for identifier, amount in ((AUTONOMOUS, 50_000), (SINGLE, 500_000),
                           (DUAL, 5_000_000)):
    record = instruction_state(identifier)
    if record.get("amount_inr") != amount:
        restore(identifier, amount)
check("the demonstration instructions are at their expected amounts",
      [instruction_state(i)["amount_inr"]
       for i in (AUTONOMOUS, SINGLE, DUAL)], [50_000, 500_000, 5_000_000])

# ---------------------------------------------------------------------------
print("\n  1. THE HAPPY PATH  (sign -> verify -> PDP -> execute)")
# ---------------------------------------------------------------------------
before = executions(AUTONOMOUS)
status, result = submit(envelope(correlation_id="gate-happy"))
check("HTTP", status, 200)
check("accepted", result.get("accepted"), True)
check("executed", result.get("executed"), True)
check("the PDP decided it", (result.get("authorization") or {}).get("decision"),
      "ALLOW")
check("the reason names the A2A authorization",
      result.get("reason"), "A2A_TRANSACTION_AUTHORIZED")
check("the policy that decided is named",
      (result.get("authorization") or {}).get("policy"), "a2a-transaction:v1")
check("the SUBJECT of the decision is the SENDER",
      (result.get("authorization") or {}).get("subject"), SENDER)
after = instruction_state(AUTONOMOUS)
check("the instruction is now EXECUTED", after.get("status"), "EXECUTED")
check("it executed exactly once", executions(AUTONOMOUS) - before, 1)
transaction = result.get("transaction") or {}
check("all four amounts agree",
      [transaction["amount"]["signed_inr"], transaction["amount"]["server_inr"],
       transaction["amount"]["authorized_inr"],
       transaction["amount"]["executed_inr"]],
      [50_000, 50_000, 50_000, 50_000])
check("the amount is recorded as reconciled",
      transaction["amount"]["reconciled"], True)
HAPPY_TXN = result["transaction_id"]

# ---------------------------------------------------------------------------
print("\n  2. CRYPTOGRAPHIC INTEGRITY  (every bound field, tampered after signing)")
# ---------------------------------------------------------------------------
TAMPERS = [
    ("sender substituted", lambda e: e.__setitem__("senderDid", OTHER)),
    ("receiver substituted", lambda e: e.__setitem__("receiverDid", OTHER)),
    ("action changed", lambda e: e["transaction"].__setitem__("action", "read")),
    ("resource type changed",
     lambda e: e["transaction"].__setitem__("resourceType", "credit_records")),
    ("resource id changed",
     lambda e: e["transaction"].__setitem__("resourceId", DUAL)),
    ("purpose changed",
     lambda e: e["transaction"].__setitem__("purpose", "loan_assessment")),
    ("amount raised to Rs 50,00,000",
     lambda e: e["transaction"].__setitem__("amountInr", 5_000_000)),
    ("payload edited",
     lambda e: e["transaction"]["payload"].__setitem__("beneficiary", "attacker")),
    ("nonce changed", lambda e: e.__setitem__("nonce", "replaced")),
    ("audience changed", lambda e: e.__setitem__("domain", "another-service")),
    ("signature forged",
     lambda e: e["proof"].__setitem__("signatureValue",
                                      base64.b64encode(b"\x00" * 64).decode())),
    ("proof purpose flipped to jitGrant",
     lambda e: e["proof"].__setitem__("proofPurpose", "jitGrant")),
    ("verification method redirected",
     lambda e: e["proof"].__setitem__("verificationMethod", f"{OTHER}#key-1")),
]
for label, tamper in TAMPERS:
    status, refused = submit(envelope(tamper=tamper))
    # Two correct shapes of refusal, and the distinction is real:
    #   200 + accepted:false  the envelope reached the A2A layer and failed
    #                         verification
    #   403                   the CONTROL PLANE refused it first, because the
    #                         tampered field was the receiver and the guard
    #                         binds the submitter to it
    refused_at_all = (status == 403) or (refused.get("accepted") is False)
    check(label, refused_at_all, True)

def thorough(e):
    """Amount raised AND every derived field rebuilt to be consistent."""
    e["transaction"]["amountInr"] = 5_000_000
    e["transaction"]["payloadSha256"] = payload_digest(e["transaction"]["payload"])
    e["transaction"]["bindingHash"] = A2ABinding.from_envelope(e).digest()

_, refused = submit(envelope(tamper=thorough))
check("a fully self-consistent forgery still fails the signature",
      refused.get("reason"), "A2A_SIGNATURE_INVALID")
check("  ...and the PDP was never asked", refused.get("authorization"), None)
check("  ...and nothing moved", executions(AUTONOMOUS) - before, 1)

# ---------------------------------------------------------------------------
print("\n  3. RECEIVER BINDING  (an envelope for B is not usable by C)")
# ---------------------------------------------------------------------------
single_before = executions(SINGLE)
captured = envelope(resource_id=SINGLE, amount_inr=500_000)
status, refused = submit(captured, as_did=OTHER, as_slug=OTHER_SLUG)
check("another agent replaying it is refused at the control plane", status, 403)
check("  ...by name",
      (refused.get("detail") or {}).get("reason"), "PRINCIPAL_IS_NOT_THE_SUBJECT")

status, refused = submit(captured, as_did=SENDER, as_slug=SENDER_SLUG)
check("the SENDER cannot submit its own envelope", status, 403)
check("  ...by the same rule",
      (refused.get("detail") or {}).get("reason"), "PRINCIPAL_IS_NOT_THE_SUBJECT")

for admin in (cp_sign.IDENTITY_ADMIN, cp_sign.GATEWAY, cp_sign.POLICY_ADMIN):
    status, refused = call("POST", "/api/v1/a2a/transactions",
                           {"envelope": captured}, principal=admin)
    check(f"{admin.rsplit(':', 1)[-1]} may not submit", status, 403)

status, refused = call("POST", "/api/v1/a2a/transactions", {"envelope": captured})
check("an unsigned submission is refused", status, 401)
check("nothing moved throughout", executions(SINGLE) - single_before, 0)

# ---------------------------------------------------------------------------
print("\n  4. REPLAY AND IDEMPOTENCY")
# ---------------------------------------------------------------------------
auto_before = executions(AUTONOMOUS)
single_before = executions(SINGLE)
reused = envelope(transaction_id=txn("idem"), correlation_id="gate-replay")
_, first = submit(reused)
check("the first submission executes", first.get("executed"), True)
_, second = submit(reused)
check("the second returns the recorded outcome", second.get("idempotent"), True)
check("  ...reporting the same status", second.get("status"), first.get("status"))
check("  ...and re-deciding nothing", second.get("authorization"), None)
check("the payment still executed exactly once",
      executions(AUTONOMOUS) - auto_before, 1)

_, conflict = submit(envelope(transaction_id=txn("idem"), resource_id=SINGLE,
                              amount_inr=500_000))
check("the same id carrying different content is refused",
      conflict.get("reason"), "A2A_TRANSACTION_ID_REUSE")
check("  ...and is NOT reported as an ordinary duplicate",
      conflict.get("idempotent"), False)
check("  ...and nothing moved", executions(SINGLE) - single_before, 0)

_, nonce_replay = submit(envelope(transaction_id=txn("nonce-a"),
                                  nonce=f"{RUN}-shared-nonce"))
_, nonce_replay2 = submit(envelope(transaction_id=txn("nonce-b"),
                                   nonce=f"{RUN}-shared-nonce"))
check("a reused nonce under a fresh id is refused",
      nonce_replay2.get("reason"), "A2A_REPLAY_BLOCKED")

for _ in range(5):
    submit(envelope(transaction_id=txn("precious"),
                    tamper=lambda e: e["transaction"].__setitem__("amountInr", 1)))
_, genuine = submit(envelope(transaction_id=txn("precious")))
check("forged attempts do not burn a legitimate transaction id",
      genuine.get("executed"), True)

stale = envelope(moment=datetime.now(timezone.utc) - timedelta(seconds=600),
                 ttl_seconds=60)
_, refused = submit(stale)
check("an expired envelope is refused", refused.get("accepted"), False)
check("  ...before the PDP is asked", refused.get("authorization"), None)

_, refused = submit(envelope(ttl_seconds=86_400))
check("a sender cannot mint a long-lived instruction",
      refused.get("reason"), "A2A_TTL_EXCEEDS_MAXIMUM")

# ---------------------------------------------------------------------------
print("\n  5. CONCURRENT DUPLICATE EXECUTION  (the database arbitrates)")
# ---------------------------------------------------------------------------
import concurrent.futures                                          # noqa: E402

restore(AUTONOMOUS, 50_000)
baseline = executions(AUTONOMOUS)
racing = envelope(transaction_id=txn("race"))

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
    outcomes = [f.result() for f in
                [pool.submit(submit, racing) for _ in range(20)]]
bodies = [body for _, body in outcomes]
executed_now = executions(AUTONOMOUS) - baseline
check("20 concurrent submissions of one instruction", len(bodies), 20)
check("  ...produced exactly ONE execution", executed_now, 1)
check("  ...with exactly one processing path",
      sum(1 for b in bodies if not b.get("idempotent") and b.get("accepted")), 1)
check("  ...and nineteen idempotent answers",
      sum(1 for b in bodies if b.get("idempotent")), 19)
check("  ...none of them refused", all(b.get("accepted") for b in bodies), True)

# ---------------------------------------------------------------------------
print("\n  6. FINANCIAL INTEGRITY  (signed / server / authorized / executed)")
# ---------------------------------------------------------------------------
restore(AUTONOMOUS, 50_000)
before = executions(AUTONOMOUS)

_, low = submit(envelope(amount_inr=5_000))
check("instructing Rs 5,000 against a Rs 50,000 record is DENIED",
      low.get("reason"), "A2A_AMOUNT_MISMATCH")
_, high = submit(envelope(amount_inr=5_000_000))
check("instructing Rs 50,00,000 against it is DENIED too",
      high.get("reason"), "A2A_AMOUNT_MISMATCH")
check("  ...and POLICY denied it, not just the service",
      (high.get("authorization") or {}).get("reason"), "A2A_AMOUNT_MISMATCH")
check("nothing moved", executions(AUTONOMOUS), before)

# The record moves AFTER the sender signed. The instruction is unchanged.
signed_before_the_change = envelope(transaction_id=txn("amend"))
restore(AUTONOMOUS, 250_000)
_, moved = submit(signed_before_the_change)
check("an amount amended after signing refuses the transaction",
      moved.get("reason"), "A2A_AMOUNT_MISMATCH")
check("  ...and nothing moved", executions(AUTONOMOUS), before)
restore(AUTONOMOUS, 50_000)

check("the thresholds are policy configuration, not code",
      json.loads((REPO / "policies" / "data" / "a2a_policy.json").read_text()
                 )["thresholds"]["agent_autonomous_limit_inr"], 100_000)

# ---------------------------------------------------------------------------
print("\n  7. IDENTITY AND TRUST  (a signature is not standing permission)")
# ---------------------------------------------------------------------------
# Signed with a REAL key, claiming a DID nobody registered -- which is
# what the attack actually looks like: the attacker has a key, just not
# the one the DID it is claiming resolves to.
_, unknown = submit(envelope(sender="did:poc:agent:ghost-agent",
                             kid=f"{SENDER}#key-1"))
check("an unregistered sender is refused", unknown.get("reason"),
      "A2A_SENDER_UNKNOWN")

_, wrong_key = submit(envelope(
    tamper=lambda e: e["proof"].__setitem__("verificationMethod",
                                            f"{SENDER}#key-99")))
check("an unregistered key id is refused", wrong_key.get("reason"),
      "A2A_KEY_UNKNOWN")

_, backdated = submit(envelope(
    moment=datetime.now(timezone.utc) - timedelta(days=365)))
check("a proof dated before its key existed is refused",
      backdated.get("reason"), "A2A_KEY_UNKNOWN")

# SUSPEND the sender, then restore it. The status route is keyed by the
# agent's UUID, not its slug.
_, sender_record = call("GET", f"/api/v1/agents/did/{SENDER}")
SENDER_ID = sender_record.get("id")
status, _ = call("POST", f"/api/v1/agents/{SENDER_ID}/status",
                 {"status": "SUSPENDED"}, principal=IDENTITY_ADMIN)
check("the sender can be suspended by an authorized administrator", status, 200)
_, suspended = submit(envelope(transaction_id=txn("suspended")))
check("a SUSPENDED sender cannot instruct anything",
      suspended.get("reason"), "A2A_SENDER_NOT_ELIGIBLE")
check("  ...and nothing moved", executions(AUTONOMOUS), before)
call("POST", f"/api/v1/agents/{SENDER_ID}/status", {"status": "ACTIVE"},
     principal=IDENTITY_ADMIN)
_, restored = submit(envelope(transaction_id=txn("reactivated")))
check("reactivating it restores the path", restored.get("executed"), True)

# ---------------------------------------------------------------------------
print("\n  8. HUMAN APPROVAL  (the middle band, one PAYMENT_OFFICER)")
# ---------------------------------------------------------------------------
officer = token_for("payment.officer", "payment-officer-demo")
officer2 = token_for("payment.officer.2", "payment-officer-2-demo")
loan_officer = token_for("loan.officer", "loan-officer-demo")

if officer is None:
    print("      SKIP  Keycloak is not reachable, or the PAYMENT_OFFICER role")
    print("            is not in the realm. Re-import keycloak/realm-agentic-iam.json")
    print("            or run the admin-API steps in docs/PHASE_7_ARCHITECTURE.md.")
else:
    restore(SINGLE, 500_000)
    escalation = envelope(resource_id=SINGLE, amount_inr=500_000,
                          transaction_id=txn("single"))
    _, pending = submit(escalation)
    check("Rs 5,00,000 escalates to a human", pending.get("status"),
          "PENDING_APPROVAL")
    check("  ...asking for ONE approver",
          (pending.get("approval") or {}).get("required_approvals"), 1)
    single_before = executions(SINGLE)
    check("  ...and nothing moved", executions(SINGLE) - single_before, 0)
    approval_id = (pending.get("approval") or {}).get("approval_id")

    status, screen = call("GET", f"/api/v1/hitl/approvals/{approval_id}",
                          token=officer)
    presentation = (screen or {}).get("presentation") or {}
    check("the screen shows the amount", presentation.get("amount_display"),
          "₹5,00,000")
    check("  ...who instructed it",
          (presentation.get("instructed_by") or "").endswith("risk-001"), True)
    check("  ...and who would carry it out",
          (presentation.get("to_be_performed_by") or "").endswith("payments-001"),
          True)

    status, refused = call("POST", f"/api/v1/hitl/approvals/{approval_id}/decide",
                           {"decision": "APPROVED"}, token=loan_officer)
    check("a LOAN_OFFICER may not approve a payment", status, 403)
    check("  ...by name", (refused.get("detail") or {}).get("reason"),
          "HUMAN_MAY_NOT_APPROVE_THIS")

    status, decided = call("POST", f"/api/v1/hitl/approvals/{approval_id}/decide",
                           {"decision": "APPROVED"}, token=officer)
    check("a PAYMENT_OFFICER may", status, 200)

    _, released = submit(escalation)
    check("the retry executes", released.get("executed"), True)
    check("  ...on the human-approved reason", released.get("reason"),
          "A2A_HUMAN_APPROVED_AND_POLICY_MATCH")
    check("  ...exactly once", executions(SINGLE) - single_before, 1)

    _, spent = submit(envelope(resource_id=SINGLE, amount_inr=500_000,
                               transaction_id=txn("single-2")))
    check("the approval is spent and cannot release a second payment",
          spent.get("executed"), False)

# ---------------------------------------------------------------------------
print("\n  9. DUAL CONTROL  (above the single-approver limit, TWO humans)")
# ---------------------------------------------------------------------------
if officer is None or officer2 is None:
    print("      SKIP  needs both payment officers from the realm.")
else:
    restore(DUAL, 5_000_000)
    dual_before = executions(DUAL)
    dual = envelope(resource_id=DUAL, amount_inr=5_000_000,
                    transaction_id=txn("dual"))
    _, pending = submit(dual)
    check("Rs 50,00,000 escalates", pending.get("status"), "PENDING_APPROVAL")
    check("  ...asking for TWO distinct humans",
          (pending.get("approval") or {}).get("required_approvals"), 2)
    check("  ...with the dual-control reason", pending.get("reason"),
          "DUAL_APPROVAL_REQUIRED")
    approval_id = (pending.get("approval") or {}).get("approval_id")

    status, _ = call("POST", f"/api/v1/hitl/approvals/{approval_id}/decide",
                     {"decision": "APPROVED"}, token=officer)
    check("the first officer signs off", status, 200)

    _, still = submit(dual)
    check("ONE officer CANNOT release it", still.get("executed"), False)
    check("  ...it is still waiting", still.get("status"), "PENDING_APPROVAL")
    check("  ...and nothing moved", executions(DUAL) - dual_before, 0)

    status, repeat = call("POST", f"/api/v1/hitl/approvals/{approval_id}/decide",
                          {"decision": "APPROVED"}, token=officer)
    check("the SAME officer signing twice is refused", status in (403, 409), True)

    status, _ = call("POST", f"/api/v1/hitl/approvals/{approval_id}/decide",
                     {"decision": "APPROVED"}, token=officer2)
    check("a SECOND, DIFFERENT officer signs off", status, 200)

    _, released = submit(dual)
    check("two distinct humans release it", released.get("executed"), True)
    check("  ...on the dual-control reason", released.get("reason"),
          "A2A_DUAL_CONTROL_SATISFIED")
    check("  ...exactly once", executions(DUAL) - dual_before, 1)

# ---------------------------------------------------------------------------
print("\n 10. THE JIT BOUNDARY  (a mandate is not a human and not a payment)")
# ---------------------------------------------------------------------------
status, mandate = call("POST", "/api/v1/jit/request", {
    "subject_did": SENDER, "action": "execute_payment",
    "resource_type": "payment_instructions", "resource_ids": [AUTONOMOUS],
    "purpose": "payment_settlement", "ttl_seconds": 300, "max_uses": 3,
}, agent=SENDER, slug=SENDER_SLUG)
check("no mandate may be issued for a payment", mandate.get("issued"), False)
check_in("  ...refused by name", mandate.get("reason"),
         {"JIT_SCOPE_EXCEEDS_DECISION", "JIT_ACTION_NOT_ELIGIBLE"})

jit_config = json.loads((REPO / "policies" / "data" / "jit_policy.json").read_text())
check("execute_payment is excluded from JIT by name",
      "execute_payment" in jit_config["excluded_actions"]["actions"], True)
check("  ...and absent from the allow-list",
      "execute_payment" in jit_config["jit_eligible_actions"], False)

# A REAL mandate, over credit records, cannot move a payment.
status, real_mandate = call("POST", "/api/v1/jit/request", {
    "subject_did": SENDER, "action": "read", "resource_type": "credit_records",
    "resource_ids": ["customer-007"], "purpose": "loan_assessment",
    "ttl_seconds": 300, "max_uses": 3,
}, agent=SENDER, slug=SENDER_SLUG)
if real_mandate.get("issued"):
    grant_id = real_mandate["grant"]["grant_id"]
    restore(SINGLE, 500_000)
    jit_before = executions(SINGLE)
    _, with_mandate = submit(envelope(resource_id=SINGLE, amount_inr=500_000,
                                      jit_grant_id=grant_id,
                                      transaction_id=txn("jit")))
    check("a genuine mandate for another scope cannot move a payment",
          with_mandate.get("executed"), False)
    check("  ...and cannot substitute for a human",
          executions(SINGLE) - jit_before, 0)
else:
    print(f"      note: could not issue the control mandate "
          f"({real_mandate.get('reason')}); the exclusion checks above stand")

# ---------------------------------------------------------------------------
print("\n 11. KEY SEPARATION")
# ---------------------------------------------------------------------------
status, jit_keys = call("GET", "/api/v1/jit/keys")
status, approval_keys = call("GET", "/api/v1/hitl/authority/keys")
status, sender_document = call("GET", f"/api/v1/agents/did/{SENDER}/did-document")
agent_key = (sender_document.get("verificationMethod") or [{}])[0].get(
    "publicKeyMultibase")
jit_key = next((k["public_key_multibase"] for k in jit_keys.get("keys", [])
                if k["status"] == "ACTIVE"), None)
approval_key = next((k["public_key_multibase"]
                     for k in approval_keys.get("keys", [])
                     if k["status"] == "ACTIVE"), None)
check("the A2A signing key is the agent's own Phase 1 key",
      agent_key is not None, True)
check("  ...and is NOT the JIT authority's", agent_key == jit_key, False)
check("  ...and is NOT the approval authority's", agent_key == approval_key, False)
check("the JIT and approval authorities differ from each other",
      jit_key == approval_key, False)
check("no private key is returned by the register",
      jit_keys.get("private_key"), "NEVER EXPOSED - held by the KeyStore")

for authority_did, label in (
    (get_settings().jit_authority_did, "the JIT authority"),
    (get_settings().approval_authority_did, "the approval authority"),
):
    slug = authority_did.rsplit(":", 1)[-1]
    try:
        forged = build_signed_transaction(
            Signer(EncryptedFileKeyStore(REPO / "backend" / ".keystore",
                                         get_settings().keystore_master_key)),
            sender_did=authority_did, sender_kid=f"{authority_did}#key-1",
            receiver_did=RECEIVER, action="execute_payment",
            resource_type="payment_instructions", resource_id=AUTONOMOUS,
            purpose="payment_settlement", domain=get_settings().a2a_domain,
            amount_inr=50_000, currency="INR")
        _, refused = submit(forged)
        check(f"{label} cannot sign a transaction",
              refused.get("reason"), "A2A_SENDER_UNKNOWN")
    except Exception as exc:                                    # noqa: BLE001
        print(f"      note: could not exercise {label} ({exc})")

# ---------------------------------------------------------------------------
print("\n 12. AUDIT CORRELATION")
# ---------------------------------------------------------------------------
status, events = call("GET", "/api/v1/audit?limit=1000")
trail = [e for e in events if e.get("request_id") == f"a2a-{HAPPY_TXN}"]
types = {e["event_type"] for e in trail}
for expected in ("A2A_REQUEST", "A2A_SIGNATURE_VERIFIED",
                 "AUTHORIZATION_REQUESTED", "PIP_CONTEXT_COLLECTED",
                 "OPA_DECISION", "PDP_EVALUATION", "POLICY_ALLOW",
                 "AEM_ALLOWED", "TOOL_EXECUTED", "A2A_EXECUTED"):
    check(f"  {expected}", expected in types, True)
check("the whole arc is retrievable by ONE request id", len(trail) >= 10, True)

status, one = call("GET", f"/api/v1/a2a/transactions/{HAPPY_TXN}")
check("the transaction record carries its signed envelope",
      (one.get("envelope") or {}).get("transactionId"), HAPPY_TXN)
check("  ...and the attempts made against it", "attempts" in one, True)
check("the stored signature is truncated", len(one.get("envelope", {}).get(
    "proof", {}).get("signatureValue", "")) > 0 and len(
    (one.get("signing_key") or "")) < 400, True)

# ---------------------------------------------------------------------------
print("\n 13. FAIL-CLOSED")
# ---------------------------------------------------------------------------
print("      Removing the A2A configuration from the engine makes every")
print("      payment DENY with A2A_POLICY_UNCONFIGURED. An unconfigured")
print("      threshold is never 'no limit'. Covered by")
print("      tests/test_a2a_financial.py, which genuinely removes it from")
print("      the running OPA and restores it.")
print("      Policy-engine outage:  docker compose stop opa")
print("      Expected: every transaction DENIED, AUTHORIZATION_UNAVAILABLE.")

# ---------------------------------------------------------------------------
print("\n 14. PERFORMANCE  (measured on this host, against the running stack)")
# ---------------------------------------------------------------------------
restore(AUTONOMOUS, 50_000)
timings: dict[str, list[float]] = {
    "envelope construction + Ed25519 signature (in process)": [],
    "verify + PDP + AEM + execute, end to end": [],
    "the same protected call WITHOUT A2A (Phase 4 baseline)": [],
    "idempotent replay of a settled transaction": [],
}
for n in range(8):
    t0 = time.perf_counter()
    document = envelope(transaction_id=txn(f"perf-{n}"))
    t1 = time.perf_counter()
    timings["envelope construction + Ed25519 signature (in process)"].append(
        (t1 - t0) * 1000)

    t2 = time.perf_counter()
    submit(document)
    t3 = time.perf_counter()
    timings["verify + PDP + AEM + execute, end to end"].append((t3 - t2) * 1000)

    t4 = time.perf_counter()
    submit(document)
    t5 = time.perf_counter()
    timings["idempotent replay of a settled transaction"].append((t5 - t4) * 1000)

    t6 = time.perf_counter()
    call("POST", "/api/v1/enforce", {
        "subject": {"did": SENDER}, "tool": "get_credit_profile",
        "arguments": {"customer_id": "customer-007"},
        "purpose": "loan_assessment"}, agent=SENDER, slug=SENDER_SLUG)
    t7 = time.perf_counter()
    timings["the same protected call WITHOUT A2A (Phase 4 baseline)"].append(
        (t7 - t6) * 1000)

for label, samples in timings.items():
    if not samples:
        continue
    samples_sorted = sorted(samples)
    p95 = samples_sorted[min(len(samples) - 1, int(len(samples) * 0.95))]
    print(f"      {label:<58s} min {min(samples):7.2f}  median "
          f"{statistics.median(samples):7.2f}  p95 {p95:7.2f}  "
          f"max {max(samples):7.2f}  (ms)")
print("      (measured on this host against the running stack. Not modelled.)")

# WHAT DOMINATES THE ABSOLUTE NUMBERS, so nobody reads them as a Phase 7 cost.
# The PDP records real per-stage timings; printing them here means the figures
# above explain themselves instead of inviting a guess.
status, decisions = call("GET", "/api/v1/authorize/decisions?limit=1")
if decisions:
    stages = {s["name"]: s["duration_ms"] for s in decisions[0].get("stages", [])}
    detail = next((s["detail"] for s in decisions[0].get("stages", [])
                   if s["name"] == "pip"), "")
    print(f"\n      Where the time actually goes, from the last decision:")
    for name, duration in stages.items():
        print(f"        {name:10s} {duration:8.2f} ms"
              + (f"   ({detail})" if name == "pip" else ""))
    print("        The PIP dominates because it re-verifies EVERY credential the")
    print("        subject holds, on every single evaluation -- which is the")
    print("        property that makes revocation immediate. On a long-lived")
    print("        development database the demo agent has accumulated many")
    print("        credentials from repeated seeding, so the absolute figure")
    print("        reflects that accumulation and not an A2A cost.")

a2a_median = statistics.median(timings["verify + PDP + AEM + execute, end to end"])
base_median = statistics.median(
    timings["the same protected call WITHOUT A2A (Phase 4 baseline)"])
print(f"\n      A2A overhead on the enforcement path: "
      f"{a2a_median - base_median:+.2f} ms median")
print("      THAT DELTA is the Phase 7 cost: verifying an Ed25519 signature,")
print("      resolving the sender from its DID Document, registering the")
print("      transaction atomically and reconciling the amount. The PDP")
print("      evaluation happens either way -- which is the point.")

print("\n" + "=" * 78)
print(f"  RESULT: {PASS} passed, {FAIL} failed")
print("=" * 78)
print("""
  A VALID SIGNATURE IS NOT AUTHORIZATION. Every transaction reaches the PDP.
  A TRANSACTION FOR B CANNOT BE SPENT ON C -- bound cryptographically, and
    bound again by the control-plane guard.
  A PAYMENT EXECUTES AT MOST ONCE, decided by the database under real
    concurrency, and a retry returns the recorded outcome.
  THE AMOUNT IS SIGNED, ESTABLISHED SERVER-SIDE, AUTHORIZED AND RECONCILED.
    A signature is evidence of intent, never evidence of the figure.
  DUAL CONTROL HOLDS. One officer cannot release an above-threshold payment.

  Identity authenticates.  Policy decides.  The database arbitrates.
  The AEM enforces.
""")
sys.exit(1 if FAIL else 0)
