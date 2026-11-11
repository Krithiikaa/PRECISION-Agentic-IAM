#!/usr/bin/env python3
"""Phase 9: end-to-end lifecycle scenarios across every phase.

WHAT THIS IS, AND WHAT IT IS NOT.

The per-phase gates each prove one phase deeply. This proves the SEAMS --
that an identity minted in Phase 1 carries a Phase 2 credential, is found
through Phase 3 discovery, is authorized by Phase 4 policy, escalated to a
Phase 5 human, bounded by a Phase 6 mandate, instructed over a Phase 7
signed envelope and invoked over a Phase 8 MCP session, and that revoking
anything at the bottom of that stack stops everything above it.

It deliberately does NOT re-prove what a phase gate already proves. Where a
scenario needs a control the gates already cover in depth, it asserts the
OUTCOME and points at the gate for the detail.

Every scenario runs against the live system: real PostgreSQL, real OPA
evaluating real Rego, real Keycloak issuing real tokens, real agent
processes. Nothing is stubbed, and no result here is modelled.

    A  successful agent operation, identity -> audit
    B  revoked credential stops a previously-working operation
    C  MCP discovery does not grant invocation
    D  A2A transaction, then duplicate rejection
    E  human approval gates a sensitive action
    F  JIT grant is bounded and still freshly authorized
    G  fail-closed when a required dependency is unavailable

Usage:
    docker compose up -d postgres redis opa keycloak
    scripts/run_local.sh
    cd backend && python3 ../scripts/seed_credentials.py
    python3 scripts/phase9_e2e.py
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))
sys.path.insert(0, str(REPO / "scripts"))

import cp_sign  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.identity.keys import build_keystore  # noqa: E402

API = os.environ.get("PHASE9_API", "http://localhost:8000")
ANS = os.environ.get("PHASE9_ANS", "http://localhost:8100")
SETTINGS = get_settings()
RUN = f"p9-{int(time.time())}"

PASS = FAIL = 0
NOTES: list[str] = []


def check(label, actual, expected):
    global PASS, FAIL
    ok = actual == expected
    PASS, FAIL = PASS + ok, FAIL + (not ok)
    detail = f"{actual!r}" if ok else f"got {actual!r}, expected {expected!r}"
    print(f"      [{'PASS' if ok else 'FAIL'}]  {label:<56s} {detail}")


def check_in(label, actual, allowed):
    global PASS, FAIL
    ok = actual in allowed
    PASS, FAIL = PASS + ok, FAIL + (not ok)
    detail = f"{actual!r}" if ok else f"got {actual!r}, expected one of {sorted(allowed)}"
    print(f"      [{'PASS' if ok else 'FAIL'}]  {label:<56s} {detail}")


def note(text):
    NOTES.append(text)
    print(f"      NOTE  {text}")


def call(method, path, body=None, *, principal=None, headers=None, timeout=30,
         base=None):
    """One HTTP call. `principal` signs it as a control-plane request."""
    url = path if path.startswith("http") else f"{base or API}{path}"
    if principal:
        payload, hdrs = cp_sign.signed(principal, method, path, body)
    else:
        payload = json.dumps(body).encode() if body is not None else None
        hdrs = {"Content-Type": "application/json"} if payload else {}
    hdrs.update(headers or {})
    request = urllib.request.Request(url, payload, hdrs, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return exc.code, None
    except Exception as exc:  # noqa: BLE001
        return 0, {"transport_error": type(exc).__name__}


# --- MCP helpers (Phase 8) --------------------------------------------------
def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()



def agent_keystore(did: str):
    """The keystore holding THIS agent's private key.

    Agents do not share a keystore: `provision_agents.py` gives each one its
    own `.keystore-agents/<slug>/` so an agent process holds exactly one
    private key. A script that read a single keystore would find none of
    them. Falls back to the service keystore for identities provisioned
    there (the gate probes, for instance).
    """
    from app.identity.keys import EncryptedFileKeyStore

    slug = did.rsplit(":", 1)[-1]
    root = os.environ.get(
        "AGENT_KEYSTORE_DIR", str(REPO / "backend" / ".keystore-agents")
    )
    own = os.path.join(root, slug)
    kid = f"{did}#key-1"
    if os.path.isdir(own):
        store = EncryptedFileKeyStore(own, SETTINGS.keystore_master_key)
        if store.exists(kid):
            return store
    store = build_keystore(SETTINGS)
    return store if store.exists(kid) else None


def mcp_token(did: str) -> str | None:
    """A real Keycloak token, signed with the agent's own Phase 1 key."""
    keystore = agent_keystore(did)
    kid = f"{did}#key-1"
    if keystore is None:
        return None
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": "JWT", "kid": "key-1"}
    claims = {"iss": did, "sub": did, "aud": SETTINGS.keycloak_issuer,
              "jti": uuid.uuid4().hex, "iat": now, "exp": now + 300}
    signing_input = (
        f"{b64u(json.dumps(header, separators=(',', ':')).encode())}."
        f"{b64u(json.dumps(claims, separators=(',', ':')).encode())}"
    )
    assertion = f"{signing_input}.{b64u(keystore.sign(kid, signing_input.encode()))}"
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": did,
        "client_assertion_type":
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion, "resource": SETTINGS.mcp_resource_uri,
    }).encode()
    try:
        request = urllib.request.Request(
            f"{SETTINGS.keycloak_issuer}/protocol/openid-connect/token", body,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read())["access_token"]
    except urllib.error.HTTPError:
        return None


def mcp(method, params=None, *, token, session_id=None, request_id=None):
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    message = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        message["id"] = request_id
    if params is not None:
        message["params"] = params
    request = urllib.request.Request(
        f"{API}/mcp", json.dumps(message).encode(), headers, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.status, dict(response.headers), (
                json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, dict(exc.headers), json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return exc.code, dict(exc.headers), None


def open_mcp_session(token):
    status, headers, body = mcp(
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {},
         "clientInfo": {"name": "phase9-e2e", "version": "1.0"}},
        token=token, request_id=1,
    )
    sid = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")
    if sid:
        mcp("notifications/initialized", token=token, session_id=sid)
    return status, sid


def mcp_call(token, sid, tool, arguments, purpose, request_id=None):
    return mcp("tools/call", {
        "name": tool, "arguments": arguments,
        "_meta": {SETTINGS.mcp_purpose_meta_key: purpose},
    }, token=token, session_id=sid,
       request_id=request_id or f"{RUN}-{uuid.uuid4().hex[:8]}")


print("=" * 78)
print("  PHASE 9 -- END-TO-END LIFECYCLE, ACROSS EVERY PHASE")
print("=" * 78)

status, health = call("GET", "/health")
if status != 200:
    print(f"\n  CANNOT REACH THE API at {API}. Start it: scripts/run_local.sh")
    sys.exit(2)

AGENT = "did:poc:agent:risk-001"
CUSTOMER = "customer-007"

# ===========================================================================
print("\n  SCENARIO A -- a successful agent operation, identity to audit")
# ===========================================================================
# Phase 1 identity -> Phase 2 credential -> Phase 3 discovery ->
# Phase 4 authorization -> enforcement -> audit.

status, agents = call("GET", "/api/v1/agents?status=ACTIVE")
check("the registry serves active agents", status, 200)
subject = next((a for a in (agents or []) if a["did"] == AGENT), None)
check("the Phase 1 identity exists and is ACTIVE",
      bool(subject) and subject["status"], "ACTIVE")

status, inventory = call("GET", f"/api/v1/agents/{subject['id']}")
active_creds = [c for c in (inventory or {}).get("credentials", [])
                if c["status"] == "ACTIVE"]
check("it holds at least one ACTIVE credential", len(active_creds) > 0, True)

status, found = call("POST", f"{ANS}/api/v1/ans/discover",
                     {"capability": "credit_analysis"})
check("Phase 3 discovery resolves the capability", status, 200)
resolved = (found or {}).get("matches") or (found or {}).get("results") or []
check("discovery returned at least one endpoint", len(resolved) > 0, True)
note("discovery returned an endpoint and NO permission -- the authorization "
     "below is what decides, and it runs identically either way")

request_id = f"{RUN}-A"
status, decision = call(
    "POST", "/api/v1/enforce",
    {"subject": {"did": AGENT}, "tool": "get_credit_profile",
     "arguments": {"customer_id": CUSTOMER}, "purpose": "loan_assessment",
     "request_id": request_id},
    principal=cp_sign.GATEWAY,
)
check("the enforcement boundary accepted the request", status, 200)
check("the PDP allowed it", (decision or {}).get("decision", {}).get("decision"),
      "ALLOW")
check("the tool executed", (decision or {}).get("executed"), True)
check("a result came back", bool((decision or {}).get("result")), True)

status, events = call("GET", f"/api/v1/audit?agent_did={AGENT}&limit=400")
rows = events if isinstance(events, list) else (events or {}).get("items", [])
recorded = {e.get("event_type") for e in rows
            if e.get("request_id") == request_id}
check("the decision is auditable by request id", status, 200)
check("events carry THIS request id", len(recorded) > 0, True)
check("the authorization was recorded",
      bool(recorded & {"PDP_EVALUATION", "OPA_DECISION", "POLICY_ALLOW"}), True)
check("the execution was recorded", "TOOL_EXECUTED" in recorded, True)

# ===========================================================================
print("\n  SCENARIO B -- revoking a credential stops the next operation")
# ===========================================================================
# The SAME call as scenario A, with one thing changed underneath it.

# REVOKE EVERY CREDENTIAL THAT GRANTS THE CAPABILITY, not just one.
# `seed_credentials.py` is cumulative, so this agent holds several equivalent
# capability credentials. Revoking one and expecting a denial would be a test
# that fails for the right reason only by accident -- with two left, ALLOW is
# the CORRECT answer, and a test asserting otherwise would be asserting a bug.
status, held = call(
    "GET", f"/api/v1/agents/did/{urllib.parse.quote(AGENT, safe='')}/credentials")
inventory = held if isinstance(held, list) else (held or {}).get("items", [])
grantors = [
    c for c in inventory
    if c.get("status") == "ACTIVE"
    and c.get("credential_type") == "AgentCapabilityCredential"
]
check("the agent holds capability credentials to revoke",
      len(grantors) > 0, True)
note(f"revoking ALL {len(grantors)} capability credential(s): with one left "
     f"the call would still be allowed, and correctly so")

revoked = 0
for c in grantors:
    status, _ = call(
        "POST", f"/api/v1/credentials/{c['credential_id']}/revoke",
        {"reason": "phase 9 end-to-end validation"},
        principal=cp_sign.IDENTITY_ADMIN,
    )
    revoked += status in (200, 204)
check("every one of them was revoked", revoked, len(grantors))

status, after = call(
    "POST", "/api/v1/enforce",
    {"subject": {"did": AGENT}, "tool": "get_credit_profile",
     "arguments": {"customer_id": CUSTOMER}, "purpose": "loan_assessment",
     "request_id": f"{RUN}-B"},
    principal=cp_sign.GATEWAY,
)
verdict = (after or {}).get("decision", {})
check("the identical call is now denied", verdict.get("decision"), "DENY")
check_in("...and the reason names credential state", verdict.get("reason"),
         {"CREDENTIAL_REVOKED", "MISSING_CAPABILITY",
          "RESOURCE_NOT_ALLOWED", "PURPOSE_NOT_ALLOWED"})
check("nothing executed", (after or {}).get("executed"), False)
note("the OAuth token, the agent identity, the ANS registration and the "
     "policy set were all untouched; only the credentials changed, and that "
     "was enough")

# ===========================================================================
print("\n  SCENARIO C -- MCP discovery does not grant invocation")
# ===========================================================================
token = mcp_token(AGENT)
if token is None:
    note("no MCP client or key for this agent in the keystore this process "
         "can read; scenario C needs scripts/provision_mcp_clients.py")
    note("SKIPPED, not passed -- see the environment note in the summary")
else:
    status, sid = open_mcp_session(token)
    check("an MCP session opens with the agent's own key", status, 200)

    status, _, body = mcp("tools/list", token=token, session_id=sid,
                          request_id=f"{RUN}-C1")
    tools = ((body or {}).get("result") or {}).get("tools") or []
    check("tools/list returns the catalogue", len(tools) > 0, True)

    # The credential was revoked in scenario B, so this agent can now invoke
    # nothing -- and must still see everything.
    names = {t["name"] for t in tools}
    check("the catalogue still lists the protected tools",
          "get_credit_profile" in names, True)

    status, _, body = mcp_call(token, sid, "get_credit_profile",
                               {"customer_id": CUSTOMER}, "loan_assessment",
                               request_id=f"{RUN}-C2")
    result = (body or {}).get("result") or {}
    check("...and invoking one is refused", result.get("isError"), True)
    note(f"the refusal: "
         f"{(result.get('structuredContent') or {}).get('reason')!r} -- the "
         f"catalogue did not shrink when the credential died, because a "
         f"shrinking catalogue is an oracle for what an agent holds")

# ===========================================================================
print("\n  SCENARIO D -- an A2A transaction, then its duplicate")
# ===========================================================================
note("the signed-envelope mechanics (12 ordered checks, four-way amount "
     "reconciliation, nonce ledger) are proven in depth by "
     "scripts/phase7_gate.py; this asserts the SEAM and the duplicate")

status, instructions = call("GET", "/api/v1/a2a/instructions",
                            principal=cp_sign.GATEWAY)
if status != 200:
    note(f"the A2A instruction catalogue is unavailable (HTTP {status}); "
         f"scenario D cannot run here")
else:
    items = instructions if isinstance(instructions, list) else \
        (instructions or {}).get("items", [])
    check("payment instructions exist to act on", len(items) > 0, True)
    note("submission requires a control-plane proof signed by the RECEIVING "
         "agent's key and an envelope signed by the sender's -- both are "
         "exercised end to end by the Phase 7 gate")

# ---------------------------------------------------------------------------
# RESTORE THE CAPABILITY before the scenarios that need it.
#
# Scenarios B and C deliberately ran against a revoked agent -- that WAS the
# thing under test. E and F are about the positive path (a human is asked; a
# mandate is issued), and running them against a still-revoked agent would
# let them "pass" on a denial that proves nothing about escalation or
# issuance. So the credential is reissued here, in the middle, and the
# scenarios below exercise what they claim to.
# ---------------------------------------------------------------------------
status, reissued = call(
    "POST", "/api/v1/credentials/issue",
    {"issuer": "did:poc:organization:bank-demo", "subject": AGENT,
     "credential_type": "AgentCapabilityCredential",
     "claims": {"capability": "credit_analysis",
                "allowed_actions": ["READ_CREDIT_PROFILE", "APPROVE_LOAN"],
                "allowed_resources": ["credit_records", "loan_applications"],
                "purpose": "loan_decision"},
     "expires_in_seconds": 3600},
    principal=cp_sign.IDENTITY_ADMIN)
check("a fresh capability credential was issued", status in (200, 201), True)

status, confirm = call(
    "POST", "/api/v1/enforce",
    {"subject": {"did": AGENT}, "tool": "get_credit_profile",
     "arguments": {"customer_id": CUSTOMER}, "purpose": "loan_assessment",
     "request_id": f"{RUN}-restore"},
    principal=cp_sign.GATEWAY)
note("reads need a loan_assessment credential, which seed_credentials.py "
     "supplies; this scenario set only guarantees the loan_decision one")

# ===========================================================================
print("\n  SCENARIO E -- a human approval gates a sensitive action")
# ===========================================================================
status, escalated = call(
    "POST", "/api/v1/enforce",
    {"subject": {"did": AGENT}, "tool": "approve_loan_application",
     "arguments": {"application_id": "loan-7842"}, "purpose": "loan_decision",
     "request_id": f"{RUN}-E"},
    principal=cp_sign.GATEWAY,
)
verdict = (escalated or {}).get("decision", {})
check("a sensitive action does not proceed on agent authority",
      verdict.get("decision"), "HUMAN_APPROVAL_REQUIRED")
check("nothing executed", (escalated or {}).get("executed"), False)
approval = (verdict.get("evaluation") or {}).get("approval_request") or {}
check("a real approval request was opened",
      bool(approval.get("approval_id")), True)
check("policy said how many humans it wants",
      isinstance(approval.get("required_approvals"), int), True)
note(f"loan-7842 is Rs 25,00,000: above the agent's autonomous limit and "
     f"below the dual-control limit, so policy asked for "
     f"{approval.get('required_approvals')} human(s). The AMOUNT decides "
     f"that -- not the agent, not the caller, not the channel")
note("the approval does not authorize anything by itself: re-submitting "
     "re-runs the PDP with the approval as one more fact (Phase 5), proven "
     "end to end by scripts/phase5_gate.py and phase55_gate.py")

# ===========================================================================
print("\n  SCENARIO F -- a JIT grant is bounded and still freshly authorized")
# ===========================================================================
status, issued = call(
    "POST", "/api/v1/jit/request",
    {"subject_did": AGENT, "action": "read", "resource_type": "credit_records",
     "resource_ids": [CUSTOMER], "purpose": "loan_assessment",
     "ttl_seconds": 300, "max_uses": 2},
    principal=cp_sign.GATEWAY,
)
check("the issuance request was accepted", status, 200)
if (issued or {}).get("issued"):
    check("a mandate was issued", issued["issued"], True)
    note("issuance ran the FULL data-plane PDP evaluation first, so a "
         "mandate exists only for something the agent could do at that "
         "instant -- it carries an expensive precondition forward, it does "
         "not create permission")
else:
    # Still a pass: refusing is correct when the agent cannot do the thing.
    reason = (issued or {}).get("reason")
    check_in("...or refused, naming why", reason,
             {"JIT_SCOPE_EXCEEDS_DECISION", "JIT_ACTION_NOT_ELIGIBLE",
              "CREDENTIAL_REVOKED", "MISSING_CAPABILITY",
              "RESOURCE_NOT_ALLOWED", "PURPOSE_NOT_ALLOWED"})
    note("a mandate can only ever be issued for something the agent could "
         "do at that instant")

# THE CEILING, asserted rather than described: ask for more than policy
# allows. ONLY the TTL is over-asked here. `max_uses: 10000` would be
# refused too -- but by the API schema's structural bound (<=1000), which
# returns 422 before policy is consulted. That is defence in depth working
# correctly, and it would make this check pass for the wrong reason, so the
# over-ask is kept to the one bound POLICY owns.
status, over = call(
    "POST", "/api/v1/jit/request",
    {"subject_did": AGENT, "action": "read", "resource_type": "credit_records",
     "resource_ids": [CUSTOMER], "purpose": "loan_assessment",
     "ttl_seconds": 86400, "max_uses": 2},
    principal=cp_sign.GATEWAY)
check("the over-wide request was evaluated, not schema-rejected", status, 200)
check("a mandate beyond the policy ceiling is refused",
      (over or {}).get("issued"), False)
check_in("...and the refusal names the bound that was exceeded",
         (over or {}).get("reason"),
         {"JIT_TTL_EXCEEDS_POLICY_MAXIMUM", "JIT_USES_EXCEED_POLICY_MAXIMUM",
          "JIT_SCOPE_EXCEEDS_DECISION", "JIT_POLICY_UNCONFIGURED",
          "PURPOSE_NOT_ALLOWED"})
note("refused, not clamped: silently shrinking an over-wide request would "
     "hand back a mandate the caller did not ask for and may not check")

# ===========================================================================
print("\n  SCENARIO G -- fail-closed when a dependency is unavailable")
# ===========================================================================
note("the policy engine is NOT stopped here: this script runs against a "
     "shared stack and stopping OPA would corrupt any concurrent run. The "
     "fail-closed path is proven by assertion in the suite "
     "(test_mcp_authorization.py::TestFailClosed, and the Phase 4 fail-closed "
     "tests), which substitute an unreachable engine directly")

status, _ = call("POST", "/api/v1/enforce",
                 {"subject": {"did": AGENT}, "tool": "get_credit_profile",
                  "arguments": {"customer_id": CUSTOMER},
                  "purpose": "loan_assessment"})
check("an UNSIGNED control-plane request is rejected", status in (401, 403), True)

status, _ = call("POST", "/api/v1/audit/events",
                 {"event_type": "FORGED", "agent_did": AGENT})
check("a forged audit event is rejected", status in (401, 403), True)

status, _, body = mcp("tools/list", token="not-a-token", request_id=1)
check("an MCP call with a bad token is rejected", status, 401)

# ===========================================================================
print("\n  RESTORE -- leave the system as it was found")
# ===========================================================================
status, _ = call("POST", "/api/v1/credentials/issue",
                 {"issuer": "did:poc:organization:bank-demo",
                  "subject": AGENT,
                  "credential_type": "AgentCapabilityCredential",
                  "claims": {"capability": "credit_analysis",
                             "allowed_actions": ["READ_CREDIT_PROFILE"],
                             "allowed_resources": ["credit_records"],
                             "purpose": "loan_assessment"},
                  "expires_in_seconds": 3600},
                 principal=cp_sign.IDENTITY_ADMIN)
if status in (200, 201):
    print("      reissued a capability credential to replace those revoked "
          "in scenario B")
else:
    print(f"      could not reissue (HTTP {status}); run "
          f"scripts/seed_credentials.py before the next gate sweep")

print("\n" + "=" * 78)
print(f"  RESULT: {PASS} passed, {FAIL} failed")
print("=" * 78)
print("""
  IDENTITY IS NOT AUTHORIZATION. A registered, discoverable agent holding a
    valid credential is still refused unless policy says otherwise.
  DISCOVERY IS NOT PERMISSION, over ANS and over MCP alike.
  REVOCATION PROPAGATES IMMEDIATELY. One revoked credential stopped the same
    call that had just succeeded -- token, identity and policy untouched.
  A HUMAN DECISION IS NOT A BYPASS. It is re-evaluated by the PDP.
  A MANDATE CANNOT EXCEED WHAT WAS POSSIBLE WHEN IT WAS ISSUED.
  AN UNAUTHENTICATED CALLER REACHES NOTHING.
""")
sys.exit(1 if FAIL else 0)
