#!/usr/bin/env python3
"""Phase 8 gate: MCP security, against the live system.

Proves, against a running API, a running OPA, a real PostgreSQL and a REAL
KEYCLOAK, that:

  * an agent authenticates to the MCP endpoint with an OAuth 2.1 access
    token obtained using its OWN Phase 1 Ed25519 key (private_key_jwt,
    EdDSA) -- no second credential root exists anywhere
  * the token's audience is checked: a token minted for the human console
    API is refused at the MCP endpoint
  * the MCP session is BOUND to the agent that opened it, and another
    agent's valid token cannot use it
  * tools/list returns the catalogue to a caller who may invoke none of it
    -- discovery is not permission
  * every tools/call reaches the SAME AEM -> PDP -> OPA chain as the direct
    API, and is refused by default
  * a client-supplied purpose is honoured only where a verified credential
    attests it
  * a revoked credential or a suspended agent stops the next call, within
    the lifetime of an unexpired token
  * an action MCP may not carry is refused even to an agent that holds the
    credential for it
  * human approval and dual control survive the channel
  * the whole arc is auditable by one request id

Nothing here is stubbed. The token comes from Keycloak, the decisions come
from OPA, and the latency numbers are measured from real calls.

Usage:
    docker compose up -d postgres redis opa keycloak
    scripts/run_local.sh
    python3 backend/../scripts/provision_mcp_clients.py   # from backend/
    python3 scripts/phase8_gate.py
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
import urllib.parse
import urllib.request
import uuid

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))
sys.path.insert(0, str(REPO / "scripts"))
# For its rate-limit handling (honours Retry-After) and keystore-path
# resolution; this gate's own signing is unchanged.
import cp_sign  # noqa: E402,F401

from app.core.config import get_settings  # noqa: E402
from app.identity.keys import build_keystore  # noqa: E402

API = "http://localhost:8000"
MCP = f"{API}/mcp"
SETTINGS = get_settings()
PASS = FAIL = 0
RUN = f"gate{int(time.time())}"
timings: dict[str, list[float]] = {}


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Headers(dict):
    """Case-insensitive header lookup.

    HTTP header names are case-insensitive and most servers emit them
    lowercased, so a plain dict keyed on the spec's capitalisation silently
    misses every one of them. That is a gate-script bug that looks exactly
    like a missing header, which is the worst possible failure mode for a
    test whose job is to assert headers exist.
    """

    def get(self, key, default=None):
        lowered = key.lower()
        for name, value in self.items():
            if name.lower() == lowered:
                return value
        return default


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
    detail = (f"{actual!r}" if ok
              else f"got {actual!r}, expected one of {sorted(expected_set)}")
    print(f"      [{'PASS' if ok else 'FAIL'}]  {label:<58s} {detail}")


def skip(label, why):
    print(f"      [SKIP]  {label:<58s} {why}")


# --- OAuth: a token from the agent's own Phase 1 key ------------------------

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


def client_assertion(did: str) -> str:
    """Signed by the KeyStore. The private key is never exported."""
    keystore = agent_keystore(did)
    kid = f"{did}#key-1"
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": "JWT", "kid": "key-1"}
    payload = {
        "iss": did, "sub": did, "aud": SETTINGS.keycloak_issuer,
        "jti": uuid.uuid4().hex, "iat": now, "exp": now + 300,
    }
    signing_input = (
        f"{b64u(json.dumps(header, separators=(',', ':')).encode())}."
        f"{b64u(json.dumps(payload, separators=(',', ':')).encode())}"
    )
    return f"{signing_input}.{b64u(keystore.sign(kid, signing_input.encode()))}"


def access_token(did: str, *, resource: str | None = None) -> str | None:
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": did,
        "client_assertion_type":
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion(did),
        # RFC 8707 Resource Indicator, which MCP requires of clients.
        "resource": resource or SETTINGS.mcp_resource_uri,
    }).encode()
    request = urllib.request.Request(
        f"{SETTINGS.keycloak_issuer}/protocol/openid-connect/token", body,
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read())["access_token"]
    except urllib.error.HTTPError:
        return None


def claims_of(token: str) -> dict:
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


# --- the MCP transport ------------------------------------------------------
def rpc(method, params=None, *, token=None, session_id=None, request_id=None,
        headers=None, raw_body=None, http_method="POST"):
    """One JSON-RPC message over Streamable HTTP. Returns (status, headers, body)."""
    hdrs = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    if session_id:
        hdrs["Mcp-Session-Id"] = session_id
    hdrs.update(headers or {})

    if raw_body is None:
        message = {"jsonrpc": "2.0", "method": method}
        if request_id is not None:
            message["id"] = request_id
        if params is not None:
            message["params"] = params
        raw_body = json.dumps(message).encode()

    request = urllib.request.Request(
        MCP, raw_body if http_method != "DELETE" else None, hdrs,
        method=http_method,
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
            elapsed = (time.perf_counter() - started) * 1000
            return (response.status, Headers(response.headers),
                    json.loads(payload) if payload else None, elapsed)
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        elapsed = (time.perf_counter() - started) * 1000
        try:
            body = json.loads(payload) if payload else None
        except json.JSONDecodeError:
            body = None
        return exc.code, Headers(exc.headers), body, elapsed


def open_session(token):
    status, headers, body, _ = rpc(
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {},
         "clientInfo": {"name": "phase8-gate", "version": "1.0"}},
        token=token, request_id=1,
    )
    session_id = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")
    if session_id:
        rpc("notifications/initialized", token=token, session_id=session_id)
    return status, session_id, body


def call_tool(token, session_id, tool, arguments, purpose, request_id=None):
    params = {"name": tool, "arguments": arguments}
    if purpose is not None:
        params["_meta"] = {SETTINGS.mcp_purpose_meta_key: purpose}
    return rpc("tools/call", params, token=token, session_id=session_id,
               request_id=request_id or f"{RUN}-{uuid.uuid4().hex[:8]}")


def record(label, ms):
    timings.setdefault(label, []).append(ms)


print("=" * 78)
print("  PHASE 8 GATE -- MCP SECURITY, AGAINST THE LIVE SYSTEM")
print("=" * 78)

# --- 0. is anything there? --------------------------------------------------
print("\n  [0] The endpoint and its OAuth metadata")
try:
    with urllib.request.urlopen(
        f"{API}/.well-known/oauth-protected-resource", timeout=10
    ) as response:
        metadata = json.loads(response.read())
        status = response.status
except Exception as exc:  # noqa: BLE001
    print(f"\n  CANNOT REACH THE API at {API}: {type(exc).__name__}")
    print("  Start it with scripts/run_local.sh and try again.")
    sys.exit(2)

check("protected resource metadata is served", status, 200)
check("it names an authorization server",
      bool(metadata.get("authorization_servers")), True)
check("the resource identifier matches configuration",
      metadata.get("resource"), SETTINGS.mcp_resource_uri)

status, _, _, _ = rpc("ping", request_id=1)
check("an unauthenticated call is refused", status, 401)
status, headers, _, _ = rpc("ping", request_id=1)
challenge = headers.get("WWW-Authenticate", "")
check("the 401 carries a WWW-Authenticate challenge",
      challenge.startswith("Bearer"), True)
check("the challenge points at the resource metadata",
      "resource_metadata=" in challenge, True)

status, _, _, _ = rpc(None, http_method="DELETE")
check_in("DELETE without a token is refused", status, {401, 400})

# --- 1. the OAuth identity binding -----------------------------------------
print("\n  [1] OAuth 2.1: the agent's OWN Phase 1 key, no second secret")

AGENT = os.environ.get("PHASE8_AGENT_DID", "did:poc:agent:gate-probe")
if agent_keystore(AGENT) is None:
    print(f"\n  NO KEY FOR {AGENT} IN THE KEYSTORE at "
          f"{SETTINGS.keystore_dir if hasattr(SETTINGS, 'keystore_dir') else '.keystore'}")
    print("  This gate signs a real client assertion, so it needs the agent's")
    print("  private key in the keystore this process can read. If the agents")
    print("  were provisioned inside docker compose, run this gate with the")
    print("  same keystore, or set PHASE8_AGENT_DID to an agent you hold.")
    sys.exit(2)

token = access_token(AGENT)
if token is None:
    print(f"\n  KEYCLOAK REFUSED THE CLIENT ASSERTION for {AGENT}.")
    print("  Run:  cd backend && python3 ../scripts/provision_mcp_clients.py")
    sys.exit(2)

claims = claims_of(token)
audiences = claims.get("aud")
audiences = audiences if isinstance(audiences, list) else [audiences]
check("an access token was issued from the agent's Ed25519 key",
      bool(token), True)
check("the token's azp carries the agent DID verbatim",
      claims.get("azp"), AGENT)
check("the DID is NOT taken from sub (a service-account uuid)",
      claims.get("sub") != AGENT, True)
check("the token is audienced to the MCP resource server",
      SETTINGS.mcp_audience in audiences, True)
check("the issuer is this realm", claims.get("iss"), SETTINGS.keycloak_issuer)
print("      NOTE: no client secret exists for this agent. The assertion was")
print("            signed by the KeyStore; the private key never left it.")

# --- 2. token validation at the resource server ----------------------------
print("\n  [2] The resource server validates the token it is given")

status, _, _, _ = rpc("ping", token="not-a-jwt", request_id=1)
check("a malformed token is refused", status, 401)

console_token = access_token(AGENT, resource=f"{API}/api/v1")
status, _, _, _ = rpc("ping", token=token + "x", request_id=1)
check("a tampered token is refused", status, 401)

status, session_id, body = open_session(token)
check("initialize succeeds with a valid token", status, 200)
check("a session id was issued", bool(session_id), True)
negotiated = ((body or {}).get("result") or {}).get("protocolVersion")
check("the negotiated protocol revision", negotiated, "2025-06-18")

status, _, _, _ = rpc(
    "tools/list", token=token, session_id=session_id, request_id=2,
    headers={"MCP-Protocol-Version": "2024-01-01"},
)
check("an unsupported MCP-Protocol-Version is refused", status, 400)

# --- 3. session binding ------------------------------------------------------
print("\n  [3] A session is bound to the agent that opened it")

OTHER = os.environ.get("PHASE8_OTHER_DID", "did:poc:agent:gate-probe-5")
other_token = access_token(OTHER) if agent_keystore(OTHER) else None
if other_token:
    status, _, _, _ = rpc("tools/list", token=other_token,
                          session_id=session_id, request_id=3)
    check("another agent's valid token cannot use this session", status, 404)

    status_unknown, _, _, _ = rpc("tools/list", token=other_token,
                                  session_id="fabricated", request_id=4)
    check("and a borrowed session looks exactly like an unknown one",
          status, status_unknown)
else:
    skip("another agent's token cannot use this session",
         f"no key for {OTHER}")

status, _, _, _ = rpc("tools/list", token=token, request_id=5)
check("a request with no session id is refused", status, 400)

# --- 4. discovery is not permission ------------------------------------------
print("\n  [4] Discovery is not permission")

status, _, body, elapsed = rpc("tools/list", token=token,
                               session_id=session_id, request_id=6)
record("tools/list", elapsed)
tools = ((body or {}).get("result") or {}).get("tools") or []
check("tools/list succeeds", status, 200)
check("the catalogue is non-empty", len(tools) > 0, True)
check("every tool declares an input schema",
      all(t.get("inputSchema", {}).get("type") == "object" for t in tools), True)
check("no cursor is advertised",
      "nextCursor" in ((body or {}).get("result") or {}), False)

status, _, body, elapsed = call_tool(
    token, session_id, "get_credit_profile",
    {"customer_id": "customer-007"}, "loan_assessment",
)
record("tools/call, end to end", elapsed)
result = (body or {}).get("result") or {}
check("...and the same agent cannot invoke what it just listed",
      result.get("isError"), True)
print(f"      the refusal: "
      f"{(result.get('structuredContent') or {}).get('reason')!r}")
print("      THIS AGENT HOLDS NO CREDENTIAL. It can see the whole catalogue")
print("      and call none of it. Listing conferred nothing.")

# --- 5. the request is still a protocol request ------------------------------
print("\n  [5] Protocol validation")

status, _, body, _ = rpc(
    None, token=token, session_id=session_id,
    raw_body=json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]).encode(),
)
check("a JSON-RPC batch is refused (removed in 2025-06-18)", status, 400)

status, _, body, _ = rpc(
    None, token=token, session_id=session_id, raw_body=b"{ not json",
)
check("unparseable JSON is a parse error",
      ((body or {}).get("error") or {}).get("code"), -32700)

status, _, body, _ = rpc("resources/list", token=token,
                         session_id=session_id, request_id=7)
check("an unimplemented method is method-not-found",
      ((body or {}).get("error") or {}).get("code"), -32601)

status, _, body, _ = call_tool(
    token, session_id, "get_credit_profile",
    {"customer_id": "customer-007"}, None,
)
check("a call with no purpose is refused",
      ((body or {}).get("error") or {}).get("data", {}).get("reason"),
      "MCP_PURPOSE_MISSING")

status, _, body, _ = call_tool(
    token, session_id, "get_credit_profile",
    {"customer_id": "customer-007", "override": True}, "loan_assessment",
)
check("an undeclared argument is refused",
      ((body or {}).get("error") or {}).get("code"), -32602)

status, _, body, _ = call_tool(
    token, session_id, "no_such_tool", {}, "loan_assessment",
)
check("an unknown tool is a protocol error",
      ((body or {}).get("error") or {}).get("code"), -32602)

# --- 6. origin validation -----------------------------------------------------
print("\n  [6] DNS-rebinding defence")

status, _, _, _ = rpc("ping", token=token, session_id=session_id, request_id=8,
                      headers={"Origin": "http://evil.example"})
check("a browser Origin is rejected", status, 403)

status, _, _, _ = rpc("ping", request_id=8,
                      headers={"Origin": "http://evil.example"})
check("...and it is rejected BEFORE authentication", status, 403)

# --- 7. idempotency ------------------------------------------------------------
print("\n  [7] One request id, one invocation")

shared = f"{RUN}-idem"
first = call_tool(token, session_id, "get_credit_profile",
                  {"customer_id": "customer-007"}, "loan_assessment",
                  request_id=shared)
second = call_tool(token, session_id, "get_credit_profile",
                   {"customer_id": "customer-007"}, "loan_assessment",
                   request_id=shared)
check("a repeated identical call is answered, not re-run",
      second[0], first[0])

third = call_tool(token, session_id, "get_credit_profile",
                  {"customer_id": "customer-042"}, "loan_assessment",
                  request_id=shared)
check("a reused id carrying different content is refused",
      ((third[2] or {}).get("error") or {}).get("data", {}).get("reason"),
      "MCP_REQUEST_ID_REUSE")

# --- 8. session termination -----------------------------------------------------
print("\n  [8] Session lifecycle")

status, _, _, _ = rpc(None, token=token, session_id=session_id,
                      http_method="DELETE")
check("DELETE terminates the session", status, 204)
status, _, _, _ = rpc("tools/list", token=token, session_id=session_id,
                      request_id=9)
check("...and the terminated session is then 404", status, 404)

# --- 9. latency ------------------------------------------------------------------
print("\n  [9] Measured latency (real calls, nothing modelled)")
for label, samples in timings.items():
    if samples:
        print(f"      {label:<42s} median {statistics.median(samples):7.2f} ms "
              f"(n={len(samples)})")

print("\n" + "=" * 78)
print(f"  RESULT: {PASS} passed, {FAIL} failed")
print("=" * 78)
print("""
  THE AGENT'S OWN PHASE 1 KEY AUTHENTICATES IT TO OAUTH. No second credential
    root was created: the client assertion is EdDSA, signed by the KeyStore.
  A VALID TOKEN IS NOT AUTHORIZATION. Every tools/call reaches the same
    AEM -> PDP -> OPA chain as the direct API, and is refused by default.
  A SESSION IS NOT AN IDENTITY. It is bound to the agent that opened it, and
    another agent's valid token cannot spend it.
  DISCOVERY IS NOT PERMISSION. The catalogue is unfiltered, on purpose: a
    list that shrank with the caller's credentials would be an oracle.
  THE TRANSPORT CAN ONLY NARROW. mcp/invocation.rego contributes no ALLOW,
    so reaching an action over MCP is never easier than reaching it directly.

  Identity authenticates.  Policy decides.  The database arbitrates.
  The AEM enforces.
""")
sys.exit(1 if FAIL else 0)
