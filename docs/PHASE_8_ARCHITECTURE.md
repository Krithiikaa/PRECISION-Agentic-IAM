# Phase 8 — MCP Security

**This is an implementation of a documented SUBSET of the Model Context
Protocol, revision 2025-06-18. It is not a complete MCP implementation and
this document does not claim blanket protocol conformance.** Section 3 states
exactly which requirements are implemented and tested, which are not
applicable, which are intentionally unsupported, and which remain unverified.

---

## 1. What Phase 8 adds, in one sentence

An authenticated, session-bound MCP transport in front of the enforcement
architecture that already existed — so an agent can discover and invoke
protected tools over a standard protocol, and every invocation is decided by
exactly the same AEM → PDP → OPA chain as the direct API.

### The three invariants

```
MCP DISCOVERY IS NOT PERMISSION TO INVOKE.
A VALID ACCESS TOKEN IS NOT AUTHORIZATION.
A SESSION ID IS NOT AN IDENTITY.
```

Each is enforced in code, asserted again in Rego, and tested.

---

## 2. Dependency decision

**Zero new runtime dependencies were added.** `requirements.txt` is
unchanged, and no installed package version moved.

The official `mcp` SDK (2.3.0, the current release) was evaluated and
**rejected**. Measured, not assumed:

| | |
|---|---|
| packages pip would add or move | 18 |
| forced upgrades | `pydantic` 2.10.4 → ≥2.12.0, `anyio` 4.7.0 → ≥4.9 |
| second HTTP stack | `httpx2` + `httpcore2` alongside `httpx` 0.28.1 |

`pydantic` is pinned at 2.10.4 and underpins every model in this codebase.
Moving it to gain a transport helper is the wrong trade in a security system
whose regression suite rests on those models. MCP is JSON-RPC 2.0 over
Streamable HTTP — a small, fully specified wire format — and FastAPI already
serves the transport, so it is implemented directly.

**The cost of that choice is that protocol conformance is ours to prove.**
`backend/tests/test_mcp_conformance.py` is that proof: every test quotes the
specification clause it asserts, so a reviewer can check the test against the
published spec without reading the server.

---

## 3. Conformance matrix

Revision **2025-06-18**. Source of truth: the published specification at
`modelcontextprotocol.io/specification/2025-06-18`.

### A. Implemented and tested

| Requirement | Where | Test |
|---|---|---|
| JSON-RPC 2.0 message shapes | `jsonrpc.py` | `TestJSONRPCMessageValidation` |
| Request `id` MUST NOT be null | `jsonrpc.py` | `test_a_null_id_is_refused` |
| `id` must be string or integer | `jsonrpc.py` | `test_a_boolean_id_is_refused`, `test_a_float_id_is_refused` |
| Notifications MUST NOT include an `id` | `jsonrpc.py` | `test_a_notification_has_no_id` |
| **Batching removed in this revision** | `jsonrpc.py` | `test_a_batch_is_refused` |
| `initialize` is the first interaction | `protocol.py` | `TestInitialization` |
| Version negotiation (unsupported → answer with a supported one) | `protocol.negotiate_version` | `test_an_unsupported_requested_version_is_answered_with_a_supported_one` |
| `notifications/initialized` | `protocol.dispatch` | `test_the_initialized_notification_is_accepted_with_202` |
| Capability negotiation; server declares only what it implements | `protocol.handle_initialize` | `test_initialize_returns_version_capabilities_and_server_info` |
| Single MCP endpoint supporting POST and GET | `routes/mcp.py` | `TestStreamableHTTPTransport` |
| `Accept` MUST list both `application/json` and `text/event-stream` | `routes/mcp.py` | `test_accept_must_list_both_content_types` |
| Request → `application/json` response | `routes/mcp.py` | `test_a_request_gets_an_application_json_response` |
| Notification → **202 Accepted**, no body | `routes/mcp.py` | `test_the_initialized_notification_is_accepted_with_202` |
| GET → **405** when no SSE stream is offered | `routes/mcp.py` | `test_get_returns_405_when_no_sse_stream_is_offered` |
| `Mcp-Session-Id` issued at initialize; visible ASCII | `session.py` | `test_initialize_issues_a_session_id_header` |
| Missing session id → **400** | `routes/mcp.py` | `test_a_missing_session_id_is_400` |
| Unknown / terminated session → **404** | `session.py` | `test_an_unknown_session_id_is_404` |
| DELETE terminates a session | `routes/mcp.py` | `test_delete_terminates_the_session` |
| Invalid `MCP-Protocol-Version` → **400** | `routes/mcp.py` | `test_an_unsupported_protocol_version_header_is_400` |
| **Origin MUST be validated** (DNS rebinding) | `routes/mcp.py` | `TestOriginValidation` |
| `tools/list` shape (`name`, `description`, `inputSchema`) | `protocol.py` | `TestToolsList` |
| `tools/call` shape (`content`, `isError`, `structuredContent`) | `protocol.py` | `TestCredentialDrivenAuthorization` |
| Protocol error vs tool execution error | `protocol.py` | `TestMethodDispatch`, `TestArgumentValidation` |
| Unknown tool → `-32602` | `protocol.py` | `test_an_unknown_tool_is_a_protocol_error` |
| Unknown method → `-32601` | `protocol.py` | `test_an_unknown_method_is_method_not_found` |
| **Server is an OAuth 2.1 Resource Server** | `auth.py` | `TestTokenValidation` |
| **RFC 9728 Protected Resource Metadata** at `/.well-known/oauth-protected-resource` | `routes/mcp.py` | `TestProtectedResourceMetadata` |
| `authorization_servers` names ≥1 server | `auth.py` | `test_the_well_known_document_is_served` |
| **`WWW-Authenticate` on 401 with `resource_metadata`** | `auth.py` | `test_a_401_carries_www_authenticate_with_resource_metadata` |
| **Token audience MUST be validated** | `auth.py` | `test_a_token_for_another_audience_is_401` |
| Tokens MUST NOT be read from the query string | `auth.py` | `test_a_token_in_the_query_string_is_not_accepted` |
| `Authorization: Bearer` on every request | `auth.bearer_token` | `TestTokenValidation` |

### B. Not applicable to this deployment

| Requirement | Why |
|---|---|
| stdio transport | This is a network service, not a subprocess. The spec says stdio implementations "SHOULD NOT" follow the authorization spec and take credentials from the environment, which is the opposite of what is needed here. |
| Dynamic Client Registration (RFC 7591) | Agents are provisioned, not self-registering. An agent's OAuth client is created by `scripts/provision_mcp_clients.py` from its existing Phase 1 key. Self-registration would be a way to obtain an identity without being issued one. |
| PKCE, redirect URIs, `state` | These belong to the authorization-code flow. Agents use `client_credentials` with `private_key_jwt`; there is no user agent and no redirect. |
| Backwards compatibility with the 2024-11-05 HTTP+SSE transport | Deliberately not offered. Supporting a superseded transport alongside this one widens the attack surface for clients that do not exist. |
| HTTPS-only endpoints | The spec requires it for authorization server endpoints. This POC runs on `http://localhost`; **any real deployment must terminate TLS** — see Limitations. |

### C. Intentionally unsupported

| Feature | Decision |
|---|---|
| Server-initiated SSE stream (`GET /mcp`) | Answered with **405**, which the transport spec explicitly provides for. Nothing here streams partial results and the server never initiates a request to a client, so the stream would exist only to stay empty. |
| SSE resumability / `Last-Event-ID` | Follows from having no stream. |
| `resources/*`, `prompts/*`, `completion/*`, `logging/*` | Not declared in server capabilities and answered with `-32601`. **Declaring a capability this server does not implement would be the overstatement this phase was told to avoid.** Protected data in this system is reached through tools, which carry the enforcement boundary. |
| `notifications/tools/list_changed` | `listChanged: false` is declared. The catalogue is static for a process lifetime, and advertising a notification that never arrives would be a false capability. |
| Pagination (`cursor` / `nextCursor`) | The catalogue is small and returned in one page. A `cursor` this server never issued is refused rather than ignored. |
| Elicitation, sampling, roots | Client capabilities; this is a server. |

### D. Unverified

| Item | Status |
|---|---|
| Interoperability with third-party MCP clients (Claude Desktop, SDK clients) | **Not tested.** No official client was run against this server. Conformance evidence is the spec-quoting test suite, not an interop run. This is the most significant gap in the evidence. |
| Behaviour under protocol revisions other than 2025-06-18 | Only one revision is accepted; others are refused at the header and answered-down at `initialize`. Nothing else was exercised. |
| TLS / proxy behaviour | Untested; the POC runs plaintext on localhost. |
| Sustained load and session-table growth | Only the bounded concurrency in `test_mcp_concurrency.py` was measured. |

---

## 4. Transport and authentication architecture

```
MCP client
    │  Authorization: Bearer <access token>
    │  Mcp-Session-Id, MCP-Protocol-Version, Accept
    ▼
routes/mcp.py ───── 1. Origin            (DNS rebinding; before auth)
                    2. Accept / Content-Type
                    3. token validation  → agent DID         auth.py
                    4. MCP-Protocol-Version
                    5. JSON-RPC parse    (batches refused)   jsonrpc.py
                    6. session resolve   FOR that DID        session.py
    ▼
protocol.py  ───── MCP method semantics; purpose from _meta; strict
                   argument validation; the invocation ledger
    ▼
AdapterEnforcementMiddleware.enforce()        ← the SAME call the direct API makes
    ▼
PIP  (credentials, approvals, mandates, agent status, + the MCP fact)
    ▼
PDP → OPA   deny-overrides, default-deny
    ▼
AEM  mints a single-use grant
    ▼
protected tool
```

**Origin is checked before authentication.** A DNS-rebinding attack rides a
browser that already holds credentials; validating the token first would
authenticate the victim and only then ask whether the page was allowed to
make the call.

---

## 5. OAuth-to-agent identity mapping

### No second credential root

Keycloak's realm supports `private_key_jwt` with **EdDSA** client assertions.
An agent therefore authenticates to the token endpoint by signing a
short-lived assertion with **the same Ed25519 key it has held since Phase 1**.

```
agent Phase 1 Ed25519 key (in the KeyStore, never exported)
        │ signs a client assertion (EdDSA)
        ▼
Keycloak client whose clientId IS the agent DID
        │ client_credentials + private_key_jwt
        ▼
access token:  azp = did:poc:agent:...     ← the identity binding
               aud = agentic-iam-mcp
               sub = <service-account uuid> ← NOT the agent
```

Verified end to end against live Keycloak; `scripts/phase8_gate.py` repeats
the exchange on every run. **No client secret is created, stored or printed.**

### Three rules that are load-bearing

1. **Bind on `azp`, never on `sub`.** `sub` is a Keycloak-internal
   service-account UUID, unrelated to the DID. A server binding on it would
   authenticate successfully and attribute the call to the wrong principal.
   Tested by giving the two different values
   (`test_identity_binds_on_azp_and_not_on_sub`).

2. **A valid token is not a valid agent.** Keycloak knows nothing about agent
   lifecycle: a token minted at 09:00 stays cryptographically valid until it
   expires even if the agent was suspended at 09:01. Agent status is
   re-established by the **PIP on every evaluation**, which is what closes
   that window (`test_deactivating_the_agent_stops_the_next_call`).

3. **Audience separation.** The MCP resource server's audience
   (`agentic-iam-mcp`) is distinct from the human console API's
   (`agentic-iam-api`), so neither token works at the other endpoint
   (`test_a_token_for_another_audience_is_401`).

---

## 6. Purpose validation

`tools/call` has no purpose field, and Phase 4 requires one. Three obvious
answers are all wrong:

- **Infer it from the tool** — collapses action and purpose, the two things
  Phase 4 deliberately separated, and makes `PURPOSE_NOT_ALLOWED` unreachable.
- **Default it** — authorises reads for a reason nobody claimed.
- **Trust the client** — a claim by the party being authorized.

**What is actually done:** the client states a purpose in `params._meta`, and
that statement is a **selector, never a grant**. The authoritative set comes
from `policies/decision.rego`:

```rego
allowed_purposes contains p if {
	some c in valid_credentials      # c.valid == true, issuer-signed, PIP-verified
	p := c.claims.purpose
}
```

A purpose the agent holds no credential for is denied `PURPOSE_NOT_ALLOWED`,
and the combining algorithm is default-deny. **The trusted source for purpose
is the Phase 2 Verifiable Credential.** Absent or malformed → refused; there
is no fallback that produces a usable purpose.

### On the `_meta` key

There is no purpose field in MCP and this implementation does not pretend to
add one. `_meta` is the specification's sanctioned place for implementation
metadata. The key used —
`agentic-iam.precisionit.co.in/purpose` — carries a non-reserved prefix
(reserved prefixes are those whose labels include `modelcontextprotocol` or
`mcp`), so it cannot collide with a future protocol key. **It is an extension
of this deployment, and is not part of MCP.**

---

## 7. Session and revocation semantics

A session id travels in a header on every request, so it is a bearer value.
It is therefore **bound** to the agent that opened it, and every request
authenticates independently; the two must agree.

| Event | Effect | Enforced by |
|---|---|---|
| Another agent presents the session | 404, identical to an unknown session | `session.resolve` (ownership checked **before** status, so an attacker learns nothing) |
| Client sends DELETE | `TERMINATED`, then 404 | `routes/mcp.py` |
| Idle past the window | `EXPIRED`, then 404 | `session.resolve` |
| Agent deactivated | **next call denied by policy**, regardless of session or token | **the PIP** |
| `revoke_for_agent()` | sessions `REVOKED` | `session.py` — a convenience, *not* the control |
| Credential revoked | next call denied | **the PIP** |

**Revocation is effective within an unexpired token's lifetime** because the
PIP re-reads credential and agent state inside every evaluation. Closing
sessions makes the refusal faster and clearer; it is not what makes it true.

---

## 8. Tool and resource authorization

**Discovery is unfiltered, deliberately.** `tools/list` returns the catalogue
without consulting policy and without regard to the caller's credentials:

1. Filtering by what the caller could invoke would put a second copy of "what
   may be called" in Python beside the real one in Rego. The copy would drift.
2. **A filtered list leaks.** If the catalogue shrank when a credential
   expired, discovery would be an oracle for which credentials an agent holds.

So an agent can see a tool it will never be allowed to call. That is correct.

**Invocation** goes through `AEM.enforce()` unchanged. The tool is looked up
in the Phase 4 `ProtectedToolRegistry`, and the authorization request is built
from the **tool's declared action and resource**, never from anything the
client said about them.

### The policy module contributes DENY only

`policies/mcp/invocation.rego` is the central design decision of the phase.
MCP is a *transport* for actions other modules already decide —
`get_credit_profile` over MCP is the same question `loan/credit.rego` already
answers. An `allow` here would be a **second** way to permit something that
already had one, and under deny-overrides a second allow is a widening.

So the module only subtracts:

| Rule | Denies |
|---|---|
| `MCP_POLICY_UNCONFIGURED` | the data document is absent (fails closed) |
| `MCP_SESSION_NOT_BOUND` | the session is not bound to the caller |
| `MCP_TOKEN_MISSING` | the transport did not authenticate |
| `MCP_ARGUMENTS_MALFORMED` | arguments did not validate |
| `MCP_ACTION_NOT_ELIGIBLE` | the action may not be carried over MCP |
| `PURPOSE_NOT_ALLOWED` | no valid credential attests the purpose |
| `RESOURCE_NOT_ALLOWED` | no valid credential names the resource |

**Zero new cross-module Rego names.** `decision.rego` and
`security/sensitive.rego` are untouched. Removing the module leaves every
other module compiling and denies rather than grants.

### Why payments are not reachable over MCP

`execute_payment` is absent from `policies/data/mcp_policy.json`. Over A2A a
payment arrives inside an envelope signed by the instructing agent's own key,
bound to a receiver, non-replayable, and reconciled four times. An MCP call
carries a bearer token and nothing else — no signed instruction to show a
human at approval time and nothing to non-repudiate with afterwards.
Exposing payments here would be a **strictly weaker path to the same action**,
and the weaker path is the one an attacker takes.

`approve_loan` *is* eligible, which is not the same as being performable:
`security/sensitive.rego` escalates it and `loan/amount.rego` decides to how
many humans. An MCP client can at most open an approval request, and dual
control is unaffected by the channel — asserted by
`test_dual_control_survives_the_mcp_channel`.

---

## 9. Threat model

| Threat | Control | Test |
|---|---|---|
| No credential presented | 401 + `WWW-Authenticate` | `test_no_token_is_401` |
| Forged / tampered token | Signature verified against Keycloak JWKS | `test_a_garbage_token_is_401` |
| `alg: none`, HS256 key confusion | Algorithm **allow-list**, checked before key fetch | `test_an_unsigned_token_is_401` |
| Token from another service reused here | Audience validation | `test_a_token_for_another_audience_is_401` |
| Token from another realm | Issuer validation | `test_a_token_from_another_issuer_is_401` |
| Expired token | Expiry validation | `test_an_expired_token_is_401` |
| Non-agent client (the console) | `azp` must be a DID | `test_a_token_whose_azp_is_not_a_did_is_401` |
| **Identity confusion (`sub` vs `azp`)** | Bind on `azp` | `test_identity_binds_on_azp_and_not_on_sub` |
| **Session theft / borrowing** | Session bound to agent; ownership checked first | `test_another_agents_session_cannot_be_used` |
| Session enumeration | Borrowed and unknown are byte-identical refusals | `test_a_borrowed_session_is_indistinguishable_from_an_unknown_one` |
| **DNS rebinding** | Origin validated, before authentication | `TestOriginValidation` |
| Replay / duplicate side effect | `UNIQUE (session_id, request_id)` | `test_twenty_concurrent_identical_calls_record_one_invocation` |
| Request-id reuse carrying new content | Content digest compared | `test_a_reused_request_id_with_different_content_is_refused` |
| Argument smuggling | Allow-list validation; unknown fields **rejected** | `test_an_undeclared_argument_is_refused` |
| Purpose forgery | Must intersect credential-attested purposes | `test_a_purpose_no_credential_attests_is_denied` |
| **Tool output treated as instructions** | Output is data; never reaches the authorization context | `test_a_tool_result_cannot_influence_the_next_decision` |
| Self-asserted verdict in the request | `strip_decision_claims()` | `test_a_self_asserted_verdict_in_the_request_is_ignored` |
| Credential revoked mid-session | PIP re-reads every evaluation | `test_revoking_the_credential_stops_the_next_call` |
| Agent deactivated mid-session | PIP re-reads every evaluation | `test_deactivating_the_agent_stops_the_next_call` |
| Policy engine unreachable | Fails closed, `AUTHORIZATION_UNAVAILABLE` | `test_an_unreachable_policy_engine_denies` |
| Policy data missing | Fails closed, `MCP_POLICY_UNCONFIGURED` | `test_removing_the_policy_data_document_fails_closed` |
| Batch smuggling a second call | Batches refused by shape | `test_a_batch_is_refused` |
| HITL bypass via the channel | Escalation unchanged | `test_a_sensitive_action_over_mcp_still_escalates` |
| Dual-control downgrade | Band decided by amount, not channel | `test_dual_control_survives_the_mcp_channel` |
| Credential leakage into storage/logs | Only `jti` stored; asserted | `test_no_token_or_secret_reaches_the_ledger` |

---

## 10. What is stored, and what is not

**Stored:** session → agent binding, negotiated protocol version, token
`jti`, tool name, declared action/resource, claimed purpose, claimed /
authorized / executed arguments, the policy decision, and the result.

**Never stored:** access tokens, client assertions, bearer credentials,
private key material. `token_jti` identifies a token without being one.

Tool **arguments** are stored, deliberately and with a bounded justification:
an argument is the thing policy authorized and the thing that was executed,
so reconciliation is impossible without it. The protected tools here take
record identifiers, not secrets. **A tool whose arguments were themselves
sensitive would need a redaction policy before being exposed over MCP** — see
Limitations.

---

## 11. Known limitations

1. **No interoperability testing with a third-party MCP client.** The
   conformance evidence is a spec-quoting test suite, not an interop run.
   This is the largest gap.
2. **Plaintext HTTP.** The POC runs on `http://localhost`. The MCP
   authorization spec requires HTTPS for authorization server endpoints; a
   real deployment must terminate TLS.
3. **Argument redaction is not implemented.** Arguments are stored verbatim.
   Safe for the current tool set; not safe for a tool taking a secret.
4. **`mcp_allowed_origins` is empty by default**, so no browser-based client
   can connect. This is correct for a service-to-service endpoint and will
   need configuring for any browser client.
5. **Keycloak client lifecycle is a separate script.** Provisioning and
   revoking an agent's OAuth client is not automatic on agent registration.
   Revocation remains *effective* regardless, because the PIP decides — but
   a disabled agent can still obtain a token until the client is disabled.
6. **One protocol revision.** Only 2025-06-18 is accepted.
7. **No rate limiting.** The tools spec says servers should rate limit tool
   invocations; this is not implemented. Exactly-once deduplication is not a
   rate limit.
8. **This does not provide legal non-repudiation.** An OAuth bearer token
   proves possession, not authorship, and nothing in this phase produces a
   signed record of intent the way the A2A envelope does. That asymmetry is
   precisely why payments are not MCP-eligible.

---

## 12. Measured performance

Against the live stack (real Keycloak, real OPA, real PostgreSQL), medians
over 10 calls each:

| | |
|---|---|
| `initialize` (OAuth token already held) | 64 ms |
| `tools/list` | 21 ms |
| `tools/call`, full AEM → PDP → OPA → tool | 81 ms |

The `tools/call` figure is dominated by the authorization evaluation, which
happens on the direct API path too — that is the point. The MCP-specific
cost is token validation (cached JWKS), the session lookup and the ledger
INSERT. Obtaining the OAuth token itself is a separate one-off exchange with
Keycloak and is not counted here, because a client holds a token for its
900-second lifetime across many calls.

## 13. Files

**New:** `backend/app/protocols/mcp/{__init__,jsonrpc,auth,session,purpose,arguments,service,protocol}.py`,
`backend/app/api/routes/mcp.py`, `backend/app/db/models/mcp.py`,
`backend/alembic/versions/a4f19c7e5b22_phase8_mcp_security.py`,
`policies/mcp/invocation.rego`, `policies/data/mcp_policy.json`,
`scripts/provision_mcp_clients.py`, `scripts/phase8_gate.py`,
`backend/tests/test_mcp_{conformance,security,authorization,concurrency,integration}.py`.

**Modified (additively):** `config.py` (Phase 8 settings),
`contracts.py` (Phase 8 reasons), `pip.py` / `pdp.py` / `aem.py` (an
*optional* `mcp` fact defaulting to absent), `monitoring/events.py`,
`db/models/__init__.py`, `main.py` (router), `policies/manifest.json`,
`keycloak/realm-agentic-iam.json` (a client scope), `tests/conftest.py`.

**Never modified:** `policies/decision.rego`, `policies/security/sensitive.rego`,
`policies/loan/*`, `policies/jit/*`, `policies/a2a/*`,
`ApprovalAuthority.rotate()`, every existing migration, and
`AEM.enforce_a2a()`.
