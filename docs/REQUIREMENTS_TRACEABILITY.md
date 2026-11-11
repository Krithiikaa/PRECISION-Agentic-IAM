# Requirements traceability matrix

**Sources.** `R-nn`: *Agentic AI Identity and Access Management: A New Approach* (CSA, 2025-08-11, 85 pp.). `P-nn`: the matching CSA presentation (29 slides). `BP`: the *Agentic IAM Complete Workflow Blueprint* and the *Complete Architecture* image. The requirement lists were extracted page by page (paper) and slide by slide (deck). Every `R` row cites the paper page. The deck adds almost nothing beyond the paper, so each deck item is cross-referenced in the **P** column rather than repeated.

**Status legend** (the prompt's categories):

| Code | Meaning |
|---|---|
| **VERIFIED** | Implemented and verified by an automated test or a live gate named in the Evidence column |
| **IMPL-UNVERIFIED** | Implemented, but no test proves the specific property |
| **PARTIAL** | Some of the requirement is built; the Gap column says what is not |
| **NOT IMPL** | Not built. Planned action and target given |
| **N/A** | Not applicable to this POC; justification given |
| **BLOCKED** | Needs infrastructure, a provider or a person this repository cannot supply |
| **DEFERRED** | Deliberately not built now; reason and completion target given |

**Evidence shorthand.**
- **New tests (this increment):**
  - `T-TC`: `tests/test_trust_and_containment.py`
  - `T-DI`: `tests/test_delegated_identities.py`
  - `T-LW`: `tests/test_loan_workflow.py`
- **Live end-to-end:** `E2E` is `scripts/loan_workflow_e2e.py`, 33/33 against the running 9-agent system.
- **Phase 12 tests:**
  - `T-AI`: `tests/test_audit_integrity.py` (tamper-evident audit)
  - `T-P12C`: `tests/test_phase12_containment.py` (containment bypass attempts)
  - `T-DW`: `tests/test_durable_loan_workflow.py` (restart, concurrency, idempotency)
  - `T-ST`: `tests/test_session_trust_sync.py` (stale trust state never authorizes)
  - `T-CORS`: `tests/test_cors_configuration.py`
  - `RT12`: `scripts/phase12_restart_test.py`, live, IAM API killed and restarted mid-workflow
  - `UI12`: `frontend/e2e/phase12_ui_e2e.py`, 57 browser checks of the Phase 12 console views
- **Phase 12 status note.** `BLOCKED` below is the prompt's `BLOCKED_EXTERNAL`: it needs a party, certificate, hardware or assessment this repository cannot supply. The Phase 12 per-requirement summary is in [PHASE_12_FINAL_REPORT.md](PHASE_12_FINAL_REPORT.md) §3.
- **Earlier gates:** `G1`–`G9` are `scripts/phaseN_gate.*` and `phase9_e2e.py`.
- **Existing test files** are cited by name.

Phase 12 is the final implementation phase; W1–W3 targets below that Phase 12 did not close are now **DEFERRED (no target)** unless marked EXT. Original targets used the plan in [FRAMEWORK_COMPLETION_REPORT.md §13](FRAMEWORK_COMPLETION_REPORT.md#13-remaining-work-and-targets): **W1** = week of 2026-11-16, **W2** = 2026-11-23, **W3** = 2026-11-30, **EXT** = needs an external party.

---

## 1. Traditional IAM gaps and OAuth changes (paper §2.1, pp. 13–17)

| Req | P | Existing implementation | Evidence | Gap | Planned action | Status |
|---|---|---|---|---|---|---|
| R-01 granular permissions | P-73 | Capability VCs name actions, resources and purpose. Rego decides per (action, resource, purpose) | `test_authorization_security_matrix.py`, G4 | — | — | VERIFIED |
| R-02 easily revocable | P-74 | VC status list. Agent suspension. JIT revocation. Kill switch (Session Authority) | `test_credential_verification.py`, T-TC `TestSessionAuthority`, E2E-E | — | — | VERIFIED |
| R-03 fully auditable | P-75 | Append-only `audit_events` with monotonic seq; every PDP and AEM step recorded; queryable by `request_id`. **Phase 12:** write-time MAC, hash chain, signed checkpoints, append-only trigger | `test_api.py`, E2E-G, T-AI | Legacy rows before the genesis are outside coverage (reported, not verified) | — | VERIFIED |
| R-04 cross-boundary agent communication | P-50 | Signed A2A envelopes; DID-based peer verification | `test_a2a_envelope.py`, G7 | Single trust domain only | see R-236/R-241 | PARTIAL |
| R-05 fluid ownership | P-31 | `owner` and `controller` recorded; identity admin can republish the profile | — | No ownership-transfer operation with audit | Add `agent_owner_transfer` op (W2) | PARTIAL |
| R-06 agents as first-class actors | P-105 | Agents have their own DID and key; MCP clients use `private_key_jwt` with `clientId` = DID | `test_mcp_authorization.py`, G8 | — | — | VERIFIED |
| R-07 agent-specific policies and tracking | — | Human and agent principals are separate types; data-plane Rego never reads human roles | `test_control_plane_security_matrix.py` | — | — | VERIFIED |
| R-08 agent permission model, not user proxy | — | Agents act on their OWN credentials. A2A authorizes the sender, never the receiver | `test_a2a_authorization.py` | — | — | VERIFIED |
| R-09 on-behalf-of chain distinguishable | P-81 | Delegated identities record parent, depth and `requested_by`. Workflow steps record `instructed_by` | T-DI `TestSpawning`, T-LW | No human-on-behalf-of claim on agent decisions | Add the submitting officer to the step context (W2) | PARTIAL |
| R-10 human request vs agent decision | P-103 | Workflow submission (human) and step execution (agent) are separate audit events | E2E-G | — | — | IMPL-UNVERIFIED |
| R-11 permission discovery and delegation | P-107 | JIT mandates; delegated identities request scopes from verified parent credentials | `test_jit_lifecycle.py`, T-DI | No "what do I need?" discovery API | DEFERRED: needs a capability ontology (R-291) | PARTIAL |
| R-12 – R-16 fine-grained scopes (collections, hierarchy, class, query, individual) | P-73 | Individual resource IDs bound into grants. Resource types per credential | `test_aem_enforcement.py` | Collections, hierarchies, classes and query scopes are not modelled | DEFERRED: no data source in the POC has hierarchies. Target W3 for `dataSensitivity` classes (R-165) | PARTIAL |
| R-17 no session-long trust | — | PDP is re-evaluated per request. Trust is recomputed live | `test_pip.py`, T-TC | — | — | VERIFIED |
| R-18 sender-bound tokens | — | Control-plane and A2A requests are signed per request with a nonce. MCP bearer tokens are NOT sender-bound | `test_control_plane_auth.py` | MCP uses bearer tokens (no DPoP) | DEFERRED W3: DPoP on MCP | PARTIAL |
| R-19 sub-agent identity model | P-06 | Delegated identities: SUB_AGENT, EPHEMERAL, FORK | T-DI | — | — | VERIFIED |
| R-20 native agent-to-agent delegation | P-79 | Delegation narrows the parent's verified credentials into child credentials | T-DI `TestDelegationCannotEscalate` | — | — | VERIFIED |
| R-21 strong trust signals in federation | — | Single domain | — | No federation | see R-236 | DEFERRED (W3 design, EXT for a second domain) |
| R-22 machine-speed authentication | — | Ed25519 per-request proofs; rate limits sized per tier | `test_rate_limiting.py` | Not load-tested at "148x" volume | see R-285 | PARTIAL |
| R-23 continuous authn/authz | — | Every request is authenticated and decided | T-TC, `test_pip.py` | — | — | VERIFIED |
| R-24 confused-deputy prevention | P-84 | A2A authorizes the sender. Workflow specialists use their OWN key and credentials | `test_a2a_authorization.py`, T-LW `TestSpecialistBoundaries` | — | — | VERIFIED |
| R-25 IdP-controlled agent connections | — | MCP client registration in Keycloak is an administrative script | G8 | No admin approval UI | DEFERRED W3 | PARTIAL |
| R-26 – R-28 MCP preference manipulation, tool squatting, rug pull | P-115 | Tools are a closed server-side registry. `tools/list` is static | `test_mcp_security.py` | No signed or versioned tool definitions (ETDI, R-131) | see R-131 | PARTIAL |
| R-29 cross-prompt injection | P-116 | The LLM never selects protected tools; the workflow uses an explicit capability (no LLM routing) | `test_runtime.py` | No prompt-content guardrails | DEFERRED W3 (input guard on `/task`) | PARTIAL |
| R-30 memory poisoning | — | Agents hold no persistent memory | — | — | — | N/A (no agent memory exists) |
| R-31 cascading hallucinations | — | Decisions are deterministic rules plus policy; the LLM output is never authoritative | `test_runtime.py` | — | — | IMPL-UNVERIFIED |

## 2. Human-scoped and MAS insufficiencies (paper §2.1.1–§2.2, pp. 17–23)

| Req | P | Existing implementation | Evidence | Gap | Planned action | Status |
|---|---|---|---|---|---|---|
| R-32 DIDs/VCs even for assistants | P-34 | Every agent, including delegated ones, has a DID and VCs | `test_did.py`, T-DI | — | — | VERIFIED |
| R-33 human OIDC to the platform | P-111 | Keycloak OIDC for every human operation | `test_oidc_human_identity.py`, G5 | — | — | VERIFIED |
| R-34 Kerberos for operators | — | — | — | — | Out of scope: no Kerberos realm exists | N/A |
| R-35 LDAP attributes seed VCs | — | — | — | No directory | Needs an LDAP/AD source | BLOCKED (EXT) |
| R-36 initial context from the human session | — | Workflow submission records the officer of record | E2E-C (maker-checker) | Agents do not inherit human permissions, by design | — | PARTIAL (by design) |
| R-37 OAuth 2.1 single-agent access | — | MCP gateway with OAuth 2.1 (`private_key_jwt`) | G8 | — | — | VERIFIED |
| R-38 no privilege retention after creator leaves | — | Credentials have a 1-hour TTL and must be re-seeded | — | No link from creator departure to revocation | DEFERRED W3: needs HR feed (EXT) | PARTIAL |
| R-39 task-specific permissions without re-auth | — | JIT mandates; ephemeral delegated identities | `test_jit_lifecycle.py`, T-DI | — | — | VERIFIED |
| R-40 granular authority to sub-agents | P-79 | Child credentials are subsets of the parent's verified credentials | T-DI | — | — | VERIFIED |
| R-41 auditable delegation chain | P-07 | Provenance VC, `agent_relationships`, `/lineage`, AGENT_SPAWNED events | T-DI `test_lineage_reports_both_directions` | — | — | VERIFIED |
| R-42 acting for multiple principals | — | — | — | Not modelled | DEFERRED W3 | NOT IMPL |
| R-43 context-aware restriction | P-76 | Amount bands; trust-adaptive escalation; anomaly rules | `test_loan_amount_policy.py`, T-TC | No semantic rules (e.g. "zero all inventory") | Business-specific; DEFERRED | PARTIAL |
| R-44 scalable ephemeral token management | P-147 | Ephemeral identities expire and are swept; spawn rate limited | T-DI `TestLifecycle` | Not load-tested | see R-285 | PARTIAL |
| R-45 P2P mutual authentication without shared secrets | — | Signed instructions verified against public DID Documents | T-LW `TestPeerInstructions` | — | — | VERIFIED |
| R-46 authorization separate from authentication | — | Authentication (proof/OIDC) and authorization (OPA) are separate stages | `test_control_plane_auth.py` | — | — | VERIFIED |
| R-47 secret sprawl control | P-52 | No agent secrets; keys in encrypted keystores; no MCP client secrets | G8 | No HSM/KMS | see R-238 | PARTIAL |
| R-48 audit at token volume | — | Indexed audit table | — | Not load-tested | see R-285 | PARTIAL |
| R-49 global logout / revocation | P-95 | **Session Authority kill switch**: SSS lockout, identity suspend, JIT and MCP revocation, ANS revoke, cascade to children. **Phase 12:** pending and approved-but-unspent human approvals cancelled | T-TC, T-P12C, E2E-E | — | — | VERIFIED |
| R-50 handle unprogrammed access attempts | — | Default-deny combining algorithm | `test_pdp_opa.py` | — | — | VERIFIED |
| R-51 ephemeral authentication | — | Ephemeral identities with short TTL; key destroyed at expiry | T-DI `test_an_expired_child_...` | — | — | VERIFIED |
| R-52 detect capability drift | — | SCOPE_VIOLATION rule; declared vs attested capabilities in PIP | T-TC | Only denial-visible drift is detected | see R-202 | PARTIAL |
| R-53 verifiable provenance | P-102 | Signed requests, signed A2A envelopes, per-step audit. **Phase 12:** each audit row MACed at write and hash-chained under signed checkpoints | `test_a2a_envelope.py`, E2E-G, T-AI | Audit rows are not signed by the acting agent's DID (the chain is signed by the platform) | — | PARTIAL |
| R-54 prevent self-granted privileges | — | Agents cannot reach admin operations (cp-agent-self). Delegation cannot exceed the parent | `test_control_plane_security_matrix.py`, T-DI | — | — | VERIFIED |
| R-55 collusion detection | — | — | — | No cross-agent correlation rule | DEFERRED W3: graph rule over A2A pairs | NOT IMPL |
| R-56 dynamic least privilege | — | Per-request decisions; JIT; trust-adaptive narrowing | T-TC, `test_jit_policy.py` | — | — | VERIFIED |
| R-57 mTLS + DIDs + micro-segmentation | — | DIDs and signed requests | — | No mTLS between services | Accepted risk (trusted segment) | DEFERRED (EXT: needs a PKI) |

## 3. The Agent ID (paper §3, pp. 24–27)

| Req | P | Existing implementation | Evidence | Gap | Planned action | Status |
|---|---|---|---|---|---|---|
| R-58 rich, verifiable, dynamic Agent ID | P-01 | DID + key + DID Document + rich **Agent ID profile** + VCs | T-DI `TestAgentIdProfile` | — | — | VERIFIED |
| R-59 unique over time, incl. clones and ephemerals | P-03/04 | Each child gets a fresh DID and key | T-DI `test_a_child_is_a_distinct_identity...` | — | — | VERIFIED |
| R-60 agents controlling other NHIs | — | MCP OAuth client per agent DID | G8 | — | — | PARTIAL |
| R-61 termination; no dormant IDs | P-16 | Terminate destroys the key. Ephemeral sweep. PIP treats expired as inactive | T-DI `TestLifecycle` | — | — | VERIFIED |
| R-62 persistent agents | P-02 | 9 provisioned agents survive restarts | `phase1_restart_test.sh` | — | — | VERIFIED |
| R-63 ephemeral agents | P-03 | `DelegationKind.EPHEMERAL` | T-DI | — | — | VERIFIED |
| R-64 forks with provenance | P-04/05 | `DelegationKind.FORK`, `FORKED_FROM` relationship, inherits no access | T-DI `test_a_fork_inherits_no_access` | — | — | VERIFIED |
| R-65 hierarchical agents with a VC parent link | P-06/07 | `AgentProvenanceCredential` verified by the Phase 2 verifier | T-DI `test_the_parent_link_is_a_verifiable_credential` | — | — | VERIFIED |
| R-66 DID anchor | P-08 | `did:poc` | `test_did.py` | Not a registered DID method | see R-225 | VERIFIED (POC method) |
| R-67 key pairs in `verificationMethod` | P-09 | Ed25519VerificationKey2020 | `test_identity_crypto.py` | — | — | VERIFIED |
| R-68 service endpoints | P-10 | `service[]` in the DID Document. **Fixed:** provisioning left new agents with none | T-LW / E2E-A (discovery cross-check) | — | — | VERIFIED |
| R-69 creator/deployer/owner/controller | P-11 | `profile.provenance` | T-DI | — | — | VERIFIED |
| R-70 SHA-3 model + software hash | P-12 | SHA3-256 over model, runtime digest, software version and prompt hash | T-DI `test_the_model_hash_is_sha3_256...` | Hashes the runtime's reported weights digest, not the weights themselves | Documented in `identity/profile.py` | VERIFIED (scope stated) |
| R-71 timestamps incl. expiry | P-13 | `profile.timestamps` | T-DI | — | — | VERIFIED |
| R-72 dependencies / AIBOM | P-14 | — | — | No AIBOM | DEFERRED W3 (optional in paper) | NOT IMPL |
| R-73 training information | P-15 | — | — | Third-party model; no training data held | — | N/A |
| R-74 lifecycle status | P-16 | ACTIVE/SUSPENDED/TERMINATED/PROVISIONING (paper: active, suspended, revoked, archived) | `test_registry.py` | No ARCHIVED state | DEFERRED W2 | PARTIAL |
| R-75 formal scope of behaviour | P-21 | `profile.scopeOfBehavior` | T-DI | Not evaluated by policy | see R-202 | PARTIAL |
| R-76 decision-making capabilities | P-22 | Model name in profile | — | Reasoning parameters not recorded | DEFERRED W2 | PARTIAL |
| R-77 toolset | P-23 | `profile.toolset`; specialists refuse tools outside their toolset | E2E, `app/agents/service.py /work` | Not in the PDP input | DEFERRED W2: add to PIP | PARTIAL |
| R-78 expected outcomes and limitations | P-24 | Optional profile fields | — | Not populated for demo agents | W1 | PARTIAL |
| R-79 protocols supported | P-17 | `profile.protocols` | T-DI | — | — | VERIFIED |
| R-80 attested security properties | P-18 | — | — | — | DEFERRED W3 | NOT IMPL |
| R-81 compliance VCs | P-19/40 | `ComplianceCredential` (SOX demo); used in discovery filters | G3 | — | — | VERIFIED |
| R-82 update mechanism | P-20 | Profile and endpoint republish with a version bump | T-DI `test_a_profile_update_...` | — | — | VERIFIED |
| R-83 VCs from trusted issuers | P-35/42 | Issuer registry | `test_credential_verification.py` | — | — | VERIFIED |
| R-84 role VCs | P-36 | `AgentRoleCredential` | `test_credential_issuance.py` | Not used by policy | W2 | PARTIAL |
| R-85 capability VCs | P-37 | `AgentCapabilityCredential` | G2, G4 | — | — | VERIFIED |
| R-86 reputation VCs | P-38 | — | — | — | DEFERRED W3 (optional) | NOT IMPL |
| R-87 provenance VCs | P-39 | `AgentProvenanceCredential` | T-DI | — | — | VERIFIED |
| R-88 agent/controller holds keys | P-28 | Agent keystores are per agent; the registry holds public keys only | `test_wallet.py`, `provision_agents.py` | — | — | VERIFIED |
| R-89 controller | P-29 | `controller_did` | `test_registry.py` | — | — | VERIFIED |
| R-90 no dependence on a single IdP | P-30 | Offline-verifiable signatures | `test_credential_verification.py` | Registry is central | see §6 deployment | PARTIAL |
| R-91 centralized platform issuance | — | `provision_agents.py` | G1 | — | — | VERIFIED |
| R-92 self-issuance | — | — | — | Agents cannot self-register (closed in Phase 5, S-7) | — | N/A (deliberately refused) |
| R-93 role/task-specific IDs | — | Ephemeral identities | T-DI | — | — | VERIFIED |
| R-94 secure runtime-ID protocol (5 steps) | — | Request → verify parent and policy → scoped VC → use → expiry/revoke | T-DI | — | — | VERIFIED |
| R-95 DID Document updates | — | Versioned republish | T-DI | — | — | VERIFIED |
| R-96 VC status lists | — | Status endpoint per credential (not a bitstring list) | `test_credential_verification.py` | Not W3C Bitstring Status List | DEFERRED W3 | PARTIAL |
| R-97 DID deactivation | — | Termination marks the DID Document status and destroys the key | `test_registry.py` | — | — | VERIFIED |

## 4. Framework architecture and Layer 4 (paper §4–§4.3, pp. 28–35)

| Req | P | Existing implementation | Evidence | Gap | Planned action | Status |
|---|---|---|---|---|---|---|
| R-98 never trust, always verify | P-63 | Per-request PDP; no cached decisions | `test_pdp_opa.py` | — | — | VERIFIED |
| R-99 assume breach | P-63 | Kill switch; trust-driven containment; key destruction on terminate | T-TC | — | — | VERIFIED |
| R-100 least privilege | P-63 | Credential-scoped; deny-overrides | G4 | — | — | VERIFIED |
| R-101 continuous verification via behaviour | P-96 | Anomaly detector → trust → PIP | T-TC `TestDetector` | Rule-based, not ML | see R-124 | VERIFIED (rule-based) |
| R-102 micro-segmentation | — | — | — | Network is flat | EXT (infrastructure) | BLOCKED |
| R-103 risk-adaptive enforcement | P-76 | `trust.rego`: REDUCED escalates, UNTRUSTED denies | T-TC `TestPolicyNarrowsOnTrustAndSession` | — | — | VERIFIED |
| R-104 SSI for agents | P-27 | Agent-held keys | `test_wallet.py` | Central registry resolves DIDs | see §6 | PARTIAL |
| R-105 offline VC verification | — | The verifier checks issuer signatures locally | `test_credential_verification.py` | Status needs the registry | — | PARTIAL |
| R-106 selective disclosure / ZKP | P-46/139 | — | — | — | DEFERRED, see §9 governance report | NOT IMPL |
| R-107 rich identities | — | Agent ID profile | T-DI | — | — | VERIFIED |
| R-108 ANS | P-53 | ANS service | G3 | — | — | VERIFIED |
| R-109 integrity attestation | — | Model hash in profile | T-DI | Not remotely attested (no TEE) | EXT | PARTIAL |
| R-110 PBAC real-time multi-attribute | P-64 | PIP: identity, credentials, resource attributes, environment, trust, session | `test_pip.py` | — | — | VERIFIED |
| R-111 natural-language policy | — | — | — | — | Research-grade | DEFERRED (no target; research) |
| R-112 resource filtering before/after retrieval | — | Before: PDP. After: workflow findings are minimised (R-243) | T-LW `test_specialists_return_findings_not_records` | No post-retrieval policy filter | W3 | PARTIAL |
| R-113 attribute-based evaluation | P-65 | ABAC in Rego | G4 | — | — | VERIFIED |
| R-114 intent/purpose authorization | P-77 | Purpose is bound into credentials and checked by policy | `test_authorization_security_matrix.py` | — | — | VERIFIED |
| R-115 dynamic policy updates | — | PAP activate/deactivate; durable | `test_policy_deactivation_is_durable.py` | — | — | VERIFIED |
| R-116 agent-specific credentials | — | Agent DIDs vs human tokens | G5 | — | — | VERIFIED |
| R-117 delegated authorization flows | — | Delegation service | T-DI | No OAuth token exchange | see R-120 | PARTIAL |
| R-118 scoped permission models | — | Yes | G4 | — | — | VERIFIED |
| R-119 revocable delegation | — | Containing a parent cascades. **Phase 12:** the PIP reports the delegation chain and `security/session.rego` v2 denies a child whose ancestor is suspended, terminated, expired or locked out by ANY route; a cascade-contained child cannot be reinstated before its parent | T-TC, T-DI, T-ST `TestDelegationFollowsTheParent`, T-P12C | — | — | VERIFIED |
| R-120/121/122 OAuth `requested_actor`, `actor_token`, delegation-chain claims | P-80 | — | — | No RFC 8693 token exchange | DEFERRED W3 | NOT IMPL |
| R-123 behaviour tracking | P-96 | Detector rules | T-TC | — | — | VERIFIED |
| R-124 ML anomaly detection | P-99 | **Rule-based only** | — | No ML | DEFERRED: stated as a non-goal for the POC; a rule engine is auditable, an untrained model is not | NOT IMPL |
| R-125 audit with authorization basis | — | Decision records carry policy id and version | `test_authorization_api.py` | — | — | VERIFIED |
| R-126 performance/DoS monitoring | — | Rate limiter; RATE_SPIKE rule | `test_rate_limiting.py`, T-TC | No metrics stack | see §8 monitoring | PARTIAL |
| R-127 dynamic trust scores | P-97 | Trust engine | T-TC `TestTrustEngine` | — | — | VERIFIED |
| R-128 continuous risk assessment adjusts permissions | — | Trust → PIP → Rego | T-TC | — | — | VERIFIED |
| R-129 automated response | — | Auto-containment on trust collapse | T-TC `test_trust_collapse_contains_only_the_offending_agent` | — | — | VERIFIED |
| R-130 MCP server verification | — | Clients reach one server under a fixed resource URI | G8 | Client-side server attestation not built | W3 | PARTIAL |
| R-131 ETDI (signed, versioned tool definitions) | — | — | — | — | DEFERRED W3 | NOT IMPL |
| R-132 PBAC for MCP tools | — | `mcp/invocation.rego` (deny-only) + the same PDP | `test_mcp_authorization.py` | — | — | VERIFIED |
| R-133 secure A2A | P-113 | Signed envelopes, receiver binding, exactly-once | G7 | Not Google A2A wire-compatible | see §7 | VERIFIED (own protocol) |
| R-134 multi-modal access control | — | API, MCP and A2A all reach one PDP | G9 | — | — | VERIFIED |
| R-135 task-oriented security across long tasks | — | Workflow pauses and resumes under the same request binding | E2E-C | — | — | VERIFIED |
| R-136 unique DID per instance | — | Yes | T-DI | — | — | VERIFIED |
| R-137 VC validity and status refs | — | Yes | G2 | — | — | VERIFIED |
| R-138 ZKP policy compliance | — | — | — | — | Research | DEFERRED (no target) |
| R-139 ANS naming structure `protocol://Function.Domain.Provider.Version` | P-55/118 | Capability, provider (organisation) and DID | `test_ans_discovery.py` | No structured ANSName, no semver ranges | DEFERRED W2 | PARTIAL |
| R-140 ANS entries secured | P-58 | Signed registration proofs | `test_ans_registration.py` | Responses not signed (R-170) | W2 | PARTIAL |
| R-141 DID registries | P-43 | Central registry | G1 | — | — | VERIFIED (centralized) |
| R-142 issuers and verifiers | P-42 | Yes | G2 | — | — | VERIFIED |
| R-143 wallets | P-44 | `CredentialWallet` per agent | `test_wallet.py` | — | — | VERIFIED |
| R-144 KMS | P-45 | Encrypted file keystore; approval and JIT key rotation | `test_approval_key_rotation.py` | No KMS/HSM | see R-238 | PARTIAL |
| R-145 ANS resolution | P-61 | Yes | G3 | — | — | VERIFIED |
| R-146 DID resolvers | P-47 | Registry resolution | G1 | Not universal-resolver compatible | — | PARTIAL |
| R-147 reputation systems | P-48 | Trust engine (internal) | T-TC | No cross-party reputation | see R-218 | PARTIAL |
| R-148 trust frameworks | P-49 | Issuer registry | — | No governance metadata (accreditation levels) | see R-230 | PARTIAL |
| R-149 PDP | P-66 | OPA | G4 | — | — | VERIFIED |
| R-150 PAP | P-67 | PAP with manifest and DB state | `test_policy_deactivation_is_durable.py` | — | — | VERIFIED |
| R-151 PIP | P-68 | Yes, now with trust and session facts | `test_pip.py` | — | — | VERIFIED |
| R-152/153 ABAC/PBAC | P-64/65 | Yes | G4 | — | — | VERIFIED |
| R-154 JIT via scoped VCs | P-70/71 | JIT mandates (signed, bounded, single-use) | G6 | Mandate is a signed artifact, not a W3C VC | — | VERIFIED (equivalent) |
| R-155 unified global session management layer | P-88/93 | **Session Authority + SSS + PIP + `session.rego`** | T-TC, E2E-E | — | — | VERIFIED |
| R-156 Session Authority | P-89 | `app/sessions/authority.py` | T-TC `TestSessionAuthority` | — | — | VERIFIED |
| R-157 AEM subscribes to SA updates | P-90 | Agent runtimes subscribe to the SSS push and fail fast locally | T-TC `TestLocalSessionView`, E2E-E (9 subscribers) | The IAM API's AEM reads the ledger rather than subscribing (it needs no push) | — | VERIFIED |
| R-158 enhanced protocol adapters linked to global sessions | P-91 | MCP sessions are revoked by the SA | T-TC | A2A has no long-lived session (per-envelope authorization) | — | VERIFIED |
| R-159 SSS | P-92 | PostgreSQL ledger (authoritative) + Redis pub/sub (push) | T-TC | Not "distributed": single PostgreSQL | see §6 | VERIFIED (POC scale) |
| R-160 OpenID SSF as an alternative | — | — | — | Not used | DEFERRED W3 (SSF transmitter for the SSS) | NOT IMPL |
| R-161 global logout flow | — | SA → SSS → push → adapters → subsequent requests blocked; Phase 12 adds approval withdrawal | E2E-E, T-P12C | — | — | VERIFIED |
| R-162 explicit verification | — | Yes | G4 | — | — | VERIFIED |
| R-163 JIT VCs expire with the task | — | Mandates are bounded by time and uses | G6 | — | — | VERIFIED |
| R-164 rapid revocation | — | Kill switch measured at 145–250 ms end to end | E2E-E | — | — | VERIFIED |
| R-165 data-centric security | — | Resource-type scoping | G4 | No sensitivity labels | W3 | PARTIAL |
| R-166 separate ephemeral and persistent domains | — | Ephemeral identities are `HELPER` type, depth ≥ 1, with their own provenance VC | T-DI | Same DID method | — | PARTIAL |

## 5. Applications (paper §5, pp. 35–60)

| Req | P | Existing implementation | Evidence | Gap | Planned action | Status |
|---|---|---|---|---|---|---|
| R-167 ANS capability query fields | P-55 | Capability, required credential types, organisation | `test_ans_discovery.py` | No protocol or semver range | W2 | PARTIAL |
| R-168 resolver with own DID, verifiable responses | — | — | — | Responses unsigned | W2 | NOT IMPL |
| R-169 registry contents | P-56 | DID, endpoint, capabilities, credentials | G3 | No PKI certificates | — | PARTIAL |
| R-170 signed ANS records verified by the requester | P-58 | The coordinator cross-checks endpoints against the DID Document instead | G3, E2E | No `ansRecordSignature` | W2 | PARTIAL |
| R-171 discovery then fine-grained authz | P-54 | Discovery never authorizes; the PDP decides | `test_ans_discovery.py`, E2E | — | — | VERIFIED |
| R-172 AEM interception with full context | — | Yes | G4 | No `sourceIpSegment` in context | — | VERIFIED |
| R-173 default-deny Rego | — | Yes | `test_pdp_opa.py` | — | — | VERIFIED |
| R-174 ANS tool-instance discovery | P-60/62 | — | — | MCP tools are not in the ANS | DEFERRED W3 | NOT IMPL |
| R-175 JIT VC content | P-71 | Mandate binds agent, action, resource, uses, expiry | G6 | No tool DID or jobId | — | PARTIAL |
| R-176 JIT in MCP transport metadata | P-114 | — | — | MCP uses OAuth; JIT is a separate path | W3 | NOT IMPL |
| R-177 AEM verifies JIT at the tool | P-72 | Mandate verified in PIP, spent atomically | G6 | — | — | VERIFIED |
| R-178 ANS-signalled requirements | — | — | — | — | DEFERRED (optional) | NOT IMPL |
| R-179/180 A2A IAM extension with VP and signature | — | Signed envelope, DID sender id, VP-based credential check | G7 | — | — | VERIFIED |
| R-181 role continuity / context-hijack prevention | — | Approval bound to request; workflow resumes under the same request id | E2E-C | No nested intent verification | W3 | PARTIAL |
| R-182 DID as log subject | — | `agent_did` on every event | E2E-G | — | — | VERIFIED |
| R-183 synchronised timestamps | — | DB clock plus monotonic seq | `test_api.py` | — | — | VERIFIED |
| R-184 – R-189 log fields (ANSName, targets, request hash, VC ids, collaborators, outcome/policy version) | — | Event type, resource, decision, policy id/version, request id | `test_authorization_api.py` | No ANSName or request-context SHA-256 | W2 | PARTIAL |
| R-190 signed log entries | P-98 | **Phase 12:** per-entry HMAC at write (key derived from the keystore master key, not in the DB); SHA-256 hash chain in `audit_chain`; Ed25519-signed checkpoints verified against a keystore or pinned key; server verifier + CRITICAL alert; standalone verifier `scripts/verify_audit_chain.py` | T-AI (35 tests incl. modification, deletion, reorder, insertion, chain rewrite, truncation, forged signer, concurrency, restart), RT12 | Not per-entry DID signatures by the actor; tail truncation together with all later checkpoints needs an externally retained checkpoint | — | VERIFIED (scope stated) |
| R-191 DID-signed critical actions | — | A2A payments are signed by the sender | G7 | Loan approvals are signed by the human authority, not the agent | — | PARTIAL |
| R-192/193 payload signatures, end-to-end integrity | — | A2A payload digest signed | G7 | Responses unsigned | W3 | PARTIAL |
| R-194 MCP provenance chain | — | Every MCP call audited with request id | G8 | Not a single linked chain | W2 | PARTIAL |
| R-195 runtime behavioural monitoring | — | Detector over audit events | T-TC | No output/semantic drift | — | PARTIAL |
| R-196 PDP decision logs with cryptographic commitment | — | Decision records are audit rows and therefore chained and checkpoint-signed (R-190) | T-AI | — | — | VERIFIED |
| R-197 ZKP audit | — | — | — | — | Research | DEFERRED (no target) |
| R-198/199 log retention and auto-expiry | — | — | — | — | W2 (operator policy plus a purge job) | NOT IMPL |
| R-200 access-controlled log redaction | — | Audit read is role-gated | `test_read_authorization.py` | No field redaction | W2 | PARTIAL |
| R-201 behavioural baselines per DID | — | Per-DID windows (rate, denials) | T-TC | Fixed thresholds, not learned baselines | — | PARTIAL |
| R-202 declared vs actual scope | — | SCOPE_VIOLATION on attested-scope denials | T-TC | `scopeOfBehavior` not machine-evaluated | W2 | PARTIAL |
| R-203 toolset / ANS query monitoring | — | Specialists refuse out-of-toolset tools | E2E | Not a detector rule | W2 | PARTIAL |
| R-204 VC presentation pattern monitoring | — | `UNVERIFIED_IDENTITY_CLAIM` alerts | T-TC | — | — | PARTIAL |
| R-205 communication graph monitoring | — | Impact analysis lists A2A counterparties | T-TC (impact) | No detection rule | W3 | PARTIAL |
| R-206 block and log scope creep | — | PDP denies; detector raises SCOPE_VIOLATION | T-TC | — | — | VERIFIED |
| R-207 anomalous JIT requests | — | JIT_ESCALATION rule | T-TC (rule), `test_jit_policy.py` | — | — | IMPL-UNVERIFIED (rule untested end to end) |
| R-208 counter-attestation | — | Discovery filters by required credential | G3 | — | — | PARTIAL |
| R-209 trust score inputs | — | Policy violations, replays, scope, rate, delegation | T-TC | No peer feedback or ANS-anomaly inputs | W3 | PARTIAL |
| R-210 risk-adaptive flow (SA → SSS → AEM → stricter PDP) | — | REDUCED_TRUST in SSS; Rego escalation | T-TC | — | — | VERIFIED |
| R-211 DID-referenced alerts with context | — | Alerts carry DID, rule, evidence seqs | T-TC | — | — | VERIFIED |
| R-212 surgical VC revocation | — | Yes (per credential), and opt-in during containment | T-TC `test_credentials_are_revoked_only_when_asked` | — | — | VERIFIED |
| R-213 DID revocation reflected in ANS | — | The SA sets the ANS entry to REVOKED immediately | T-TC, E2E-E | — | — | VERIFIED |
| R-214 instantaneous global session invalidation | P-95 | Kill switch | T-TC, E2E-E (145 ms) | — | — | VERIFIED |
| R-215 stale cached DIDs fail at discovery | — | ANS never returns REVOKED; the coordinator re-discovers per step | E2E-E | — | — | VERIFIED |
| R-216 forensics with blast radius | — | `/security/impact/{did}`, frozen into the incident | T-TC `test_impact_is_frozen_into_the_incident` | — | — | VERIFIED |
| R-217 incident clustering | — | — | — | — | W3 | NOT IMPL |
| R-218 decentralized reputation VCs | — | — | — | — | DEFERRED (optional extension) | NOT IMPL |
| R-219 billing and quotas | — | Per-identity rate limits | `test_rate_limiting.py` | No billing | — | N/A (no billing domain) |
| R-220 supply-chain attestations at registration | — | Model hash in profile | T-DI | No SBOM/ModelCard VCs | W3 | PARTIAL |
| R-221 dynamic coalitions | — | — | — | — | DEFERRED (optional extension) | NOT IMPL |
| R-222 ethical governance services via ANS | — | — | — | — | — | N/A (optional; no such service) |

## 6. Deployment and governance (paper §6, pp. 60–70)

These are mostly organisational. See [FRAMEWORK_COMPLETION_REPORT.md §9 and §10](FRAMEWORK_COMPLETION_REPORT.md) for the reasoning; each row here gives the disposition.

| Req | P | Technical control present | Organisational owner needed | Status |
|---|---|---|---|---|
| R-223 ephemeral lifecycle governance | — | Bounds are enforced in code (depth, TTL, rate) | Approving the bounds | PARTIAL |
| R-224 deployment model selection | P-142–146 | Centralized model chosen and justified | — | VERIFIED (documented) |
| R-225 DID method governance | P-119 | `did:poc` is local | A method steward | DEFERRED (EXT) |
| R-226 ANS registration authority | P-120 | Signed registration; identity must exist | Namespace authority | PARTIAL |
| R-227 ANS dispute resolution | — | — | Arbiter | DEFERRED (EXT) |
| R-228 reserved namespaces | — | — | Namespace authority | NOT IMPL (W3, config list) |
| R-229 issuer accreditation | P-121 | Issuer registry (2 issuers) | Accreditation body | PARTIAL |
| R-230 trust registries | P-121 | Issuer registry with DIDs | Governance metadata | PARTIAL |
| R-231 VC schema governance | — | `REQUIRED_CLAIMS` per type in code | Schema board | PARTIAL |
| R-232 Agent ID lifecycle policies | P-122 | Suspend vs revoke vs terminate are separate operations | Renewal and re-attestation cadence | PARTIAL |
| R-233 policy authorship and approval | P-123 | Policies in git with version and owner in the manifest | Multi-party approval workflow | PARTIAL |
| R-234 policy-as-code | P-124 | Rego in git, unit-tested against real OPA | — | VERIFIED |
| R-235 emergency override with review | P-125 | Containment requires justification; reinstatement requires a review, a different principal and (**Phase 12**) a trust revalidation (not terminated/expired, an ACTIVE key, no contained ancestor) | Review board | VERIFIED (technical part) |
| R-236 policy harmonisation | P-126 | — | Federation partners | DEFERRED (EXT) |
| R-237 IR playbooks | P-127 | `OPERATIONS_RUNBOOK.md` §4 key compromise, **§5a audit-integrity response, §5b kill-switch playbook (Phase 12)** | Playbook ownership and rehearsal | PARTIAL (documented; not rehearsed; owner EXT) |
| R-238 key management governance, HSM | P-128 | Rotation for approval and JIT keys | HSM procurement | BLOCKED (EXT) |
| R-239 audits and pen-testing | P-129 | — | Independent tester | BLOCKED (EXT) |
| R-240 vulnerability disclosure | P-130 | `SECURITY.md` (Phase 12): private reporting route, scope, secrets rule | Named owner and response SLA | PARTIAL |
| R-241 cross-environment governance | P-131 | — | — | DEFERRED (single environment) |
| R-242 DPIA | P-132 | Data inventory in this report | DPO | BLOCKED (EXT) |
| R-243 data minimisation | P-133 | Specialists return findings, not records; the coordinator receives no customer data at claim | T-LW, E2E-A | VERIFIED |
| R-244 bias review | P-134 | — | Ethics owner | BLOCKED (EXT) |
| R-245 ethical oversight | P-135 | — | Board | BLOCKED (EXT) |
| R-246 change management | P-136 | Git history, policy versions | Process owner | PARTIAL |
| R-247 standards liaison | P-137 | — | Owner | N/A (POC) |
| R-248 on-chain vs off-chain design | — | No ledger | — | N/A (centralized model) |

## 7. Security considerations and MAESTRO (paper §7, pp. 71–75)

The full matrix is in [FRAMEWORK_COMPLETION_REPORT.md §5](FRAMEWORK_COMPLETION_REPORT.md#5-maestro-threat-coverage-matrix).

| Req | Existing implementation | Evidence | Status |
|---|---|---|---|
| R-249 MAESTRO analysis | Seven-layer matrix with residual risk | report §5 | VERIFIED (document) |
| R-250 impostor with valid keys / liveness | — | — | DEFERRED (research; paper's own open problem) |
| R-251 resolver pinning, DID Document validation | Single registry; endpoint cross-check | G3 | PARTIAL |
| R-252 nonce-bound, time-limited VCs | Single-use presentation challenges | `test_presentation_replay.py` | VERIFIED |
| R-253 rate-limit ephemeral spawning | Hard limit plus SPAWN_BURST rule | T-DI `test_spawn_rate_is_bounded` | VERIFIED |
| R-254 limit re-delegation chains | Max depth | T-DI `test_re_delegation_depth_is_bounded` | VERIFIED |
| R-255 prompt guardrails | — | — | NOT IMPL (W3) |
| R-256 dataset integrity | — | — | N/A (no training pipeline) |
| R-257 encryption at rest for models | Keys encrypted at rest | `test_identity_crypto.py` | PARTIAL |
| R-258 defence in depth | Layered: guard → PDP → AEM → grant → SSS | G9 | VERIFIED |
| R-259 separation of duties | Maker-checker; contain vs reinstate | E2E-C, E2E-E | VERIFIED |
| R-260 configuration drift | PAP drift report; reconciler | `test_policy_deactivation_is_durable.py` | VERIFIED |
| R-261 preventative, detective and corrective controls | All three exist | this matrix | VERIFIED |
| R-262/263 red teaming, chaos engineering | — | — | BLOCKED (EXT) |
| R-264 trust boundary validation | Security matrices | `test_*_security_matrix.py` | VERIFIED |
| R-265 data leakage | Findings minimisation | T-LW | PARTIAL |
| R-266 plugin/tool lateral movement | Closed tool registry; AEM-only path | `test_aem_enforcement.py` | VERIFIED |
| R-267 identity abuse simulation | Replay, spoof and forged-claim tests | T-TC, `test_a2a_replay.py` | VERIFIED |

## 8. Contributions, KPIs and future work (paper §8–§9, pp. 76–83)

| Req | Status and note |
|---|---|
| R-268 end-to-end lifecycle | VERIFIED: birth (provision/spawn), operation, containment, expiry, termination |
| R-269 least function | PARTIAL: toolset is enforced by specialists, not by the PDP (W2) |
| R-270 context-based access control | VERIFIED |
| R-271 cross-protocol propagation | VERIFIED: one PDP behind API, MCP and A2A; SSS push |
| R-272 credentials vs trust frameworks | PARTIAL (issuer registry) |
| R-273 SA override even for self-controlled DIDs | VERIFIED: containment needs no cooperation from the agent |
| R-274 three-level verifiability | PARTIAL: identities and claims yes; actions only for A2A |
| R-275 provenance answer | VERIFIED: who/what/when/authority via audit plus impact |
| R-276 – R-284 KPIs | PARTIAL: authorization latency and revocation time are measured (`latency_ms`, `containment_ms`). No KPI dashboard (W2) |
| R-285 – R-317 research and future work | DEFERRED with no POC target; the paper itself lists them as open research. Two exceptions: **R-311 management UIs** (PARTIAL: 13-page console incl. the Phase 12 audit-integrity, transition-history, containment and reinstatement views and idempotent submission — `frontend/e2e/phase12_ui_e2e.py` 57/57; no agent-registration UI or policy editor) and **R-301/R-316 explainable decisions** (VERIFIED: every decision carries policy, reason and stages) |

## 9. Blueprint workflow (BP)

| Step | Status | Evidence |
|---|---|---|
| 1 customer applies (via bank employee) | VERIFIED | E2E-A |
| 2 Keycloak authenticates the human | VERIFIED | E2E-F, G5 |
| 3 coordinator receives and orchestrates | VERIFIED | E2E-A |
| 4 discovery via ANS | VERIFIED | E2E-A (5 capabilities, 6 agents) |
| 5–9 KYC, risk, credit, documents, fraud | VERIFIED (**simulated adapters**) | E2E-A, T-LW |
| 10 agents request only authorized resources | VERIFIED | T-LW `TestSpecialistBoundaries` |
| 11 PDP evaluates | VERIFIED | E2E-G |
| 12 AEM enforces | VERIFIED | E2E-A ("every step executed through the AEM") |
| 13 high-risk triggers HITL | VERIFIED | E2E-C, E2E-D |
| 14 enterprise services via the MCP gateway | PARTIAL: workflow specialists use the AEM directly; the MCP gateway fronts the same AEM but the workflow does not route through it (W2) |
| 15 core banking, LMS, document store integrated | SIMULATED adapters (labelled `simulated: true`). **Phase 12:** LMS state (applications, documents, workflow queue, transitions) is DURABLE in PostgreSQL with leases, fencing tokens, at-most-once decisions and idempotent submission; survives an API restart (RT12 18/18) |
| 16 coordinator aggregates | VERIFIED |
| 17 decision communicated | VERIFIED (`customer_message`) |
| 18 auditable | VERIFIED (E2E-G) |
| Kill-switch panel (architecture image) | VERIFIED (E2E-E) |
