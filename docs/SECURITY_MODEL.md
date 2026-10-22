# Security model

## Principles and where they are actually enforced

| Principle | Phase 1 reality |
|-----------|-----------------|
| **Zero trust** | Partially. Every signature is verified against the DID Document on every check; nothing is trusted because it verified earlier. But there is no authorization layer yet, so "trust nothing" currently applies to identity claims only. |
| **Least privilege** | Attested, not enforced. A credential is an authority's signed statement about scope (Phase 2); nothing acts on it until the PDP exists (Phase 4). |
| **Assume breach** | Structurally: private keys never leave their keystore, so a compromised API cannot exfiltrate them. Containment (Phase 11) does not exist yet. |
| **Continuous verification** | Signature verification is stateless and repeated per request. Session and credential state checks arrive in Phases 2 and 9. |
| **Separation of concerns** | Enforced in code today: `AgentRuntime` proposes, and has no authorization method to call. The decision path is a separate plane that Phase 4 adds. |

## Key custody

The `KeyStore` interface (`app/identity/keys.py`) exposes `generate_key`,
`get_public_key`, `sign`, `exists`, `delete`. There is deliberately no `export`
or `get_private_key`. Callers ask the store to sign; they never hold key bytes.

Consequences, each covered by a test:

- No API response can contain a private key — no schema has a field for one.
- The frontend never receives one.
- Nothing logs key material.
- PostgreSQL stores public keys and an opaque `keystore_ref` only.
- `.keystore/` and `.keystore-agents/` are gitignored.

### Development backend: `EncryptedFileKeyStore`

```
data key   = HKDF-SHA256(master_key, salt="agentic-iam-keystore-v1", info=kid)
ciphertext = AES-256-GCM(data key, nonce=random 12B, aad=kid) over the raw key
file       = 0600, in a 0700 directory, written O_EXCL so it is never
             world-readable even transiently
```

Binding `kid` as associated data means a key file cannot be renamed onto another
identity — the tag check fails. Per-kid derivation means one leaked file does not
compromise the others.

**What this does not do:** the master key is in the process environment. A host
compromise reads it. This is a development backend; production replaces it with
a KMS/HSM binding behind the same interface, where the key is non-exportable in
hardware.

`ENV=production` with the shipped development master key is a hard startup
failure, not a warning.

## Trust chain for a signature

```
message + signature + claimed DID
        -> resolve the DID Document from the registry
        -> read verificationMethod[0].publicKeyMultibase
        -> multibase/multicodec decode to a 32-byte Ed25519 public key
        -> Ed25519 verify
        -> record SIGNATURE_VERIFIED or SIGNATURE_INVALID
```

Verification deliberately goes through the DID Document rather than the key
table: that is the path a third party takes, so it exercises the same chain the
A2A layer will use in Phase 7.

An invalid signature is a normal outcome (HTTP 200, `valid: false`), never an
exception. Tampering must be recorded, not crash the caller.

## Credential trust chain

```
credential + claimed issuer DID
        -> resolve the issuer from the issuer registry
        -> compare proof.verificationMethod with the issuer's own key id
        -> JCS-canonicalise the document plus its proof options
        -> Ed25519 verify with the issuer's published public key
        -> check subject binding, validity window, revocation status, claims
        -> record CREDENTIAL_VERIFIED or a specific failure event
```

Two proofs, two keys, two questions:

| Proof | Key | Proves |
|-------|-----|--------|
| Issuer proof, on the credential | issuer's Ed25519 key | an authority made these claims about this subject |
| Holder proof, on the presentation | the **agent's** Phase 1 key | the presenter controls the subject DID |

Neither proves the request should be allowed. That is Phase 4.

### Why an agent cannot forge a credential about itself

An agent holds a key, so it can produce a valid signature over any document it
likes — including one naming itself as issuer. That document is worthless: the
verifier resolves the `issuer` DID against the issuer registry, finds nothing,
and rejects it as `ISSUER_UNKNOWN` without even evaluating the signature. The
separation of issuer keys from agent keys is what makes this hold, and there is
a test that performs the attack.

## Naming and discovery trust chain (Phase 3)

```
agent registers
    -> signs {did, endpoint, capabilities, organization, nonce, timestamp}
    -> ANS resolves the DID Document from the IDENTITY registry
    -> Ed25519 verify against the published key
    -> nonce checked single-use, timestamp checked fresh
    -> accepted; the name now points where the key-holder said

caller discovers
    -> ANS filters on capability, status, identity, liveness, credentials
    -> credentials re-verified by the Phase 2 verifier, live
    -> caller cross-checks the endpoint against the DID Document
       (which the ANS does not control)
```

The endpoint is inside the signed payload. That is the whole defence against
the most damaging attack on a naming service: pointing an existing, trusted
name at an attacker's endpoint. A signature over `localhost:9003` cannot be
replayed for `attacker.invalid:9999`, and a heartbeat cannot move an endpoint
at all.

### Three registries, deliberately not one

| Registry | Authority over | Can it lie about the others? |
|---|---|---|
| Agent registry (Phase 1) | identity, public keys, DID Documents | — |
| Credential store (Phase 2) | what authorities attested | no: proofs are issuer-signed |
| ANS (Phase 3) | where an agent can be reached | no: the caller cross-checks the DID Document |

A compromised ANS can deny service or mis-rank candidates. It cannot forge an
identity, forge a credential, or silently redirect a caller that performs the
cross-check.

## What a signature does and does not prove

A valid signature proves the holder of that private key produced those bytes.
It does **not** prove the agent is currently permitted to act. This is why:

- termination revokes the key and destroys it, stopping *new* signatures, while
  signatures issued earlier remain mathematically valid (there is a test
  asserting exactly this);
- Phase 2 adds credential status, Phase 9 adds session state, and Phase 4 makes
  every action re-check both.

## Threat model

### Addressed today

| Threat | Mitigation |
|--------|-----------|
| Agent impersonation by message forgery | Ed25519 verification against the published DID Document |
| Tampering with a signed agent result | The result is signed over a canonical payload; any edit breaks verification |
| DID hijack by a rogue process | On a DID collision the agent compares the published key with its own and refuses to start on mismatch |
| Key theft from the database | Private keys are not in the database |
| Key theft from a repository checkout | Keystore directories are gitignored; keys are encrypted at rest |
| Key file relabelling | `kid` is AES-GCM associated data |
| Silent LLM failure presented as a result | `LLMUnavailableError` propagates; the task returns FAILED with no output |
| Untraceable identity operations | Every lifecycle and signature operation writes an audit event |
| Forged or edited credential | Ed25519 proof over canonical bytes; any edit fails verification |
| Agent self-issuing its own capabilities | Issuer keys are never held by agents; unregistered issuer is rejected |
| Presenting another agent's credential | Holder proof plus subject binding |
| Continued use of a withdrawn attestation | Credential status checked on every verification |
| Hijacking an agent's name/endpoint | Registration proof; endpoint is inside the signature |
| Replaying a captured registration | Single-use nonce plus a freshness window |
| Moving an endpoint via a heartbeat | Heartbeats cannot change the endpoint |
| Routing work to a dead agent | Observed liveness: heartbeat lapse and endpoint probing |
| Routing work to a revoked identity | Identity state mirrored into the registry and re-checked per query |
| Routing work to an agent whose credential lapsed | Credentials re-verified live on every discovery |
| A compromised directory redirecting a caller | Caller cross-checks the endpoint against the DID Document |
| Indefinite credential lifetime | Expiry is inside the signature and compared against wall clock |

### Not addressed yet

| Threat | Phase |
|--------|-------|
| Unauthorized tool or data access | 4 (AEM + PDP), 8 (MCP) |
| Over-privileged agents | 2 (credentials), 4 (policy) |
| Prompt injection driving an agent outside its scope | 10 (detection), 11 (containment). Phase 1 has no enforcement to bypass. |
| Replay of a captured presentation | 9 — challenges are checked but not recorded as used |
| Unauthorized credential issuance or revocation | 4 — the credential endpoints are unauthenticated |
| Unauthorized discovery queries or deregistration | 4 — only ANS *registration* is authenticated |
| Denial of service by a compromised ANS | out of scope for this POC |
| Compromised agent continuing to act | 11 (kill switch) |
| Telemetry forgery via the ingest endpoint | 7 (signed A2A messages) |
| Any human authentication at the boundary | 12 (OIDC at the banking app) |

### Accepted for a POC

No blockchain, no zero-knowledge proofs, no production federation, no real
banking or credit-bureau integration, no ML anomaly model. None of these are
implemented and none are claimed.

## Current attack surface

Everything is unauthenticated through Phase 3 **except ANS registration**: any
caller reaching `:8000` can register an agent, terminate one, make a
registry-custodied agent sign, issue a credential from any authority, or revoke
one. Any caller reaching `:8100` can run discovery queries or deregister an
agent. Any caller reaching an agent port can run tasks on it or ask it to
present its credentials.

ANS registration is the one operation that already proves identity, because
name hijacking is the attack that would compromise every subsequent routing
decision. The rest waits for Phase 4, which is the next security-relevant
milestone. Until then the POC binds to localhost / the compose network.
