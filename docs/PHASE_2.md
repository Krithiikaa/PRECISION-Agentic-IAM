# Phase 2 — Verifiable Credentials

Phase 1 answered *who is this agent?* Phase 2 answers *what can a trusted
authority prove about it?*

---

## 1. What is a verifiable credential?

A set of claims about a subject, signed by an issuer, that anyone can check
without contacting that issuer. Three things make it verifiable rather than
merely stored:

1. the claims are inside a document whose exact bytes are signed;
2. the issuer's public key is independently resolvable (from its DID Document);
3. any edit to any part of the document breaks the signature.

A row in a database saying `is_compliant = true` has none of these properties.
Whoever can write to the database can set it, and nobody downstream can tell
the difference between a genuine value and a forged one.

## 2. Why agents need them

An agent that arrives at a tool gateway can prove it is
`did:poc:agent:risk-001` (Phase 1). That says nothing about whether it is
supposed to be doing credit analysis. The gateway has three bad options
without credentials: trust the agent's own claim about itself, hold a central
table of what every agent may do, or ask an authority synchronously on every
request.

A credential removes all three. The agent carries signed evidence, the verifier
checks it offline, and the authority that issued it is not in the request path.

## 3. DID vs VC

| | DID + Ed25519 | Verifiable credential |
|---|---|---|
| Question | Who is this agent? | What has an authority attested about it? |
| Produced by | the agent itself | an issuer |
| Signed with | the agent's key | the **issuer's** key |
| Can the agent forge it? | it *is* the agent's key | no — it has no issuer key |
| Lifetime | until the key is revoked | until expiry or revocation |

Neither is authorization. See section 14.

## 4. Issuer

An organisation-level authority with its own Ed25519 key pair:

```
did:poc:organization:bank-demo             Demo Bank Identity Authority
did:poc:organization:compliance-authority  Demo Compliance Authority
```

Created at API startup from `CREDENTIAL_ISSUERS`, idempotently. Each has a DID
Document listing its public key under `assertionMethod` — the proof purpose an
issuer uses. Issuer keys live in the same `KeyStore` abstraction as agent keys
and are equally non-exportable.

**No agent ever holds an issuer key.** This is the property the whole model
rests on: an agent can sign, but a self-signed "credential" resolves to an
issuer DID that is not registered, so it is rejected as `ISSUER_UNKNOWN`.
There is a test asserting exactly this attack fails.

## 5. Holder

The agent named in `credentialSubject.id`. Each agent process carries a
`CredentialWallet` (`app/agents/wallet.py`) that loads its credentials from the
registry at boot and can present them. The wallet exposes
`attested_capabilities()` — capabilities backed by a live credential — which is
deliberately distinct from `AgentIdentity.capabilities`, the agent's own
unbacked declaration.

## 6. Verifier

`app/credentials/verifier.py`. Runs eight independent checks and reports every
one of them with a human-readable detail string. It never returns a bare
`{"valid": true}`.

## 7. Credential lifecycle

```
ISSUE ──> STORE ──> PRESENT ──> VERIFY ──> ACTIVE ──┬──> EXPIRED   (time passes)
                                                    └──> REVOKED   (authority acts)
```

Status lives in its own table, not in the credential. The signed document
cannot carry status because revocation happens *after* signing — so a verifier
has to look it up.

## 8. Signature process

```
document without proof
      +  proof options (type, created, verificationMethod, proofPurpose, …)
      ↓
JCS canonicalisation (RFC 8785 style: sorted keys, no whitespace, UTF-8)
      ↓
Ed25519 sign with the ISSUER key, inside the KeyStore
      ↓
proof.proofValue  (base64, 64 bytes)
```

The proof options are inside the signed payload, so `created`,
`verificationMethod`, `proofPurpose`, `challenge` and `domain` are covered too.
Repointing a proof at another key invalidates it rather than silently
redirecting the verifier.

**Honest scope note.** This is *not* the W3C `Ed25519Signature2020` suite,
which canonicalises JSON-LD with URDNA2015. We do not run a JSON-LD processor
and our `@context` URLs are not dereferenceable. The proof type is therefore
named `PocEd25519Signature2026`, deliberately distinct, so no real W3C verifier
can mistake it for the standard suite. The document *shape* follows the VC data
model so a compliant implementation could replace this one.

Floating-point numbers are rejected in claims: RFC 8785 mandates ECMAScript
number formatting, which Python's `repr` does not reproduce for every value, so
a verifier in another language could compute different bytes for the same
credential and reject something valid.

## 9. Verification process

| # | Check | Fails with |
|---|-------|-----------|
| 1 | structure, proof type, required fields | `MALFORMED_CREDENTIAL` |
| 2 | issuer is registered, and the proof names its key | `ISSUER_UNKNOWN` |
| 3 | Ed25519 proof verifies against the issuer's published key | `SIGNATURE_INVALID` |
| 4 | subject matches the DID the verifier expected | `SUBJECT_MISMATCH` |
| 5 | `issuanceDate` is not in the future | `CREDENTIAL_NOT_YET_VALID` |
| 6 | `expirationDate` has not passed | `CREDENTIAL_EXPIRED` |
| 7 | registry status is ACTIVE | `CREDENTIAL_REVOKED` / `CREDENTIAL_NOT_REGISTERED` |
| 8 | required claims present, and matching if a value was required | `MISSING_REQUIRED_CLAIM` |

Every check runs even after one fails, so the report shows the full picture.
The first failure in the order above determines the reported reason.

An invalid credential returns **HTTP 200 with `valid: false`**. Rejection is a
normal outcome that must be recorded, not an exception.

## 10. Revocation

`POST /api/v1/credentials/{id}/revoke` writes to `credential_status`. Every
subsequent verification fails with `CREDENTIAL_REVOKED`, immediately and across
restarts. Note what stays true: the signature still verifies. That is the point
— cryptographic validity and current authority are different questions.

## 11. Expiration

`expirationDate` is inside the signed document, so it cannot be extended
without breaking the proof. The verifier compares it against wall-clock time on
every check. A background sweep reconciles stored status, but verification does
not depend on it: a credential is rejected the instant it expires, swept or not.

For demos, `VC_DEMO_TTL_SECONDS` (default 15) issues a short-lived credential.
The UI countdown is display only — expiry is decided by the backend.

## 12. Subject binding

A credential names its subject. A verifier that knows which agent it is talking
to passes `expected_subject`; a mismatch is `SUBJECT_MISMATCH`.

For presentations this is automatic: the expected subject is the holder whose
proof was just verified, so an agent cannot present a credential belonging to
another agent even though credentials are meant to be copied and shown.

## 13. Credential tampering

Change `capability` from `credit_analysis` to `payroll_access` and reuse the
proof: verification fails with `SIGNATURE_INVALID`. Tests cover edits to the
issuer, subject, expiry, issuance date, resources, credential id, a flipped
signature byte, and repointing `verificationMethod`.

## 14. Security model

```
DID + Ed25519   "Who is this agent?"                        Phase 1  ✔
Credential      "What has an authority attested about it?"  Phase 2  ✔
PDP             "Is this request allowed right now?"        Phase 4  ✘ not built
AEM             "How is a disallowed request stopped?"      Phase 4  ✘ not built
```

**Holding a credential is evidence, not permission.** A credential saying
`capability: credit_analysis` means an issuer attested that capability. It does
not mean the agent may read any particular record. Nothing in Phase 2 makes an
access decision, and no code path treats a credential as authorization.

Two distinct proofs are involved in a presentation:

```
ISSUER proof (per credential)   "The bank authority attests these claims about risk-001."
HOLDER proof (on the envelope)  "I am risk-001, and I am handing you these now."
```

The holder proof uses the agent's existing Phase 1 key. No new key material is
introduced anywhere in this phase.

### Known gaps

- **Presentation replay.** `challenge` is checked for equality when the
  verifier supplies one, but used challenges are not recorded, so a captured
  presentation can be replayed against a verifier that reuses a challenge.
  Single-use nonces need state shared across processes — Phase 9 (SSS).
  `GET /api/v1/credentials/challenge` reports `single_use_enforced: false`.
- **Issuance is unauthenticated.** Anything that can reach the API can ask an
  issuer to sign a credential. There is no authorization layer until Phase 4.
- **No credential schema registry.** Required claims per type are a Python
  constant, not a published, versioned schema.
- **No selective disclosure, no ZKPs, no decentralised revocation registry.**
  Out of scope, and not claimed.

## 15. APIs

See [API.md](API.md) for the full list. Core:

```
POST /api/v1/credentials/issue                 issue and sign
POST /api/v1/credentials/verify                verify, with the full check breakdown
GET  /api/v1/credentials                       list
GET  /api/v1/credentials/{id}                  fetch the signed document
GET  /api/v1/credentials/{id}/status           ACTIVE / REVOKED / EXPIRED
POST /api/v1/credentials/{id}/revoke           revoke
GET  /api/v1/credentials/{id}/verifications    verification history
POST /api/v1/credentials/present               presentation (registry-held keys)
POST /api/v1/credentials/verify-presentation   verify holder proof + credentials
GET  /api/v1/credentials/challenge             nonce for a presentation
GET  /api/v1/credentials/issuers               trust roots and their public keys
GET  /api/v1/agents/{id}/credentials           an agent's inventory

POST http://localhost:900X/present             the AGENT signs its own presentation
GET  http://localhost:900X/credentials         the agent's wallet
```

## 16. Database

| Table | Holds |
|-------|-------|
| `issuer_identities` | issuing authorities, their public keys, their DID Documents |
| `credentials` | the signed document, its claims, issuance and expiry |
| `credential_status` | ACTIVE / REVOKED / EXPIRED, revocation reason and time |
| `credential_presentations` | what was presented, by whom, with which challenge |
| `credential_verification_events` | one row per verification, with per-check results |

Alembic revision `74a919455a7a`. No Phase 1 table was modified.

**Key custody vs the database.** Public keys live in PostgreSQL; private keys
live in a keystore. A deployment that shares the database but not the keystore
— for example running docker-compose against a database seeded from the host —
can verify every existing credential but cannot issue from those issuers, and
fails with `KEYSTORE_ERROR: No key material` rather than pretending. That is
the abstraction working as intended: signing requires custody, verification
requires only the published public key.

## 17. Testing

88 Phase 2 tests, 234 in total (see PHASE_3.md for the current count).

```bash
cd backend && .venv/bin/python -m pytest tests -q
```

Covers issuance (structure, binding, timestamps, real signature, refusals),
signature verification (six field-edit variants, flipped byte, redirected
verification method, agent self-issuance), expiry (injected clock *and* real
elapsed time), revocation, subject binding, unknown issuer, missing claims,
presentations (holder proof, challenge, stolen credential, subject mismatch)
and the wallet.

## 18. Demonstrations

```bash
scripts/run_local.sh                      # start everything
python3 scripts/seed_credentials.py       # issue the demo credential set
python3 scripts/phase2_gate.py            # the mandatory E2E + failure tests
bash scripts/phase2_restart_test.sh       # credentials survive a restart
cd frontend && npm run dev                # the Credentials screen
```

Step-by-step walkthroughs are in [DEMO.md](DEMO.md).

## 19. Limitations

Restating plainly, because the point of this POC is that claims are checkable:

- The proof suite is POC-specific, not W3C Data Integrity (section 8).
- `did:poc:` is not a registered DID method and there is no resolver network.
- The compliance credential is **synthetic demo data**. It is not a real SOX
  attestation and the UI says so wherever it is displayed.
- Issuance and revocation are unauthenticated in this phase.
- Presentations are replayable (section 14).
- The development keystore is not an HSM — see [SECURITY_MODEL.md](SECURITY_MODEL.md).
- Nothing here authorizes anything. Phase 4 does that.
