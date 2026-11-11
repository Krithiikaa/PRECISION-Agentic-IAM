# Operations Runbook — Backup, Recovery and Key Rotation

**Scope:** what an operator must do to keep this system recoverable, and
what to do when a key is compromised.

**Honesty note up front.** The rotation procedures below are *implemented and
tested in code*. The backup and restore procedures are *documented and
locally verified against this POC's PostgreSQL*; they have **not** been
exercised against a production-scale database, and no disaster-recovery
rehearsal has been performed. Section 6 states exactly which claims rest on
which evidence.

---

## 1. What has to survive

Two things, and losing either is unrecoverable in a different way.

| | Lost means |
|---|---|
| **PostgreSQL** | every agent identity, credential, approval, mandate, transaction and audit record is gone |
| **The keystore** | every private key is gone. Credentials already issued can still be *verified* (public keys live in DID documents in the database) but nothing can be *issued, approved, mandated or signed* again |

**They must be backed up together and restored together.** A database
restored next to a different keystore produces a system that can read its
own history and sign nothing — and the failure appears as unexplained
signing errors, not as a restore problem.

The keystore is encrypted at rest with `KEYSTORE_MASTER_KEY`. **That key is
not in the backup and must not be.** Store it in a secrets manager. A backup
of the keystore without the master key is inert; the master key without the
backup is useless. That is the intended split.

---

## 2. Database backup

```bash
# Logical backup, custom format so it can be restored selectively.
docker compose exec -T postgres \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc \
  > "backup-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

### Verifying the backup is real

A backup nobody has restored is a hypothesis. Verify integrity **without**
touching production:

```bash
# 1. The file is a well-formed archive and lists its contents.
pg_restore --list backup-*.dump | head

# 2. It restores into a scratch database.
createdb restore_check
pg_restore -d restore_check backup-*.dump

# 3. The schema is at the expected migration head.
psql -d restore_check -c "SELECT version_num FROM alembic_version;"

# 4. The security-critical tables are populated and their constraints
#    survived -- a restore that dropped a UNIQUE constraint would silently
#    remove the exactly-once guarantees behind A2A and MCP.
psql -d restore_check -c "
  SELECT conname FROM pg_constraint
  WHERE conname IN ('uq_a2a_transaction_sender_id',
                    'uq_mcp_invocation_request',
                    'uq_presentation_challenge');"

dropdb restore_check
```

**Step 4 is the one most backup procedures omit.** The exactly-once
properties in this system are enforced by database constraints, not by
application code. A restore that lost them would leave a system that looks
healthy and executes payments twice.

### Restore

```bash
docker compose stop iam-api ans
docker compose exec -T postgres psql -U "$POSTGRES_USER" -c \
  "DROP DATABASE IF EXISTS $POSTGRES_DB; CREATE DATABASE $POSTGRES_DB;"
docker compose exec -T postgres pg_restore -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" < backup.dump
docker compose start iam-api ans   # migrations run on start
```

### Migration recovery

Migrations are a single linear chain with no branches. On start the API runs
`alembic upgrade head`.

- **Restore is older than the code.** Migrations replay forward on start.
  Every Phase 7–10 migration has a tested `downgrade()` and contains no
  `ALTER TABLE`, so forward replay cannot lose a column.
- **Restore is *newer* than the code** (rolled back the app but not the
  database). The API will start against a schema it does not expect. Roll
  the schema back explicitly first: `alembic downgrade <revision>`.
- **A migration fails mid-run.** PostgreSQL applies DDL transactionally
  here, so a failed migration leaves the previous revision intact. Fix the
  cause and re-run; do not hand-edit `alembic_version`.

### Recovery objectives

**Not established.** RPO and RTO depend on backup frequency and the restore
time of a real dataset, neither of which has been measured for a production
volume. The procedures above are correct; the numbers are the operator's to
determine. Stating invented figures here would be worse than stating none.

---

## 3. Key rotation

Four signing authorities, each rotated independently and each with a
different consequence if compromised.

| Authority | Rotate with | If compromised, an attacker can |
|---|---|---|
| **Agent signing keys** | re-provision the agent | impersonate that agent: sign A2A envelopes, control-plane proofs and OAuth client assertions as it |
| **Credential issuer** | re-key the issuer identity | mint credentials granting any capability — **the worst of the four** |
| **Approval authority** | `POST /api/v1/hitl/authority/keys/rotate` | forge human approvals, defeating HITL and dual control |
| **JIT authority** | `POST /api/v1/jit/keys/rotate` | forge mandates for actions the PDP already permits |

### What rotation does, and deliberately does not do

Rotation **retires** the outgoing key and starts signing with a new one. It
does **not** invalidate artifacts already signed: the retired key stays
published in the DID document and its artifacts remain valid *within their
own validity window*. That is correct for rotation — a scheduled key change
must not void every approval ever granted.

**It is therefore not a compromise response.** See §4.

Both rotations are atomic: a single conditional `UPDATE` moves the ACTIVE
row to RETIRED, and whoever wins it creates the next generation. Two
operators rotating simultaneously produce one rotation and one refusal, not
two active keys. Covered by `tests/test_approval_key_rotation.py` (6 tests)
and `tests/test_jit_key_rotation.py` (7 tests).

```bash
# Approval authority. identity_admin only -- NOT policy_admin: whoever
# decides the rules should not also decide which key attests that a human
# agreed to something.
curl -X POST https://api.example.com/api/v1/hitl/authority/keys/rotate \
  -H 'Content-Type: application/json' -d '{"reason":"scheduled rotation"}'
  # ...plus a control-plane proof signed by the identity administrator.

# Verify: the new key is ACTIVE, the old one RETIRED and still published.
curl https://api.example.com/api/v1/hitl/authority/keys
```

### Agent and issuer keys

`scripts/provision_agents.py` creates an agent's key in that agent's own
`.keystore-agents/<slug>/` directory. Re-provisioning generates a new key and
republishes the DID document.

**After rotating an agent key you must also update its OAuth client**, or
MCP authentication breaks — Keycloak still holds the old public key:

```bash
cd backend && python3 ../scripts/provision_mcp_clients.py --agent <slug>
```

---

## 4. Key compromise response

**Rotation is not containment.** A rotated key stays published and its
artifacts stay valid. For a compromise you must *revoke*.

Order matters — stop the bleeding before cleaning up.

1. **Contain first.**
   - Agent key: `POST /api/v1/agents/{id}/status` → `SUSPENDED`. Effective on
     the *next call*, because the PIP re-reads agent status inside every
     authorization evaluation — it does not wait for a token to expire.
   - Also disable its OAuth client:
     `python3 ../scripts/provision_mcp_clients.py --revoke <did>`.
     Existing access tokens stay valid until expiry (900s); the PDP refuses
     the agent regardless, which is why step one is the control and this is
     the faster door.
2. **Revoke what the key produced.** Credentials:
   `POST /api/v1/credentials/{id}/revoke`. Revocation is immediate and
   system-wide — verified by `scripts/phase9_e2e.py` scenario B.
3. **Kill live mandates:** `POST /api/v1/jit/agents/{did}/revoke`.
4. **Rotate**, now that the compromised key can no longer be used.
5. **Establish the blast radius** from the audit trail. Everything the key
   signed is correlated by `request_id`:
   `GET /api/v1/audit?agent_did=<did>` (requires `audit_read`).
6. **Re-issue** credentials to the replacement identity.

### If the credential issuer key is compromised

The worst case, and it has no clean containment: an attacker holding it can
mint a credential granting any capability, and those credentials verify
correctly because they *are* correctly signed.

- Revoke the issuer identity so new credentials from it fail issuer checks.
- Revoke **every credential it issued** — not only the ones you can see.
  Anything it signed must be presumed hostile.
- Rotate and re-issue from a new issuer identity.

Plan for this before it happens. The recovery is long and there is no
shortcut.

### If `KEYSTORE_MASTER_KEY` is compromised

Every private key in the keystore must be considered exposed, because the
keystore is encrypted with it. Rotate **all four** authorities and
re-provision every agent. There is no partial recovery.

---

## 5. Routine operational tasks

| Task | Command | Why |
|---|---|---|
| Sweep expired mandates | `POST /api/v1/jit/sweep` | moves overdue grants to EXPIRED |
| Sweep A2A transactions | `POST /api/v1/a2a/sweep` | moves overdue transactions to EXPIRED |
| Sweep spent challenges | `ChallengeService.sweep()` | housekeeping only — an expired challenge is already refused |
| Re-seed demo credentials | `scripts/seed_credentials.py` | **development only**, 1-hour TTL |

Policy state reconciles itself: a 15-second loop restores any ACTIVE module
missing from OPA, which recovers automatically from an OPA restart. Since
Phase 9 it correctly honours an operator's deactivation and will **not**
resurrect a policy you switched off.

---

## 6. What is verified, and what is not

| Claim | Evidence |
|---|---|
| Approval key rotation is atomic and does not invalidate prior artifacts | `tests/test_approval_key_rotation.py`, 6 tests |
| JIT key rotation, same | `tests/test_jit_key_rotation.py`, 7 tests |
| Rotation survives concurrent operators | covered in both files |
| Credential revocation is immediate | `scripts/phase9_e2e.py` scenario B; `test_mcp_authorization.py` |
| Agent deactivation is immediate | `test_mcp_authorization.py` |
| Migrations round-trip forward and backward | verified for every Phase 7–10 migration |
| Backup/restore commands are correct | **locally verified** against this POC's PostgreSQL |
| Backup integrity verification | **documented, locally verified** |
| Restore at production scale | **NOT VERIFIED** — no production-scale dataset exists |
| RPO / RTO | **NOT ESTABLISHED** — see §2 |
| Disaster-recovery rehearsal | **NOT PERFORMED** |
| Key compromise response | **DOCUMENTED, NOT REHEARSED.** The individual controls it relies on (revocation, suspension, rotation) are each tested; the end-to-end procedure has never been run against a real incident |

`ApprovalAuthority.rotate()` was re-inspected during Phase 10 following the
standing instruction not to modify it. **No defect was found.** The
retirement is a single atomic conditional `UPDATE`, a lost race raises
`ConflictError` rather than creating a second active key, an orphaned
keystore entry is refused rather than adopted, and a failure after key
generation deletes the new key before re-raising. It was **not modified**.
