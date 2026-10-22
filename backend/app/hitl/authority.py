"""The approval authority: the service principal that signs approvals.

WHO SIGNS AN APPROVAL, and why it is not the obvious candidates.

NOT THE AGENT. If the agent's key signed the artifact, the agent could
manufacture its own human approval and the entire phase would be theatre. Its
key is never involved, and a test asserts the approval authority's key is not
any agent's key.

NOT KEYCLOAK. Keycloak signs IDENTITY tokens -- it can state who someone is.
It has no idea what a loan is, never sees the approval screen, and is not asked
to attest to a decision. Claiming it signs approvals would be false, so it does
not.

NOT THE HUMAN. People in this system hold no key material. A POC that issued
one to every human would be inventing a second PKI, which the phase forbids,
and would still be a key the person never actually controls.

So: a distinct SERVICE principal with its own Ed25519 key, its own DID and a
published DID Document, in the same KeyStore as every other principal here.

    did:poc:service:approval-authority

WHAT THE ARTIFACT ACTUALLY MEANS -- stated plainly rather than overclaimed:

    "I, the approval authority, authenticated this human against Keycloak,
     showed them exactly this action, and they decided X."

It is attributable to the human THROUGH the service. That is the honest
strength of this model, and `docs/HITL_SECURITY_MODEL.md` says so.

SEPARATION, which is what makes it worth anything:

  * no agent holds this key, so no agent can approve its own action
  * no credential issuer holds it, so an approval is not a credential
  * no control-plane administrator holds it, so administering the system does
    not confer the ability to approve loans

--------------------------------------------------------------------------
KEY ROTATION (Phase 5.5)
--------------------------------------------------------------------------

Phase 5 refused to rotate: `ensure()` would not regenerate, because doing so
would have invalidated every artifact already issued. That is the right
instinct and the wrong conclusion -- a signing key that can never change is a
key you can never respond to a suspicion about.

The fix is a KEY REGISTER rather than a single key:

    generation 1   ACTIVE   -> RETIRED at T1
    generation 2   ACTIVE   (from T1)

    * exactly ONE key is ACTIVE, and only the ACTIVE key signs. A retired key
      cannot issue a new artifact, because signing resolves the active row
      rather than a key id somebody supplied.
    * the DID Document publishes EVERY non-revoked key, so an artifact signed
      by generation 1 still verifies after generation 2 takes over.
    * a retired key's window ends at `retired_at`, so an artifact CLAIMING to
      have been signed by it afterwards is refused (`APPROVAL_KEY_RETIRED`)
      while the history it really did sign is untouched.
    * a `kid` nobody registered is refused (`APPROVAL_KEY_UNKNOWN`).

ROTATION IS NOT REVOCATION. Rotation retires a key and keeps its history
valid; revocation says the key was never trustworthy and drops that history
too. Conflating them would mean either "we cannot rotate without an outage" or
"a compromised key keeps working". They are separate operations with separate
states.

NO PRIVATE KEY IS EXPOSED BY ANY OF THIS. Rotation asks the KeyStore to
generate; the KeyStore signs on request and never exports. The register holds
public material and a reference.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.db.models.controlplane import ControlPlanePrincipal, PrincipalStatus
from app.db.models.hitl import ApprovalAuthorityKey, SigningKeyStatus
from app.identity.did import build_service_did, key_id, validate_slug
from app.identity.did_document import DID_CONTEXT, VERIFICATION_KEY_TYPE
from app.identity.keys import KeyStore
from app.monitoring.events import Event, EventType

log = get_logger("hitl.authority")

# The approval authority is stored in the control-plane principal registry: it
# is a platform principal with a key and a DID Document, exactly like an
# administrator. It is given NO control-plane roles -- it administers nothing,
# and being able to sign approvals must never imply being able to change policy.
APPROVAL_AUTHORITY_ROLES: tuple[str, ...] = ()


def generation_key_id(did: str, generation: int) -> str:
    """`did#key-N`. Generation 1 keeps the Phase 5 id, so nothing already
    signed has to be re-identified when the register is introduced."""
    return f"{did}#key-{generation}"


def build_service_did_document(
    *, did: str, keys: list[ApprovalAuthorityKey], name: str, active_kid: str | None
) -> dict:
    """DID Document for a signing service, publishing every usable key.

    The keys are listed under `assertionMethod`, not `authentication`: this
    principal ASSERTS a statement (that a human decided something). It never
    logs in anywhere, and listing it under `authentication` would suggest it
    could act as a control-plane caller.

    ALL non-revoked keys appear, because a verifier needs the public key of
    whichever generation signed the artifact in front of it. Which key may
    SIGN is a separate question, answered by the register and named here in
    `serviceMetadata.activeVerificationMethod` for a reader's benefit -- never
    read as authority by the signer, which resolves the ACTIVE row itself.
    """
    usable = [k for k in keys if k.status is not SigningKeyStatus.REVOKED]
    return {
        "@context": DID_CONTEXT,
        "id": did,
        "controller": did,
        "verificationMethod": [
            {
                "id": key.kid,
                "type": VERIFICATION_KEY_TYPE,
                "controller": did,
                "publicKeyMultibase": key.public_key_multibase,
            }
            for key in usable
        ],
        "assertionMethod": [key.kid for key in usable],
        "service": [],
        "serviceMetadata": {
            "name": name,
            "role": "HumanApprovalAuthority",
            "activeVerificationMethod": active_kid,
            "keyGenerations": [
                {
                    "kid": key.kid,
                    "generation": key.generation,
                    "status": key.status.value,
                    "not_before": key.not_before.isoformat(),
                    "retired_at": key.retired_at.isoformat() if key.retired_at else None,
                }
                for key in keys
            ],
            "attests": (
                "That an authenticated human, identified by an OIDC token from "
                "the configured identity provider, made a specific decision "
                "about a specific agent action."
            ),
            "doesNotAttest": (
                "That the human personally signed anything. Humans hold no key "
                "material in this system."
            ),
            "rotation": (
                "Only the active verification method may sign a new artifact. "
                "Retired methods remain published so artifacts they signed while "
                "active stay verifiable."
            ),
        },
    }


class ApprovalAuthority:
    """Creates, rotates and resolves the approval-signing service principal."""

    def __init__(
        self, session: AsyncSession, keystore: KeyStore, settings: Settings | None = None
    ) -> None:
        self.session = session
        self.keystore = keystore
        self.settings = settings or get_settings()
        self.audit = AuditService(session)

    @property
    def did(self) -> str:
        return build_service_did(
            self.settings.approval_authority_slug, self.settings.did_method
        )

    async def get(self) -> ControlPlanePrincipal | None:
        result = await self.session.execute(
            select(ControlPlanePrincipal).where(ControlPlanePrincipal.did == self.did)
        )
        return result.scalar_one_or_none()

    async def require(self) -> ControlPlanePrincipal:
        principal = await self.get()
        if principal is None:
            raise NotFoundError(
                f"The approval authority {self.did} does not exist. It is created "
                f"at application startup; an approval cannot be signed without it."
            )
        return principal

    # --- the key register -------------------------------------------------
    async def keys(self) -> list[ApprovalAuthorityKey]:
        result = await self.session.execute(
            select(ApprovalAuthorityKey)
            .where(ApprovalAuthorityKey.did == self.did)
            .order_by(ApprovalAuthorityKey.generation)
        )
        return list(result.scalars().all())

    async def active_key(self) -> ApprovalAuthorityKey | None:
        result = await self.session.execute(
            select(ApprovalAuthorityKey).where(
                ApprovalAuthorityKey.did == self.did,
                ApprovalAuthorityKey.status == SigningKeyStatus.ACTIVE,
            )
        )
        return result.scalar_one_or_none()

    async def require_active_key(self) -> ApprovalAuthorityKey:
        """The key that may SIGN. Resolved from the register, never supplied.

        This is what makes "a retired key cannot issue new artifacts" a
        structural property rather than a rule someone has to remember: there
        is no parameter here for a caller to pass the wrong key id to.
        """
        key = await self.active_key()
        if key is None:
            raise NotFoundError(
                f"The approval authority {self.did} has no ACTIVE signing key. "
                f"Refusing to sign an approval: there is nothing authorised to "
                f"sign it with."
            )
        return key

    async def key_register(self) -> dict[str, dict]:
        """The verification window of every key, keyed by `kid`.

        Handed to `verify_artifact`, which uses it to decide whether the key on
        a proof was allowed to have signed at the moment the proof claims.
        """
        return {
            key.kid: {
                "status": key.status.value,
                "not_before": key.not_before,
                "retired_at": key.retired_at,
                "generation": key.generation,
            }
            for key in await self.keys()
        }

    # --- creation ---------------------------------------------------------
    async def ensure(self) -> ControlPlanePrincipal:
        """Idempotently create the approval authority and its first key.

        Runs at startup, before any approval can be signed or verified. It does
        NOT rotate: rotation is a deliberate operator action with an audit
        event, never a side effect of a restart. A restart that silently
        produced a new signing key would be indistinguishable from a compromise.
        """
        existing = await self.get()
        if existing is not None:
            # Backfill: a principal created before the key register existed has
            # a real key and no row describing it. Register it as generation 1
            # rather than leaving the register empty, which would make its own
            # artifacts unverifiable under the Phase 5.5 key check.
            if await self.active_key() is None and not await self.keys():
                await self._register_key(
                    kid=existing.kid,
                    generation=1,
                    algorithm=existing.algorithm,
                    public_key_multibase=existing.public_key_multibase,
                    public_key_b64=existing.public_key_b64,
                    keystore_ref=existing.keystore_ref,
                    not_before=existing.created_at or datetime.now(timezone.utc),
                    reason="registered at first Phase 5.5 startup",
                )
                existing.did_document = build_service_did_document(
                    did=self.did, keys=await self.keys(),
                    name="Human Approval Authority", active_kid=existing.kid,
                )
                await self.session.flush()
            return existing

        slug = validate_slug(self.settings.approval_authority_slug)
        did = self.did
        kid = key_id(did)
        if self.keystore.exists(kid):
            raise ConflictError(
                f"Key material for {kid} already exists but no principal record "
                f"does. Refusing to adopt an orphaned key for a signing authority."
            )

        handle = self.keystore.generate_key(kid)
        try:
            now = datetime.now(timezone.utc)
            await self._register_key(
                kid=handle.kid, generation=1, algorithm=handle.algorithm,
                public_key_multibase=handle.public_key_multibase,
                public_key_b64=handle.public_key_b64,
                keystore_ref=handle.keystore_ref, not_before=now,
                reason="initial signing key",
            )
            principal = ControlPlanePrincipal(
                slug=slug,
                did=did,
                name="Human Approval Authority",
                kid=handle.kid,
                algorithm=handle.algorithm,
                public_key_multibase=handle.public_key_multibase,
                public_key_b64=handle.public_key_b64,
                keystore_backend=self.keystore.backend_name,
                keystore_ref=handle.keystore_ref,
                did_document=build_service_did_document(
                    did=did, keys=await self.keys(),
                    name="Human Approval Authority", active_kid=handle.kid,
                ),
                # No control-plane roles. Signing approvals confers no
                # authority over agents, credentials or policy.
                roles=list(APPROVAL_AUTHORITY_ROLES),
                status=PrincipalStatus.ACTIVE,
            )
            self.session.add(principal)
            await self.session.flush()
            log.info("approval_authority_ready", did=did, kid=handle.kid)
            return principal
        except Exception:
            self.keystore.delete(handle.kid)
            raise

    async def _register_key(
        self, *, kid: str, generation: int, algorithm: str,
        public_key_multibase: str, public_key_b64: str, keystore_ref: str,
        not_before: datetime, reason: str,
    ) -> ApprovalAuthorityKey:
        record = ApprovalAuthorityKey(
            did=self.did, kid=kid, generation=generation, algorithm=algorithm,
            public_key_multibase=public_key_multibase,
            public_key_b64=public_key_b64,
            keystore_backend=self.keystore.backend_name,
            keystore_ref=keystore_ref,
            status=SigningKeyStatus.ACTIVE,
            not_before=not_before, reason=reason,
        )
        self.session.add(record)
        await self.session.flush()
        return record

    # --- rotation ---------------------------------------------------------
    async def rotate(
        self, *, reason: str, actor: str | None = None,
        now: datetime | None = None,
    ) -> dict:
        """Retire the active key and start signing with a new one.

        THE RETIREMENT IS THE ATOMIC STEP. A single conditional UPDATE moves
        the ACTIVE row to RETIRED; whoever wins that UPDATE creates the next
        generation. Two operators rotating at the same moment therefore produce
        one rotation and one refusal, rather than two ACTIVE keys -- which
        would mean two keys able to sign, and no way to say which one was
        supposed to.

        Nothing already issued is invalidated: the retired key stays published
        and its artifacts stay dated inside its window.
        """
        now = now or datetime.now(timezone.utc)
        principal = await self.require()
        outgoing = await self.require_active_key()

        won = await self.session.execute(
            update(ApprovalAuthorityKey)
            .where(
                ApprovalAuthorityKey.kid == outgoing.kid,
                ApprovalAuthorityKey.status == SigningKeyStatus.ACTIVE,
            )
            .values(status=SigningKeyStatus.RETIRED, retired_at=now, reason=reason)
            .returning(ApprovalAuthorityKey.kid)
        )
        if won.scalar_one_or_none() is None:
            raise ConflictError(
                f"{outgoing.kid} is no longer the active signing key; another "
                f"rotation completed first. Not creating a second new key."
            )

        generation = outgoing.generation + 1
        kid = generation_key_id(self.did, generation)
        if self.keystore.exists(kid):
            raise ConflictError(
                f"Key material for {kid} already exists. Refusing to adopt an "
                f"orphaned key as the new approval-signing key."
            )
        handle = self.keystore.generate_key(kid)
        try:
            await self._register_key(
                kid=handle.kid, generation=generation, algorithm=handle.algorithm,
                public_key_multibase=handle.public_key_multibase,
                public_key_b64=handle.public_key_b64,
                keystore_ref=handle.keystore_ref, not_before=now, reason=reason,
            )
            principal.kid = handle.kid
            principal.algorithm = handle.algorithm
            principal.public_key_multibase = handle.public_key_multibase
            principal.public_key_b64 = handle.public_key_b64
            principal.keystore_ref = handle.keystore_ref
            principal.did_document = build_service_did_document(
                did=self.did, keys=await self.keys(),
                name=principal.name, active_kid=handle.kid,
            )
            await self.session.flush()
        except Exception:
            self.keystore.delete(handle.kid)
            raise

        await self.audit.record(
            Event(
                EventType.APPROVAL_KEY_ROTATED,
                agent_did=self.did,
                resource="approval_authority",
                action="APPROVAL_KEY_ROTATE",
                decision="ROTATED",
                reason=reason,
                metadata={
                    "did": self.did,
                    "retired_kid": outgoing.kid,
                    "retired_generation": outgoing.generation,
                    "retired_at": now.isoformat(),
                    "active_kid": handle.kid,
                    "active_generation": generation,
                    "actor": actor,
                    # Said explicitly in the audit trail, because "we rotated a
                    # signing key" is exactly the moment somebody will ask.
                    "private_key_exposed": False,
                    "historical_artifacts": (
                        "remain verifiable: the retired key stays published and "
                        "its artifacts are dated inside its window"
                    ),
                },
            )
        )
        log.warning("approval_key_rotated", did=self.did, retired=outgoing.kid,
                    active=handle.kid, generation=generation, actor=actor)
        return {
            "did": self.did,
            "rotated_at": now.isoformat(),
            "retired": outgoing.to_dict(),
            "active": (await self.require_active_key()).to_dict(),
            "reason": reason,
        }

    async def revoke_key(
        self, kid: str, *, reason: str, actor: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalAuthorityKey:
        """Declare a key untrustworthy, including for what it already signed.

        Destructive on purpose, and deliberately NOT what rotation does. Use it
        when a key is believed compromised: every artifact it signed stops
        verifying, because a compromised key's history is exactly what cannot
        be relied on.

        The ACTIVE key cannot be revoked directly -- rotate first, so the
        authority is never left with nothing able to sign.
        """
        now = now or datetime.now(timezone.utc)
        result = await self.session.execute(
            select(ApprovalAuthorityKey).where(ApprovalAuthorityKey.kid == kid)
        )
        record = result.scalar_one_or_none()
        if record is None:
            raise NotFoundError(f"Unknown approval-authority key {kid!r}")
        if record.status is SigningKeyStatus.ACTIVE:
            raise ConflictError(
                f"{kid} is the ACTIVE signing key. Rotate first: revoking it "
                f"here would leave the approval authority unable to sign."
            )
        record.status = SigningKeyStatus.REVOKED
        record.revoked_at = now
        record.reason = reason
        principal = await self.get()
        if principal is not None:
            principal.did_document = build_service_did_document(
                did=self.did, keys=await self.keys(),
                name=principal.name, active_kid=principal.kid,
            )
        await self.session.flush()
        await self.audit.record(
            Event(
                EventType.APPROVAL_KEY_REVOKED,
                agent_did=self.did, resource="approval_authority",
                action="APPROVAL_KEY_REVOKE", decision="REVOKED", reason=reason,
                metadata={"did": self.did, "kid": kid,
                          "generation": record.generation, "actor": actor,
                          "historical_artifacts": "no longer verifiable"},
            )
        )
        log.error("approval_key_revoked", did=self.did, kid=kid, actor=actor)
        return record
