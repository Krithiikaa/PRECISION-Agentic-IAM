"""The JIT authority: the service principal that signs temporary mandates.

WHO SIGNS A GRANT, and why it is not any of the obvious candidates.

NOT THE AGENT. If the agent's key signed its own mandate, it could mint itself
temporary access to anything and the phase would be theatre. Its key is never
involved, and a test asserts the JIT authority's key is no agent's key.

NOT THE APPROVAL AUTHORITY. This is the important one, and it is a deliberate
separation rather than tidiness. Attesting that *a human decided something* and
minting *temporary machine authority* are different powers. Sharing one key
would mean that compromising it yields both -- an attacker could forge the
human approval AND the mandate that carries it forward, which is precisely the
pair you would want to forge together. So:

    did:poc:service:approval-authority    what a person decided
    did:poc:service:jit-authority         what an agent may do, briefly

NOT KEYCLOAK. It signs identity tokens. It has no idea what a loan is.

WHAT A GRANT ACTUALLY MEANS -- stated plainly rather than overclaimed:

    "I, the JIT authority, observed the PDP permit this exact action at this
     moment, and I am recording that permission as reusable within these
     bounds, for this agent only."

It is NOT a statement that the action will still be permitted later. That is
the whole reason every use is re-decided.

--------------------------------------------------------------------------
KEY ROTATION
--------------------------------------------------------------------------

Identical in shape to the Phase 5.5 approval-authority register, because the
problem is identical: a signing key that can never change is a key you can
never respond to a suspicion about.

    generation 1   ACTIVE   -> RETIRED at T1
    generation 2   ACTIVE   (from T1)

  * exactly ONE key is ACTIVE, and only the ACTIVE key signs. A retired key
    cannot issue a new mandate, because signing resolves the active row rather
    than a key id somebody supplied.
  * the DID Document publishes EVERY non-revoked key, so a mandate signed by
    generation 1 still verifies after generation 2 takes over.
  * a retired key's window ends at `retired_at`, so a grant CLAIMING to have
    been signed by it afterwards is refused (`JIT_KEY_RETIRED`) while the
    mandates it really did sign are untouched.
  * a `kid` nobody registered is refused (`JIT_KEY_UNKNOWN`).

ROTATION IS NOT REVOCATION. Rotation retires a key and keeps its history valid;
revocation says the key was never trustworthy and drops that history too.

NO PRIVATE KEY IS EXPOSED BY ANY OF THIS. Rotation asks the KeyStore to
generate; the KeyStore signs on request and never exports. The register holds
public material and a reference, and no route returns a private key.
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
from app.db.models.hitl import SigningKeyStatus
from app.db.models.jit import JITAuthorityKey
from app.identity.did import build_service_did, key_id, validate_slug
from app.identity.did_document import DID_CONTEXT, VERIFICATION_KEY_TYPE
from app.identity.keys import KeyStore
from app.monitoring.events import Event, EventType

log = get_logger("jit.authority")

# The JIT authority is stored in the control-plane principal registry: a
# platform principal with a key and a DID Document, exactly like the approval
# authority. It is given NO control-plane roles -- signing mandates confers no
# authority over agents, credentials or policy, and being able to mint
# temporary access must never imply being able to change what it means.
JIT_AUTHORITY_ROLES: tuple[str, ...] = ()


def generation_key_id(did: str, generation: int) -> str:
    """`did#key-N`. Generation 1 keeps the plain key id."""
    return key_id(did) if generation == 1 else f"{did}#key-{generation}"


def _generation_of(kid: str) -> int:
    """Recover a generation number from a key id.

    Used only when backfilling a register that was rebuilt while the KeyStore
    kept its files. Registering an existing `#key-8` as generation 1 would make
    the NEXT rotation compute `#key-2` and collide with material already on
    disk, so the number has to come from the kid rather than be assumed.

    A kid that does not carry a number is generation 1, which is what the
    original unnumbered form means.
    """
    _, _, suffix = kid.rpartition("#key-")
    try:
        return max(int(suffix), 1)
    except ValueError:
        return 1


def build_jit_did_document(
    *, did: str, keys: list[JITAuthorityKey], name: str, active_kid: str | None
) -> dict:
    """DID Document for the JIT authority, publishing every usable key.

    Keys are listed under `assertionMethod`, not `authentication`: this
    principal ASSERTS a statement (that the PDP permitted something, within
    bounds). It never logs in anywhere, and listing it under `authentication`
    would suggest it could act as a control-plane caller.

    ALL non-revoked keys appear, because a verifier needs the public key of
    whichever generation signed the grant in front of it.
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
            "role": "JITAccessAuthority",
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
                "That the PDP permitted a specific action for a specific agent "
                "at a specific moment, and that the permission may be reused "
                "within the bounds stated in the grant."
            ),
            "doesNotAttest": (
                "That the action is still permitted. Every use of a grant is "
                "re-decided by the PDP; a grant is an input to authorization, "
                "never a substitute for it."
            ),
            "rotation": (
                "Only the active verification method may sign a new grant. "
                "Retired methods remain published so mandates they signed while "
                "active stay verifiable."
            ),
        },
    }


class JITAuthority:
    """Creates, rotates and resolves the JIT-signing service principal."""

    def __init__(
        self, session: AsyncSession, keystore: KeyStore, settings: Settings | None = None
    ) -> None:
        self.session = session
        self.keystore = keystore
        self.settings = settings or get_settings()
        self.audit = AuditService(session)

    @property
    def did(self) -> str:
        return build_service_did(self.settings.jit_authority_slug, self.settings.did_method)

    async def get(self) -> ControlPlanePrincipal | None:
        result = await self.session.execute(
            select(ControlPlanePrincipal).where(ControlPlanePrincipal.did == self.did)
        )
        return result.scalar_one_or_none()

    async def require(self) -> ControlPlanePrincipal:
        principal = await self.get()
        if principal is None:
            raise NotFoundError(
                f"The JIT authority {self.did} does not exist. It is created at "
                f"application startup; a mandate cannot be signed without it."
            )
        return principal

    # --- the key register -------------------------------------------------
    async def keys(self) -> list[JITAuthorityKey]:
        result = await self.session.execute(
            select(JITAuthorityKey)
            .where(JITAuthorityKey.did == self.did)
            .order_by(JITAuthorityKey.generation)
        )
        return list(result.scalars().all())

    async def active_key(self) -> JITAuthorityKey | None:
        result = await self.session.execute(
            select(JITAuthorityKey).where(
                JITAuthorityKey.did == self.did,
                JITAuthorityKey.status == SigningKeyStatus.ACTIVE,
            )
        )
        return result.scalar_one_or_none()

    async def require_active_key(self) -> JITAuthorityKey:
        """The key that may SIGN. Resolved from the register, never supplied.

        This is what makes "a retired key cannot issue new mandates" a
        structural property rather than a rule someone has to remember: there
        is no parameter here for a caller to pass the wrong key id to.
        """
        key = await self.active_key()
        if key is None:
            raise NotFoundError(
                f"The JIT authority {self.did} has no ACTIVE signing key. "
                f"Refusing to sign a grant: there is nothing authorised to "
                f"sign it with."
            )
        return key

    async def key_register(self) -> dict[str, dict]:
        """The verification window of every key, keyed by `kid`."""
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
        """Idempotently create the JIT authority and its first key.

        Runs at startup, before any grant can be signed OR VERIFIED. It does
        NOT rotate: a restart that silently produced a new signing key would be
        indistinguishable from a compromise.
        """
        existing = await self.get()
        if existing is not None:
            if await self.active_key() is None and not await self.keys():
                await self._register_key(
                    kid=existing.kid, generation=_generation_of(existing.kid),
                    algorithm=existing.algorithm,
                    public_key_multibase=existing.public_key_multibase,
                    public_key_b64=existing.public_key_b64,
                    keystore_ref=existing.keystore_ref,
                    not_before=existing.created_at or datetime.now(timezone.utc),
                    reason="registered at first Phase 6 startup",
                )
                existing.did_document = build_jit_did_document(
                    did=self.did, keys=await self.keys(),
                    name="JIT Access Authority", active_kid=existing.kid,
                )
                await self.session.flush()
            return existing

        slug = validate_slug(self.settings.jit_authority_slug)
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
                name="JIT Access Authority",
                kid=handle.kid,
                algorithm=handle.algorithm,
                public_key_multibase=handle.public_key_multibase,
                public_key_b64=handle.public_key_b64,
                keystore_backend=self.keystore.backend_name,
                keystore_ref=handle.keystore_ref,
                did_document=build_jit_did_document(
                    did=did, keys=await self.keys(),
                    name="JIT Access Authority", active_kid=handle.kid,
                ),
                roles=list(JIT_AUTHORITY_ROLES),
                status=PrincipalStatus.ACTIVE,
            )
            self.session.add(principal)
            await self.session.flush()
            log.info("jit_authority_ready", did=did, kid=handle.kid)
            return principal
        except Exception:
            self.keystore.delete(handle.kid)
            raise

    async def _register_key(
        self, *, kid: str, generation: int, algorithm: str,
        public_key_multibase: str, public_key_b64: str, keystore_ref: str,
        not_before: datetime, reason: str,
    ) -> JITAuthorityKey:
        record = JITAuthorityKey(
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
        self, *, reason: str, actor: str | None = None, now: datetime | None = None
    ) -> dict:
        """Retire the active key and start signing with a new one.

        THE RETIREMENT IS THE ATOMIC STEP. A single conditional UPDATE moves the
        ACTIVE row to RETIRED; whoever wins creates the next generation. Two
        operators rotating at the same moment therefore produce one rotation and
        one refusal, rather than two ACTIVE keys -- which would mean two keys
        able to sign and no way to say which was supposed to.

        Nothing already issued is invalidated: the retired key stays published
        and its mandates stay dated inside its window.
        """
        now = now or datetime.now(timezone.utc)
        principal = await self.require()
        outgoing = await self.require_active_key()

        # CHECKED BEFORE THE RETIREMENT, deliberately. Retiring first and
        # discovering afterwards that the new key cannot be created leaves the
        # authority with NO active key -- it can no longer sign, and it cannot
        # rotate again either, because rotation starts by resolving an active
        # key. That is a self-inflicted outage reached by a refusal that was
        # itself correct, so the order matters more than it looks.
        generation = outgoing.generation + 1
        kid = generation_key_id(self.did, generation)
        while self.keystore.exists(kid):
            # Orphaned material from a register that was rebuilt while the
            # KeyStore kept its files. Skipping forward is safe -- generations
            # only have to be increasing and unique, not contiguous -- and is
            # much better than refusing to rotate at all, which is exactly the
            # moment an operator cannot afford to be blocked.
            log.warning("jit_key_generation_occupied", kid=kid,
                        detail="keystore already holds material for this "
                               "generation; skipping forward")
            generation += 1
            kid = generation_key_id(self.did, generation)

        won = await self.session.execute(
            update(JITAuthorityKey)
            .where(
                JITAuthorityKey.kid == outgoing.kid,
                JITAuthorityKey.status == SigningKeyStatus.ACTIVE,
            )
            .values(status=SigningKeyStatus.RETIRED, retired_at=now, reason=reason)
            .returning(JITAuthorityKey.kid)
        )
        if won.scalar_one_or_none() is None:
            raise ConflictError(
                f"{outgoing.kid} is no longer the active signing key; another "
                f"rotation completed first. Not creating a second new key."
            )

        # If the KeyStore refuses for any other reason, PUT THE OUTGOING KEY
        # BACK. Checking the collision case above is not enough on its own: any
        # failure between the retirement and the new key existing would
        # otherwise leave the authority with no ACTIVE key -- unable to sign,
        # and unable to rotate again either, because rotation starts by
        # resolving an active key.
        try:
            handle = self.keystore.generate_key(kid)
        except Exception:
            await self.session.execute(
                update(JITAuthorityKey)
                .where(JITAuthorityKey.kid == outgoing.kid)
                .values(status=SigningKeyStatus.ACTIVE, retired_at=None,
                        reason=outgoing.reason)
            )
            await self.session.flush()
            log.error("jit_rotation_rolled_back", did=self.did,
                      restored=outgoing.kid,
                      detail="the new key could not be created; the outgoing "
                             "key remains ACTIVE so the authority can still sign")
            raise
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
            principal.did_document = build_jit_did_document(
                did=self.did, keys=await self.keys(),
                name=principal.name, active_kid=handle.kid,
            )
            await self.session.flush()
        except Exception:
            # Same compensation, for a failure after the key exists: destroy the
            # material we just made and restore the outgoing key, so a failed
            # rotation is a no-op rather than an outage.
            self.keystore.delete(handle.kid)
            await self.session.execute(
                update(JITAuthorityKey)
                .where(JITAuthorityKey.kid == outgoing.kid)
                .values(status=SigningKeyStatus.ACTIVE, retired_at=None,
                        reason=outgoing.reason)
            )
            await self.session.flush()
            log.error("jit_rotation_rolled_back", did=self.did,
                      restored=outgoing.kid)
            raise

        await self.audit.record(
            Event(
                EventType.JIT_KEY_ROTATED,
                agent_did=self.did,
                resource="jit_authority",
                action="JIT_KEY_ROTATE",
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
                    "private_key_exposed": False,
                    "historical_grants": (
                        "remain verifiable: the retired key stays published and "
                        "its grants are dated inside its window"
                    ),
                },
            )
        )
        log.warning("jit_key_rotated", did=self.did, retired=outgoing.kid,
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
    ) -> JITAuthorityKey:
        """Declare a key untrustworthy, including for what it already signed.

        Destructive on purpose, and deliberately NOT what rotation does. Every
        mandate it signed stops verifying, because a compromised key's history
        is exactly what cannot be relied on.
        """
        now = now or datetime.now(timezone.utc)
        result = await self.session.execute(
            select(JITAuthorityKey).where(JITAuthorityKey.kid == kid)
        )
        record = result.scalar_one_or_none()
        if record is None:
            raise NotFoundError(f"No JIT-authority key {kid!r} is registered.")
        if record.status is SigningKeyStatus.REVOKED:
            raise ConflictError(f"{kid} is already revoked.")

        was_active = record.status is SigningKeyStatus.ACTIVE
        record.status = SigningKeyStatus.REVOKED
        record.revoked_at = now
        record.reason = reason
        principal = await self.require()
        principal.did_document = build_jit_did_document(
            did=self.did, keys=await self.keys(), name=principal.name,
            active_kid=None if was_active else principal.kid,
        )
        await self.session.flush()

        await self.audit.record(
            Event(
                EventType.JIT_KEY_REVOKED,
                agent_did=self.did,
                resource="jit_authority",
                action="JIT_KEY_REVOKE",
                decision="REVOKED",
                reason=reason,
                metadata={
                    "did": self.did, "kid": kid,
                    "generation": record.generation,
                    "was_active": was_active, "actor": actor,
                    "private_key_exposed": False,
                    "historical_grants": (
                        "STOP verifying: revocation declares the key was never "
                        "trustworthy, which is what distinguishes it from rotation"
                    ),
                },
            )
        )
        log.error("jit_key_revoked", did=self.did, kid=kid, actor=actor, reason=reason)
        return record
