"""Control-plane administrator identities.

WHY THIS EXISTS, and why it is not a federated identity provider. Some
control-plane actions are not an agent acting for itself -- activating a
policy, signing as a custodied identity, forcing a registry sweep. Those need a
principal that is not an agent. Phase 4.5 is explicitly forbidden from building
the human identity model (no external identity provider, no OIDC, no SAML: that
is HITL), so an administrator is the simplest principal this architecture
ALREADY supports and can already verify:

    a DID + an Ed25519 key pair in the KeyStore + a published DID Document

Identical in every mechanism to a credential issuer. The only differences are
the namespace (`did:poc:administrator:*`) and that it carries ROLES rather than
a signing authority over credentials.

SEPARATION, which is the point of a separate registry:

  * no agent holds an administrator key, so no agent can authorise policy
    changes however many credentials it accumulates
  * no administrator holds an agent key, so an administrator cannot heartbeat
    as an agent or present an agent's credential
  * an administrator key cannot issue credentials -- that is the issuer
    registry, and a verifier resolving an issuer DID gets a different key

Roles are granted by configuration, not self-declared, and the ROLE NAMES MEAN
NOTHING HERE. This module records them; Rego decides what they permit. That
split is deliberate: privilege logic lives with all the other policy, in OPA.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.errors import ConflictError
from app.core.logging import get_logger
from app.db.models.controlplane import ControlPlanePrincipal, PrincipalStatus
from app.identity.did import build_administrator_did, key_id, validate_slug
from app.identity.did_document import DID_CONTEXT, VERIFICATION_KEY_TYPE
from app.identity.keys import KeyStore

log = get_logger("controlplane.principals")

# Every role the system recognises. Declared here so an unknown role in
# configuration is a startup error rather than a privilege that silently never
# matches -- an operator who typos `policy-admin` should be told, not left with
# an administrator that authenticates and can do nothing.
KNOWN_ROLES = frozenset({
    "policy_admin",       # PAP: load, activate and deactivate policy in OPA
    "registry_admin",     # ANS: force a sweep, deregister another agent
    "identity_admin",     # sign as a registry-custodied identity, rotate the
                          # approval-signing key
    "enforcement",        # ask the PDP / AEM on behalf of another subject (PEP)
    # Phase 5.5. Restate the amount on a loan application. Its OWN role, held
    # by nobody else: the amount decides how many humans a request needs, so
    # being able to change it is as consequential as being able to approve, and
    # must not arrive as a side effect of administering identity or policy.
    "loan_admin",
})


class UnknownRoleError(ValueError):
    """Configuration named a role this system does not define."""


def build_administrator_did_document(
    *, did: str, kid: str, public_key_multibase: str, name: str, roles: list[str]
) -> dict:
    """DID Document for a control-plane administrator.

    Same W3C shape as every other document here. The key is listed under
    `authentication` and NOT under `assertionMethod`: an administrator
    authenticates control-plane requests, it does not assert claims about
    anyone. Getting that wrong would suggest an administrator could sign
    credentials.
    """
    return {
        "@context": DID_CONTEXT,
        "id": did,
        "controller": did,
        "verificationMethod": [
            {
                "id": kid,
                "type": VERIFICATION_KEY_TYPE,
                "controller": did,
                "publicKeyMultibase": public_key_multibase,
            }
        ],
        "authentication": [kid],
        "service": [],
        "administratorMetadata": {
            "name": name,
            "role": "ControlPlaneAdministrator",
            # Recorded for transparency. NOT consulted when authorising: the
            # granted roles come from the database row, so a published document
            # can never widen a principal's privileges.
            "grantedRoles": sorted(roles),
        },
    }


class ControlPlanePrincipalRegistry:
    def __init__(
        self, session: AsyncSession, keystore: KeyStore, settings: Settings | None = None
    ) -> None:
        self.session = session
        self.keystore = keystore
        self.settings = settings or get_settings()

    async def get_by_did(self, did: str) -> ControlPlanePrincipal | None:
        result = await self.session.execute(
            select(ControlPlanePrincipal).where(ControlPlanePrincipal.did == did)
        )
        return result.scalar_one_or_none()

    async def get_by_slug(self, slug: str) -> ControlPlanePrincipal | None:
        result = await self.session.execute(
            select(ControlPlanePrincipal).where(ControlPlanePrincipal.slug == slug)
        )
        return result.scalar_one_or_none()

    async def list_principals(self) -> list[ControlPlanePrincipal]:
        result = await self.session.execute(
            select(ControlPlanePrincipal).order_by(ControlPlanePrincipal.slug)
        )
        return list(result.scalars().all())

    async def create(
        self, slug: str, name: str, roles: tuple[str, ...]
    ) -> ControlPlanePrincipal:
        validate_slug(slug)
        unknown = sorted(set(roles) - KNOWN_ROLES)
        if unknown:
            raise UnknownRoleError(
                f"Administrator {slug!r} was granted unknown role(s) {unknown}. "
                f"Known roles: {sorted(KNOWN_ROLES)}"
            )
        if await self.get_by_slug(slug) is not None:
            raise ConflictError(f"Control-plane principal {slug!r} already exists")

        did = build_administrator_did(slug, self.settings.did_method)
        kid = key_id(did)
        if self.keystore.exists(kid):
            raise ConflictError(f"Key material for {kid} already exists in the keystore")

        handle = self.keystore.generate_key(kid)
        try:
            principal = ControlPlanePrincipal(
                slug=slug,
                did=did,
                name=name,
                kid=handle.kid,
                algorithm=handle.algorithm,
                public_key_multibase=handle.public_key_multibase,
                public_key_b64=handle.public_key_b64,
                keystore_backend=self.keystore.backend_name,
                keystore_ref=handle.keystore_ref,
                did_document=build_administrator_did_document(
                    did=did, kid=handle.kid,
                    public_key_multibase=handle.public_key_multibase,
                    name=name, roles=list(roles),
                ),
                roles=sorted(roles),
                status=PrincipalStatus.ACTIVE,
            )
            self.session.add(principal)
            await self.session.flush()
            return principal
        except Exception:
            # Never leave orphaned key material behind for an identity that
            # does not exist.
            self.keystore.delete(handle.kid)
            raise

    async def ensure_configured_principals(self) -> list[ControlPlanePrincipal]:
        """Idempotently create the administrators named in configuration.

        Runs at API startup, before anything can be authenticated. Roles are
        RECONCILED on every start: a privilege removed from configuration is
        removed from the principal, so revoking an administrator's rights does
        not require a database edit. Key material and the DID are never
        regenerated -- rotating a key is a deliberate operator action, not a
        side effect of a restart.
        """
        principals: list[ControlPlanePrincipal] = []
        for slug, name, roles in self.settings.administrator_definitions:
            existing = await self.get_by_slug(slug)
            if existing is None:
                created = await self.create(slug, name, roles)
                log.info("control_plane_principal_bootstrapped",
                         did=created.did, roles=created.roles)
                principals.append(created)
                continue
            desired = sorted(roles)
            if list(existing.roles or []) != desired:
                unknown = sorted(set(roles) - KNOWN_ROLES)
                if unknown:
                    raise UnknownRoleError(
                        f"Administrator {slug!r} was granted unknown role(s) "
                        f"{unknown}. Known roles: {sorted(KNOWN_ROLES)}"
                    )
                log.warning("control_plane_roles_reconciled", did=existing.did,
                            previous=list(existing.roles or []), current=desired)
                existing.roles = desired
                document = dict(existing.did_document)
                metadata = dict(document.get("administratorMetadata") or {})
                metadata["grantedRoles"] = desired
                document["administratorMetadata"] = metadata
                existing.did_document = document
                await self.session.flush()
            principals.append(existing)
        return principals
