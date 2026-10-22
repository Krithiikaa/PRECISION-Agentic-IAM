"""Issuer identities: the trust roots of the credential layer.

An issuer is an organisation-level authority with its own Ed25519 key pair,
held in the same KeyStore abstraction as everything else. The critical property
is separation: **no agent ever holds an issuer key**. An agent cannot mint a
credential attesting to its own capabilities, because the signature it could
produce is its own agent key, and a verifier resolving the issuer DID would get
a different public key.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.db.models.credential import IssuerIdentity, IssuerStatus
from app.identity.did import build_organization_did, key_id, validate_slug
from app.identity.did_document import build_issuer_did_document
from app.identity.keys import KeyStore

log = get_logger("credentials.issuers")


class IssuerRegistry:
    def __init__(
        self, session: AsyncSession, keystore: KeyStore, settings: Settings | None = None
    ) -> None:
        self.session = session
        self.keystore = keystore
        self.settings = settings or get_settings()

    async def get_by_did(self, did: str) -> IssuerIdentity | None:
        result = await self.session.execute(
            select(IssuerIdentity).where(IssuerIdentity.did == did)
        )
        return result.scalar_one_or_none()

    async def require(self, did: str) -> IssuerIdentity:
        issuer = await self.get_by_did(did)
        if issuer is None:
            raise NotFoundError(f"Unknown issuer: {did}")
        return issuer

    async def get_by_slug(self, slug: str) -> IssuerIdentity | None:
        result = await self.session.execute(
            select(IssuerIdentity).where(IssuerIdentity.slug == slug)
        )
        return result.scalar_one_or_none()

    async def list_issuers(self) -> list[IssuerIdentity]:
        result = await self.session.execute(
            select(IssuerIdentity).order_by(IssuerIdentity.created_at)
        )
        return list(result.scalars().all())

    async def create(self, slug: str, name: str) -> IssuerIdentity:
        validate_slug(slug)
        if await self.get_by_slug(slug) is not None:
            raise ConflictError(f"Issuer {slug!r} already exists")

        did = build_organization_did(slug, self.settings.did_method)
        kid = key_id(did)
        if self.keystore.exists(kid):
            raise ConflictError(f"Key material for {kid} already exists in the keystore")

        handle = self.keystore.generate_key(kid)
        try:
            issuer = IssuerIdentity(
                slug=slug,
                did=did,
                name=name,
                kid=handle.kid,
                algorithm=handle.algorithm,
                public_key_multibase=handle.public_key_multibase,
                public_key_b64=handle.public_key_b64,
                keystore_backend=self.keystore.backend_name,
                keystore_ref=handle.keystore_ref,
                did_document=build_issuer_did_document(
                    did=did,
                    kid=handle.kid,
                    public_key_multibase=handle.public_key_multibase,
                    name=name,
                    service_endpoint=f"{self.settings.api_public_url}/api/v1/credentials",
                ),
                status=IssuerStatus.ACTIVE,
            )
            self.session.add(issuer)
            await self.session.flush()
            return issuer
        except Exception:
            self.keystore.delete(handle.kid)
            raise

    async def ensure_configured_issuers(self) -> list[IssuerIdentity]:
        """Idempotently create the issuers named in CREDENTIAL_ISSUERS.

        Runs at API startup. Verification of any existing credential depends on
        its issuer being resolvable, so these identities must exist before the
        credential endpoints can answer honestly.
        """
        issuers: list[IssuerIdentity] = []
        for slug, name in self.settings.issuer_definitions:
            existing = await self.get_by_slug(slug)
            if existing is not None:
                issuers.append(existing)
                continue
            created = await self.create(slug, name)
            log.info("issuer_bootstrapped", did=created.did, name=created.name)
            issuers.append(created)
        return issuers
