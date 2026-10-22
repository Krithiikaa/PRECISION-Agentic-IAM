"""Human principals: the minimum this system needs to know about a person.

KEYCLOAK REMAINS AUTHORITATIVE. This table is not a copy of its user database
and must not become one. It holds what the application itself needs:

  * a stable local handle for audit correlation
  * the display information the approval screen shows
  * a LOCAL status, so a person can be stood down here without touching the IdP

`last_seen_roles` is an audit record of what a token carried. It is never read
when deciding anything. Authorization roles come from the validated token on
every single request -- so removing `LOAN_OFFICER` in Keycloak takes effect on
the next call, with no synchronisation, no cache to invalidate, and no window
in which a stored copy still says yes.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.logging import get_logger
from app.db.models.hitl import HumanPrincipal, HumanStatus
from app.humans.oidc import HumanIdentity
from app.monitoring.events import Event, EventType

log = get_logger("humans.principals")


class HumanPrincipalRegistry:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.audit = AuditService(session)

    async def get(self, *, issuer: str, subject: str) -> HumanPrincipal | None:
        result = await self.session.execute(
            select(HumanPrincipal).where(
                HumanPrincipal.issuer == issuer,
                HumanPrincipal.subject == subject,
            )
        )
        return result.scalar_one_or_none()

    async def list_principals(self) -> list[HumanPrincipal]:
        result = await self.session.execute(
            select(HumanPrincipal).order_by(HumanPrincipal.username)
        )
        return list(result.scalars().all())

    async def upsert(self, identity: HumanIdentity) -> HumanPrincipal:
        """Record that this person authenticated. Called only after validation.

        The subject id is scoped to its issuer: two realms can both mint
        `sub=1234`, and treating those as the same person would merge two
        humans into one identity.
        """
        now = datetime.now(timezone.utc)
        existing = await self.get(issuer=identity.issuer, subject=identity.subject)
        if existing is not None:
            existing.username = identity.username
            existing.display_name = identity.display_name
            existing.email = identity.email
            existing.last_seen_roles = sorted(identity.roles)
            existing.last_seen_at = now
            existing.authentications = (existing.authentications or 0) + 1
            await self.session.flush()
            return existing

        principal = HumanPrincipal(
            subject=identity.subject,
            issuer=identity.issuer,
            provider=identity.provider,
            username=identity.username,
            display_name=identity.display_name,
            email=identity.email,
            last_seen_roles=sorted(identity.roles),
            status=HumanStatus.ACTIVE,
            first_seen_at=now,
            last_seen_at=now,
            authentications=1,
        )
        self.session.add(principal)
        await self.session.flush()
        await self.audit.record(
            Event(
                EventType.HUMAN_PRINCIPAL_REGISTERED,
                resource="human_principals",
                action="register",
                decision="REGISTERED",
                metadata={
                    "principal": identity.principal_urn,
                    "username": identity.username,
                    "issuer": identity.issuer,
                    "provider": identity.provider,
                    "roles": sorted(identity.roles),
                },
            )
        )
        log.info("human_principal_registered", principal=identity.principal_urn,
                 username=identity.username)
        return principal
