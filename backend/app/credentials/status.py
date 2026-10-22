"""Credential status: the mutable half of a credential's life.

The signed document cannot carry status, because revocation happens after
signing. Status therefore lives here, is looked up by the verifier on every
check, and survives restarts because it is a database row.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.errors import ConflictError, NotFoundError
from app.db.models.credential import Credential, CredentialStatusValue
from app.db.repositories.credentials import CredentialRepository
from app.monitoring.events import Event, EventType


class CredentialStatusService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = CredentialRepository(session)
        self.audit = AuditService(session)

    async def get(self, credential_id: str) -> dict:
        record = await self.repo.get(credential_id)
        if record is None:
            raise NotFoundError(f"Unknown credential {credential_id}")
        status = record.status_record
        now = datetime.now(timezone.utc)

        # Report EXPIRED as an effective status even when the stored row still
        # says ACTIVE: wall-clock time is authoritative, not the sweep.
        effective = status.status.value if status else "UNKNOWN"
        if effective == CredentialStatusValue.ACTIVE.value and record.expires_at <= now:
            effective = CredentialStatusValue.EXPIRED.value

        return {
            "credential_id": credential_id,
            "status": effective,
            "stored_status": status.status.value if status else "UNKNOWN",
            "issued_at": record.issued_at.isoformat(),
            "expires_at": record.expires_at.isoformat(),
            "seconds_remaining": max(0, int((record.expires_at - now).total_seconds())),
            "revoked_at": status.revoked_at.isoformat() if status and status.revoked_at else None,
            "revocation_reason": status.revocation_reason if status else None,
            "updated_at": status.updated_at.isoformat() if status else None,
        }

    async def revoke(
        self, credential_id: str, reason: str, request_id: str | None = None
    ) -> dict:
        record = await self.repo.get(credential_id)
        if record is None:
            raise NotFoundError(f"Unknown credential {credential_id}")
        status = record.status_record
        if status is not None and status.status == CredentialStatusValue.REVOKED:
            raise ConflictError(f"Credential {credential_id} is already revoked")

        await self.repo.set_status(credential_id, CredentialStatusValue.REVOKED, reason)
        await self.audit.record(
            Event(
                EventType.CREDENTIAL_REVOKED,
                agent_did=record.subject_did,
                request_id=request_id,
                resource=credential_id,
                action="REVOKE",
                decision="REVOKED",
                reason=reason,
                metadata={
                    "credential_id": credential_id,
                    "credential_type": record.credential_type,
                    "issuer": record.issuer_did,
                },
            )
        )
        return await self.get(credential_id)

    async def sweep_expired(self) -> list[str]:
        """Reconcile stored status with wall-clock expiry.

        Purely bookkeeping so the registry reads correctly. Verification does
        not depend on it -- the verifier compares timestamps directly, so a
        credential is rejected the instant it expires, swept or not.
        """
        now = datetime.now(timezone.utc)
        expired: list[Credential] = await self.repo.list_expired_active(now)
        for record in expired:
            await self.repo.set_status(
                record.credential_id, CredentialStatusValue.EXPIRED, None, now
            )
            await self.audit.record(
                Event(
                    EventType.CREDENTIAL_EXPIRED,
                    agent_did=record.subject_did,
                    resource=record.credential_id,
                    decision="EXPIRED",
                    reason="CREDENTIAL_EXPIRED",
                    metadata={
                        "credential_id": record.credential_id,
                        "expired_at": record.expires_at.isoformat(),
                    },
                )
            )
        return [r.credential_id for r in expired]
