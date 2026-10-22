"""Data access for credentials, status, presentations and verification events."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.credential import (
    Credential,
    CredentialPresentation,
    CredentialStatus,
    CredentialStatusValue,
    CredentialVerificationEvent,
)


class CredentialRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # --- credentials -----------------------------------------------------
    async def get(self, credential_id: str) -> Credential | None:
        result = await self.session.execute(
            select(Credential).where(Credential.credential_id == credential_id)
        )
        return result.scalar_one_or_none()

    async def list_credentials(
        self,
        *,
        subject_did: str | None = None,
        issuer_did: str | None = None,
        credential_type: str | None = None,
        status: CredentialStatusValue | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Credential]:
        stmt = select(Credential).order_by(Credential.issued_at.desc())
        if subject_did:
            stmt = stmt.where(Credential.subject_did == subject_did)
        if issuer_did:
            stmt = stmt.where(Credential.issuer_did == issuer_did)
        if credential_type:
            stmt = stmt.where(Credential.credential_type == credential_type)
        result = await self.session.execute(stmt.limit(limit).offset(offset))
        records = list(result.scalars().all())
        if status is not None:
            records = [
                r for r in records
                if r.status_record and r.status_record.status == status
            ]
        return records

    # --- status ----------------------------------------------------------
    async def get_status(self, credential_id: str) -> CredentialStatus | None:
        return await self.session.get(CredentialStatus, credential_id)

    async def set_status(
        self,
        credential_id: str,
        status: CredentialStatusValue,
        reason: str | None = None,
        when: datetime | None = None,
    ) -> CredentialStatus | None:
        record = await self.get_status(credential_id)
        if record is None:
            return None
        when = when or datetime.now(timezone.utc)
        record.status = status
        record.updated_at = when
        if status == CredentialStatusValue.REVOKED:
            record.revoked_at = when
            record.revocation_reason = reason
        await self.session.flush()
        return record

    async def list_expired_active(self, now: datetime) -> list[Credential]:
        """ACTIVE credentials whose expiry has passed.

        Used to reconcile the stored status with wall-clock time. Note the
        verifier does NOT depend on this sweep: it compares timestamps itself,
        so an expired credential is rejected whether or not the sweep has run.
        """
        result = await self.session.execute(
            select(Credential)
            .join(CredentialStatus, CredentialStatus.credential_id == Credential.credential_id)
            .where(
                Credential.expires_at <= now,
                CredentialStatus.status == CredentialStatusValue.ACTIVE,
            )
        )
        return list(result.scalars().all())

    # --- presentations ---------------------------------------------------
    async def record_presentation(
        self,
        *,
        presentation_id: str,
        holder_did: str,
        credential_ids: list[str],
        document: dict[str, Any],
        challenge: str | None = None,
        domain: str | None = None,
    ) -> CredentialPresentation:
        record = CredentialPresentation(
            presentation_id=presentation_id,
            holder_did=holder_did,
            credential_ids=credential_ids,
            document=document,
            challenge=challenge,
            domain=domain,
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(record)
        await self.session.flush()
        return record

    async def list_presentations(
        self, *, holder_did: str | None = None, limit: int = 100
    ) -> list[CredentialPresentation]:
        stmt = select(CredentialPresentation).order_by(
            CredentialPresentation.created_at.desc()
        )
        if holder_did:
            stmt = stmt.where(CredentialPresentation.holder_did == holder_did)
        result = await self.session.execute(stmt.limit(limit))
        return list(result.scalars().all())

    # --- verification events ---------------------------------------------
    async def record_verification(
        self,
        *,
        credential_id: str | None,
        issuer_did: str | None,
        subject_did: str | None,
        credential_type: str | None,
        verifier: str | None,
        request_id: str | None,
        valid: bool,
        reason: str,
        detail: str | None,
        checks: dict[str, bool],
        presentation_id: str | None = None,
    ) -> CredentialVerificationEvent:
        record = CredentialVerificationEvent(
            occurred_at=datetime.now(timezone.utc),
            credential_id=credential_id,
            presentation_id=presentation_id,
            issuer_did=issuer_did,
            subject_did=subject_did,
            credential_type=credential_type,
            verifier=verifier,
            request_id=request_id,
            valid=valid,
            reason=reason,
            detail=detail,
            checks=checks,
        )
        self.session.add(record)
        await self.session.flush()
        return record

    async def list_verifications(
        self, *, credential_id: str | None = None, limit: int = 100
    ) -> list[CredentialVerificationEvent]:
        stmt = select(CredentialVerificationEvent).order_by(
            CredentialVerificationEvent.occurred_at.desc()
        )
        if credential_id:
            stmt = stmt.where(CredentialVerificationEvent.credential_id == credential_id)
        result = await self.session.execute(stmt.limit(limit))
        return list(result.scalars().all())
