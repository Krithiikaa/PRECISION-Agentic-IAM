"""Credential Issuer service.

Mints and signs credentials with an issuer's Ed25519 key. The signature is
produced by the KeyStore, so the issuer private key is never in this module's
hands either -- it asks the store to sign, exactly as Phase 1 does for agents.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.errors import ConflictError, IdentityError, NotFoundError
from app.credentials.canonical import canonical_bytes
from app.credentials.issuer_registry import IssuerRegistry
from app.credentials.vc import (
    CREDENTIAL_PROOF_PURPOSE,
    REQUIRED_CLAIMS,
    RESERVED_CLAIM_KEYS,
    build_credential_document,
    build_proof_options,
    default_expiry,
    new_credential_id,
    normalize_claims,
    signing_payload,
    utcnow,
)
from app.db.models.credential import Credential, CredentialStatus, CredentialStatusValue
from app.db.repositories.agents import AgentRepository
from app.db.repositories.credentials import CredentialRepository
from app.identity.keys import KeyStore
from app.identity.signer import Signer
from app.monitoring.events import Event, EventType


@dataclass
class IssueRequest:
    issuer_did: str
    subject_did: str
    credential_type: str
    claims: dict[str, Any]
    ttl_seconds: int | None = None
    credential_id: str | None = None
    request_id: str | None = None


class CredentialIssuer:
    def __init__(
        self,
        session: AsyncSession,
        keystore: KeyStore,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.keystore = keystore
        self.settings = settings or get_settings()
        self.issuers = IssuerRegistry(session, keystore, self.settings)
        self.repo = CredentialRepository(session)
        self.agents = AgentRepository(session)
        self.audit = AuditService(session)
        self.signer = Signer(keystore)

    def _validate_claims(self, credential_type: str, claims: dict[str, Any]) -> None:
        reserved = RESERVED_CLAIM_KEYS & set(claims)
        if reserved:
            raise IdentityError(
                f"Claim keys {sorted(reserved)} are reserved by the credential data model"
            )
        required = REQUIRED_CLAIMS.get(credential_type)
        if required:
            missing = [claim for claim in required if claim not in claims]
            if missing:
                raise IdentityError(
                    f"{credential_type} requires claims {list(required)}; missing {missing}"
                )

    async def issue(
        self, request: IssueRequest, *, validate_claims: bool = True
    ) -> Credential:
        """Issue and sign a credential.

        `validate_claims=False` exists so tests can construct a deliberately
        malformed credential to prove the verifier rejects it. It is not
        reachable through the HTTP API.
        """
        issuer = await self.issuers.get_by_did(request.issuer_did)
        if issuer is None:
            raise NotFoundError(
                f"Unknown issuer {request.issuer_did}. Credentials may only be "
                f"issued by a registered authority."
            )
        if issuer.keystore_backend == "external":
            raise IdentityError(
                f"Issuer {issuer.did} holds its own key; this service cannot sign for it"
            )

        # The subject must be a real, registered agent identity from Phase 1.
        subject = await self.agents.get_by_did(request.subject_did)
        if subject is None:
            raise NotFoundError(
                f"Credential subject {request.subject_did} is not a registered agent"
            )

        claims = normalize_claims(request.claims)
        if validate_claims:
            self._validate_claims(request.credential_type, claims)

        ttl = request.ttl_seconds or self.settings.vc_default_ttl_seconds
        if ttl <= 0 or ttl > self.settings.vc_max_ttl_seconds:
            raise IdentityError(
                f"expires_in_seconds must be between 1 and {self.settings.vc_max_ttl_seconds}"
            )

        credential_id = request.credential_id or new_credential_id()
        if await self.repo.get(credential_id) is not None:
            raise ConflictError(f"Credential {credential_id} already exists")

        issued_at = utcnow()
        expires_at = default_expiry(issued_at, ttl)

        document = build_credential_document(
            credential_id=credential_id,
            credential_type=request.credential_type,
            issuer_did=issuer.did,
            subject_did=request.subject_did,
            claims=claims,
            issued_at=issued_at,
            expires_at=expires_at,
            status_endpoint=(
                f"{self.settings.api_public_url}/api/v1/credentials/{credential_id}/status"
            ),
        )

        proof_options = build_proof_options(
            verification_method=issuer.kid,
            proof_purpose=CREDENTIAL_PROOF_PURPOSE,
            created=issued_at,
        )
        payload = canonical_bytes(signing_payload(document, proof_options))
        signature = self.signer.sign(issuer.kid, payload)

        proof = {**proof_options, "proofValue": signature.signature_b64}
        document["proof"] = proof

        record = Credential(
            credential_id=credential_id,
            issuer_did=issuer.did,
            subject_did=request.subject_did,
            credential_type=request.credential_type,
            claims=claims,
            document=document,
            proof=proof,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        self.session.add(record)
        await self.session.flush()

        self.session.add(
            CredentialStatus(
                credential_id=credential_id,
                status=CredentialStatusValue.ACTIVE,
                updated_at=issued_at,
            )
        )
        await self.session.flush()
        await self.session.refresh(record, ["status_record"])

        metadata = {
            "credential_id": credential_id,
            "credential_type": request.credential_type,
            "issuer": issuer.did,
            "issuer_name": issuer.name,
            "ttl_seconds": ttl,
            "expires_at": expires_at.isoformat(),
        }
        await self.audit.record(
            Event(
                EventType.CREDENTIAL_ISSUED,
                agent_did=request.subject_did,
                request_id=request.request_id,
                resource=credential_id,
                action="ISSUE",
                decision="ISSUED",
                metadata=metadata,
            )
        )
        await self.audit.record(
            Event(
                EventType.CREDENTIAL_STORED,
                agent_did=request.subject_did,
                request_id=request.request_id,
                resource=credential_id,
                metadata={"credential_id": credential_id, "status": "ACTIVE"},
            )
        )
        return record
