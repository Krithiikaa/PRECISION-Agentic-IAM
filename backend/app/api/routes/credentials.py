"""Credential endpoints: issue, verify, list, status, revoke, present."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, status as http_status
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import KeyStoreDep, RegistryDep, SessionDep, SettingsDep
from app.controlplane.guard import ControlPlaneGuard, body_key, fixed, path_param
from app.core.errors import NotFoundError
from app.credentials.issuer import CredentialIssuer, IssueRequest
from app.credentials.challenge import ChallengeService
from app.credentials.issuer_registry import IssuerRegistry
from app.credentials.presentation import new_challenge
from app.credentials.presenter import CredentialPresenter, PresentationVerifier
from app.credentials.status import CredentialStatusService
from app.credentials.verifier import CredentialVerifier
from app.db.models.credential import Credential, CredentialStatusValue
from app.db.repositories.credentials import CredentialRepository

router = APIRouter(prefix="/api/v1/credentials", tags=["credentials"])


# --- schemas ---------------------------------------------------------------
class IssueCredentialRequest(BaseModel):
    issuer: str = Field(description="Issuer DID, e.g. did:poc:organization:bank-demo")
    subject: str = Field(description="Subject DID; must be a registered agent")
    credential_type: str
    claims: dict[str, Any] = Field(default_factory=dict)
    expires_in_seconds: int | None = Field(
        default=None, ge=1, description="Defaults to VC_DEFAULT_TTL_SECONDS."
    )
    request_id: str | None = None


class VerifyCredentialRequest(BaseModel):
    credential: dict[str, Any]
    expected_subject: str | None = Field(
        default=None,
        description="When set, the credential must name this DID as its subject.",
    )
    required_claims: dict[str, Any] | list[str] | None = Field(
        default=None,
        description="Claims the verifier requires. A list checks presence; an "
                    "object also checks the value.",
    )
    request_id: str | None = None


class RevokeRequest(BaseModel):
    reason: str = Field(default="OPERATOR_REQUEST", max_length=256)
    request_id: str | None = None


class PresentRequest(BaseModel):
    holder: str
    credential_ids: list[str] | None = None
    credential_type: str | None = None
    challenge: str | None = None
    domain: str | None = None
    request_id: str | None = None


class VerifyPresentationRequest(BaseModel):
    presentation: dict[str, Any]
    expected_challenge: str | None = None
    expected_domain: str | None = Field(
        default=None,
        description="Audience binding. When set, the presentation's signed "
                    "`domain` must equal this exactly, otherwise verification "
                    "fails with DOMAIN_MISMATCH. Omitted means this verifier "
                    "declares no audience and the presentation's domain, if "
                    "any, is reported but not enforced.",
    )
    required_claims: dict[str, Any] | list[str] | None = None
    request_id: str | None = None


class CredentialSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    credential_id: str
    credential_type: str
    issuer: str
    subject: str
    status: str
    issued_at: datetime
    expires_at: datetime
    seconds_remaining: int
    claims: dict[str, Any]

    @classmethod
    def from_model(cls, record: Credential, now: datetime | None = None) -> "CredentialSummary":
        now = now or datetime.now(timezone.utc)
        stored = record.status_record.status if record.status_record else None
        effective = stored.value if stored else "UNKNOWN"
        # Wall clock beats the stored row: an ACTIVE credential past its expiry
        # is reported EXPIRED even if the sweep has not run.
        if effective == CredentialStatusValue.ACTIVE.value and record.expires_at <= now:
            effective = CredentialStatusValue.EXPIRED.value
        return cls(
            credential_id=record.credential_id,
            credential_type=record.credential_type,
            issuer=record.issuer_did,
            subject=record.subject_did,
            status=effective,
            issued_at=record.issued_at,
            expires_at=record.expires_at,
            seconds_remaining=max(0, int((record.expires_at - now).total_seconds())),
            claims=record.claims,
        )


# --- issuers ---------------------------------------------------------------
@router.get("/issuers", dependencies=[Depends(
    ControlPlaneGuard("credential_read", target=fixed("issuer_registry")))])
async def list_issuers(session: SessionDep, keystore: KeyStoreDep) -> list[dict]:
    """The trust roots. Public keys only; issuer private keys never leave the keystore."""
    issuers = await IssuerRegistry(session, keystore).list_issuers()
    return [
        {
            "did": issuer.did,
            "name": issuer.name,
            "slug": issuer.slug,
            "status": issuer.status.value,
            "verification_method": issuer.kid,
            "public_key_multibase": issuer.public_key_multibase,
            "algorithm": issuer.algorithm,
            "created_at": issuer.created_at.isoformat(),
        }
        for issuer in issuers
    ]


@router.get("/issuers/{did}/did-document")
async def issuer_did_document(did: str, session: SessionDep, keystore: KeyStoreDep) -> dict:
    return (await IssuerRegistry(session, keystore).require(did)).did_document


# --- issuance --------------------------------------------------------------
@router.post("/issue", status_code=http_status.HTTP_201_CREATED, dependencies=[Depends(
    ControlPlaneGuard("credential_issue", target=body_key("subject")))])
async def issue(
    body: IssueCredentialRequest, session: SessionDep, keystore: KeyStoreDep
) -> dict:
    record = await CredentialIssuer(session, keystore).issue(
        IssueRequest(
            issuer_did=body.issuer,
            subject_did=body.subject,
            credential_type=body.credential_type,
            claims=body.claims,
            ttl_seconds=body.expires_in_seconds,
            request_id=body.request_id,
        )
    )
    return {
        "credential_id": record.credential_id,
        "credential": record.document,
        "summary": CredentialSummary.from_model(record).model_dump(mode="json"),
    }


# --- verification ----------------------------------------------------------
@router.post("/verify")
async def verify(
    body: VerifyCredentialRequest, session: SessionDep, keystore: KeyStoreDep
) -> dict:
    """Verify a credential. Always 200: 'invalid' is an answer, not an error."""
    report = await CredentialVerifier(session, keystore).verify(
        body.credential,
        expected_subject=body.expected_subject,
        required_claims=body.required_claims,
        request_id=body.request_id,
    )
    return report.to_dict()


@router.post("/verify-presentation")
async def verify_presentation(
    body: VerifyPresentationRequest, session: SessionDep, keystore: KeyStoreDep
) -> dict:
    report = await PresentationVerifier(session, keystore).verify(
        body.presentation,
        expected_challenge=body.expected_challenge,
        expected_domain=body.expected_domain,
        required_claims=body.required_claims,
        request_id=body.request_id,
    )
    return report.to_dict()


@router.get("/challenge")
async def challenge(
    session: SessionDep, settings: SettingsDep, domain: str | None = None,
) -> dict:
    """A fresh, RECORDED, single-use nonce for a holder to bind into a
    presentation.

    PHASE 10 MADE THIS REAL. Until now the endpoint returned an
    unpredictable value and recorded nothing, so a captured presentation
    could be replayed against any verifier that reused a challenge -- a gap
    this codebase had documented since Phase 2 and carried through Phase 9.

    Recording at ISSUE time is what lets an unknown value be refused. If
    challenges were only remembered once used, an attacker could invent one
    and have it accepted precisely because it had never been seen.

    STILL UNAUTHENTICATED, deliberately: a holder must be able to obtain a
    challenge before it can prove anything, and the value grants nothing. It
    is single-use, short-lived, bound to its verifier, and useless without a
    valid holder proof over credentials that pass every other check.
    """
    record = await ChallengeService(session, settings).issue(domain=domain)
    return {
        "challenge": record.challenge,
        "domain": record.domain,
        "expires_at": record.expires_at.isoformat(),
        "single_use_enforced": True,
    }


# --- presentation ----------------------------------------------------------
@router.post("/present", dependencies=[Depends(
    ControlPlaneGuard("credential_present", target=body_key("holder")))])
async def present(body: PresentRequest, session: SessionDep, keystore: KeyStoreDep) -> dict:
    document = await CredentialPresenter(session, keystore).present(
        holder_did=body.holder,
        credential_ids=body.credential_ids,
        credential_type=body.credential_type,
        challenge=body.challenge,
        domain=body.domain,
        request_id=body.request_id,
    )
    return {"presentation_id": document["id"], "presentation": document}


# --- registry --------------------------------------------------------------
@router.get("", dependencies=[Depends(
    ControlPlaneGuard("credential_read", target=fixed("credential_inventory")))])
async def list_credentials(
    session: SessionDep,
    subject: str | None = None,
    issuer: str | None = None,
    credential_type: str | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
) -> list[dict]:
    records = await CredentialRepository(session).list_credentials(
        subject_did=subject, issuer_did=issuer, credential_type=credential_type,
        limit=limit, offset=offset,
    )
    return [CredentialSummary.from_model(r).model_dump(mode="json") for r in records]


@router.get("/{credential_id:path}/status", dependencies=[Depends(
    ControlPlaneGuard("credential_read", target=path_param("credential_id")))])
async def credential_status(credential_id: str, session: SessionDep) -> dict:
    return await CredentialStatusService(session).get(credential_id)


@router.post("/{credential_id:path}/revoke", dependencies=[Depends(
    ControlPlaneGuard("credential_revoke", target=path_param("credential_id")))])
async def revoke(credential_id: str, body: RevokeRequest, session: SessionDep) -> dict:
    return await CredentialStatusService(session).revoke(
        credential_id, body.reason, body.request_id
    )


@router.get("/{credential_id:path}/verifications", dependencies=[Depends(
    ControlPlaneGuard("credential_read", target=path_param("credential_id")))])
async def credential_verifications(
    credential_id: str, session: SessionDep, limit: int = 50
) -> list[dict]:
    events = await CredentialRepository(session).list_verifications(
        credential_id=credential_id, limit=limit
    )
    return [
        {
            "timestamp": e.occurred_at.isoformat(),
            "valid": e.valid,
            "reason": e.reason,
            "detail": e.detail,
            "checks": e.checks,
            "verifier": e.verifier,
        }
        for e in events
    ]


@router.get("/{credential_id:path}", dependencies=[Depends(
    ControlPlaneGuard("credential_read", target=path_param("credential_id")))])
async def get_credential(credential_id: str, session: SessionDep) -> dict:
    record = await CredentialRepository(session).get(credential_id)
    if record is None:
        raise NotFoundError(f"Unknown credential {credential_id}")
    return {
        "summary": CredentialSummary.from_model(record).model_dump(mode="json"),
        "credential": record.document,
    }
