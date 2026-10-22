"""Credential verifier.

Runs an ordered sequence of independent checks and reports every one of them.
It never returns a bare `{"valid": true}`: a consumer (and, from Phase 4, the
PDP) needs to know *which* property held and which failed.

Check order matters. Cheap structural checks run first, then cryptography, then
lookups that touch the database. The first failure determines the reported
reason, but every check that could still be evaluated is evaluated, so the
report shows the full picture rather than stopping at the first problem.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.credentials.canonical import CanonicalizationError, canonical_bytes
from app.credentials.issuer_registry import IssuerRegistry
from app.credentials.vc import (
    BASE_CREDENTIAL_TYPE,
    CREDENTIAL_PROOF_PURPOSE,
    PROOF_TYPE,
    REQUIRED_CLAIMS,
    credential_claims,
    credential_subject_did,
    parse_iso,
    signing_payload,
    specific_type,
)
from app.db.models.credential import CredentialStatusValue
from app.db.repositories.credentials import CredentialRepository
from app.identity.keys import KeyStore
from app.identity.signer import verify_signature
from app.monitoring.events import Event, EventType


class Reason:
    VALID = "CREDENTIAL_VALID"
    MALFORMED = "MALFORMED_CREDENTIAL"
    ISSUER_UNKNOWN = "ISSUER_UNKNOWN"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
    NOT_YET_VALID = "CREDENTIAL_NOT_YET_VALID"
    EXPIRED = "CREDENTIAL_EXPIRED"
    REVOKED = "CREDENTIAL_REVOKED"
    NOT_REGISTERED = "CREDENTIAL_NOT_REGISTERED"
    MISSING_CLAIM = "MISSING_REQUIRED_CLAIM"


# Check name -> the reason reported when that check fails.
CHECK_REASONS = {
    "structure": Reason.MALFORMED,
    "issuer": Reason.ISSUER_UNKNOWN,
    "signature": Reason.SIGNATURE_INVALID,
    "subject": Reason.SUBJECT_MISMATCH,
    "not_before": Reason.NOT_YET_VALID,
    "expiration": Reason.EXPIRED,
    "status": Reason.REVOKED,
    "claims": Reason.MISSING_CLAIM,
}

CHECK_ORDER = ("structure", "issuer", "signature", "subject", "not_before",
               "expiration", "status", "claims")

REQUIRED_FIELDS = ("@context", "id", "type", "issuer", "issuanceDate",
                   "expirationDate", "credentialSubject", "proof")


@dataclass
class Check:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class VerificationReport:
    valid: bool
    reason: str
    checks: list[Check] = field(default_factory=list)
    credential_id: str | None = None
    issuer: str | None = None
    subject: str | None = None
    credential_type: str | None = None
    expires_at: str | None = None
    status: str | None = None
    verified_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "credential_id": self.credential_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "credential_type": self.credential_type,
            "expires_at": self.expires_at,
            "status": self.status,
            # Flat booleans for quick consumption...
            "checks": {check.name: check.passed for check in self.checks},
            # ...and the ordered detail, which is what a human or the PDP reads.
            "check_details": [check.to_dict() for check in self.checks],
            "verified_at": self.verified_at,
        }


class CredentialVerifier:
    def __init__(
        self,
        session: AsyncSession,
        keystore: KeyStore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.issuers = IssuerRegistry(session, keystore, self.settings) if keystore else None
        self.repo = CredentialRepository(session)
        self.audit = AuditService(session)
        self._issuer_lookup = IssuerRegistry(session, keystore, self.settings)

    async def verify(
        self,
        document: dict[str, Any],
        *,
        expected_subject: str | None = None,
        required_claims: dict[str, Any] | list[str] | None = None,
        check_type_claims: bool = True,
        verifier: str = "api",
        request_id: str | None = None,
        presentation_id: str | None = None,
        now: datetime | None = None,
        record_event: bool = True,
    ) -> VerificationReport:
        """Verify a credential.

        `presentation_id` is the presentation this verification happened
        INSIDE, when there was one. It is recorded on the verification event so
        the trail reads credential -> presentation -> verification event rather
        than leaving the link to be guessed from timestamps. It stays NULL for a
        standalone credential verification, because that is what actually
        happened.
        """
        now = now or datetime.now(timezone.utc)
        checks: list[Check] = []
        report = VerificationReport(valid=False, reason=Reason.VALID, checks=checks)
        report.verified_at = now.isoformat()

        await self._emit(
            EventType.CREDENTIAL_VERIFICATION_STARTED,
            document.get("credentialSubject", {}).get("id")
            if isinstance(document.get("credentialSubject"), dict) else None,
            {"credential_id": document.get("id"), "verifier": verifier},
            request_id,
            record_event,
        )

        # --- 1. structure -------------------------------------------------
        missing = [f for f in REQUIRED_FIELDS if f not in document]
        proof = document.get("proof") if isinstance(document.get("proof"), dict) else None
        structure_problems: list[str] = []
        if missing:
            structure_problems.append(f"missing fields {missing}")
        if proof is None:
            structure_problems.append("proof is missing or not an object")
        else:
            if proof.get("type") != PROOF_TYPE:
                structure_problems.append(
                    f"unsupported proof type {proof.get('type')!r}, expected {PROOF_TYPE!r}"
                )
            if not proof.get("proofValue"):
                structure_problems.append("proof.proofValue is empty")
            if not proof.get("verificationMethod"):
                structure_problems.append("proof.verificationMethod is empty")
            # Proof purpose. A credential proof is an ISSUER ASSERTING CLAIMS, so
            # it must carry `assertionMethod`. The presentation verifier has
            # always enforced the matching rule for holder proofs
            # (`authentication`); this closes the asymmetry so both halves of the
            # pair keep the same proof purposes apart.
            #
            # This is domain separation, not a new cryptographic control:
            # `proofPurpose` is already inside the signed payload, so editing it
            # on an issued credential breaks the signature. What it prevents is a
            # signature made by a registered issuer key FOR A DIFFERENT PURPOSE
            # being accepted as a credential proof -- which is what matters once
            # further proof purposes exist.
            #
            # Backwards compatible: every credential this system has ever issued
            # is signed with `assertionMethod` (see `issuer.py`), so no existing
            # credential's outcome changes.
            if proof.get("proofPurpose") != CREDENTIAL_PROOF_PURPOSE:
                structure_problems.append(
                    f"proof.proofPurpose must be {CREDENTIAL_PROOF_PURPOSE!r} for a "
                    f"credential, got {proof.get('proofPurpose')!r}"
                )
        types = document.get("type") or []
        if BASE_CREDENTIAL_TYPE not in types:
            structure_problems.append(f"type does not include {BASE_CREDENTIAL_TYPE}")
        if not isinstance(document.get("credentialSubject"), dict):
            structure_problems.append("credentialSubject is not an object")

        checks.append(
            Check("structure", not structure_problems,
                  "well formed" if not structure_problems else "; ".join(structure_problems))
        )

        report.credential_id = document.get("id")
        report.issuer = document.get("issuer")
        report.subject = credential_subject_did(document) if isinstance(
            document.get("credentialSubject"), dict) else None
        report.credential_type = specific_type(document)
        report.expires_at = document.get("expirationDate")

        if structure_problems:
            # Nothing further can be evaluated meaningfully.
            return await self._finish(report, Reason.MALFORMED, verifier, request_id,
                                      record_event, presentation_id)

        # --- 2. issuer ----------------------------------------------------
        issuer_did = document["issuer"]
        issuer = await self._issuer_lookup.get_by_did(issuer_did)
        if issuer is None:
            checks.append(Check("issuer", False, f"{issuer_did} is not a registered issuer"))
        elif proof["verificationMethod"] != issuer.kid:
            checks.append(
                Check("issuer", False,
                      f"proof.verificationMethod {proof['verificationMethod']!r} is not the "
                      f"issuer's verification method {issuer.kid!r}")
            )
            issuer = None
        else:
            checks.append(
                Check("issuer", True, f"{issuer_did} ({issuer.name}), key {issuer.kid}")
            )

        # --- 3. signature -------------------------------------------------
        if issuer is None:
            checks.append(Check("signature", False, "not evaluated: issuer key unavailable"))
        else:
            options = {k: v for k, v in proof.items() if k != "proofValue"}
            try:
                payload = canonical_bytes(signing_payload(document, options))
            except CanonicalizationError as exc:
                checks.append(Check("signature", False, f"not canonicalisable: {exc}"))
            else:
                result = verify_signature(
                    issuer.public_key_multibase, payload, proof["proofValue"], issuer.kid
                )
                checks.append(
                    Check("signature", result.valid,
                          "Ed25519 proof verifies against the issuer's published key"
                          if result.valid else result.reason)
                )

        # --- 4. subject binding -------------------------------------------
        subject_did = report.subject
        if not subject_did:
            checks.append(Check("subject", False, "credentialSubject.id is missing"))
        elif expected_subject is None:
            checks.append(
                Check("subject", True, f"{subject_did} (no expected subject supplied)")
            )
        elif subject_did != expected_subject:
            checks.append(
                Check("subject", False,
                      f"credential names {subject_did}, but it is being presented for "
                      f"{expected_subject}")
            )
        else:
            checks.append(Check("subject", True, f"bound to {subject_did}"))

        # --- 5/6. validity window -----------------------------------------
        try:
            issued_at = parse_iso(document["issuanceDate"])
            checks.append(
                Check("not_before", issued_at <= now,
                      f"issued {document['issuanceDate']}"
                      if issued_at <= now else
                      f"issuanceDate {document['issuanceDate']} is in the future")
            )
        except (ValueError, KeyError) as exc:
            checks.append(Check("not_before", False, f"unparseable issuanceDate: {exc}"))

        try:
            expires_at = parse_iso(document["expirationDate"])
            remaining = (expires_at - now).total_seconds()
            checks.append(
                Check("expiration", remaining > 0,
                      f"valid for another {int(remaining)}s (expires {document['expirationDate']})"
                      if remaining > 0 else
                      f"expired {int(-remaining)}s ago at {document['expirationDate']}")
            )
        except (ValueError, KeyError) as exc:
            checks.append(Check("expiration", False, f"unparseable expirationDate: {exc}"))

        # --- 7. status ----------------------------------------------------
        record = await self.repo.get(document["id"])
        if record is None:
            checks.append(
                Check("status", False,
                      f"{document['id']} is not in the credential registry, so its "
                      f"revocation status cannot be established")
            )
            report.status = "UNKNOWN"
        else:
            status = record.status_record.status if record.status_record else None
            report.status = status.value if status else "UNKNOWN"
            if status == CredentialStatusValue.REVOKED:
                revoked = record.status_record
                checks.append(
                    Check("status", False,
                          f"REVOKED at {revoked.revoked_at.isoformat() if revoked.revoked_at else '?'}"
                          f" ({revoked.revocation_reason or 'no reason given'})")
                )
            elif status == CredentialStatusValue.EXPIRED:
                checks.append(Check("status", False, "marked EXPIRED in the registry"))
            elif status == CredentialStatusValue.ACTIVE:
                checks.append(Check("status", True, "ACTIVE"))
            else:
                checks.append(Check("status", False, f"unexpected status {status}"))

        # --- 8. claims ----------------------------------------------------
        claims = credential_claims(document)
        problems: list[str] = []
        if check_type_claims:
            for claim in REQUIRED_CLAIMS.get(report.credential_type or "", ()):
                if claim not in claims:
                    problems.append(f"{report.credential_type} requires claim {claim!r}")
        if isinstance(required_claims, list):
            for claim in required_claims:
                if claim not in claims:
                    problems.append(f"verifier requires claim {claim!r}")
        elif isinstance(required_claims, dict):
            for claim, expected in required_claims.items():
                if claim not in claims:
                    problems.append(f"verifier requires claim {claim!r}")
                elif claims[claim] != expected:
                    problems.append(
                        f"claim {claim!r} is {claims[claim]!r}, verifier requires {expected!r}"
                    )
        checks.append(
            Check("claims", not problems,
                  f"{sorted(claims)} satisfy the requirements" if not problems
                  else "; ".join(problems))
        )

        # --- outcome ------------------------------------------------------
        failed = next(
            (c for name in CHECK_ORDER for c in checks if c.name == name and not c.passed),
            None,
        )
        reason = Reason.VALID if failed is None else CHECK_REASONS.get(
            failed.name, Reason.MALFORMED
        )
        if failed is not None and failed.name == "status" and report.status == "UNKNOWN":
            reason = Reason.NOT_REGISTERED
        return await self._finish(report, reason, verifier, request_id, record_event,
                                  presentation_id)

    async def _finish(
        self, report: VerificationReport, reason: str, verifier: str,
        request_id: str | None, record_event: bool,
        presentation_id: str | None = None,
    ) -> VerificationReport:
        report.reason = reason
        report.valid = reason == Reason.VALID

        if record_event:
            await self.repo.record_verification(
                credential_id=report.credential_id,
                issuer_did=report.issuer,
                subject_did=report.subject,
                credential_type=report.credential_type,
                verifier=verifier,
                request_id=request_id,
                presentation_id=presentation_id,
                valid=report.valid,
                reason=reason,
                detail=next(
                    (c.detail for c in report.checks if not c.passed), "all checks passed"
                ),
                checks={c.name: c.passed for c in report.checks},
            )
            event_type = (
                EventType.CREDENTIAL_VERIFIED if report.valid
                else _FAILURE_EVENTS.get(reason, EventType.CREDENTIAL_VERIFICATION_FAILED)
            )
            await self._emit(
                event_type,
                report.subject,
                {
                    "credential_id": report.credential_id,
                    "credential_type": report.credential_type,
                    "issuer": report.issuer,
                    "verifier": verifier,
                    "checks": {c.name: c.passed for c in report.checks},
                    "failed_check": next(
                        (c.name for c in report.checks if not c.passed), None
                    ),
                },
                request_id,
                True,
                decision="VALID" if report.valid else "INVALID",
                reason=reason,
            )
        return report

    async def _emit(
        self, event_type: str, subject: str | None, metadata: dict[str, Any],
        request_id: str | None, record: bool, decision: str | None = None,
        reason: str | None = None,
    ) -> None:
        if not record:
            return
        await self.audit.record(
            Event(
                event_type,
                agent_did=subject,
                request_id=request_id,
                resource=metadata.get("credential_id"),
                action="VERIFY",
                decision=decision,
                reason=reason,
                metadata=metadata,
            )
        )


_FAILURE_EVENTS = {
    Reason.SIGNATURE_INVALID: EventType.CREDENTIAL_SIGNATURE_INVALID,
    Reason.SUBJECT_MISMATCH: EventType.CREDENTIAL_SUBJECT_MISMATCH,
    Reason.ISSUER_UNKNOWN: EventType.CREDENTIAL_ISSUER_UNKNOWN,
    Reason.EXPIRED: EventType.CREDENTIAL_EXPIRED,
    Reason.REVOKED: EventType.CREDENTIAL_REVOKED_REJECTED,
}
