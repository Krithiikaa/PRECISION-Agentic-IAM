"""Building and verifying Verifiable Presentations."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.errors import IdentityError, NotFoundError
from app.credentials.canonical import CanonicalizationError
from app.credentials.presentation import (
    attach_proof,
    build_unsigned_presentation,
    holder_signing_payload,
    presentation_structure_problems,
)
from app.credentials.verifier import Check, CredentialVerifier, VerificationReport
from app.db.models.agent import AgentStatus
from app.db.repositories.agents import AgentRepository
from app.db.repositories.credentials import CredentialRepository
from app.identity.did_document import public_key_from_document
from app.identity.keys import KeyStore
from app.identity.signer import Signer, verify_signature
from app.monitoring.events import Event, EventType


class PresentationReason:
    VALID = "PRESENTATION_VALID"
    MALFORMED = "MALFORMED_PRESENTATION"
    HOLDER_UNKNOWN = "HOLDER_UNKNOWN"
    HOLDER_PROOF_INVALID = "HOLDER_PROOF_INVALID"
    CHALLENGE_MISMATCH = "CHALLENGE_MISMATCH"
    DOMAIN_MISMATCH = "DOMAIN_MISMATCH"
    CREDENTIAL_INVALID = "CREDENTIAL_INVALID"


@dataclass
class PresentationReport:
    valid: bool
    reason: str
    holder: str | None = None
    presentation_id: str | None = None
    checks: list[Check] = field(default_factory=list)
    credentials: list[VerificationReport] = field(default_factory=list)
    verified_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "holder": self.holder,
            "presentation_id": self.presentation_id,
            "checks": {c.name: c.passed for c in self.checks},
            "check_details": [c.to_dict() for c in self.checks],
            "credentials": [report.to_dict() for report in self.credentials],
            "verified_at": self.verified_at,
        }


class CredentialPresenter:
    """Builds and signs a presentation on behalf of a registry-custodied holder.

    Agents that hold their own key (the running agent services) sign their own
    presentations on their own endpoint; this service refuses to do it for
    them, exactly as the Phase 1 registry refuses to sign for them.
    """

    def __init__(
        self, session: AsyncSession, keystore: KeyStore, settings: Settings | None = None
    ) -> None:
        self.session = session
        self.keystore = keystore
        self.settings = settings or get_settings()
        self.agents = AgentRepository(session)
        self.repo = CredentialRepository(session)
        self.audit = AuditService(session)
        self.signer = Signer(keystore)

    async def present(
        self,
        *,
        holder_did: str,
        credential_ids: list[str] | None = None,
        credential_type: str | None = None,
        challenge: str | None = None,
        domain: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        agent = await self.agents.get_by_did(holder_did)
        if agent is None:
            raise NotFoundError(f"Unknown holder {holder_did}")
        if agent.status != AgentStatus.ACTIVE:
            raise IdentityError(
                f"Holder {holder_did} is {agent.status.value}; only ACTIVE agents may present"
            )
        key = await self.agents.get_active_key(agent.id)
        if key is None:
            raise IdentityError(f"Holder {holder_did} has no active key")
        if key.keystore_backend == "external":
            raise IdentityError(
                f"Holder {holder_did} holds its own key ({key.keystore_ref}); this service "
                f"cannot produce a holder proof for it. Ask the agent to present on its "
                f"own endpoint (POST /present)."
            )

        documents = await self._collect(holder_did, credential_ids, credential_type)
        unsigned = build_unsigned_presentation(
            holder_did=holder_did,
            holder_kid=key.kid,
            credentials=documents,
            challenge=challenge,
            domain=domain,
        )
        signature = self.signer.sign(key.kid, unsigned.payload)
        document = attach_proof(unsigned, signature.signature_b64)

        await self._record(document, holder_did, documents, challenge, domain, request_id)
        return document

    async def _collect(
        self, holder_did: str, credential_ids: list[str] | None, credential_type: str | None
    ) -> list[dict[str, Any]]:
        if credential_ids:
            documents = []
            for credential_id in credential_ids:
                record = await self.repo.get(credential_id)
                if record is None:
                    raise NotFoundError(f"Unknown credential {credential_id}")
                documents.append(record.document)
            return documents
        records = await self.repo.list_credentials(
            subject_did=holder_did, credential_type=credential_type
        )
        if not records:
            raise NotFoundError(
                f"{holder_did} holds no credentials"
                + (f" of type {credential_type}" if credential_type else "")
            )
        return [record.document for record in records]

    async def _record(
        self, document, holder_did, documents, challenge, domain, request_id
    ) -> None:
        credential_ids = [d.get("id") for d in documents]
        await self.repo.record_presentation(
            presentation_id=document["id"],
            holder_did=holder_did,
            credential_ids=credential_ids,
            document=document,
            challenge=challenge,
            domain=domain,
        )
        await self.audit.record(
            Event(
                EventType.CREDENTIAL_PRESENTED,
                agent_did=holder_did,
                request_id=request_id,
                action="PRESENT",
                metadata={
                    "presentation_id": document["id"],
                    "credential_ids": credential_ids,
                    "challenge": challenge,
                    "domain": domain,
                },
            )
        )


class PresentationVerifier:
    def __init__(
        self, session: AsyncSession, keystore: KeyStore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.agents = AgentRepository(session)
        self.repo = CredentialRepository(session)
        self.audit = AuditService(session)
        self.credential_verifier = CredentialVerifier(session, keystore, self.settings)

    async def verify(
        self,
        document: dict[str, Any],
        *,
        expected_challenge: str | None = None,
        expected_domain: str | None = None,
        required_claims: dict[str, Any] | list[str] | None = None,
        verifier: str = "api",
        request_id: str | None = None,
    ) -> PresentationReport:
        """Verify a presentation.

        AUDIENCE BINDING (`expected_domain`)
        ------------------------------------
        `domain` names the audience a presentation was made FOR. It is written
        into the proof options, so it is inside the signed payload: a captured
        presentation cannot have its audience rewritten without breaking the
        holder proof.

            SIGNED DOMAIN + EXPECTED VERIFIER DOMAIN = AUDIENCE BINDING

        Both halves are required, and until now only the first existed -- the
        domain was created, signed, stored and transmitted, but never compared
        against the verifier's own context, so a presentation minted for one
        service verified cleanly at another.

        COMPATIBILITY BEHAVIOUR, chosen deliberately:

          * `expected_domain` supplied  -> the presentation MUST carry exactly
            that domain. A different domain, or no domain at all, fails with
            `DOMAIN_MISMATCH`.
          * `expected_domain` omitted   -> the check passes and records that
            this verifier declared no audience.

        The permissive default is what preserves backwards compatibility, and
        it is also the only honest behaviour: a verifier that never told the
        holder which audience to bind to cannot then demand one. It mirrors
        `expected_challenge` exactly. A verifier that cares about audience --
        which, once a human-approval artifact exists, it should -- must say so
        by passing `expected_domain`.

        This does NOT make presentations single-use. Challenges are still not
        recorded as used (Phase 9); audience binding narrows a replay to one
        audience, it does not eliminate it.
        """
        now = datetime.now(timezone.utc)
        checks: list[Check] = []
        report = PresentationReport(valid=False, reason=PresentationReason.VALID, checks=checks)
        report.verified_at = now.isoformat()
        report.holder = document.get("holder")
        report.presentation_id = document.get("id")

        # --- structure ----------------------------------------------------
        problems = presentation_structure_problems(document)
        checks.append(
            Check("structure", not problems,
                  "well formed" if not problems else "; ".join(problems))
        )
        if problems:
            return await self._finish(report, PresentationReason.MALFORMED, verifier, request_id)

        holder_did = document["holder"]
        proof = document["proof"]

        # --- holder identity resolves -------------------------------------
        holder_document = await self.agents.get_did_document(holder_did)
        if holder_document is None:
            checks.append(
                Check("holder", False, f"{holder_did} does not resolve to a registered agent")
            )
            return await self._finish(
                report, PresentationReason.HOLDER_UNKNOWN, verifier, request_id
            )
        try:
            holder_public_key = public_key_from_document(
                holder_document.document, proof["verificationMethod"]
            )
        except ValueError as exc:
            checks.append(
                Check("holder", False,
                      f"proof.verificationMethod {proof['verificationMethod']!r} is not in "
                      f"the holder's DID Document: {exc}")
            )
            return await self._finish(
                report, PresentationReason.HOLDER_PROOF_INVALID, verifier, request_id
            )
        checks.append(
            Check("holder", True,
                  f"{holder_did} resolves; key {proof['verificationMethod']}")
        )

        # --- holder proof ---------------------------------------------------
        try:
            payload = holder_signing_payload(document)
        except CanonicalizationError as exc:
            checks.append(Check("holder_proof", False, f"not canonicalisable: {exc}"))
            return await self._finish(
                report, PresentationReason.HOLDER_PROOF_INVALID, verifier, request_id
            )
        result = verify_signature(
            holder_public_key, payload, proof["proofValue"], proof["verificationMethod"]
        )
        checks.append(
            Check("holder_proof", result.valid,
                  "holder proved control of the subject DID" if result.valid else result.reason)
        )
        if not result.valid:
            return await self._finish(
                report, PresentationReason.HOLDER_PROOF_INVALID, verifier, request_id
            )

        # --- challenge ------------------------------------------------------
        if expected_challenge is not None:
            matched = proof.get("challenge") == expected_challenge
            checks.append(
                Check("challenge", matched,
                      "matches the challenge issued by the verifier" if matched else
                      f"presentation carries {proof.get('challenge')!r}, verifier expected "
                      f"{expected_challenge!r}")
            )
            if not matched:
                return await self._finish(
                    report, PresentationReason.CHALLENGE_MISMATCH, verifier, request_id
                )
        else:
            checks.append(
                Check("challenge", True, "no challenge required by this verifier")
            )

        # --- domain / audience ----------------------------------------------
        # `domain` is signature-covered, so a mismatch here means the holder
        # genuinely signed this presentation for a DIFFERENT audience -- not
        # that someone edited it in transit. Editing it breaks holder_proof
        # above and never reaches this check.
        presented_domain = proof.get("domain")
        if expected_domain is not None:
            matched = presented_domain == expected_domain
            checks.append(
                Check("domain", matched,
                      f"bound to this verifier's audience {expected_domain!r}"
                      if matched else
                      (f"presentation is bound to audience {presented_domain!r}, "
                       f"this verifier is {expected_domain!r}"
                       if presented_domain is not None else
                       f"presentation carries no domain, but this verifier "
                       f"requires audience {expected_domain!r}"))
            )
            if not matched:
                return await self._finish(
                    report, PresentationReason.DOMAIN_MISMATCH, verifier, request_id
                )
        else:
            checks.append(
                Check("domain", True,
                      f"no audience required by this verifier "
                      f"(presentation declares {presented_domain!r})"
                      if presented_domain is not None
                      else "no audience required by this verifier")
            )

        # --- each credential -------------------------------------------------
        # expected_subject is the proven holder: this is what stops an agent
        # presenting a credential that belongs to a different agent.
        for credential in document["verifiableCredential"]:
            report.credentials.append(
                await self.credential_verifier.verify(
                    credential,
                    expected_subject=holder_did,
                    required_claims=required_claims,
                    verifier=verifier,
                    request_id=request_id,
                    # S-3: correlate the credential verification event with the
                    # presentation it happened inside.
                    presentation_id=report.presentation_id,
                )
            )
        all_valid = all(r.valid for r in report.credentials)
        checks.append(
            Check("credentials", all_valid,
                  f"{len(report.credentials)} credential(s) verified" if all_valid else
                  "; ".join(
                      f"{r.credential_id}: {r.reason}" for r in report.credentials if not r.valid
                  ))
        )
        reason = PresentationReason.VALID if all_valid else PresentationReason.CREDENTIAL_INVALID
        return await self._finish(report, reason, verifier, request_id)

    async def _finish(
        self, report: PresentationReport, reason: str, verifier: str, request_id: str | None
    ) -> PresentationReport:
        report.reason = reason
        report.valid = reason == PresentationReason.VALID
        await self.audit.record(
            Event(
                EventType.PRESENTATION_VERIFIED if report.valid
                else EventType.PRESENTATION_VERIFICATION_FAILED,
                agent_did=report.holder,
                request_id=request_id,
                resource=report.presentation_id,
                action="VERIFY_PRESENTATION",
                decision="VALID" if report.valid else "INVALID",
                reason=reason,
                metadata={
                    "presentation_id": report.presentation_id,
                    "verifier": verifier,
                    "checks": {c.name: c.passed for c in report.checks},
                    "credentials": [
                        {"credential_id": r.credential_id, "valid": r.valid, "reason": r.reason}
                        for r in report.credentials
                    ],
                },
            )
        )
        return report
