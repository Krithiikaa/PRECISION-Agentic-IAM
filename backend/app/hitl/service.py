"""The approval service: request, decide, verify, consume.

    HUMAN AUTHENTICATION   Keycloak says who someone is
    HUMAN APPROVAL         this service records what they decided   <- here
    AUTHORIZATION          the PDP decides whether it may proceed
    ENFORCEMENT            the AEM lets the tool run

This file is the second line only. It never decides that an action is
permitted: it records a decision, signs it, and hands the PDP a fact. The one
place it could be tempted to authorize -- "should this human be allowed to
approve this?" -- it delegates, to the same PDP and the same OPA everything
else uses.

STATE MACHINE. Transitions are an explicit table, not a convention:

    PENDING ──approve──> APPROVED ──consume──> CONSUMED
       │                    │
       ├──reject──> REJECTED└──expire──> EXPIRED
       ├──expire──> EXPIRED
       └──cancel──> CANCELLED

Terminal is terminal. CONSUMED -> APPROVED and REJECTED -> CONSUMED are
refused, so an approval cannot be "un-spent" or a refusal reinterpreted.

DUAL CONTROL ADDS NO STATE (Phase 5.5). An approval that needs two people and
has one is still PENDING -- it is still waiting on a human, which is exactly
what PENDING means. The transition table above is untouched; what changed is
that the move to APPROVED requires N distinct sign-offs rather than one. A
"PARTIALLY_APPROVED" state would have been a new terminal-adjacent state to
reason about for no gain, and every existing transition test would have had to
be re-read.

    PENDING ──signoff 1 of 2──> PENDING ──signoff 2 of 2──> APPROVED

One REJECTION ends it, whatever the count. Dual control means two people must
AGREE; it must never degrade into "keep asking until somebody says yes".

CONSUMPTION IS A DATABASE OPERATION. A single conditional UPDATE decides the
winner, because two concurrent requests presenting the same approval is a race
that Python state cannot arbitrate -- and the losing branch must not be
"probably fine".

SO IS THE TWO-PERSON RULE. `UNIQUE (approval_id, approver_issuer,
approver_subject)`. Not `if approver in already_approved`: two requests from
the same person arriving together would both pass that check and both proceed.
Only one can win an INSERT.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.db.models.hitl import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalSignoff,
    ApprovalStatus,
)
from app.hitl.artifact import (
    ApprovalBinding,
    ArtifactReason,
    approver_identity,
    build_artifact,
    new_approval_id,
    new_nonce,
    sign_artifact,
    verify_artifact,
)
from app.hitl.authority import ApprovalAuthority
from app.identity.keys import KeyStore
from app.identity.signer import Signer
from app.monitoring.events import Event, EventType

log = get_logger("hitl.service")

# The only permitted transitions. Anything absent is refused by name.
ALLOWED_TRANSITIONS: dict[ApprovalStatus, frozenset[ApprovalStatus]] = {
    ApprovalStatus.PENDING: frozenset({
        ApprovalStatus.APPROVED, ApprovalStatus.REJECTED,
        ApprovalStatus.EXPIRED, ApprovalStatus.CANCELLED,
    }),
    ApprovalStatus.APPROVED: frozenset({
        ApprovalStatus.CONSUMED, ApprovalStatus.EXPIRED,
    }),
    ApprovalStatus.REJECTED: frozenset(),
    ApprovalStatus.EXPIRED: frozenset(),
    ApprovalStatus.CANCELLED: frozenset(),
    ApprovalStatus.CONSUMED: frozenset(),
}


def binding_of(record: ApprovalRequest) -> ApprovalBinding:
    """The binding this approval was opened against.

    Read from the RECORDED document, not re-derived. The signer therefore binds
    exactly what the request bound, and the artifact's `bindingHash` always
    equals the row's `binding_sha256` -- one resolver, run once.

    Re-deriving here would open a window nobody wants: an amount that moved
    between the escalation and the decision would be silently absorbed into the
    signature instead of being caught. Detecting that change is the entire
    point of the binding, so the binding must not be the thing that follows it.

    Rows written before the `binding` column existed fall back to the flat
    columns, which is exactly what they were bound to.
    """
    document = record.binding or {}
    if not document:
        return ApprovalBinding(
            request_id=record.request_id, agent_did=record.agent_did,
            action=record.action, resource_type=record.resource_type,
            resource_id=record.resource_id, purpose=record.purpose,
        )
    return ApprovalBinding(**document)


class InvalidTransition(ConflictError):
    """A state change the lifecycle does not permit."""


class ApprovalNotPending(ConflictError):
    """Someone tried to decide an approval that is no longer open."""


class DuplicateApprover(ConflictError):
    """The same human tried to satisfy a second approval on one request.

    The whole point of two-person control. Raised when the database refuses the
    INSERT, so it reports a fact rather than the outcome of a check that could
    have been raced.
    """


class SelfApprovalRefused(ConflictError):
    """The person who put the request forward tried to sign it off.

    Maker-checker. Policy refuses this first; this is the hard stop behind it,
    for the same reason the route refuses a machine principal even though
    policy already has.
    """


@dataclass
class ApprovalFact:
    """What the PIP reports to policy about an approval.

    A VERDICT plus its reason -- exactly the shape the credential facts use, so
    Rego consumes approvals the same way it consumes credentials and never sees
    a signature.
    """

    present: bool
    valid: bool
    reason: str
    approval_id: str | None = None
    status: str | None = None
    decision: str | None = None
    approver: dict[str, Any] | None = None
    expires_at: str | None = None
    bound_to_request: bool = False
    checks: list[dict[str, Any]] | None = None
    # --- dual control (Phase 5.5) ----------------------------------------
    # `distinct_approvers` counts (issuer, subject) pairs in the VERIFIED
    # artifact, not rows in a table -- policy must weigh what the approval
    # authority actually attested to.
    #
    # `required_approvals` here is what was RECORDED when the request was
    # opened. Policy does not gate on it: Rego recomputes the requirement live
    # from the amount, so lowering this number cannot let anything through. It
    # is reported so a queue can honestly say "1 of 2".
    required_approvals: int = 1
    distinct_approvers: int = 0
    approvers: list[dict[str, Any]] | None = None
    signoffs_recorded: int = 0
    signing_key: str | None = None
    amount_inr: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "valid": self.valid,
            "reason": self.reason,
            "approval_id": self.approval_id,
            "status": self.status,
            "decision": self.decision,
            "approver": self.approver,
            "approvers": self.approvers or [],
            "required_approvals": self.required_approvals,
            "distinct_approvers": self.distinct_approvers,
            "signoffs_recorded": self.signoffs_recorded,
            "signing_key": self.signing_key,
            "amount_inr": self.amount_inr,
            "expires_at": self.expires_at,
            "bound_to_request": self.bound_to_request,
            "checks": self.checks or [],
        }

    @classmethod
    def absent(cls) -> "ApprovalFact":
        return cls(present=False, valid=False, reason=ArtifactReason.MISSING)


class ApprovalService:
    def __init__(
        self,
        session: AsyncSession,
        keystore: KeyStore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.keystore = keystore
        self.audit = AuditService(session)
        self.authority = ApprovalAuthority(session, keystore, self.settings) if keystore else None

    # --- lookup -----------------------------------------------------------
    async def get(self, approval_id: str) -> ApprovalRequest | None:
        result = await self.session.execute(
            select(ApprovalRequest).where(ApprovalRequest.approval_id == approval_id)
        )
        return result.scalar_one_or_none()

    async def require(self, approval_id: str) -> ApprovalRequest:
        record = await self.get(approval_id)
        if record is None:
            raise NotFoundError(f"Unknown approval {approval_id}")
        return record

    async def list_requests(
        self, *, status: ApprovalStatus | None = None, agent_did: str | None = None,
        limit: int = 50,
    ) -> list[ApprovalRequest]:
        stmt = select(ApprovalRequest).order_by(ApprovalRequest.requested_at.desc())
        if status is not None:
            stmt = stmt.where(ApprovalRequest.status == status)
        if agent_did:
            stmt = stmt.where(ApprovalRequest.agent_did == agent_did)
        result = await self.session.execute(stmt.limit(limit))
        return list(result.scalars().all())

    # --- 1. request -------------------------------------------------------
    async def request_approval(
        self,
        *,
        binding: ApprovalBinding,
        presentation: dict[str, Any],
        reason: str,
        context: dict[str, Any] | None = None,
        now: datetime | None = None,
        required_approvals: int = 1,
    ) -> ApprovalRequest:
        """Open a request for a human decision.

        Idempotent per authorization request+binding: asking twice for the same
        thing returns the existing PENDING request rather than queuing a second
        screen for the same action. Two open approvals for one action would let
        an operator approve while a colleague rejects, with both artifacts
        valid.
        """
        now = now or datetime.now(timezone.utc)
        digest = binding.digest()

        existing = await self.session.execute(
            select(ApprovalRequest).where(
                ApprovalRequest.binding_sha256 == digest,
                ApprovalRequest.status == ApprovalStatus.PENDING,
            )
        )
        open_request = existing.scalar_one_or_none()
        if open_request is not None:
            if open_request.request_expires_at > now:
                # Policy is asked again on every retry, so the requirement can
                # legitimately have moved (a threshold was changed, an amount
                # was corrected). Reflect the LIVE requirement on the open
                # request rather than leaving a stale number on the screen the
                # approvers are looking at.
                if open_request.required_approvals != required_approvals:
                    log.info("approval_requirement_updated",
                             approval_id=open_request.approval_id,
                             was=open_request.required_approvals,
                             now=required_approvals)
                    open_request.required_approvals = required_approvals
                    await self.session.flush()
                return open_request
            await self._expire(open_request, now)

        record = ApprovalRequest(
            approval_id=new_approval_id(),
            request_id=binding.request_id,
            agent_did=binding.agent_did,
            action=binding.action,
            resource_type=binding.resource_type,
            resource_id=binding.resource_id,
            purpose=binding.purpose,
            binding_sha256=digest,
            # The binding as a document, so the signer uses exactly what was
            # requested and the artifact is guaranteed to hash to the digest
            # above.
            binding=binding.to_dict(),
            presentation=presentation,
            context=context or {},
            reason=reason,
            # From the POLICY decision that escalated. The AEM carries the
            # number; it does not choose it.
            required_approvals=required_approvals,
            status=ApprovalStatus.PENDING,
            requested_at=now,
            request_expires_at=now + timedelta(
                seconds=self.settings.approval_request_ttl_seconds
            ),
            nonce=new_nonce(),
            domain=self.settings.approval_domain,
        )
        self.session.add(record)
        await self.session.flush()

        await self.audit.record(
            Event(
                EventType.APPROVAL_REQUESTED,
                agent_did=binding.agent_did,
                request_id=binding.request_id,
                resource=binding.resource_type,
                action=binding.action,
                decision="PENDING",
                reason=reason,
                metadata={
                    "approval_id": record.approval_id,
                    "resource_id": binding.resource_id,
                    "purpose": binding.purpose,
                    "expires_at": record.request_expires_at.isoformat(),
                    "binding_sha256": digest,
                    "required_approvals": required_approvals,
                    "amount_inr": binding.amount_inr,
                    "currency": binding.currency,
                },
            )
        )
        await self.audit.record(
            Event(
                EventType.POLICY_ESCALATED,
                agent_did=binding.agent_did,
                request_id=binding.request_id,
                resource=binding.resource_type,
                action=binding.action,
                decision="HUMAN_APPROVAL_REQUIRED",
                reason=reason,
                metadata={
                    "approval_id": record.approval_id,
                    "resource_id": binding.resource_id,
                    # WHY this many people. Answerable from the trail alone,
                    # without anyone having to re-derive it from the amount.
                    "required_approvals": required_approvals,
                    "tier": "DUAL_CONTROL" if required_approvals > 1 else "SINGLE_APPROVER",
                    "amount_inr": binding.amount_inr,
                    "currency": binding.currency,
                },
            )
        )
        log.info("approval_requested", approval_id=record.approval_id,
                 agent=binding.agent_did, action=binding.action)
        return record

    # --- 2. view ----------------------------------------------------------
    async def mark_viewed(self, record: ApprovalRequest, viewer: Any) -> None:
        """Record that a human actually looked at the request.

        Auditable evidence that the decision was informed: an approval nobody
        opened is a very different thing from one somebody read.
        """
        now = datetime.now(timezone.utc)
        if record.first_viewed_at is None:
            record.first_viewed_at = now
            await self.session.flush()
        await self.audit.record(
            Event(
                EventType.APPROVAL_VIEWED,
                agent_did=record.agent_did,
                request_id=record.request_id,
                resource=record.resource_type,
                action=record.action,
                metadata={
                    "approval_id": record.approval_id,
                    "viewer": viewer.principal_urn,
                    "viewer_username": viewer.username,
                    "roles": sorted(viewer.roles),
                },
            )
        )

    # --- 3. decide --------------------------------------------------------
    async def signoffs_for(
        self, approval_ids: list[str]
    ) -> dict[str, list[ApprovalSignoff]]:
        """Sign-offs for many approvals in ONE query.

        The queue view needs "1 of 2" on every row; a per-row query would make
        rendering the queue O(n) round trips for information that is a single
        `IN` away.
        """
        if not approval_ids:
            return {}
        result = await self.session.execute(
            select(ApprovalSignoff)
            .where(ApprovalSignoff.approval_id.in_(approval_ids))
            .order_by(ApprovalSignoff.approval_id, ApprovalSignoff.sequence)
        )
        grouped: dict[str, list[ApprovalSignoff]] = {}
        for signoff in result.scalars().all():
            grouped.setdefault(signoff.approval_id, []).append(signoff)
        return grouped

    async def signoffs(self, approval_id: str) -> list[ApprovalSignoff]:
        result = await self.session.execute(
            select(ApprovalSignoff)
            .where(ApprovalSignoff.approval_id == approval_id)
            .order_by(ApprovalSignoff.sequence)
        )
        return list(result.scalars().all())

    async def decide(
        self,
        *,
        record: ApprovalRequest,
        approver: Any,
        decision: ApprovalDecision,
        note: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRequest:
        """Record ONE human's decision, and complete the approval if that was
        the last one it was waiting for.

        The caller must already have been AUTHENTICATED (OIDC) and AUTHORIZED
        (PDP) to make this decision. This method does neither: it is the record
        keeper, and mixing the two would put an authorization rule here instead
        of in Rego.

        Under dual control this is called twice, by two different people. The
        first call records a sign-off and leaves the request PENDING; the
        second completes it and the artifact is signed once, naming both.
        """
        now = now or datetime.now(timezone.utc)

        # SERIALISE DECISIONS ON THIS APPROVAL. `SELECT ... FOR UPDATE` holds a
        # row lock for the rest of the transaction, so two people deciding at
        # the same instant are ordered rather than interleaved.
        #
        # Without it, two legitimate sign-offs on a two-person approval can each
        # see only their own -- both count 1 of 2, neither completes, and the
        # approval is left with every signature it needed and no artifact.
        # Nobody would ever complete it, because no third person is required.
        # That is a liveness failure rather than a security one, which is
        # exactly the kind that survives review.
        #
        # This does not replace the unique constraint or the conditional UPDATE
        # below. Those are what hold when a lock cannot be taken -- a different
        # process, a replica, a future queue. This makes the ordinary path
        # correct rather than merely safe.
        await self.session.execute(
            select(ApprovalRequest.id)
            .where(ApprovalRequest.approval_id == record.approval_id)
            .with_for_update()
        )
        await self.session.refresh(record)

        if record.status is not ApprovalStatus.PENDING:
            raise ApprovalNotPending(
                f"Approval {record.approval_id} is {record.status.value} and can "
                f"no longer be decided."
            )
        if record.request_expires_at <= now:
            await self._expire(record, now)
            raise ApprovalNotPending(
                f"Approval {record.approval_id} expired at "
                f"{record.request_expires_at.isoformat()} without a decision."
            )

        await self._refuse_self_approval(record, approver)
        signoff = await self._record_signoff(record, approver, decision, note, now)

        await self.audit.record(
            Event(
                EventType.APPROVAL_SIGNOFF_RECORDED,
                agent_did=record.agent_did,
                request_id=record.request_id,
                resource=record.resource_type,
                action=record.action,
                decision=decision.value,
                reason=note or "one human sign-off recorded",
                metadata={
                    "approval_id": record.approval_id,
                    "sequence": signoff.sequence,
                    "required_approvals": record.required_approvals,
                    "approver": approver.principal_urn,
                    "approver_username": approver.username,
                    "approver_subject": approver.subject,
                    "approver_issuer": approver.issuer,
                    "approver_roles": sorted(approver.roles),
                    "resource_id": record.resource_id,
                },
            )
        )

        if decision is ApprovalDecision.REJECTED:
            return await self._finish_rejected(record, approver, signoff, note, now)

        recorded = [
            s for s in await self.signoffs(record.approval_id)
            if s.decision is ApprovalDecision.APPROVED
        ]
        if len(recorded) < record.required_approvals:
            # Still PENDING, and deliberately so: it is still waiting on a
            # human. Nothing is signed, so nothing can be presented.
            log.info("approval_awaiting_second_human",
                     approval_id=record.approval_id,
                     have=len(recorded), need=record.required_approvals,
                     approver=approver.username)
            return record

        return await self._finish_approved(record, approver, recorded, note, now)

    async def _refuse_self_approval(self, record: ApprovalRequest, approver: Any) -> None:
        """Maker-checker: the person who submitted it may not sign it off.

        POLICY refuses this first -- `cp-humans` denies `approval_decide` when
        the principal is the officer of record, and that is where the rule
        lives. This is the hard stop behind it, kept for the same reason the
        route refuses a machine principal even though policy already has:
        separation of duties must fail loudly rather than depend on exactly one
        rule staying correct.
        """
        from app.enforcement.resources import material_attributes

        material = material_attributes(record.resource_type, record.resource_id)
        submitted_by = material.get("submitted_by")
        if not submitted_by or submitted_by != approver.username:
            return
        await self.audit.record(
            Event(
                EventType.APPROVAL_SELF_APPROVAL_REJECTED,
                agent_did=record.agent_did,
                request_id=record.request_id,
                resource=record.resource_type,
                action=record.action,
                decision="DENY",
                reason="SELF_APPROVAL_PROHIBITED",
                metadata={
                    "approval_id": record.approval_id,
                    "approver_username": approver.username,
                    "approver_subject": approver.subject,
                    "submitted_by": submitted_by,
                    "resource_id": record.resource_id,
                },
            )
        )
        log.error("self_approval_refused", approval_id=record.approval_id,
                  approver=approver.username, submitted_by=submitted_by)
        raise SelfApprovalRefused(
            f"{approver.username} submitted {record.resource_id} and cannot "
            f"also sign it off. The maker and the checker must be different "
            f"people."
        )

    async def _record_signoff(
        self, record: ApprovalRequest, approver: Any,
        decision: ApprovalDecision, note: str | None, now: datetime,
    ) -> ApprovalSignoff:
        """INSERT one sign-off. The database decides whether it is allowed.

        The two-person rule is `UNIQUE (approval_id, issuer, subject)`. It is
        enforced by trying the INSERT rather than by looking first: two
        requests from the same person arriving together would both find no
        existing row and both proceed, and the second approval would be
        satisfied by the first person.
        """
        existing = await self.signoffs(record.approval_id)
        signoff = ApprovalSignoff(
            approval_id=record.approval_id,
            sequence=len(existing) + 1,
            approver_subject=approver.subject,
            approver_issuer=approver.issuer,
            approver_username=approver.username,
            approver_provider=getattr(approver, "provider", None),
            approver_roles=sorted(approver.roles),
            decision=decision,
            decided_at=now,
            note=note,
            decision_latency_ms=(now - record.requested_at).total_seconds() * 1000,
        )
        try:
            async with self.session.begin_nested():
                self.session.add(signoff)
                await self.session.flush()
        except IntegrityError as exc:
            # Which constraint fired decides what the caller is told. A repeat
            # approver and a lost race for a sequence number are different
            # events, and only one of them is an attempt to defeat dual control.
            clashed = [
                s for s in await self.signoffs(record.approval_id)
                if (s.approver_issuer, s.approver_subject)
                == (approver.issuer, approver.subject)
            ]
            if clashed:
                await self.audit.record(
                    Event(
                        EventType.APPROVAL_DUPLICATE_APPROVER_REJECTED,
                        agent_did=record.agent_did,
                        request_id=record.request_id,
                        resource=record.resource_type,
                        action=record.action,
                        decision="DENY",
                        reason="APPROVER_ALREADY_SIGNED",
                        metadata={
                            "approval_id": record.approval_id,
                            "approver_username": approver.username,
                            "approver_subject": approver.subject,
                            "approver_issuer": approver.issuer,
                            "existing_sequence": clashed[0].sequence,
                            "required_approvals": record.required_approvals,
                        },
                    )
                )
                log.error("duplicate_approver_refused",
                          approval_id=record.approval_id,
                          approver=approver.username)
                raise DuplicateApprover(
                    f"{approver.username or approver.subject} has already signed "
                    f"off approval {record.approval_id} (sign-off "
                    f"{clashed[0].sequence}). Two-person control requires two "
                    f"different people; one person cannot satisfy both."
                ) from exc
            raise ConflictError(
                f"A concurrent sign-off took position {signoff.sequence} on "
                f"approval {record.approval_id}. Retry."
            ) from exc
        return signoff

    async def _finish_rejected(
        self, record: ApprovalRequest, approver: Any,
        signoff: ApprovalSignoff, note: str | None, now: datetime,
    ) -> ApprovalRequest:
        """One refusal ends the request, whatever the sign-off count.

        Dual control means two people must AGREE. If a rejection merely failed
        to count, the request would stay open for somebody else to approve --
        which turns two-person control into "ask until one of them says yes".
        """
        self._assert_transition(record, ApprovalStatus.REJECTED)
        record.status = ApprovalStatus.REJECTED
        record.decision = ApprovalDecision.REJECTED
        record.decided_at = now
        self._record_approver(record, approver)
        record.decision_latency_ms = (now - record.requested_at).total_seconds() * 1000
        # A rejection is still a real, recorded decision -- it just has no
        # artifact to present, because there is nothing to permit.
        record.expires_at = now
        await self.session.flush()
        await self._audit_decision(record, approver, ApprovalDecision.REJECTED, note)
        log.info("approval_decided", approval_id=record.approval_id,
                 decision="REJECTED", approver=approver.username)
        return record

    async def _finish_approved(
        self, record: ApprovalRequest, approver: Any,
        recorded: list[ApprovalSignoff], note: str | None, now: datetime,
    ) -> ApprovalRequest:
        """Every required sign-off is in. Complete the approval and sign once.

        The flip to APPROVED is a conditional UPDATE, for the same reason
        consumption is: two people completing a dual approval at the same
        instant both reach this line, and exactly one may sign. The loser is
        told the approval is no longer PENDING rather than producing a second
        artifact for the same decision.
        """
        won = await self.session.execute(
            update(ApprovalRequest)
            .where(
                ApprovalRequest.approval_id == record.approval_id,
                ApprovalRequest.status == ApprovalStatus.PENDING,
            )
            .values(status=ApprovalStatus.APPROVED)
            .returning(ApprovalRequest.approval_id)
        )
        if won.scalar_one_or_none() is None:
            raise ApprovalNotPending(
                f"Approval {record.approval_id} was completed by a concurrent "
                f"sign-off. It is no longer pending."
            )

        record.status = ApprovalStatus.APPROVED
        record.decision = ApprovalDecision.APPROVED
        record.decided_at = now
        self._record_approver(record, approver)
        record.decision_latency_ms = (now - record.requested_at).total_seconds() * 1000
        record.expires_at = now + timedelta(seconds=self.settings.approval_ttl_seconds)
        record.artifact = await self._sign(record, approver, recorded, now)
        record.artifact_signed_by = self.settings.approval_authority_did
        await self.session.flush()

        await self._audit_decision(record, approver, ApprovalDecision.APPROVED, note)
        if record.required_approvals > 1:
            await self.audit.record(
                Event(
                    EventType.APPROVAL_DUAL_CONTROL_SATISFIED,
                    agent_did=record.agent_did,
                    request_id=record.request_id,
                    resource=record.resource_type,
                    action=record.action,
                    decision="APPROVED",
                    reason="two distinct humans approved",
                    metadata={
                        "approval_id": record.approval_id,
                        "required_approvals": record.required_approvals,
                        "approvers": [s.to_dict() for s in recorded],
                        "resource_id": record.resource_id,
                    },
                )
            )
        log.info("approval_decided", approval_id=record.approval_id,
                 decision="APPROVED", approver=approver.username,
                 approvals=len(recorded), required=record.required_approvals)
        return record

    @staticmethod
    def _record_approver(record: ApprovalRequest, approver: Any) -> None:
        """The COMPLETING approver, on the request row.

        Kept for Phase 5 readers, which expect exactly one approver here. The
        authoritative list is `approval_signoffs` and the `approvers` array
        inside the signed artifact.
        """
        record.approver_subject = approver.subject
        record.approver_issuer = approver.issuer
        record.approver_username = approver.username
        record.approver_roles = sorted(approver.roles)

    async def _audit_decision(
        self, record: ApprovalRequest, approver: Any,
        decision: ApprovalDecision, note: str | None,
    ) -> None:
        await self.audit.record(
            Event(
                EventType.APPROVAL_APPROVED if decision is ApprovalDecision.APPROVED
                else EventType.APPROVAL_REJECTED,
                agent_did=record.agent_did,
                request_id=record.request_id,
                resource=record.resource_type,
                action=record.action,
                decision=decision.value,
                reason=note or ("approved by an authorized human"
                                if decision is ApprovalDecision.APPROVED
                                else "rejected by an authorized human"),
                metadata={
                    "approval_id": record.approval_id,
                    "approver": approver.principal_urn,
                    "approver_username": approver.username,
                    "approver_roles": sorted(approver.roles),
                    "resource_id": record.resource_id,
                    "purpose": record.purpose,
                    "required_approvals": record.required_approvals,
                    "approvers": [
                        s.to_dict() for s in await self.signoffs(record.approval_id)
                    ],
                    "expires_at": record.expires_at.isoformat() if record.expires_at else None,
                    "decision_latency_ms": round(record.decision_latency_ms or 0, 2),
                    "signed_by": record.artifact_signed_by,
                    "signing_key": (record.artifact or {}).get("proof", {}).get(
                        "verificationMethod"),
                },
            )
        )

    async def _sign(
        self, record: ApprovalRequest, approver: Any,
        recorded: list[ApprovalSignoff], now: datetime,
    ) -> dict[str, Any]:
        if self.keystore is None or self.authority is None:
            raise RuntimeError(
                "The approval service was constructed without a KeyStore and "
                "cannot sign. Refusing to record an unsigned approval."
            )
        principal = await self.authority.require()
        # The ACTIVE key, resolved from the register. There is deliberately no
        # parameter here for a key id: that is what makes "a retired key cannot
        # issue a new artifact" structural rather than a rule to remember.
        signing_key = await self.authority.require_active_key()
        approvers = [
            {
                # Who Keycloak said each person was, and under what roles. A
                # RECORD of the basis for the decision -- policy re-checks
                # authority independently rather than trusting these.
                "subject": s.approver_subject,
                "issuer": s.approver_issuer,
                "username": s.approver_username,
                "roles": list(s.approver_roles or []),
                "provider": s.approver_provider,
                "sequence": s.sequence,
                "decided_at": s.decided_at.isoformat(),
            }
            for s in recorded
        ]
        completing = next(
            (a for a in approvers if a["subject"] == approver.subject),
            approvers[-1] if approvers else None,
        )
        artifact = build_artifact(
            approval_id=record.approval_id,
            binding=binding_of(record),
            approver=completing,
            approvers=approvers,
            required_approvals=record.required_approvals,
            decision=ApprovalDecision.APPROVED.value,
            issued_at=now,
            expires_at=record.expires_at,
            nonce=record.nonce,
            domain=record.domain,
            authority_did=principal.did,
            session_id=record.session_id,
        )
        return sign_artifact(
            artifact, Signer(self.keystore), signing_key.kid, moment=now
        )

    # --- 4. verify, for the PDP -------------------------------------------
    async def fact_for(
        self, binding: ApprovalBinding, *, approval_id: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalFact:
        """Establish the truth about an approval for THIS request.

        Returns a verdict for policy. It decides nothing: an ALLOW never
        happens here, only a report of what is and is not true.
        """
        now = now or datetime.now(timezone.utc)

        if approval_id:
            record = await self.get(approval_id)
        else:
            # No id offered: look for one bound to exactly this request.
            result = await self.session.execute(
                select(ApprovalRequest)
                .where(ApprovalRequest.binding_sha256 == binding.digest())
                .order_by(ApprovalRequest.requested_at.desc())
            )
            record = result.scalars().first()

        if record is None:
            # Nothing matches the full binding. Before reporting "no approval",
            # look for one opened against the SAME OPERATION -- same request,
            # agent, action, resource and purpose -- whose MATERIAL ATTRIBUTES
            # have since moved.
            #
            # The two halves of the binding answer different questions:
            #
            #   identity    is this the same operation?
            #   material    is this the same decision?
            #
            # A different ACTION is a different operation, so it is genuinely
            # NOT FOUND -- an approval to disburse funds has nothing to say
            # about approving a loan, and reporting it as a mismatch would
            # invite someone to go looking for a relationship that does not
            # exist.
            #
            # A different AMOUNT is the same operation and a different
            # decision. THIS IS THE TAMPERING PATH. Without this lookup, a loan
            # approved at Rs 25,00,000 and then raised to Rs 2,50,00,000 finds
            # no approval and looks like a fresh request nobody has answered
            # yet. It would still be blocked -- but as "go and get this
            # approved" rather than "the amount changed after somebody agreed
            # to it", and only one of those is an incident.
            #
            # Finding it here cannot make anything permitted: the artifact is
            # verified against the LIVE binding immediately below and reports
            # APPROVAL_BINDING_MISMATCH, naming the field that moved.
            result = await self.session.execute(
                select(ApprovalRequest)
                .where(
                    ApprovalRequest.request_id == binding.request_id,
                    ApprovalRequest.agent_did == binding.agent_did,
                    ApprovalRequest.action == binding.action,
                    ApprovalRequest.resource_type == binding.resource_type,
                    ApprovalRequest.resource_id == binding.resource_id,
                    ApprovalRequest.purpose == binding.purpose,
                )
                .order_by(ApprovalRequest.requested_at.desc())
            )
            record = result.scalars().first()

        if record is None:
            return ApprovalFact.absent()

        # Lazily reflect expiry. Time passing is not an event anyone fires.
        if record.status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED):
            deadline = (record.expires_at if record.status is ApprovalStatus.APPROVED
                        else record.request_expires_at)
            if deadline is not None and deadline <= now:
                await self._expire(record, now)

        recorded = await self.signoffs(record.approval_id)
        base = dict(
            approval_id=record.approval_id, status=record.status.value,
            decision=record.decision.value if record.decision else None,
            required_approvals=record.required_approvals,
            signoffs_recorded=len(recorded),
            amount_inr=binding.amount_inr,
        )

        # State first: these are facts the artifact cannot express, because a
        # signed document cannot know it has since been spent.
        if record.status is ApprovalStatus.PENDING:
            return ApprovalFact(present=True, valid=False,
                                reason=ArtifactReason.PENDING, **base)
        if record.status is ApprovalStatus.REJECTED:
            return ApprovalFact(present=True, valid=False,
                                reason=ArtifactReason.REJECTED, **base)
        if record.status is ApprovalStatus.EXPIRED:
            return ApprovalFact(present=True, valid=False,
                                reason=ArtifactReason.EXPIRED, **base)
        if record.status is ApprovalStatus.CANCELLED:
            return ApprovalFact(present=True, valid=False,
                                reason=ArtifactReason.CANCELLED, **base)
        if record.status is ApprovalStatus.CONSUMED:
            return ApprovalFact(present=True, valid=False,
                                reason=ArtifactReason.ALREADY_CONSUMED, **base)

        # APPROVED: now verify the artifact cryptographically and check that it
        # is about this exact request.
        authority = await self.authority.get() if self.authority else None
        report = verify_artifact(
            record.artifact,
            authority_document=authority.did_document if authority else None,
            expected_binding=binding,
            expected_domain=self.settings.approval_domain,
            now=now,
            # The signing-key register. Without it a rotated-out key would look
            # exactly like the active one, and "a retired key cannot issue new
            # artifacts" would be unverifiable at the point it matters.
            authority_keys=await self.authority.key_register() if self.authority else None,
        )
        return ApprovalFact(
            present=True,
            valid=report.valid,
            reason=report.reason,
            approver=report.approver,
            # From the VERIFIED artifact, not from the table: policy must weigh
            # what the approval authority actually attested to.
            approvers=report.approvers,
            distinct_approvers=report.distinct_approvers,
            signing_key=report.signing_key,
            expires_at=report.expires_at,
            bound_to_request=report.reason != ArtifactReason.BINDING_MISMATCH,
            checks=[c.to_dict() for c in report.checks],
            **base,
        )

    # --- 5. consume -------------------------------------------------------
    async def consume(
        self, approval_id: str, *, request_id: str, now: datetime | None = None
    ) -> bool:
        """Spend the approval. Exactly one caller can win.

        A single conditional UPDATE: the WHERE clause is the guard, so the
        database decides the winner. Two requests arriving together with the
        same approval both reach this line; one updates a row, the other
        updates none and is told the approval is already consumed.

        Deliberately NOT a read-then-write: `if record.status == APPROVED:
        record.status = CONSUMED` is a race with a comfortable-looking shape.
        """
        now = now or datetime.now(timezone.utc)
        result = await self.session.execute(
            update(ApprovalRequest)
            .where(
                ApprovalRequest.approval_id == approval_id,
                ApprovalRequest.status == ApprovalStatus.APPROVED,
                # Expiry is part of the same atomic condition. Checking it
                # separately would leave a window where an approval expires
                # between the check and the update.
                ApprovalRequest.expires_at > now,
            )
            .values(status=ApprovalStatus.CONSUMED, consumed_at=now,
                    consumed_by_request=request_id)
            .returning(ApprovalRequest.approval_id)
        )
        won = result.scalar_one_or_none() is not None
        await self.session.flush()

        record = await self.get(approval_id)
        await self.audit.record(
            Event(
                EventType.APPROVAL_CONSUMED if won
                else EventType.APPROVAL_REPLAY_REJECTED,
                agent_did=record.agent_did if record else None,
                request_id=request_id,
                resource=record.resource_type if record else None,
                action=record.action if record else None,
                decision="CONSUMED" if won else "REJECTED",
                reason=None if won else ArtifactReason.ALREADY_CONSUMED,
                metadata={
                    "approval_id": approval_id,
                    "status": record.status.value if record else "UNKNOWN",
                    "consumed_by_request": request_id,
                },
            )
        )
        if not won:
            log.warning("approval_reuse_refused", approval_id=approval_id,
                        request_id=request_id,
                        status=record.status.value if record else "UNKNOWN")
        return won

    # --- lifecycle helpers -------------------------------------------------
    def _assert_transition(self, record: ApprovalRequest, target: ApprovalStatus) -> None:
        permitted = ALLOWED_TRANSITIONS[record.status]
        if target not in permitted:
            raise InvalidTransition(
                f"Approval {record.approval_id} cannot move from "
                f"{record.status.value} to {target.value}. Permitted from "
                f"{record.status.value}: "
                f"{sorted(s.value for s in permitted) or 'nothing -- it is terminal'}."
            )

    async def _expire(self, record: ApprovalRequest, now: datetime) -> ApprovalRequest:
        self._assert_transition(record, ApprovalStatus.EXPIRED)
        previous = record.status
        record.status = ApprovalStatus.EXPIRED
        await self.session.flush()
        await self.audit.record(
            Event(
                EventType.APPROVAL_EXPIRED,
                agent_did=record.agent_did,
                request_id=record.request_id,
                resource=record.resource_type,
                action=record.action,
                decision="EXPIRED",
                reason="the approval window closed",
                metadata={"approval_id": record.approval_id,
                          "previous_status": previous.value},
            )
        )
        return record

    async def cancel(self, record: ApprovalRequest, reason: str) -> ApprovalRequest:
        self._assert_transition(record, ApprovalStatus.CANCELLED)
        record.status = ApprovalStatus.CANCELLED
        await self.session.flush()
        await self.audit.record(
            Event(EventType.APPROVAL_CANCELLED, agent_did=record.agent_did,
                  request_id=record.request_id, decision="CANCELLED", reason=reason,
                  metadata={"approval_id": record.approval_id})
        )
        return record

    async def expire_overdue(self, now: datetime | None = None) -> list[str]:
        """Move overdue requests and approvals to EXPIRED.

        Run on a timer. `fact_for` also expires lazily, so a stale row can
        never be USED -- this exists so the queue an operator looks at reflects
        reality without someone having to query it first.
        """
        now = now or datetime.now(timezone.utc)
        expired: list[str] = []
        result = await self.session.execute(
            select(ApprovalRequest).where(
                ApprovalRequest.status.in_(
                    [ApprovalStatus.PENDING, ApprovalStatus.APPROVED]
                )
            )
        )
        for record in result.scalars().all():
            deadline = (record.expires_at if record.status is ApprovalStatus.APPROVED
                        else record.request_expires_at)
            if deadline is not None and deadline <= now:
                await self._expire(record, now)
                expired.append(record.approval_id)
        return expired
