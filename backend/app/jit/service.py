"""The JIT grant service: issue, verify, spend, revoke.

WHAT THIS FILE IS NOT ALLOWED TO DO, stated first because it is the whole risk
of the phase: it does not decide whether a mandate may be issued. There is no
`if agent_is_valid: issue_grant()` here, and there is no threshold comparison,
no eligibility list and no TTL ceiling in Python. Every one of those is in Rego
(`policies/jit/issuance.rego`) reading configuration (`data.agentic_iam.config.jit`).
This file collects context, carries a policy verdict out, signs what policy
permitted, and refuses everything else.

STATE MACHINE. Transitions are an explicit table, not a convention:

    ACTIVE ──use (budget left)──▶ ACTIVE
      ├──use (last of budget)───▶ EXHAUSTED
      ├──expiry reached─────────▶ EXPIRED
      └──revoke─────────────────▶ REVOKED

Every terminal state has an EMPTY transition set, so `EXPIRED -> ACTIVE`,
`REVOKED -> ACTIVE` and `EXHAUSTED -> ACTIVE` are refused by name rather than
by nobody happening to write that code. A mandate cannot be un-spent, un-
expired or un-revoked.

THE THREE THINGS THE DATABASE DECIDES, not Python:

    the budget       `uses < max_uses` is in the WHERE clause of a single
                     conditional UPDATE, so ten concurrent uses of a mandate
                     with three left produce exactly three winners
    expiry           folded into the SAME atomic condition, so there is no
                     window in which a grant expires between the check and the
                     spend
    idempotency      UNIQUE (grant_id, request_id) means a retried request
                     cannot burn a second use out of a budget a human granted

WHY A GRANT IS NOT A BEARER TOKEN. Holding the signed document is necessary and
NEVER sufficient. A grant names an agent DID, and reaching the enforcement
boundary at all requires a control-plane proof signed by that DID's private
key. Theft of the artifact alone therefore buys nothing -- which is what makes
a reusable mandate defensible in the first place.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.db.models.jit import JITGrant, JITGrantStatus, JITGrantUse
from app.identity.keys import KeyStore
from app.identity.signer import Signer
from app.jit.authority import JITAuthority
from app.jit.grant import (
    GrantReason,
    JITBinding,
    build_grant,
    new_grant_id,
    new_nonce,
    sign_grant,
    verify_grant,
)
from app.jit.presentation import describe_mandate
from app.monitoring.events import Event, EventType

log = get_logger("jit.service")

# The only permitted transitions. Anything absent is refused by name.
ALLOWED_TRANSITIONS: dict[JITGrantStatus, frozenset[JITGrantStatus]] = {
    JITGrantStatus.ACTIVE: frozenset({
        JITGrantStatus.EXHAUSTED, JITGrantStatus.EXPIRED, JITGrantStatus.REVOKED,
    }),
    JITGrantStatus.EXHAUSTED: frozenset(),
    JITGrantStatus.EXPIRED: frozenset(),
    JITGrantStatus.REVOKED: frozenset(),
}


class InvalidGrantTransition(ConflictError):
    """A mandate was asked to move somewhere the table does not permit."""


class GrantNotActive(ConflictError):
    """The mandate is no longer spendable."""


@dataclass
class JITFact:
    """What the PIP reports to policy about a JIT grant.

    A VERDICT plus its reason -- the same shape the credential and approval
    facts use, so Rego consumes mandates the way it consumes everything else
    and never sees a signature.
    """

    present: bool
    valid: bool
    reason: str
    grant_id: str | None = None
    status: str | None = None
    agent_did: str | None = None
    action: str | None = None
    resource_type: str | None = None
    resource_ids: list[str] = field(default_factory=list)
    purpose: str | None = None
    constraints: dict[str, Any] = field(default_factory=dict)
    bound_to_request: bool = False
    covers_resource: bool = False
    binding_differences: list[str] = field(default_factory=list)
    expires_at: str | None = None
    not_before: str | None = None
    max_uses: int | None = None
    uses: int | None = None
    uses_remaining: int | None = None
    approval_id: str | None = None
    # The credentials the mandate was predicated on. Policy asserts these are
    # STILL valid -- defence in depth behind the PIP re-verifying them anyway.
    justified_by_credentials: list[str] = field(default_factory=list)
    signing_key: str | None = None
    issuer: str | None = None
    checks: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "valid": self.valid,
            "reason": self.reason,
            "grant_id": self.grant_id,
            "status": self.status,
            "agent_did": self.agent_did,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_ids": list(self.resource_ids),
            "purpose": self.purpose,
            "constraints": dict(self.constraints),
            "bound_to_request": self.bound_to_request,
            "covers_resource": self.covers_resource,
            "binding_differences": list(self.binding_differences),
            "expires_at": self.expires_at,
            "not_before": self.not_before,
            "max_uses": self.max_uses,
            "uses": self.uses,
            "uses_remaining": self.uses_remaining,
            "approval_id": self.approval_id,
            "justified_by_credentials": list(self.justified_by_credentials),
            "signing_key": self.signing_key,
            "issuer": self.issuer,
            "checks": list(self.checks),
        }

    @classmethod
    def absent(cls) -> "JITFact":
        """No mandate applies to this request.

        A FACT, not an omission, and never a permissive default: an action that
        needs one is denied, and an action that does not is unaffected.
        """
        return cls(present=False, valid=False, reason=GrantReason.MISSING)


class JITService:
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
        self.authority = JITAuthority(session, keystore, self.settings) if keystore else None

    # --- lookup -----------------------------------------------------------
    async def get(self, grant_id: str) -> JITGrant | None:
        result = await self.session.execute(
            select(JITGrant).where(JITGrant.grant_id == grant_id)
        )
        return result.scalar_one_or_none()

    async def require(self, grant_id: str) -> JITGrant:
        record = await self.get(grant_id)
        if record is None:
            raise NotFoundError(f"No JIT grant {grant_id!r}")
        return record

    async def for_agent(
        self, agent_did: str, *, active_only: bool = False
    ) -> list[JITGrant]:
        stmt = select(JITGrant).where(JITGrant.agent_did == agent_did)
        if active_only:
            stmt = stmt.where(JITGrant.status == JITGrantStatus.ACTIVE)
        stmt = stmt.order_by(JITGrant.issued_at.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().unique().all())

    async def uses_of(self, grant_id: str) -> list[JITGrantUse]:
        result = await self.session.execute(
            select(JITGrantUse)
            .where(JITGrantUse.grant_id == grant_id)
            .order_by(JITGrantUse.sequence)
        )
        return list(result.scalars().all())

    # --- 1. issue ---------------------------------------------------------
    async def issue(
        self,
        *,
        binding: JITBinding,
        ttl_seconds: int,
        max_uses: int,
        issuing_request_id: str,
        justification: dict[str, Any],
        approval_id: str | None = None,
        now: datetime | None = None,
    ) -> JITGrant:
        """Sign and persist a mandate that POLICY has already permitted.

        THE CALLER IS RESPONSIBLE for having obtained a policy ALLOW and for
        having had the issuance rules check the TTL and use ceilings. This
        method does not re-decide any of that -- it is the signing step, and
        putting an eligibility check here would create a second opinion that
        could disagree with Rego, silently, with Python winning.

        What it DOES enforce are structural bounds that are not policy
        questions at all: a non-positive TTL, a non-positive budget, and the
        absolute ceilings from settings, which exist so a nonsensical request
        is refused without an OPA round trip. Policy is stricter; it can never
        be more permissive than these.
        """
        if self.authority is None:
            raise RuntimeError(
                "JITService was constructed without a KeyStore and cannot sign. "
                "Refusing to issue an unsigned mandate."
            )
        if ttl_seconds <= 0:
            raise ConflictError("A mandate TTL must be positive.")
        if max_uses < 1:
            raise ConflictError("A mandate must permit at least one use.")
        if ttl_seconds > self.settings.jit_absolute_max_ttl_seconds:
            raise ConflictError(
                f"TTL {ttl_seconds}s exceeds the absolute ceiling "
                f"{self.settings.jit_absolute_max_ttl_seconds}s."
            )
        if max_uses > self.settings.jit_absolute_max_uses:
            raise ConflictError(
                f"{max_uses} uses exceeds the absolute ceiling "
                f"{self.settings.jit_absolute_max_uses}."
            )

        now = now or datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)
        grant_id = new_grant_id()
        nonce = new_nonce()

        key = await self.authority.require_active_key()
        principal = await self.authority.require()

        document = build_grant(
            grant_id=grant_id,
            binding=binding,
            issued_at=now,
            not_before=now,
            expires_at=expires_at,
            max_uses=max_uses,
            nonce=nonce,
            domain=self.settings.jit_domain,
            authority_did=self.authority.did,
            issuing_request_id=issuing_request_id,
            justification=justification,
        )
        signed = sign_grant(document, Signer(self.keystore), key.kid, moment=now)

        presentation = describe_mandate(
            binding=binding, max_uses=max_uses, ttl_seconds=ttl_seconds,
            expires_at=expires_at.isoformat(), justification=justification,
        )

        record = JITGrant(
            grant_id=grant_id,
            agent_did=binding.agent_did,
            action=binding.action,
            resource_type=binding.resource_type,
            resource_ids=list(binding.resource_ids),
            purpose=binding.purpose,
            constraints=dict(binding.constraints),
            binding_sha256=binding.digest(),
            binding=binding.to_dict(),
            justification=dict(justification),
            presentation=presentation,
            issued_at=now,
            not_before=now,
            expires_at=expires_at,
            max_uses=max_uses,
            uses=0,
            status=JITGrantStatus.ACTIVE,
            issuing_request_id=issuing_request_id,
            approval_id=approval_id,
            nonce=nonce,
            domain=self.settings.jit_domain,
            artifact=signed,
            signed_by_kid=key.kid,
            issuer_did=principal.did,
        )
        self.session.add(record)
        await self.session.flush()

        await self.audit.record(
            Event(
                EventType.JIT_ISSUED,
                agent_did=binding.agent_did,
                request_id=issuing_request_id,
                resource=binding.resource_type,
                action=binding.action,
                decision="ISSUED",
                reason=justification.get("decision_reason"),
                metadata={
                    "grant_id": grant_id,
                    "purpose": binding.purpose,
                    "resource_ids": list(binding.resource_ids),
                    "constraints": dict(binding.constraints),
                    "ttl_seconds": ttl_seconds,
                    "expires_at": expires_at.isoformat(),
                    "max_uses": max_uses,
                    "approval_id": approval_id,
                    "policy": justification.get("policy"),
                    "signed_by_kid": key.kid,
                    "issuer": principal.did,
                    # Stated on the record because it is the thing a reader of
                    # this event will otherwise assume the wrong way round.
                    "grant_is_not_permission": (
                        "every use is re-decided by the PDP"
                    ),
                },
            )
        )
        log.info("jit_issued", grant_id=grant_id, agent=binding.agent_did,
                 action=binding.action, resource=binding.resource_type,
                 ttl_seconds=ttl_seconds, max_uses=max_uses,
                 request_id=issuing_request_id)
        return record

    async def record_denial(
        self, *, agent_did: str, action: str, resource_type: str,
        request_id: str, reason: str, detail: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """A mandate was refused. Audited as its own event, never silently."""
        await self.audit.record(
            Event(
                EventType.JIT_DENIED,
                agent_did=agent_did,
                request_id=request_id,
                resource=resource_type,
                action=action,
                decision="DENY",
                reason=reason,
                metadata={"detail": detail, **(metadata or {})},
            )
        )
        log.warning("jit_denied", agent=agent_did, action=action,
                    resource=resource_type, reason=reason, request_id=request_id)

    # --- 2. verify, for the PIP -------------------------------------------
    async def fact_for(
        self,
        binding: JITBinding,
        *,
        grant_id: str | None = None,
        resource_id: str | None = None,
        resource_attributes: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> JITFact:
        """What is true about a mandate for THIS request.

        A VERDICT, not a decision. The signature, the key's window, the
        audience, the validity window and the binding are all established here;
        Rego decides what that means.

        A failure is never a permissive default. `JITFact.absent()` means "no
        mandate applies", which leaves the request to be decided exactly as it
        would have been without one.
        """
        now = now or datetime.now(timezone.utc)

        record: JITGrant | None = None
        if grant_id:
            record = await self.get(grant_id)
            if record is None:
                # An offered id that names nothing. Distinct from "no mandate
                # offered", because presenting an unknown grant is a different
                # event from not presenting one.
                return JITFact(
                    present=True, valid=False, reason=GrantReason.UNKNOWN,
                    grant_id=grant_id,
                )
        else:
            # NO ID OFFERED -> NO MANDATE APPLIES. Deliberately not a lookup.
            #
            # This is where a mandate differs from an approval, and the
            # difference is load-bearing. An approval is REQUIRED for an
            # escalated action, so the PIP looks one up by binding -- otherwise
            # a human could approve something and the agent could never use it.
            # A mandate is never required: it is additional evidence a caller
            # chooses to present.
            #
            # Auto-discovering one would mean a live mandate could REDUCE an
            # agent's baseline authority -- a mandate whose ceiling a record
            # has outgrown would start denying actions the agent's own
            # credential already permits, without anyone having presented it.
            # A mandate must only ever be able to help, never to silently
            # sabotage, so it applies exactly when it is offered.
            return JITFact.absent()

        base = {
            "grant_id": record.grant_id,
            "status": record.status.value,
            "agent_did": record.agent_did,
            "action": record.action,
            "resource_type": record.resource_type,
            "resource_ids": list(record.resource_ids or []),
            "purpose": record.purpose,
            "constraints": dict(record.constraints or {}),
            "expires_at": record.expires_at.isoformat(),
            "not_before": record.not_before.isoformat(),
            "max_uses": record.max_uses,
            "uses": record.uses,
            "uses_remaining": max(record.max_uses - record.uses, 0),
            "approval_id": record.approval_id,
            "justified_by_credentials": list(
                (record.justification or {}).get("credential_ids") or []
            ),
            "signing_key": record.signed_by_kid,
            "issuer": record.issuer_did,
        }

        # --- lifecycle, from the RECORD ----------------------------------
        # Checked before the signature, deliberately. A revoked mandate is
        # still perfectly signed, and reporting "signature invalid" for one
        # would send an operator hunting the wrong problem.
        if record.status is JITGrantStatus.REVOKED:
            return JITFact(present=True, valid=False,
                           reason=GrantReason.REVOKED, **base)
        if record.status is JITGrantStatus.EXHAUSTED or record.uses >= record.max_uses:
            return JITFact(present=True, valid=False,
                           reason=GrantReason.EXHAUSTED, **base)
        if record.status is JITGrantStatus.EXPIRED or now >= record.expires_at:
            return JITFact(present=True, valid=False,
                           reason=GrantReason.EXPIRED, **base)

        # --- the artifact -------------------------------------------------
        authority_document = None
        authority_keys = None
        if self.authority is not None:
            principal = await self.authority.get()
            authority_document = principal.did_document if principal else None
            authority_keys = await self.authority.key_register()

        report = verify_grant(
            record.artifact,
            authority_document=authority_document,
            expected_binding=binding,
            expected_domain=self.settings.jit_domain,
            resource_id=resource_id,
            resource_attributes=resource_attributes,
            now=now,
            authority_keys=authority_keys,
        )

        fact = JITFact(
            present=True,
            valid=report.valid,
            reason=report.reason,
            bound_to_request=report.bound_to_request,
            covers_resource=report.covers_resource,
            binding_differences=list(report.binding_differences),
            checks=[c.to_dict() for c in report.checks],
            **base,
        )
        return fact

    # --- 3. spend ---------------------------------------------------------
    async def record_use(
        self,
        grant_id: str,
        *,
        request_id: str,
        resource_id: str | None = None,
        action: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Spend one use. Exactly one concurrent caller can win each unit.

        A single conditional UPDATE: the WHERE clause is the guard, so the
        DATABASE decides the winner. Ten requests arriving together against a
        mandate with three uses left produce three winners and seven refusals.

        Deliberately NOT a read-then-write. `if grant.uses < grant.max_uses:
        grant.uses += 1` is a race with a comfortable-looking shape, and it is
        the exact bug the approval service avoids the same way.

        IDEMPOTENCY: a retry of the SAME request_id does not burn a second use.
        The unique constraint catches it and the call reports success, because
        the request it is retrying did legitimately hold a use.
        """
        now = now or datetime.now(timezone.utc)

        existing = await self.session.execute(
            select(JITGrantUse).where(
                JITGrantUse.grant_id == grant_id,
                JITGrantUse.request_id == request_id,
            )
        )
        if existing.scalar_one_or_none() is not None:
            # Already spent BY THIS REQUEST. Not a replay: the same request
            # asking again is the retry the unique constraint exists for.
            log.info("jit_use_idempotent", grant_id=grant_id, request_id=request_id)
            return True

        result = await self.session.execute(
            update(JITGrant)
            .where(
                JITGrant.grant_id == grant_id,
                JITGrant.status == JITGrantStatus.ACTIVE,
                JITGrant.uses < JITGrant.max_uses,
                # Expiry is part of the SAME atomic condition. Checking it
                # separately would leave a window in which a mandate expires
                # between the check and the spend.
                JITGrant.expires_at > now,
            )
            .values(uses=JITGrant.uses + 1)
            .returning(JITGrant.uses, JITGrant.max_uses)
        )
        row = result.one_or_none()
        if row is None:
            record = await self.get(grant_id)
            await self.audit.record(
                Event(
                    EventType.JIT_REPLAY_BLOCKED,
                    agent_did=record.agent_did if record else None,
                    request_id=request_id,
                    resource=record.resource_type if record else None,
                    action=action or (record.action if record else None),
                    decision="DENY",
                    reason=self._dead_reason(record, now),
                    metadata={
                        "grant_id": grant_id,
                        "status": record.status.value if record else "UNKNOWN",
                        "uses": record.uses if record else None,
                        "max_uses": record.max_uses if record else None,
                        "resource_id": resource_id,
                        "detail": "a mandate that is spent, expired or revoked "
                                  "was presented again",
                    },
                )
            )
            log.warning("jit_use_refused", grant_id=grant_id, request_id=request_id,
                        status=record.status.value if record else "UNKNOWN")
            return False

        uses, max_uses = row
        try:
            self.session.add(
                JITGrantUse(
                    grant_id=grant_id, sequence=uses, request_id=request_id,
                    resource_id=resource_id, action=action,
                    decision="ALLOW", used_at=now,
                )
            )
            await self.session.flush()
        except IntegrityError:
            # Two callers raced to the same sequence number, which the unique
            # constraint refuses. The spend itself already succeeded for one of
            # them; this one loses.
            await self.session.rollback()
            log.warning("jit_use_sequence_conflict", grant_id=grant_id,
                        request_id=request_id, sequence=uses)
            return False

        record = await self.get(grant_id)
        await self.audit.record(
            Event(
                EventType.JIT_USED,
                agent_did=record.agent_did if record else None,
                request_id=request_id,
                resource=record.resource_type if record else None,
                action=action or (record.action if record else None),
                decision="USED",
                metadata={
                    "grant_id": grant_id,
                    "resource_id": resource_id,
                    "use": uses,
                    "max_uses": max_uses,
                    "uses_remaining": max_uses - uses,
                    "approval_id": record.approval_id if record else None,
                },
            )
        )

        if uses >= max_uses:
            await self._exhaust(grant_id, now=now, request_id=request_id)

        log.info("jit_used", grant_id=grant_id, request_id=request_id,
                 use=uses, max_uses=max_uses)
        return True

    @staticmethod
    def _dead_reason(record: JITGrant | None, now: datetime) -> str:
        """Why a mandate could not be spent -- named, never 'invalid'."""
        if record is None:
            return GrantReason.UNKNOWN
        if record.status is JITGrantStatus.REVOKED:
            return GrantReason.REVOKED
        if record.status is JITGrantStatus.EXPIRED or now >= record.expires_at:
            return GrantReason.EXPIRED
        if record.uses >= record.max_uses:
            return GrantReason.EXHAUSTED
        return GrantReason.UNKNOWN

    async def _exhaust(
        self, grant_id: str, *, now: datetime, request_id: str | None = None
    ) -> None:
        """Budget spent. Conditional so it cannot be reached twice."""
        result = await self.session.execute(
            update(JITGrant)
            .where(
                JITGrant.grant_id == grant_id,
                JITGrant.status == JITGrantStatus.ACTIVE,
                JITGrant.uses >= JITGrant.max_uses,
            )
            .values(status=JITGrantStatus.EXHAUSTED, exhausted_at=now)
            .returning(JITGrant.grant_id)
        )
        if result.scalar_one_or_none() is None:
            return
        record = await self.get(grant_id)
        await self.audit.record(
            Event(
                EventType.JIT_EXHAUSTED,
                agent_did=record.agent_did if record else None,
                request_id=request_id,
                resource=record.resource_type if record else None,
                action=record.action if record else None,
                decision="EXHAUSTED",
                metadata={
                    "grant_id": grant_id,
                    "uses": record.uses if record else None,
                    "max_uses": record.max_uses if record else None,
                    "detail": "the mandate's budget is spent; it is terminal",
                },
            )
        )
        log.info("jit_exhausted", grant_id=grant_id)

    # --- 4. revoke --------------------------------------------------------
    async def revoke(
        self,
        grant_id: str,
        *,
        reason: str,
        revoked_by: str | None = None,
        now: datetime | None = None,
    ) -> JITGrant:
        """Kill a mandate before its window closes.

        Conditional on ACTIVE, so revoking an already-terminal mandate is a
        refusal rather than a silent no-op that would let an operator believe
        they had contained something they had not.
        """
        now = now or datetime.now(timezone.utc)
        record = await self.require(grant_id)
        self._assert_transition(record, JITGrantStatus.REVOKED)

        won = await self.session.execute(
            update(JITGrant)
            .where(
                JITGrant.grant_id == grant_id,
                JITGrant.status == JITGrantStatus.ACTIVE,
            )
            .values(
                status=JITGrantStatus.REVOKED, revoked_at=now,
                revoked_by=revoked_by, revocation_reason=reason,
            )
            .returning(JITGrant.grant_id)
        )
        if won.scalar_one_or_none() is None:
            raise GrantNotActive(
                f"Grant {grant_id} is no longer ACTIVE and cannot be revoked."
            )
        await self.session.flush()

        record = await self.require(grant_id)
        await self.audit.record(
            Event(
                EventType.JIT_REVOKED,
                agent_did=record.agent_did,
                request_id=record.issuing_request_id,
                resource=record.resource_type,
                action=record.action,
                decision="REVOKED",
                reason=reason,
                metadata={
                    "grant_id": grant_id,
                    "revoked_by": revoked_by,
                    "revoked_at": now.isoformat(),
                    "uses_at_revocation": record.uses,
                    "max_uses": record.max_uses,
                    "would_have_expired_at": record.expires_at.isoformat(),
                },
            )
        )
        log.warning("jit_revoked", grant_id=grant_id, agent=record.agent_did,
                    revoked_by=revoked_by, reason=reason)
        return record

    async def revoke_for_agent(
        self,
        agent_did: str,
        *,
        reason: str,
        revoked_by: str | None = None,
        now: datetime | None = None,
    ) -> list[str]:
        """Revoke every live mandate held by one agent.

        THE CONTAINMENT INTEGRATION POINT. Phase 6 provides the mechanism and
        calls it from the control-plane route only. Phase 10 (threat
        detection) and Phase 12 (the kill switch) are the callers that do not
        exist yet -- this is deliberately a method rather than a feature, so
        those phases have something to call instead of a reason to invent a
        second revocation path.

        NOTE what this is NOT needed for: an agent whose credential was revoked
        or whose identity was suspended is already stopped, because every use
        re-runs the PDP. This is for containing an agent whose credentials are
        still perfectly valid.
        """
        now = now or datetime.now(timezone.utc)
        live = await self.for_agent(agent_did, active_only=True)
        revoked: list[str] = []
        for record in live:
            try:
                await self.revoke(record.grant_id, reason=reason,
                                  revoked_by=revoked_by, now=now)
                revoked.append(record.grant_id)
            except (GrantNotActive, InvalidGrantTransition):
                # Something else terminated it between the read and the write.
                # The outcome an operator wanted is the outcome they have.
                continue
        if revoked:
            log.warning("jit_revoked_for_agent", agent=agent_did,
                        count=len(revoked), reason=reason)
        return revoked

    async def revoke_for_approval(
        self, approval_id: str, *, reason: str, revoked_by: str | None = None
    ) -> list[str]:
        """Revoke mandates that carry a particular human approval forward.

        If the decision a mandate rests on is withdrawn, the mandate resting on
        it should not outlive it.
        """
        result = await self.session.execute(
            select(JITGrant).where(
                JITGrant.approval_id == approval_id,
                JITGrant.status == JITGrantStatus.ACTIVE,
            )
        )
        revoked: list[str] = []
        for record in result.scalars().unique().all():
            try:
                await self.revoke(record.grant_id, reason=reason, revoked_by=revoked_by)
                revoked.append(record.grant_id)
            except (GrantNotActive, InvalidGrantTransition):
                continue
        return revoked

    # --- 5. expiry sweep --------------------------------------------------
    async def sweep_expired(self, *, now: datetime | None = None) -> list[str]:
        """Move overdue mandates to EXPIRED.

        HOUSEKEEPING, NOT ENFORCEMENT. A mandate past its expiry is already
        unusable -- `record_use` and `fact_for` both compare against the server
        clock, and neither waits for this sweep. This exists so the stored
        status matches reality for anyone reading the table, and so the
        JIT_EXPIRED event gets emitted at all.
        """
        now = now or datetime.now(timezone.utc)
        result = await self.session.execute(
            update(JITGrant)
            .where(
                JITGrant.status == JITGrantStatus.ACTIVE,
                JITGrant.expires_at <= now,
            )
            .values(status=JITGrantStatus.EXPIRED, expired_at=now)
            .returning(JITGrant.grant_id)
        )
        expired = [row[0] for row in result.all()]
        await self.session.flush()

        for grant_id in expired:
            record = await self.get(grant_id)
            await self.audit.record(
                Event(
                    EventType.JIT_EXPIRED,
                    agent_did=record.agent_did if record else None,
                    request_id=record.issuing_request_id if record else None,
                    resource=record.resource_type if record else None,
                    action=record.action if record else None,
                    decision="EXPIRED",
                    metadata={
                        "grant_id": grant_id,
                        "expires_at": record.expires_at.isoformat() if record else None,
                        "uses": record.uses if record else None,
                        "max_uses": record.max_uses if record else None,
                        "unused_budget": (record.max_uses - record.uses) if record else None,
                    },
                )
            )
        if expired:
            log.info("jit_swept_expired", count=len(expired))
        return expired

    # --- state machine ----------------------------------------------------
    @staticmethod
    def _assert_transition(record: JITGrant, target: JITGrantStatus) -> None:
        """Refuse an impossible transition BY NAME.

        Terminal is terminal: EXPIRED, EXHAUSTED and REVOKED all have empty
        permitted-target sets, so nothing can bring a dead mandate back.
        """
        permitted = ALLOWED_TRANSITIONS.get(record.status, frozenset())
        if target not in permitted:
            raise InvalidGrantTransition(
                f"Grant {record.grant_id} is {record.status.value}; "
                f"{record.status.value} -> {target.value} is not a permitted "
                f"transition. Permitted from here: "
                f"{sorted(s.value for s in permitted) or 'nothing (terminal)'}."
            )

    # --- reporting --------------------------------------------------------
    async def stats(self) -> dict[str, int]:
        """Counts by status, for the gate and the health endpoint."""
        result = await self.session.execute(
            select(JITGrant.status, func.count()).group_by(JITGrant.status)
        )
        counts = {status.value: 0 for status in JITGrantStatus}
        for status, count in result.all():
            counts[status.value] = count
        return counts
