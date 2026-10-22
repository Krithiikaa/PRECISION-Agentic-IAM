"""Policy Information Point: gathers the context a policy needs.

THE PIP DECIDES NOTHING. It answers "what is true right now?" and hands that to
the PDP. Every allow/deny judgement belongs to Rego.

Two rules it must never break:

1. IT DOES NOT RE-IMPLEMENT PHASE 2. Credential validity comes from
   `CredentialVerifier` -- the same code path the credentials API and ANS
   discovery use. Signature, expiry and revocation are decided in exactly one
   place in this system. The PIP reports the verdict; it does not second-guess
   it, and Rego never sees a signature.

2. IT DOES NOT INVENT INFORMATION. An attribute that cannot be established is
   reported as `None` and named in `unavailable`. It is never defaulted to a
   value, and never defaulted to something trusted. `trust_score` stays NULL
   until Phase 10 builds a trust engine; a session stays NULL until Phase 9.
   Guessing here would let policy authorise on a number nobody computed.

3. (Phase 5.5) IT READS MATERIAL RESOURCE ATTRIBUTES FROM THE SERVER. The
   amount on a loan is an authorization input, so it is established here from
   the resource record -- never taken from the caller, and never taken from the
   browser that displayed it. What the amount MEANS is decided in Rego against
   thresholds held as policy configuration; this file supplies the number and
   nothing else.

4. (Phase 7) IT DOES NOT RE-VERIFY AN A2A ENVELOPE. The A2A service already
   did, before the PDP was asked at all, and a second verification here would
   be a second opinion that could disagree with the first. The verdict is
   INJECTED into `collect()` by the caller and passed through to policy
   unchanged -- the PIP reports it, it does not reach it.

5. (Phase 6) IT ESTABLISHES A VERDICT ABOUT A JIT MANDATE, exactly as it does
   for an approval. The signature, the signing key's window, the audience, the
   validity window against the SERVER clock, and whether the mandate's scope
   covers this request are all settled here; Rego decides what that means. A
   mandate is never a shortcut through this file -- it is one more fact, and
   every other fact is still collected alongside it.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.authorization.contracts import AuthorizationRequest
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.credentials.vc import credential_claims, specific_type
from app.credentials.verifier import CredentialVerifier
from app.db.models.agent import AgentStatus
from app.db.models.credential import Credential
from app.db.repositories.agents import AgentRepository
from app.hitl.artifact import ApprovalBinding
from app.hitl.service import ApprovalFact, ApprovalService
from app.identity.keys import KeyStore
from app.jit.grant import JITBinding
from app.jit.service import JITFact, JITService
from app.protocols.a2a.service import A2AFact

log = get_logger("authz.pip")

# Attributes no phase of this system computes yet. Named explicitly so policy
# and auditors can tell "not implemented" from "absent for this request".
UNAVAILABLE_ATTRIBUTES = {
    "trust_score": "Phase 10 owns the trust engine; no score is computed anywhere yet",
    "session": "Phase 9 owns the Session Authority; there is no session state",
    "anomaly": "Phase 10 owns anomaly detection",
}


@dataclass
class CredentialFact:
    """One credential, as the Phase 2 verifier judged it."""

    credential_id: str
    credential_type: str | None
    valid: bool
    reason: str
    status: str | None
    issuer: str | None
    expires_at: str | None
    claims: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "credential_type": self.credential_type,
            "valid": self.valid,
            "reason": self.reason,
            "status": self.status,
            "issuer": self.issuer,
            "expires_at": self.expires_at,
            "claims": self.claims,
        }


@dataclass
class PIPContext:
    subject_resolved: bool
    subject: dict[str, Any]
    credentials: list[CredentialFact] = field(default_factory=list)
    resource: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)
    # Explicitly null. See UNAVAILABLE_ATTRIBUTES.
    trust_score: None = None
    session: None = None
    # Phase 5. No longer null: the approval service establishes a VERDICT about
    # any human approval bound to this request, exactly as the Phase 2 verifier
    # does for credentials. Absent means "no approval applies to this request",
    # which is a fact, not an omission.
    approval: dict[str, Any] = field(default_factory=dict)
    # Phase 6. The verdict about any JIT mandate covering this request. Absent
    # means "no mandate applies", which is a fact and never a permissive
    # default: the request is then decided exactly as it would have been
    # before Phase 6 existed.
    jit: dict[str, Any] = field(default_factory=dict)
    # Phase 7. The verdict about an A2A transaction, when this evaluation is
    # deciding one. Absent means "this is not an A2A request", which is a fact
    # and never a permissive default: every rule in a2a/transaction.rego
    # guards on `present == true`, so an ordinary Phase 1-6 request is decided
    # exactly as it was before Phase 7 existed.
    a2a: dict[str, Any] = field(default_factory=dict)
    unavailable: dict[str, str] = field(default_factory=lambda: dict(UNAVAILABLE_ATTRIBUTES))
    collection_ms: float = 0.0

    @property
    def verified_capabilities(self) -> list[str]:
        """Capabilities attested by a credential the verifier ACCEPTED.

        Recorded for the audit trail and for operators. Policy does NOT read
        this field -- `decision.rego` derives capabilities from the per-
        credential `valid` verdicts itself, so no single supplied field can
        confer a capability.
        """
        return sorted({
            c.claims.get("capability") for c in self.credentials
            if c.valid and isinstance(c.claims.get("capability"), str)
        } - {None})

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_resolved": self.subject_resolved,
            "subject": self.subject,
            "credentials": [c.to_dict() for c in self.credentials],
            "verified_capabilities": self.verified_capabilities,
            "resource": self.resource,
            "environment": self.environment,
            "trust_score": self.trust_score,
            "session": self.session,
            "approval": self.approval,
            "jit": self.jit,
            "a2a": self.a2a,
            "unavailable": self.unavailable,
            "collection_ms": round(self.collection_ms, 2),
        }


class PolicyInformationPoint:
    def __init__(
        self,
        session: AsyncSession,
        keystore: KeyStore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.agents = AgentRepository(session)
        # The Phase 2 verifier, used verbatim.
        self.verifier = CredentialVerifier(session, keystore, self.settings)
        # The Phase 5 approval service, used the same way: it establishes the
        # verdict about an approval; nothing here re-derives one.
        self.approvals = ApprovalService(session, keystore, self.settings)
        # The Phase 6 mandate service, used the same way: it establishes the
        # verdict about a grant; nothing here re-derives one.
        self.jit = JITService(session, keystore, self.settings)

    async def collect(
        self, request: AuthorizationRequest, *, a2a: "A2AFact | None" = None
    ) -> PIPContext:
        """Gather what is true right now.

        `a2a` is the verdict the A2A service already reached about an inbound
        transaction envelope. It is INJECTED rather than recollected: the
        service verified the signature, the receiver binding, the freshness
        and the payload digest before the PDP was asked, and re-verifying here
        would create a second opinion that could disagree with the first.
        Defaulting to `absent()` keeps every existing caller unchanged.
        """
        started = time.perf_counter()
        a2a_fact = a2a or A2AFact.absent()

        # --- subject ------------------------------------------------------
        agent = await self.agents.get_by_did(request.subject.did)
        if agent is None:
            context = PIPContext(
                subject_resolved=False,
                subject={"did": request.subject.did, "type": request.subject.type,
                         "status": None, "detail": "not a registered agent identity"},
                resource=self._resource(request),
                environment=self._environment(),
                # An unknown subject can hold no approval: an approval names an
                # agent DID, and this one is not a registered identity.
                approval=ApprovalFact.absent().to_dict(),
                # Nor a mandate, for exactly the same reason.
                jit=JITFact.absent().to_dict(),
                # The A2A verdict IS still reported for an unknown subject.
                # An envelope from an unregistered sender is refused long
                # before this, but if one ever reached here policy must be
                # able to see that the sender is unresolvable rather than
                # being handed a blank where a verdict should be.
                a2a=a2a_fact.to_dict(),
            )
            context.collection_ms = (time.perf_counter() - started) * 1000
            return context

        subject = {
            "did": agent.did,
            "type": request.subject.type,
            "status": agent.status.value,
            "active": agent.status == AgentStatus.ACTIVE,
            "agent_type": agent.agent_type.value if agent.agent_type else None,
            "controller": agent.controller_did,
            # What the agent DECLARES about itself. Never authorisation
            # evidence -- an agent can claim any capability. Present so policy
            # can compare declaration against attestation if it wants to.
            "declared_capabilities": list(agent.capabilities or []),
        }

        # --- credentials, verified live ------------------------------------
        facts = await self._credential_facts(request)

        context = PIPContext(
            subject_resolved=True,
            subject=subject,
            credentials=facts,
            resource=self._resource(request),
            environment=self._environment(),
            approval=await self._approval_fact(request),
            jit=await self._jit_fact(request),
            a2a=a2a_fact.to_dict(),
        )
        context.collection_ms = (time.perf_counter() - started) * 1000
        return context

    async def _approval_fact(self, request: AuthorizationRequest) -> dict[str, Any]:
        """What is true about a human approval for THIS request.

        A VERDICT, not a decision. The service verifies the artifact's
        signature against the approval authority's DID Document, its audience
        and validity window, and whether its binding matches this exact
        request; Rego decides what that means.

        A failure here is not a permissive default. `ApprovalFact.absent()`
        means "no approval applies", which for a sensitive action escalates to
        HUMAN_APPROVAL_REQUIRED rather than proceeding.
        """
        binding = ApprovalBinding.from_request(request)
        fact = await self.approvals.fact_for(binding, approval_id=request.approval_id)
        return fact.to_dict()

    async def _jit_fact(self, request: AuthorizationRequest) -> dict[str, Any]:
        """What is true about a JIT mandate for THIS request.

        A VERDICT, not a decision -- the same shape `_approval_fact` produces.
        The service verifies the grant's signature against the JIT authority's
        DID Document, checks that the signing key was permitted to sign when
        the proof claims it did, checks the audience and the validity window
        against the SERVER clock, and compares the mandate's scope against this
        exact request. Rego decides what that means.

        THE MATERIAL ATTRIBUTES ARE PASSED IN, so a mandate's ceilings are
        compared against what the server reads from the resource record rather
        than against anything a caller supplied. A mandate that says "up to Rs
        10,00,000" is worth nothing if the amount it is checked against came
        from the request.

        A failure here is never a permissive default. `JITFact.absent()` means
        "no mandate applies", and the request is then decided exactly as it
        would have been before Phase 6 existed.
        """
        binding = JITBinding.from_request(request)
        fact = await self.jit.fact_for(
            binding,
            grant_id=request.jit_grant_id,
            resource_id=request.resource.id,
            resource_attributes=self._resource(request).get("attributes") or {},
        )
        return fact.to_dict()

    async def _credential_facts(self, request: AuthorizationRequest) -> list[CredentialFact]:
        """Verify the subject's credentials with the Phase 2 verifier.

        `record_event=False` follows the pattern ANS discovery already uses: the
        authorization layer emits its own correlated events rather than writing
        a second verification row per policy evaluation. The `request_id`
        carried on the authorization event is what ties the two together.
        """
        stmt = select(Credential).where(Credential.subject_did == request.subject.did)
        if request.credentials:
            # An offered id is a CLAIM. It narrows which credentials are
            # considered; it never substitutes for verifying them.
            stmt = stmt.where(Credential.credential_id.in_(request.credentials))
        result = await self.session.execute(stmt)
        records = list(result.scalars().unique().all())

        facts: list[CredentialFact] = []
        for record in records:
            report = await self.verifier.verify(
                record.document,
                # Binds the credential to the subject actually asking. A
                # credential issued to another agent cannot be borrowed.
                expected_subject=request.subject.did,
                verifier="pdp-pip",
                request_id=request.request_id,
                record_event=False,
            )
            facts.append(
                CredentialFact(
                    credential_id=record.credential_id,
                    credential_type=specific_type(record.document),
                    valid=report.valid,
                    reason=report.reason,
                    status=report.status,
                    issuer=report.issuer,
                    expires_at=report.expires_at,
                    claims=credential_claims(record.document),
                )
            )
        return facts

    def _resource(self, request: AuthorizationRequest) -> dict[str, Any]:
        """The resource, with its MATERIAL ATTRIBUTES read server-side.

        `attributes` (Phase 5.5) carries the facts that change the meaning or
        the risk of acting on this record -- for a loan, the amount and the
        officer who put it forward. Policy weighs them; a caller cannot supply
        them. That distinction is the whole reason they are collected here
        rather than accepted from `input.context`:

            input.context.amount              a claim. No rule reads it.
            input.pip.resource.attributes     established. Rules read this.

        An attribute that cannot be established is reported as
        `{"available": false}` with a reason, never defaulted to a number. A
        defaulted amount would be a threshold decision made by a missing record.
        """
        from app.enforcement.resources import material_attributes

        return {
            "type": request.resource.type,
            "id": request.resource.id,
            "classification": request.resource.classification,
            "attributes": material_attributes(request.resource.type, request.resource.id),
        }

    def _environment(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        return {
            "time": now.isoformat(),
            "hour_utc": now.hour,
            "day_of_week": now.isoweekday(),
        }
