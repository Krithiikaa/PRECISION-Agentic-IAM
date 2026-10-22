"""Adapter Enforcement Middleware: the enforcement boundary.

    PDP DECIDES.  AEM ENFORCES.

The AEM intercepts an attempt to use a protected tool, builds an
AuthorizationRequest from the tool's own declared resource and action, asks the
PDP, and then acts on the verdict:

    ALLOW                       consume any approval, mint a single-use grant,
                                execute, return the result
    DENY                        block; the tool is never called
    HUMAN_APPROVAL_REQUIRED     block, and OPEN AN APPROVAL REQUEST (Phase 5)

PHASE 5 adds two things to this file, and neither is a policy decision.

PHASE 5.5 adds a third, and it is not a policy decision either: when policy
escalates, it also says HOW MANY distinct humans it wants, and the AEM carries
that number onto the approval request. There is no amount comparison in this
file -- `required_approvals` is read off the Rego decision document, because
the moment the enforcement layer starts deciding how many people a loan needs,
there are two answers to that question and only one of them is reviewable.

First, when the PDP escalates, the AEM opens an approval request describing
exactly what the agent wanted -- so a human has something concrete to look at
rather than an alert. It still blocks. Nothing resumes automatically; the agent
retries, the PDP is asked AGAIN, and policy decides with the approval in hand.

Second, on ALLOW, an approval that made that ALLOW possible is CONSUMED before
the tool runs. Spending it first is deliberate: if the tool then fails, the
approval is still gone. A human approved ONE attempt, and a failed attempt was
that attempt -- silently handing back a fresh chance would turn a single-use
approval into a retry budget nobody granted.

PHASE 6 adds two things, and neither is a policy decision either.

First, `issue_jit_grant()`: the AEM runs the FULL PDP evaluation for the action
being mandated, asks the JIT issuance policy whether a mandate may be issued
with the requested bounds, and only then signs one. There is no
`if agent_is_valid: issue_grant()` here -- issuance is two policy evaluations
and a signature, and a HUMAN_APPROVAL_REQUIRED verdict refuses the mandate
outright rather than proceeding without a human.

Second, on ALLOW, a mandate that was PRESENTED is spent -- one atomic UPDATE,
before the tool runs, for exactly the reason an approval is. What has NOT
changed is that the PDP still decided this invocation: a mandate never
short-circuits the evaluation, it is one more fact inside it.

PHASE 7 adds `enforce_a2a()`, and it is not a policy decision either.

An A2A transaction is an INSTRUCTION one agent signed for another. The
differences from `enforce()` are all in where the facts come from, never in
who decides:

  * the SUBJECT is the SENDER, read from the signed envelope. The receiver's
    authority is never borrowed -- that is the confused-deputy mitigation, and
    it is structural rather than a rule.
  * the TOOL is DERIVED from the signed (action, resource_type) pair, never
    named by a caller. An envelope signed for one thing cannot be executed
    through another.
  * the AMOUNT is reconciled FOUR times: what the sender signed, what the
    server holds, what the PDP authorized, and what the tool is about to move.
    All four must agree. A signature over an amount is evidence of intent, not
    evidence of the figure -- so a signed amount is never trusted merely
    because it is signed.
  * EXECUTION IS CLAIMED ATOMICALLY, so a duplicate submission that somehow
    passed the unique INSERT still cannot move money twice.

WHAT IS DELIBERATELY ABSENT FROM THIS FILE: policy. There is no `if capability
== ...`, no allow-list, no resource table. Duplicating policy here would create
a second decision that could disagree with Rego -- and the Python one would win,
silently. The AEM's only judgement is "did the PDP say ALLOW".

The resource and action are taken from the TOOL'S OWN SPEC, not from the
caller. An agent therefore cannot describe its own request in flattering terms:
asking for `get_payroll_record` is always an authorization request about
`payroll_records`/`read`, whatever the caller claims.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.authorization.contracts import (
    AuthorizationDecision,
    AuthorizationRequest,
    Decision,
    Reason,
    Resource,
    Subject,
    new_request_id,
)
from app.authorization.pdp import PolicyDecisionPoint
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.enforcement.resources import AmountReconciliationError, material_attributes
from app.enforcement.tools import (
    EnforcementBypassError,
    ProtectedToolRegistry,
    build_default_registry,
    mint_grant,
)
from app.hitl.artifact import ApprovalBinding
from app.hitl.presentation import describe_for_human
from app.hitl.service import ApprovalService
from app.identity.keys import KeyStore
from app.jit.grant import JITBinding
from app.jit.service import JITService
from app.protocols.a2a.envelope import A2AReason
from app.protocols.a2a.presentation import describe_transaction
from app.protocols.a2a.service import (
    A2AFact,
    A2ATransactionService,
    RegistrationOutcome,
    authorization_request_id,
)
from app.monitoring.events import Event, EventType

log = get_logger("enforcement.aem")


class UnknownToolError(KeyError):
    """No such protected tool. Never a reason to fall back to an unprotected path."""


@dataclass
class EnforcementResult:
    executed: bool
    decision: AuthorizationDecision
    tool_name: str
    result: Any = None
    error: str | None = None
    grant: dict[str, Any] | None = None
    stages: list[dict[str, Any]] = field(default_factory=list)
    enforcement_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "executed": self.executed,
            "tool": self.tool_name,
            "decision": self.decision.to_dict(),
            "result": self.result,
            "error": self.error,
            "grant": self.grant,
            "enforcement_ms": round(self.enforcement_ms, 2),
            # Stated on every response so nothing downstream can mistake a
            # successful call for an unconditional permission.
            "enforcement": {
                "boundary": "AEM",
                "note": "The tool is reachable only through this boundary. "
                        "A decision authorises exactly one invocation.",
            },
        }


@dataclass
class JITIssuanceResult:
    """The outcome of asking for a mandate.

    Carries the PDP decision whether or not a grant was issued, because "your
    mandate was refused" and "you may not perform that action at all" are
    different answers and a caller needs to be able to tell them apart.
    """

    issued: bool
    decision: AuthorizationDecision
    request_id: str
    reason: str | None = None
    detail: str | None = None
    grant: Any = None
    issuance_document: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "issued": self.issued,
            "request_id": self.request_id,
            "reason": self.reason,
            "detail": self.detail,
            "grant": self.grant.to_dict() if self.grant is not None else None,
            "artifact": self.grant.artifact if self.grant is not None else None,
            "authorization": self.decision.to_dict(),
            "issuance_policy": self.issuance_document,
            "latency_ms": round(self.latency_ms, 2),
            "note": (
                "A mandate is an INPUT to authorization, not a permission. "
                "Every use is re-decided by the PDP."
            ),
        }


@dataclass
class A2ATransactionResult:
    """The outcome of one inbound A2A transaction.

    Carries the PDP decision whether or not anything executed, because "your
    instruction was refused", "you may not instruct that at all" and "a human
    must agree first" are different answers and a sender needs to tell them
    apart.
    """

    accepted: bool
    executed: bool
    status: str
    reason: str
    transaction_id: str | None = None
    decision: AuthorizationDecision | None = None
    record: Any = None
    result: Any = None
    detail: str | None = None
    idempotent: bool = False
    approval_id: str | None = None
    required_approvals: int | None = None
    signoffs_recorded: int | None = None
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "executed": self.executed,
            "status": self.status,
            "reason": self.reason,
            "detail": self.detail,
            "idempotent": self.idempotent,
            "transaction_id": self.transaction_id,
            "transaction": self.record.to_dict() if self.record is not None else None,
            "authorization": self.decision.to_dict() if self.decision else None,
            "result": self.result,
            "approval": {
                "approval_id": self.approval_id,
                "required_approvals": self.required_approvals,
                "signoffs_recorded": self.signoffs_recorded,
            } if self.approval_id else None,
            "latency_ms": round(self.latency_ms, 2),
            "note": (
                "A valid signature is not authorization. Every A2A transaction "
                "is decided by the PDP, and the amount is reconciled against "
                "server-side state before anything executes."
            ),
        }


class AdapterEnforcementMiddleware:
    def __init__(
        self,
        session: AsyncSession,
        keystore: KeyStore | None = None,
        settings: Settings | None = None,
        pdp: PolicyDecisionPoint | None = None,
        registry: ProtectedToolRegistry | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.pdp = pdp or PolicyDecisionPoint(session, keystore, self.settings)
        self.tools = registry or build_default_registry()
        self.audit = AuditService(session)
        self.approvals = ApprovalService(session, keystore, self.settings)
        self.jit = JITService(session, keystore, self.settings)
        self.a2a = A2ATransactionService(session, self.settings)
        self.keystore = keystore

    async def enforce(
        self,
        *,
        subject_did: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        purpose: str,
        request_id: str | None = None,
        context: dict[str, Any] | None = None,
        credentials: list[str] | None = None,
        approval_id: str | None = None,
        jit_grant_id: str | None = None,
    ) -> EnforcementResult:
        started = time.perf_counter()
        arguments = dict(arguments or {})
        request_id = request_id or new_request_id()

        tool = self.tools.get(tool_name)
        if tool is None:
            raise UnknownToolError(
                f"No protected tool named {tool_name!r}. Available: {self.tools.names()}"
            )

        resource_id = arguments.get(tool.resource_id_argument)

        await self.audit.record(
            Event(
                EventType.AEM_INTERCEPT,
                agent_did=subject_did,
                request_id=request_id,
                resource=tool.spec.resource,
                action=tool.spec.action,
                metadata={
                    "tool": tool_name,
                    "resource_id": resource_id,
                    "purpose": purpose,
                },
            )
        )

        # The request is built from the TOOL's declared resource/action, never
        # from anything the caller supplied.
        request = AuthorizationRequest(
            request_id=request_id,
            subject=Subject(did=subject_did),
            action=tool.spec.action,
            resource=Resource(type=tool.spec.resource, id=resource_id),
            purpose=purpose,
            credentials=list(credentials or []),
            context=dict(context or {}),
            # An OFFERED approval id. A claim, never evidence: the PIP verifies
            # the artifact and checks it is bound to THIS request. Offering an
            # id narrows which approval is considered; it cannot make one apply.
            approval_id=approval_id,
            # An OFFERED mandate id, handled identically: a claim, never
            # evidence. The PIP loads it, verifies the signature against the
            # JIT authority and checks the mandate's scope covers THIS request.
            jit_grant_id=jit_grant_id,
        )

        decision = await self.pdp.decide(request)

        # --- Phase 5: escalation opens a real approval request -------------
        if decision.decision is Decision.HUMAN_APPROVAL_REQUIRED:
            approval = await self._open_approval(request, tool, decision)
            decision.evaluation["approval_request"] = {
                "approval_id": approval.approval_id,
                "status": approval.status.value,
                "expires_at": approval.request_expires_at.isoformat(),
                # How many DISTINCT humans policy asked for, and how many have
                # signed. Reported so a caller retrying a dual-control action
                # can tell "still waiting for the second person" from "your
                # approval is not usable" -- the same distinction the reasons
                # draw, surfaced where the agent will actually look.
                "required_approvals": approval.required_approvals,
                "signoffs_recorded": len(
                    await self.approvals.signoffs(approval.approval_id)
                ),
                # The approval is bound to THIS request. Retrying under a new
                # request id is a NEW request that needs its own approval --
                # which is the intended semantics, not a limitation. Told to
                # the caller explicitly so the retry is obvious rather than
                # something to discover by getting a binding mismatch.
                "retry_with_request_id": request.request_id,
                "note": (
                    "Once a human has approved this, retry the SAME call with "
                    "request_id set to the value above. The PDP will be asked "
                    "again, with the approval as evidence."
                ),
            }

        if decision.decision is not Decision.ALLOW:
            enforcement_ms = (time.perf_counter() - started) * 1000
            await self.audit.record(
                Event(
                    EventType.AEM_BLOCKED,
                    agent_did=subject_did,
                    request_id=request_id,
                    resource=tool.spec.resource,
                    action=tool.spec.action,
                    decision=decision.decision.value,
                    reason=decision.reason,
                    metadata={
                        "tool": tool_name,
                        "resource_id": resource_id,
                        "policy": decision.policy_ref,
                        "executed": False,
                    },
                )
            )
            # A REPLAY, named as one (Phase 5.5). The approval service emits
            # APPROVAL_REPLAY_REJECTED when it LOSES the consumption race --
            # but the common case never reaches consumption at all, because the
            # PDP already denied on a spent approval. Without this, an operator
            # filtering the trail for replays would see only the rare racing
            # ones and none of the ordinary attempts.
            if decision.reason == Reason.APPROVAL_ALREADY_CONSUMED:
                spent = (decision.evaluation.get("pip") or {}).get("approval") or {}
                await self.audit.record(
                    Event(
                        EventType.APPROVAL_REPLAY_REJECTED,
                        agent_did=subject_did,
                        request_id=request_id,
                        resource=tool.spec.resource,
                        action=tool.spec.action,
                        decision="DENY",
                        reason=Reason.APPROVAL_ALREADY_CONSUMED,
                        metadata={
                            "tool": tool_name,
                            "resource_id": resource_id,
                            "approval_id": spent.get("approval_id"),
                            "approval_status": spent.get("status"),
                            "detail": "an approval already spent was presented again",
                        },
                    )
                )
            # A MANDATE REPLAY, named as one (Phase 6). Same reasoning as the
            # approval case just above: the common path never reaches
            # `record_use`, because the PDP already denied on the PIP's verdict
            # that the mandate is spent, expired or revoked. Without this, an
            # operator filtering the trail for reuse of a dead mandate would
            # see only the rare racing ones and none of the ordinary attempts.
            jit_dead = {
                Reason.JIT_GRANT_EXHAUSTED, Reason.JIT_GRANT_EXPIRED,
                Reason.JIT_GRANT_REVOKED,
            }
            if decision.reason in jit_dead:
                fact = (decision.evaluation.get("pip") or {}).get("jit") or {}
                await self.audit.record(
                    Event(
                        EventType.JIT_REPLAY_BLOCKED,
                        agent_did=subject_did,
                        request_id=request_id,
                        resource=tool.spec.resource,
                        action=tool.spec.action,
                        decision="DENY",
                        reason=decision.reason,
                        metadata={
                            "tool": tool_name,
                            "resource_id": resource_id,
                            "grant_id": fact.get("grant_id"),
                            "status": fact.get("status"),
                            "uses": fact.get("uses"),
                            "max_uses": fact.get("max_uses"),
                            "detail": "a mandate that is spent, expired or "
                                      "revoked was presented again",
                        },
                    )
                )
            log.warning("aem_blocked", request_id=request_id, subject=subject_did,
                        tool=tool_name, decision=decision.decision.value,
                        reason=decision.reason)
            return EnforcementResult(
                executed=False, decision=decision, tool_name=tool_name,
                error=decision.reason, enforcement_ms=enforcement_ms,
            )

        # --- Phase 5: spend the approval BEFORE the tool runs --------------
        # An atomic conditional UPDATE decides the winner, so two requests
        # presenting the same approval cannot both proceed. Losing the race is
        # a hard stop, not a warning: the losing caller has no approval.
        approval_fact = (decision.evaluation.get("pip") or {}).get("approval") or {}
        approval_id = approval_fact.get("approval_id")
        if approval_fact.get("valid") and approval_id:
            won = await self.approvals.consume(approval_id, request_id=request_id)
            if not won:
                enforcement_ms = (time.perf_counter() - started) * 1000
                blocked = AuthorizationDecision.denied(
                    request_id, Reason.APPROVAL_ALREADY_CONSUMED,
                    detail="the approval was spent by a concurrent request",
                    request=request, stages=decision.stages,
                )
                await self.audit.record(
                    Event(
                        EventType.AEM_BLOCKED,
                        agent_did=subject_did, request_id=request_id,
                        resource=tool.spec.resource, action=tool.spec.action,
                        decision="DENY", reason=Reason.APPROVAL_ALREADY_CONSUMED,
                        metadata={"tool": tool_name, "resource_id": resource_id,
                                  "approval_id": approval_id, "executed": False,
                                  "detail": "lost the race for a single-use approval"},
                    )
                )
                log.warning("approval_race_lost", request_id=request_id,
                            approval_id=approval_id, tool=tool_name)
                return EnforcementResult(
                    executed=False, decision=blocked, tool_name=tool_name,
                    error=Reason.APPROVAL_ALREADY_CONSUMED,
                    enforcement_ms=enforcement_ms,
                )

        # --- Phase 6: spend the MANDATE, also before the tool runs --------
        # Same ordering and the same reasoning as the approval above: a budget
        # authorises an attempt, and a failed attempt was that attempt. The
        # atomic UPDATE is what decides the winner, so two requests presenting
        # the same last use cannot both proceed.
        jit_fact = (decision.evaluation.get("pip") or {}).get("jit") or {}
        spent_grant_id = jit_fact.get("grant_id")
        if jit_fact.get("valid") and spent_grant_id:
            won = await self.jit.record_use(
                spent_grant_id, request_id=request_id,
                resource_id=resource_id, action=tool.spec.action,
            )
            if not won:
                enforcement_ms = (time.perf_counter() - started) * 1000
                blocked = AuthorizationDecision.denied(
                    request_id, Reason.JIT_GRANT_EXHAUSTED,
                    detail="the mandate was spent, expired or revoked by a "
                           "concurrent request",
                    request=request, stages=decision.stages,
                )
                await self.audit.record(
                    Event(
                        EventType.AEM_BLOCKED,
                        agent_did=subject_did, request_id=request_id,
                        resource=tool.spec.resource, action=tool.spec.action,
                        decision="DENY", reason=Reason.JIT_GRANT_EXHAUSTED,
                        metadata={"tool": tool_name, "resource_id": resource_id,
                                  "grant_id": spent_grant_id, "executed": False,
                                  "detail": "lost the race for a mandate's last use"},
                    )
                )
                log.warning("jit_race_lost", request_id=request_id,
                            grant_id=spent_grant_id, tool=tool_name)
                return EnforcementResult(
                    executed=False, decision=blocked, tool_name=tool_name,
                    error=Reason.JIT_GRANT_EXHAUSTED,
                    enforcement_ms=enforcement_ms,
                )

        # ALLOW: mint a grant bound to exactly this invocation.
        grant = mint_grant(
            request_id=request_id,
            tool_name=tool_name,
            subject_did=subject_did,
            resource_type=tool.spec.resource,
            resource_id=resource_id,
            policy_ref=decision.policy_ref,
        )
        try:
            result = await tool(_grant=grant, **arguments)
        except EnforcementBypassError:
            # Should be unreachable: the AEM just minted this grant. If it
            # happens, something is wrong with the boundary itself -- fail.
            raise
        except Exception as exc:  # noqa: BLE001 - a tool fault is not an authz fault
            enforcement_ms = (time.perf_counter() - started) * 1000
            log.error("tool_failed", request_id=request_id, tool=tool_name,
                      error=f"{type(exc).__name__}: {exc}")
            return EnforcementResult(
                executed=False, decision=decision, tool_name=tool_name,
                error=f"{type(exc).__name__}: {exc}",
                grant=grant.to_dict(), enforcement_ms=enforcement_ms,
            )

        enforcement_ms = (time.perf_counter() - started) * 1000
        await self.audit.record(
            Event(
                EventType.AEM_ALLOWED,
                agent_did=subject_did,
                request_id=request_id,
                resource=tool.spec.resource,
                action=tool.spec.action,
                decision="ALLOW",
                reason=decision.reason,
                metadata={"tool": tool_name, "resource_id": resource_id,
                          "policy": decision.policy_ref, "grant_id": grant.grant_id,
                          # The MANDATE, if one was in play. Named distinctly
                          # from `grant_id` above, which is the per-invocation
                          # enforcement grant -- two different objects at two
                          # different layers, and conflating them in the trail
                          # would make both unreadable.
                          "jit_grant_id": spent_grant_id},
            )
        )
        await self.audit.record(
            Event(
                EventType.TOOL_EXECUTED,
                agent_did=subject_did,
                request_id=request_id,
                resource=tool.spec.resource,
                action=tool.spec.action,
                decision="EXECUTED",
                metadata={"tool": tool_name, "resource_id": resource_id,
                          "grant_id": grant.grant_id,
                          "policy": decision.policy_ref},
            )
        )
        log.info("aem_allowed", request_id=request_id, subject=subject_did,
                 tool=tool_name, policy=decision.policy_ref,
                 latency_ms=round(enforcement_ms, 2))
        return EnforcementResult(
            executed=True, decision=decision, tool_name=tool_name, result=result,
            grant=grant.to_dict(), enforcement_ms=enforcement_ms,
        )

    # --- Phase 7: inbound A2A transactions -------------------------------
    async def enforce_a2a(
        self,
        *,
        envelope: dict[str, Any] | None,
        submitted_by: str,
        source_ip: str | None = None,
        now: datetime | None = None,
    ) -> "A2ATransactionResult":
        """Verify, authorize and execute one inbound A2A transaction.

        THE SEQUENCE, and every step of it is load-bearing:

            1.  VERIFY the envelope -- signature, sender resolution, key
                window, receiver binding, audience, freshness, payload digest.
                A failure here NEVER reaches the PDP and NEVER writes a
                transaction row.
            2.  REGISTER it, atomically. The database decides whether this is
                the first presentation, a retry, or a reused id.
            3.  RECONCILE the signed amount against what the server holds.
            4.  ask the PDP -- the FULL evaluation, with the A2A verdict as
                one more fact alongside credentials, approvals and mandates.
            5.  on escalation, open an approval through the EXISTING Phase 5/5.5
                machinery and stop. Nothing resumes on its own.
            6.  on ALLOW, reconcile the AUTHORIZED amount against the signed
                one, claim execution atomically, derive the tool from the
                SIGNED action, and execute -- with the authorized amount
                carried down so the handler refuses if the record has moved.

        THE PROPERTY THAT FALLS OUT of doing (1) before (2): a forged envelope
        cannot burn a legitimate sender's transaction id, because it never
        reaches the ledger.

        AND THE ONE THAT FALLS OUT of (4) being unconditional: there is no
        path in this method from "the signature verified" to "the tool ran".
        """
        started = time.perf_counter()
        now = now or datetime.now(timezone.utc)
        claimed_id = (envelope or {}).get("transactionId") if isinstance(envelope, dict) else None

        await self.audit.record(
            Event(
                EventType.A2A_REQUEST,
                # The claimed sender is NOT used to attribute this event: at
                # this point it is an assertion nobody has checked. The
                # principal that actually authenticated is in the metadata.
                agent_did=None,
                request_id=authorization_request_id(claimed_id) if claimed_id else None,
                resource=((envelope or {}).get("transaction") or {}).get("resourceType")
                if isinstance(envelope, dict) else None,
                action=((envelope or {}).get("transaction") or {}).get("action")
                if isinstance(envelope, dict) else None,
                metadata={
                    "claimed_transaction_id": claimed_id,
                    "claimed_sender": (envelope or {}).get("senderDid")
                    if isinstance(envelope, dict) else None,
                    "submitted_by": submitted_by,
                    "source_ip": source_ip,
                    "stage": "received; nothing has been verified yet",
                },
            )
        )

        # --- 1. VERIFY ----------------------------------------------------
        report = await self.a2a.verify(
            envelope, expected_receiver_did=submitted_by, now=now,
        )
        if not report.valid:
            elapsed = (time.perf_counter() - started) * 1000
            await self.a2a.record_rejection(
                envelope=envelope, submitted_by=submitted_by, report=report,
                reason=report.reason,
                detail="; ".join(c.detail for c in report.checks if not c.passed)
                or None,
                source_ip=source_ip, latency_ms=elapsed,
            )
            return A2ATransactionResult(
                accepted=False, executed=False, status="REJECTED",
                reason=report.reason, transaction_id=report.transaction_id,
                detail="the envelope was refused before any authorization was "
                       "attempted",
                latency_ms=elapsed,
            )

        # --- 2. REGISTER, atomically -------------------------------------
        outcome = await self.a2a.register(
            envelope, report, submitted_by=submitted_by, now=now,
        )
        if outcome.resumed:
            # THE HITL RETRY. The transaction was escalated, humans have had
            # the chance to decide, and the sender is asking again under the
            # SAME id -- which is exactly what it was told to do. It
            # re-enters the pipeline: reconciled again, decided again, with
            # any approval now weighed. Exactly-once is untouched, because
            # execution is gated by the atomic claim below.
            log.info("a2a_retry_after_escalation",
                     transaction_id=report.transaction_id,
                     approval_id=outcome.record.approval_id)
        elif not outcome.registered:
            elapsed = (time.perf_counter() - started) * 1000
            await self.a2a.record_replay(
                outcome, submitted_by=submitted_by, envelope=envelope,
            )
            existing = outcome.record
            if outcome.conflict:
                # A reused id carrying different content, or a spent nonce.
                # An attack, not a retry, and refused as one.
                return A2ATransactionResult(
                    accepted=False, executed=False, status="REJECTED",
                    reason=outcome.reason or A2AReason.TRANSACTION_ID_REUSE,
                    transaction_id=report.transaction_id,
                    detail=outcome.detail, record=existing, latency_ms=elapsed,
                )
            # IDEMPOTENT. The recorded outcome is returned verbatim: nothing is
            # re-decided, because the amount band, the credential state or the
            # approval could all have moved since, and a retry must not get a
            # different answer for a transaction that already settled.
            return A2ATransactionResult(
                accepted=True, executed=(existing.status.value == "EXECUTED"),
                status=existing.status.value,
                reason=existing.reason or existing.decision_reason
                or A2AReason.REPLAY_BLOCKED,
                transaction_id=existing.transaction_id,
                record=existing, result=existing.execution_result,
                idempotent=True, approval_id=existing.approval_id,
                required_approvals=existing.required_approvals,
                detail="already recorded; the previously determined outcome is "
                       "returned and nothing was re-executed",
                latency_ms=elapsed,
            )

        record = outcome.record

        # --- 3. RECONCILE the signed amount against the server -----------
        attributes = material_attributes(report.resource_type, report.resource_id)
        reconciled, server_amount, amount_reason = self.a2a.reconcile_amount(
            report, attributes,
        )
        await self.a2a.mark_verified(
            record, server_amount_inr=server_amount, amount_reconciled=reconciled,
        )
        if not reconciled:
            # Its own event, because an amount that disagrees with the record
            # is an incident rather than a validation error. Policy denies it
            # too -- this is the notification, not the control.
            await self.audit.record(
                Event(
                    EventType.A2A_AMOUNT_MISMATCH,
                    agent_did=report.sender_did,
                    request_id=record.authorization_request_id,
                    resource=report.resource_type,
                    action=report.action,
                    decision="DENY",
                    reason=amount_reason,
                    metadata={
                        "transaction_id": report.transaction_id,
                        "signed_amount_inr": report.amount_inr,
                        "server_amount_inr": server_amount,
                        "resource_id": report.resource_id,
                        "detail": "a signed amount is evidence of what the "
                                  "sender intended, never evidence of the "
                                  "figure on the record",
                    },
                )
            )

        fact = A2AFact.from_report(
            report, submitted_by=submitted_by, status=record.status.value,
            server_amount_inr=server_amount, amount_reconciled=reconciled,
        )
        if amount_reason:
            fact.reason = amount_reason

        # --- 4. THE PDP ---------------------------------------------------
        # Built ENTIRELY from the signed envelope. Nothing the submitting
        # process supplied reaches the request, which is what stops a receiver
        # widening an instruction it was asked to carry out.
        request = AuthorizationRequest(
            request_id=record.authorization_request_id,
            subject=Subject(did=report.sender_did),
            action=report.action,
            resource=Resource(type=report.resource_type, id=report.resource_id),
            purpose=report.purpose,
            credentials=list(report.credential_ids),
            context={
                # UNTRUSTED, and passed only so a rule that legitimately wants
                # transport metadata can see it. No rule reads an amount from
                # here -- `strip_decision_claims` removes self-asserted
                # verdicts, and the amount policy decides on comes from
                # `input.pip.resource.attributes`.
                "a2a": {
                    "transaction_id": report.transaction_id,
                    "receiver_did": report.receiver_did,
                    "correlation_id": report.correlation_id,
                },
            },
            approval_id=report.approval_id,
            jit_grant_id=report.jit_grant_id,
        )
        decision = await self.pdp.decide(request, a2a=fact)

        policy_document = (decision.evaluation or {}).get("opa_document") or {}
        pip_snapshot = (decision.evaluation or {}).get("pip") or {}
        authorized_amount = ((pip_snapshot.get("resource") or {})
                             .get("attributes") or {}).get("amount_inr")
        required_approvals = self._required_approvals(decision) \
            if decision.decision is Decision.HUMAN_APPROVAL_REQUIRED else None

        # --- 5. ESCALATION -------------------------------------------------
        if decision.decision is Decision.HUMAN_APPROVAL_REQUIRED:
            approval = await self._open_approval_a2a(request, fact, decision)
            await self.a2a.mark_decided(
                record, decision=decision.decision.value, reason=decision.reason,
                policy_id=decision.policy_id, policy_version=decision.policy_version,
                approval_id=approval.approval_id,
                required_approvals=approval.required_approvals,
                now=now,
            )
            recorded = len(await self.approvals.signoffs(approval.approval_id))
            elapsed = (time.perf_counter() - started) * 1000
            log.info("a2a_escalated", transaction_id=report.transaction_id,
                     approval_id=approval.approval_id,
                     required_approvals=approval.required_approvals,
                     have=recorded)
            return A2ATransactionResult(
                accepted=True, executed=False, status="PENDING_APPROVAL",
                reason=decision.reason, transaction_id=report.transaction_id,
                decision=decision, record=record,
                approval_id=approval.approval_id,
                required_approvals=approval.required_approvals,
                signoffs_recorded=recorded,
                detail=(
                    "re-submit the SAME transaction id once the required "
                    "humans have decided. The PDP will be asked again, with "
                    "the approval as evidence."
                ),
                latency_ms=elapsed,
            )

        # --- DENY ----------------------------------------------------------
        if decision.decision is not Decision.ALLOW:
            await self.a2a.mark_decided(
                record, decision=decision.decision.value, reason=decision.reason,
                policy_id=decision.policy_id, policy_version=decision.policy_version,
                now=now,
            )
            elapsed = (time.perf_counter() - started) * 1000
            await self.audit.record(
                Event(
                    EventType.AEM_BLOCKED,
                    agent_did=report.sender_did,
                    request_id=record.authorization_request_id,
                    resource=report.resource_type, action=report.action,
                    decision=decision.decision.value, reason=decision.reason,
                    metadata={
                        "transaction_id": report.transaction_id,
                        "resource_id": report.resource_id,
                        "policy": decision.policy_ref, "executed": False,
                        "channel": "a2a",
                    },
                )
            )
            log.warning("a2a_denied", transaction_id=report.transaction_id,
                        sender=report.sender_did, reason=decision.reason)
            return A2ATransactionResult(
                accepted=True, executed=False, status="DENIED",
                reason=decision.reason, transaction_id=report.transaction_id,
                decision=decision, record=record, latency_ms=elapsed,
            )

        # --- 6. ALLOW -------------------------------------------------------
        await self.a2a.mark_decided(
            record, decision="ALLOW", reason=decision.reason,
            policy_id=decision.policy_id, policy_version=decision.policy_version,
            authorized_amount_inr=authorized_amount,
            approval_id=(pip_snapshot.get("approval") or {}).get("approval_id"),
            required_approvals=policy_document.get("required_approvals"),
            now=now,
        )

        # RECONCILIATION, THE THIRD TIME. The PDP decided on whatever the PIP
        # read during ITS evaluation, which is a different read from the one
        # step 3 reconciled against. If the record moved in between, the
        # amount policy authorized is not the amount the sender signed -- and
        # executing either of them would be executing something nobody agreed
        # to. Refused before anything is claimed.
        if record.amount_inr is not None and authorized_amount != record.amount_inr:
            await self.a2a.mark_failed(
                record, reason=A2AReason.AMOUNT_MISMATCH,
                detail=f"policy authorized {authorized_amount} but the sender "
                       f"signed {record.amount_inr}; the record moved between "
                       f"verification and the decision",
                now=now,
            )
            elapsed = (time.perf_counter() - started) * 1000
            log.error("a2a_authorized_amount_mismatch",
                      transaction_id=report.transaction_id,
                      signed=record.amount_inr, authorized=authorized_amount)
            return A2ATransactionResult(
                accepted=True, executed=False, status="FAILED",
                reason=A2AReason.AMOUNT_MISMATCH,
                transaction_id=report.transaction_id, decision=decision,
                record=record,
                detail="the amount policy authorized is not the amount the "
                       "sender signed",
                latency_ms=elapsed,
            )

        # Spend the approval and the mandate BEFORE anything executes, for the
        # reason Phase 5 established: a human approved ONE attempt, and a
        # failed attempt was that attempt.
        blocked = await self._spend_prerequisites(
            decision, request_id=record.authorization_request_id,
            resource_id=report.resource_id, action=report.action,
        )
        if blocked is not None:
            await self.a2a.mark_failed(
                record, reason=blocked, detail="lost the race for a single-use "
                                               "approval or a mandate's last use",
                now=now,
            )
            elapsed = (time.perf_counter() - started) * 1000
            return A2ATransactionResult(
                accepted=True, executed=False, status="FAILED", reason=blocked,
                transaction_id=report.transaction_id, decision=decision,
                record=record, latency_ms=elapsed,
            )

        # THE ATOMIC EXECUTION CLAIM. The second independent layer behind the
        # unique INSERT: even one processing path cannot enter execution
        # twice, and expiry is folded into the same condition so there is no
        # window between the check and the spend.
        if not await self.a2a.claim_execution(record, now=now):
            elapsed = (time.perf_counter() - started) * 1000
            await self.a2a.record_replay(
                RegistrationOutcome(
                    registered=False, idempotent=False, conflict=True,
                    record=record, reason=A2AReason.REPLAY_BLOCKED,
                    detail="a concurrent submission entered execution first",
                ),
                submitted_by=submitted_by, envelope=envelope,
            )
            return A2ATransactionResult(
                accepted=True, executed=False, status=record.status.value,
                reason=A2AReason.REPLAY_BLOCKED,
                transaction_id=report.transaction_id, decision=decision,
                record=record,
                detail="a concurrent submission entered execution first",
                latency_ms=elapsed,
            )

        # THE TOOL IS DERIVED, never named by a caller.
        tool = self.tools.for_action(report.action, report.resource_type)
        if tool is None:
            await self.a2a.mark_failed(
                record, reason=A2AReason.NO_ENFORCEMENT_PATH,
                detail=f"no protected tool enforces "
                       f"({report.action!r}, {report.resource_type!r})",
                now=now,
            )
            elapsed = (time.perf_counter() - started) * 1000
            log.error("a2a_no_enforcement_path", action=report.action,
                      resource_type=report.resource_type,
                      transaction_id=report.transaction_id)
            return A2ATransactionResult(
                accepted=True, executed=False, status="FAILED",
                reason=A2AReason.NO_ENFORCEMENT_PATH,
                transaction_id=report.transaction_id, decision=decision,
                record=record,
                detail="an action with no enforcement path is not an action "
                       "this system performs",
                latency_ms=elapsed,
            )

        arguments = self._a2a_arguments(tool, report, authorized_amount)
        grant = mint_grant(
            request_id=record.authorization_request_id,
            tool_name=tool.spec.name,
            subject_did=report.sender_did,
            resource_type=report.resource_type,
            resource_id=report.resource_id,
            policy_ref=decision.policy_ref,
        )
        try:
            result = await tool(_grant=grant, **arguments)
        except EnforcementBypassError:
            raise
        except AmountReconciliationError as exc:
            # RECONCILIATION, THE FOURTH AND LAST TIME, and it happened INSIDE
            # the boundary. The record moved between the PDP decision and the
            # handler, by some path nobody anticipated, and the handler
            # refused to move a different sum from the one authorized.
            await self.a2a.mark_failed(
                record, reason=A2AReason.AMOUNT_MISMATCH, detail=str(exc), now=now,
            )
            elapsed = (time.perf_counter() - started) * 1000
            await self.audit.record(
                Event(
                    EventType.A2A_AMOUNT_MISMATCH,
                    agent_did=report.sender_did,
                    request_id=record.authorization_request_id,
                    resource=report.resource_type, action=report.action,
                    decision="DENY", reason=A2AReason.AMOUNT_MISMATCH,
                    metadata={
                        "transaction_id": report.transaction_id,
                        "authorized_amount_inr": authorized_amount,
                        "detail": str(exc),
                        "stage": "execution",
                    },
                )
            )
            log.error("a2a_execution_amount_mismatch",
                      transaction_id=report.transaction_id, detail=str(exc))
            return A2ATransactionResult(
                accepted=True, executed=False, status="FAILED",
                reason=A2AReason.AMOUNT_MISMATCH,
                transaction_id=report.transaction_id, decision=decision,
                record=record, detail=str(exc), latency_ms=elapsed,
            )
        except Exception as exc:  # noqa: BLE001 - a tool fault is not an authz fault
            await self.a2a.mark_failed(
                record, reason=A2AReason.EXECUTION_FAILED,
                detail=f"{type(exc).__name__}: {exc}", now=now,
            )
            elapsed = (time.perf_counter() - started) * 1000
            log.error("a2a_tool_failed", transaction_id=report.transaction_id,
                      tool=tool.spec.name, error=f"{type(exc).__name__}: {exc}")
            return A2ATransactionResult(
                accepted=True, executed=False, status="FAILED",
                reason=A2AReason.EXECUTION_FAILED,
                transaction_id=report.transaction_id, decision=decision,
                record=record, detail=f"{type(exc).__name__}: {exc}",
                latency_ms=elapsed,
            )

        executed_amount = (result.get("amount_inr")
                           if isinstance(result, dict) else None)
        await self.a2a.mark_executed(
            record, result=result, executed_amount_inr=executed_amount, now=now,
        )
        elapsed = (time.perf_counter() - started) * 1000
        record.latency_ms = elapsed
        await self.session.flush()

        await self.audit.record(
            Event(
                EventType.AEM_ALLOWED,
                agent_did=report.sender_did,
                request_id=record.authorization_request_id,
                resource=report.resource_type, action=report.action,
                decision="ALLOW", reason=decision.reason,
                metadata={
                    "transaction_id": report.transaction_id,
                    "tool": tool.spec.name, "resource_id": report.resource_id,
                    "policy": decision.policy_ref, "grant_id": grant.grant_id,
                    "channel": "a2a",
                },
            )
        )
        await self.audit.record(
            Event(
                EventType.TOOL_EXECUTED,
                agent_did=report.sender_did,
                request_id=record.authorization_request_id,
                resource=report.resource_type, action=report.action,
                decision="EXECUTED",
                metadata={
                    "transaction_id": report.transaction_id,
                    "tool": tool.spec.name, "resource_id": report.resource_id,
                    "grant_id": grant.grant_id, "policy": decision.policy_ref,
                    "channel": "a2a",
                },
            )
        )
        log.info("a2a_allowed", transaction_id=report.transaction_id,
                 sender=report.sender_did, receiver=report.receiver_did,
                 tool=tool.spec.name, policy=decision.policy_ref,
                 latency_ms=round(elapsed, 2))
        return A2ATransactionResult(
            accepted=True, executed=True, status="EXECUTED",
            reason=decision.reason, transaction_id=report.transaction_id,
            decision=decision, record=record, result=result,
            approval_id=record.approval_id, latency_ms=elapsed,
        )

    @staticmethod
    def _a2a_arguments(tool, report, authorized_amount: int | None) -> dict[str, Any]:
        """The tool arguments, built from the SIGNED envelope.

        The resource id comes from the tool's own declared argument name, so a
        tool that binds a different parameter cannot be handed the wrong one.
        The AUTHORIZED amount is carried down so the handler can refuse if the
        record has moved since -- the last link in the reconciliation chain,
        and it is inside the boundary precisely so no caller can skip it.
        """
        arguments: dict[str, Any] = {tool.resource_id_argument: report.resource_id}
        properties = (tool.spec.parameters or {}).get("properties") or {}
        if "expected_amount_inr" in properties and authorized_amount is not None:
            arguments["expected_amount_inr"] = authorized_amount
        if "narrative" in properties:
            narrative = ((report.to_dict().get("correlation_id") or "")
                         if hasattr(report, "to_dict") else "")
            arguments["narrative"] = f"a2a:{report.transaction_id}" + (
                f" ({narrative})" if narrative else ""
            )
        return arguments

    async def _spend_prerequisites(
        self, decision: AuthorizationDecision, *, request_id: str,
        resource_id: str | None, action: str,
    ) -> str | None:
        """Consume an approval and spend a mandate, before anything executes.

        Shared by the A2A path so the ordering Phase 5 and Phase 6 established
        is not re-derived here and cannot drift from `enforce()`. Returns the
        refusal reason on a lost race, or None on success.
        """
        approval_fact = (decision.evaluation.get("pip") or {}).get("approval") or {}
        approval_id = approval_fact.get("approval_id")
        if approval_fact.get("valid") and approval_id:
            if not await self.approvals.consume(approval_id, request_id=request_id):
                log.warning("a2a_approval_race_lost", request_id=request_id,
                            approval_id=approval_id)
                return Reason.APPROVAL_ALREADY_CONSUMED

        jit_fact = (decision.evaluation.get("pip") or {}).get("jit") or {}
        grant_id = jit_fact.get("grant_id")
        if jit_fact.get("valid") and grant_id:
            if not await self.jit.record_use(
                grant_id, request_id=request_id,
                resource_id=resource_id, action=action,
            ):
                log.warning("a2a_jit_race_lost", request_id=request_id,
                            grant_id=grant_id)
                return Reason.JIT_GRANT_EXHAUSTED
        return None

    async def _open_approval_a2a(self, request, fact, decision):
        """Turn an A2A escalation into something a human can actually answer.

        Uses the EXISTING Phase 5/5.5 approval machinery verbatim -- the same
        `ApprovalBinding`, the same `ApprovalService`, the same signing
        authority, the same `UNIQUE (approval_id, issuer, subject)` two-person
        rule, the same maker-checker refusal. PHASE 7 BUILDS NO SECOND
        APPROVAL MECHANISM, and the number of humans comes off the Rego
        decision document exactly as it does for a loan.

        The PRESENTATION is A2A-specific, because what a person needs to see
        is different: who instructed this, who would carry it out, and that
        the figure on the screen is the figure the sender signed. The approval
        itself is not.
        """
        binding = ApprovalBinding.from_request(request)
        required = self._required_approvals(decision)
        approval = await self.approvals.request_approval(
            binding=binding,
            presentation=describe_transaction(
                sender_did=fact.sender_did,
                receiver_did=fact.receiver_did,
                action=fact.action,
                resource_type=fact.resource_type,
                resource_id=fact.resource_id,
                purpose=fact.purpose,
                signed_amount_inr=fact.signed_amount_inr,
                decision_reason=decision.reason,
                required_approvals=required,
                transaction_id=fact.transaction_id,
            ),
            reason=decision.reason,
            context=request.strip_decision_claims(),
            required_approvals=required,
        )
        log.info("a2a_approval_opened", request_id=request.request_id,
                 approval_id=approval.approval_id,
                 required_approvals=approval.required_approvals)
        return approval

    # --- Phase 6: mandate issuance ---------------------------------------
    async def issue_jit_grant(
        self,
        *,
        subject_did: str,
        action: str,
        resource_type: str,
        resource_ids: list[str] | None = None,
        purpose: str,
        ttl_seconds: int,
        max_uses: int,
        request_id: str | None = None,
        context: dict[str, Any] | None = None,
        credentials: list[str] | None = None,
        approval_id: str | None = None,
    ) -> "JITIssuanceResult":
        """Issue a mandate, if BOTH policy evaluations permit it.

        THE SEQUENCE, and every step of it is load-bearing:

            1. the FULL data-plane PDP evaluation for the action being
               mandated. Not a subset, not a cheaper check -- the same
               evaluation the action itself would get.
            2. the JIT issuance policy, which decides eligibility and whether
               the requested bounds are within the configured ceilings.
            3. only then, a signature.

        THE PROPERTY THAT FALLS OUT of doing (1) first: a mandate can only ever
        be issued for something the agent could do at that instant. It can
        never confer authority the PDP would have refused, which is what makes
        "JIT cannot be used to escalate" structural rather than a rule.

        AND THE HITL BOUNDARY: a HUMAN_APPROVAL_REQUIRED verdict refuses the
        mandate. A mandate is not a human, and policy asking for one is not
        satisfied by asking for a grant instead.

        There is no `if agent_is_valid: issue_grant()` in this method, and no
        TTL comparison -- step 2 is an OPA call against Rego reading
        `data.agentic_iam.config.jit`.
        """
        started = time.perf_counter()
        request_id = request_id or new_request_id()
        resource_ids = list(resource_ids or [])

        await self.audit.record(
            Event(
                EventType.JIT_REQUESTED,
                agent_did=subject_did,
                request_id=request_id,
                resource=resource_type,
                action=action,
                metadata={
                    "purpose": purpose,
                    "resource_ids": resource_ids,
                    "requested_ttl_seconds": ttl_seconds,
                    "requested_max_uses": max_uses,
                    "approval_id": approval_id,
                },
            )
        )

        # --- 1. would this action be permitted, right now? ----------------
        # Built with the FIRST resource id when the mandate names instances,
        # so the evaluation is about a concrete record rather than a type. A
        # mandate over several records is only issued if the agent may act on
        # the representative one AND policy permits the scope.
        probe_resource_id = resource_ids[0] if resource_ids else None
        request = AuthorizationRequest(
            request_id=request_id,
            subject=Subject(did=subject_did),
            action=action,
            resource=Resource(type=resource_type, id=probe_resource_id),
            purpose=purpose,
            credentials=list(credentials or []),
            context=dict(context or {}),
            approval_id=approval_id,
        )
        decision = await self.pdp.decide(request)

        # --- 2. may a mandate be issued for it, with these bounds? --------
        issuance = await self._jit_issuance_decision(
            decision=decision, request_id=request_id, action=action,
            resource_type=resource_type, resource_ids=resource_ids,
            ttl_seconds=ttl_seconds, max_uses=max_uses,
        )
        if issuance.get("decision") != "ALLOW":
            reason = issuance.get("reason") or Reason.JIT_POLICY_UNCONFIGURED
            await self.jit.record_denial(
                agent_did=subject_did, action=action,
                resource_type=resource_type, request_id=request_id,
                reason=reason, detail=issuance.get("detail"),
                metadata={
                    "policy": issuance.get("policy_id"),
                    "pdp_decision": decision.decision.value,
                    "pdp_reason": decision.reason,
                    "requested_ttl_seconds": ttl_seconds,
                    "requested_max_uses": max_uses,
                    "escalation_reason": issuance.get("escalation_reason"),
                },
            )
            return JITIssuanceResult(
                issued=False, decision=decision, reason=reason,
                detail=issuance.get("detail"), issuance_document=issuance,
                request_id=request_id,
                latency_ms=(time.perf_counter() - started) * 1000,
            )

        # --- 3. sign what policy permitted --------------------------------
        # The bounds come off the POLICY document, not off the request. They
        # are equal here only because a request over a ceiling is refused
        # rather than silently reduced -- but reading them from the decision is
        # what keeps that true if the policy ever does start reducing them.
        granted_ttl = issuance.get("granted_ttl_seconds", ttl_seconds)
        granted_uses = issuance.get("granted_max_uses", max_uses)
        # THE AMOUNT CEILING IS ONLY ATTACHED TO A RESOURCE THAT HAS AN AMOUNT.
        #
        # `evaluate_constraints` fails closed: a ceiling on an attribute that
        # cannot be established is a violation, not a pass. That is right for a
        # loan whose amount has become unreadable -- and wrong for a credit
        # record, which never had an amount at all. Attaching the ceiling
        # unconditionally would make every mandate over such a resource
        # instantly unusable, by a check that can never succeed.
        #
        # So the ceiling is attached from SERVER-SIDE evidence that this
        # resource carries an amount, read by the PIP during the evaluation
        # above. A resource type with material attributes gets the ceiling and
        # the fail-closed behaviour with it; one without gets neither.
        constraints: dict[str, Any] = {}
        ceiling = issuance.get("max_amount_inr")
        attributes = ((decision.evaluation.get("pip") or {}).get("resource")
                      or {}).get("attributes") or {}
        if isinstance(ceiling, int) and attributes.get("available") is True \
                and isinstance(attributes.get("amount_inr"), int):
            constraints["max_amount_inr"] = ceiling

        binding = JITBinding(
            agent_did=subject_did,
            action=action,
            resource_type=resource_type,
            resource_ids=tuple(sorted(resource_ids)),
            purpose=purpose,
            constraints=constraints,
        )
        approval_fact = (decision.evaluation.get("pip") or {}).get("approval") or {}
        justification = {
            "policy": decision.policy_ref,
            "decision_reason": decision.reason,
            "issuance_policy": issuance.get("policy_id"),
            "decided_at": decision.decided_at.isoformat(),
            # The credentials the mandate rests on. Policy asserts these are
            # STILL valid at use time; recording them makes that intent
            # reviewable rather than emergent.
            "credential_ids": [
                c["credential_id"]
                for c in ((decision.evaluation.get("pip") or {}).get("credentials") or [])
                if c.get("valid")
            ],
            "approval_id": approval_fact.get("approval_id"),
            "approvers": approval_fact.get("approvers") or [],
        }

        record = await self.jit.issue(
            binding=binding,
            ttl_seconds=granted_ttl,
            max_uses=granted_uses,
            issuing_request_id=request_id,
            justification=justification,
            approval_id=approval_fact.get("approval_id"),
        )
        return JITIssuanceResult(
            issued=True, decision=decision, reason=issuance.get("reason"),
            grant=record, issuance_document=issuance, request_id=request_id,
            latency_ms=(time.perf_counter() - started) * 1000,
        )

    async def _jit_issuance_decision(
        self, *, decision: AuthorizationDecision, request_id: str, action: str,
        resource_type: str, resource_ids: list[str], ttl_seconds: int,
        max_uses: int,
    ) -> dict[str, Any]:
        """Ask the JIT issuance package. Fail-closed on every error path.

        A separate Rego package through the SAME OPA client, exactly as the
        control plane is evaluated -- so an unreachable engine, an unparseable
        body or an unrecognised verdict all deny here for the same reasons and
        by the same code they do everywhere else.
        """
        from app.authorization.opa import OPAUnavailableError

        document = {
            "request_id": request_id,
            "decision": decision.to_dict(),
            "requested": {
                "action": action,
                "resource_type": resource_type,
                "resource_ids": resource_ids,
                "ttl_seconds": ttl_seconds,
                "max_uses": max_uses,
            },
            "pip": (decision.evaluation or {}).get("pip") or {},
        }
        try:
            result = await self.pdp.opa.evaluate(
                document, decision_url=self.settings.jit_decision_url
            )
        except OPAUnavailableError as exc:
            log.error("jit_issuance_opa_unavailable", request_id=request_id,
                      error=str(exc))
            return {
                "decision": "DENY",
                "reason": Reason.AUTHORIZATION_UNAVAILABLE,
                "detail": "the policy engine is unreachable; failing closed",
            }
        verdict = result.document
        if verdict.get("decision") not in {"ALLOW", "DENY"}:
            # An issuance policy cannot invent a verdict, and notably cannot
            # return HUMAN_APPROVAL_REQUIRED: there is no approval flow for
            # issuing a mandate, and pretending otherwise would leave a caller
            # waiting for something nobody will ever be asked.
            log.error("jit_issuance_invalid_decision", request_id=request_id,
                      value=verdict.get("decision"))
            return {
                "decision": "DENY",
                "reason": Reason.AUTHORIZATION_UNAVAILABLE,
                "detail": f"policy returned an unrecognised decision "
                          f"{verdict.get('decision')!r}",
            }
        return verdict

    async def _open_approval(self, request, tool, decision):
        """Turn an escalation into something a human can actually answer.

        The AEM does not decide that a human is needed -- policy did. It only
        makes the escalation actionable, by recording WHAT was being attempted
        in the terms a person needs to judge it: which agent, which
        application, how much money, and why it was stopped.

        An approval screen that said only "an agent wants access" would produce
        approvals that are technically valid and worthless.
        """
        binding = ApprovalBinding.from_request(request)
        approval = await self.approvals.request_approval(
            binding=binding,
            presentation=describe_for_human(request, tool, decision),
            reason=decision.reason,
            context=request.strip_decision_claims(),
            # POLICY decided how many humans this needs; the AEM only carries
            # the number. There is deliberately no amount comparison here --
            # `required_approvals` is read off the Rego decision document, and
            # if policy did not say, the answer is one.
            required_approvals=self._required_approvals(decision),
        )
        log.info("approval_opened", request_id=request.request_id,
                 approval_id=approval.approval_id, tool=tool.spec.name,
                 required_approvals=approval.required_approvals)
        return approval

    @staticmethod
    def _required_approvals(decision: AuthorizationDecision) -> int:
        """How many distinct humans the POLICY asked for.

        Read from the Rego decision document. Defaulting to 1 when policy is
        silent is the conservative reading in the only direction that matters:
        a request that needs a human still gets one. It can never default to
        zero, because this method is only reached on HUMAN_APPROVAL_REQUIRED.
        """
        document = (decision.evaluation or {}).get("opa_document") or {}
        value = document.get("required_approvals")
        return value if isinstance(value, int) and value >= 1 else 1

    async def record_bypass_attempt(
        self, *, subject_did: str | None, tool_name: str, detail: str
    ) -> None:
        """Record a direct-call attempt on a protected tool.

        The attempt has already failed by the time this is called -- the tool
        raised. This makes it visible rather than merely unsuccessful.
        """
        await self.audit.record(
            Event(
                EventType.AEM_BYPASS_ATTEMPT,
                agent_did=subject_did,
                resource=tool_name,
                action="DIRECT_CALL",
                decision="BLOCKED",
                reason="ENFORCEMENT_BYPASS_ATTEMPT",
                metadata={"tool": tool_name, "detail": detail},
            )
        )
        log.error("aem_bypass_attempt", subject=subject_did, tool=tool_name, detail=detail)
