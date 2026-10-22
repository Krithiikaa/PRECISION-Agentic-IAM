"""Policy Decision Point.

    PDP DECIDES.  AEM ENFORCES.

The PDP takes an AuthorizationRequest, asks the PIP what is true, asks OPA what
policy says about it, and returns a decision. It deliberately does NOT:

  * execute the requested action
  * read or write the resource on the agent's behalf
  * call any tool
  * trust anything the agent or the LLM asserts about permission

The last point is enforced, not just documented: `strip_decision_claims()`
removes self-asserted verdicts from the caller's context before it reaches
policy, and the attempt is recorded.

Phase 4.5 adds `decide_control_plane()`. It is a METHOD ON THIS CLASS, not a
second decision point: there must be exactly one component in this system that
turns a question into a policy verdict. It evaluates a SEPARATE Rego package
through the SAME OPA runtime, so control-plane hardening cannot alter
data-plane semantics while still being decided by policy rather than by code.

FAIL-CLOSED. Every error path in this module produces DENY. There is no branch
that returns ALLOW without OPA having evaluated Rego and said so.
"""
from __future__ import annotations

import time
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.authorization.contracts import (
    AuthorizationDecision,
    AuthorizationRequest,
    Decision,
    MalformedAuthorizationRequest,
    Reason,
    Stage,
)
from app.authorization.opa import OPAClient, OPAUnavailableError
from app.authorization.pip import PolicyInformationPoint
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.models.authorization import AuthorizationDecisionRecord
from app.identity.keys import KeyStore
from app.monitoring.events import Event, EventType

log = get_logger("authz.pdp")

# Rego decision strings the PDP will accept. Anything else is treated as a
# malformed policy result and denied -- a policy cannot invent a new verdict.
_VALID_DECISIONS = {d.value for d in Decision}


class PolicyDecisionPoint:
    def __init__(
        self,
        session: AsyncSession,
        keystore: KeyStore | None = None,
        settings: Settings | None = None,
        opa: OPAClient | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.pip = PolicyInformationPoint(session, keystore, self.settings)
        self.opa = opa or OPAClient(self.settings)
        self.audit = AuditService(session)

    async def decide(
        self, request: AuthorizationRequest, *, record: bool = True,
        a2a: Any = None,
    ) -> AuthorizationDecision:
        """Decide one authorization request.

        `a2a` (Phase 7) is the verdict the A2A service established about an
        inbound transaction envelope, passed straight through to the PIP and
        then to policy. It is optional and defaults to absent, so every
        existing caller is unchanged and an ordinary request is decided
        exactly as it was before Phase 7 existed.

        Nothing about the decision moves because of it: an A2A verdict is one
        more FACT in the input document, and `a2a/transaction.rego` is what
        decides what it means. A valid signature has never been an ALLOW.
        """
        stages: list[Stage] = []

        # --- 0. validate --------------------------------------------------
        started = time.perf_counter()
        try:
            request.validate()
        except MalformedAuthorizationRequest as exc:
            stages.append(Stage("validate", False, str(exc),
                                (time.perf_counter() - started) * 1000))
            decision = AuthorizationDecision.denied(
                request.request_id, Reason.MALFORMED_REQUEST,
                detail=str(exc), request=request, stages=stages,
            )
            if record:
                await self._record(request, decision, None)
            return decision
        stages.append(Stage("validate", True, "request is well formed",
                            (time.perf_counter() - started) * 1000))

        if record:
            await self.audit.record(
                Event(
                    EventType.AUTHORIZATION_REQUESTED,
                    agent_did=request.subject.did,
                    request_id=request.request_id,
                    resource=request.resource.type,
                    action=request.action,
                    metadata={
                        "resource_id": request.resource.id,
                        "purpose": request.purpose,
                        "offered_credentials": len(request.credentials),
                    },
                )
            )

        # --- 1. PIP -------------------------------------------------------
        started = time.perf_counter()
        try:
            context = await self.pip.collect(request, a2a=a2a)
        except Exception as exc:  # noqa: BLE001 - a PIP failure must not open the gate
            stages.append(Stage("pip", False, f"{type(exc).__name__}: {exc}",
                                (time.perf_counter() - started) * 1000))
            log.error("pip_failed", request_id=request.request_id,
                      error=f"{type(exc).__name__}: {exc}")
            decision = AuthorizationDecision.denied(
                request.request_id, Reason.AUTHORIZATION_UNAVAILABLE,
                detail="context collection failed", request=request, stages=stages,
            )
            if record:
                await self._record(request, decision, None)
                await self._emit(request, decision)
            return decision

        stages.append(Stage(
            "pip", True,
            f"{len(context.credentials)} credential(s) verified, "
            f"{len(context.verified_capabilities)} attested capability(ies)",
            context.collection_ms,
        ))
        if record:
            await self.audit.record(
                Event(
                    EventType.PIP_CONTEXT_COLLECTED,
                    agent_did=request.subject.did,
                    request_id=request.request_id,
                    resource=request.resource.type,
                    metadata={
                        "subject_resolved": context.subject_resolved,
                        "verified_capabilities": context.verified_capabilities,
                        "credentials": [
                            {"credential_id": c.credential_id, "valid": c.valid,
                             "reason": c.reason}
                            for c in context.credentials
                        ],
                        "unavailable": sorted(context.unavailable),
                    },
                )
            )

        # --- 2. OPA -------------------------------------------------------
        rejected_keys = request.rejected_context_keys()
        if rejected_keys:
            # Not an error: a caller may send anything. It is simply not
            # allowed to influence the verdict, and the attempt is on record.
            log.warning("self_asserted_authorization_ignored",
                        request_id=request.request_id,
                        subject=request.subject.did, keys=rejected_keys)

        input_document = self._build_input(request, context)
        started = time.perf_counter()
        try:
            result = await self.opa.evaluate(input_document)
        except OPAUnavailableError as exc:
            stages.append(Stage("opa", False, str(exc),
                                (time.perf_counter() - started) * 1000))
            log.error("opa_unavailable", request_id=request.request_id, error=str(exc))
            decision = AuthorizationDecision.denied(
                request.request_id, Reason.AUTHORIZATION_UNAVAILABLE,
                detail="policy engine unavailable", request=request, stages=stages,
            )
            decision.evaluation["rejected_context_keys"] = rejected_keys
            if record:
                await self.audit.record(
                    Event(
                        EventType.AUTHORIZATION_UNAVAILABLE,
                        agent_did=request.subject.did,
                        request_id=request.request_id,
                        resource=request.resource.type,
                        action=request.action,
                        decision="DENY",
                        reason=Reason.AUTHORIZATION_UNAVAILABLE,
                        metadata={"detail": "OPA unreachable; failing closed"},
                    )
                )
                await self._record(request, decision, context)
                await self._emit(request, decision)
            return decision

        stages.append(Stage("opa", True, "Rego policy evaluated", result.latency_ms))

        # --- 3. map the Rego document to a decision ------------------------
        document = result.document
        raw = document.get("decision")
        if raw not in _VALID_DECISIONS:
            log.error("opa_invalid_decision", request_id=request.request_id, value=raw)
            decision = AuthorizationDecision.denied(
                request.request_id, Reason.AUTHORIZATION_UNAVAILABLE,
                detail=f"policy returned an unrecognised decision {raw!r}",
                request=request, stages=stages,
            )
            if record:
                await self._record(request, decision, context)
                await self._emit(request, decision)
            return decision

        decision = AuthorizationDecision(
            decision=Decision(raw),
            request_id=request.request_id,
            reason=document.get("reason") or Reason.NO_MATCHING_POLICY,
            policy_id=document.get("policy_id"),
            policy_version=document.get("policy_version"),
            subject_did=request.subject.did,
            action=request.action,
            resource_type=request.resource.type,
            resource_id=request.resource.id,
            purpose=request.purpose,
            stages=stages,
            evaluation={
                "pip": context.to_dict(),
                "opa_document": document,
                "rejected_context_keys": rejected_keys,
                "policy_engine": {"url": self.opa.base_url, "engine": "OPA"},
            },
        )

        if record:
            await self.audit.record(
                Event(
                    EventType.OPA_DECISION,
                    agent_did=request.subject.did,
                    request_id=request.request_id,
                    resource=request.resource.type,
                    action=request.action,
                    decision=decision.decision.value,
                    reason=decision.reason,
                    metadata={
                        "policy_id": decision.policy_id,
                        "policy_version": decision.policy_version,
                        "opa_latency_ms": round(result.latency_ms, 2),
                    },
                )
            )
            # Phase 5. When an approval was part of the input, this evaluation
            # IS the re-evaluation -- the second time the PDP was asked about
            # this action, now with a human decision in hand. Recorded as its
            # own event because it is the evidence that an approval did not
            # become an ALLOW on its own.
            approval = (context.approval or {}) if context is not None else {}
            if approval.get("present"):
                await self.audit.record(
                    Event(
                        EventType.AUTHORIZATION_REEVALUATED,
                        agent_did=request.subject.did,
                        request_id=request.request_id,
                        resource=request.resource.type,
                        action=request.action,
                        decision=decision.decision.value,
                        reason=decision.reason,
                        metadata={
                            "approval_id": approval.get("approval_id"),
                            "approval_status": approval.get("status"),
                            "approval_valid": approval.get("valid"),
                            "approval_reason": approval.get("reason"),
                            "approver": (approval.get("approver") or {}).get("username"),
                            "policy": decision.policy_ref,
                            "resource_id": request.resource.id,
                        },
                    )
                )
            await self._record(request, decision, context)
            await self._emit(request, decision)
        return decision

    # --- control plane (Phase 4.5) ----------------------------------------
    async def decide_control_plane(
        self,
        *,
        principal: dict[str, Any],
        operation: str,
        target: dict[str, Any],
        request_id: str,
        classification: str | None = None,
        record: bool = True,
    ) -> "ControlPlaneDecision":
        """May this AUTHENTICATED principal perform this control-plane operation?

        `principal` arrives already authenticated -- the authenticator proved
        control of that DID against the published DID Document, and the roles
        in it come from the principal registry. This method never re-checks a
        signature and never reads a role from the caller's request.

        Fail-closed, identically to the data plane: OPA unreachable, no
        decision loaded, or an unrecognised verdict all produce DENY.
        """
        from app.controlplane.contracts import (
            ControlPlaneDecision,
            ControlPlaneDecisionValue,
        )

        input_document = {
            "request_id": request_id,
            "principal": principal,
            "operation": operation,
            "target": target,
        }
        started = time.perf_counter()
        try:
            result = await self.opa.evaluate(
                input_document,
                decision_url=self.settings.control_plane_decision_url,
            )
        except OPAUnavailableError as exc:
            elapsed = (time.perf_counter() - started) * 1000
            log.error("control_plane_opa_unavailable", request_id=request_id,
                      operation=operation, error=str(exc))
            decision = ControlPlaneDecision.denied(
                request_id, operation,
                "CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE",
                principal_did=principal.get("did"),
                principal_type=principal.get("type"),
                target=target.get("id"), classification=classification,
                authorization_ms=elapsed,
                evaluation={"detail": "policy engine unavailable; failing closed"},
            )
            if record:
                await self.audit.record(
                    Event(
                        EventType.AUTHORIZATION_UNAVAILABLE,
                        agent_did=principal.get("did"),
                        request_id=request_id,
                        resource="control_plane",
                        action=operation,
                        decision="DENY",
                        reason=decision.reason,
                        metadata={"detail": "OPA unreachable; control-plane "
                                            "request refused"},
                    )
                )
            return decision

        elapsed = (time.perf_counter() - started) * 1000
        document = result.document
        raw = document.get("decision")
        if raw not in {v.value for v in ControlPlaneDecisionValue}:
            # A control-plane policy cannot invent a verdict -- and notably
            # cannot return HUMAN_APPROVAL_REQUIRED, which has no meaning here
            # because no approval flow exists to satisfy it.
            log.error("control_plane_invalid_decision", request_id=request_id, value=raw)
            return ControlPlaneDecision.denied(
                request_id, operation, "CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE",
                principal_did=principal.get("did"),
                principal_type=principal.get("type"),
                target=target.get("id"), classification=classification,
                authorization_ms=elapsed,
                evaluation={"detail": f"policy returned an unrecognised "
                                      f"decision {raw!r}"},
            )

        decision = ControlPlaneDecision(
            decision=ControlPlaneDecisionValue(raw),
            request_id=request_id,
            reason=document.get("reason") or "NO_MATCHING_CONTROL_PLANE_POLICY",
            operation=operation,
            policy_id=document.get("policy_id"),
            policy_version=document.get("policy_version"),
            principal_did=principal.get("did"),
            principal_type=principal.get("type"),
            target=target.get("id"),
            classification=classification,
            authorization_ms=elapsed,
            evaluation={
                "opa_document": document,
                "policy_engine": {"url": self.opa.base_url, "engine": "OPA"},
                "principal": principal,
                "target": target,
            },
        )
        if record:
            await self.audit.record(
                Event(
                    EventType.OPA_DECISION,
                    agent_did=principal.get("did"),
                    request_id=request_id,
                    resource="control_plane",
                    action=operation,
                    decision=decision.decision.value,
                    reason=decision.reason,
                    metadata={
                        "plane": "control",
                        "policy_id": decision.policy_id,
                        "policy_version": decision.policy_version,
                        "opa_latency_ms": round(result.latency_ms, 2),
                    },
                )
            )
        return decision

    # --- input document ---------------------------------------------------
    def _build_input(
        self, request: AuthorizationRequest, context: Any
    ) -> dict[str, Any]:
        """The exact document Rego evaluates.

        `context` is the caller's, with self-asserted verdicts stripped. `pip`
        is what the system independently established. Policy is written against
        `pip`; `input.context` exists for rules that legitimately need caller
        metadata and is never sufficient on its own.
        """
        return {
            "request_id": request.request_id,
            "subject": request.subject.to_dict(),
            "action": request.action,
            "resource": request.resource.to_dict(),
            "purpose": request.purpose,
            "context": request.strip_decision_claims(),
            "session": request.session,
            "pip": context.to_dict(),
        }

    # --- persistence and events -------------------------------------------
    async def _record(
        self, request: AuthorizationRequest, decision: AuthorizationDecision, context: Any
    ) -> None:
        self.session.add(
            AuthorizationDecisionRecord(
                request_id=decision.request_id,
                subject_did=request.subject.did,
                subject_type=request.subject.type,
                action=request.action,
                resource_type=request.resource.type,
                resource_id=request.resource.id,
                purpose=request.purpose,
                decision=decision.decision.value,
                reason=decision.reason,
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                latency_ms=decision.total_latency_ms,
                stages=[s.to_dict() for s in decision.stages],
                # The context the decision was actually made on. No secrets:
                # credential CLAIMS and verdicts only, never key material,
                # never a proof value.
                context_snapshot=context.to_dict() if context is not None else {},
                decided_at=decision.decided_at,
            )
        )
        await self.session.flush()

    async def _emit(
        self, request: AuthorizationRequest, decision: AuthorizationDecision
    ) -> None:
        event_type = {
            Decision.ALLOW: EventType.POLICY_ALLOW,
            Decision.DENY: EventType.POLICY_DENY,
            Decision.HUMAN_APPROVAL_REQUIRED: EventType.POLICY_HUMAN_APPROVAL_REQUIRED,
        }[decision.decision]
        await self.audit.record(
            Event(
                EventType.PDP_EVALUATION,
                agent_did=request.subject.did,
                request_id=request.request_id,
                resource=request.resource.type,
                action=request.action,
                decision=decision.decision.value,
                reason=decision.reason,
                metadata={
                    "policy_id": decision.policy_id,
                    "policy_version": decision.policy_version,
                    "resource_id": request.resource.id,
                    "purpose": request.purpose,
                    "latency_ms": decision.total_latency_ms,
                    "stages": [s.to_dict() for s in decision.stages],
                },
            )
        )
        await self.audit.record(
            Event(
                event_type,
                agent_did=request.subject.did,
                request_id=request.request_id,
                resource=request.resource.type,
                action=request.action,
                decision=decision.decision.value,
                reason=decision.reason,
                metadata={
                    "policy": decision.policy_ref,
                    "resource_id": request.resource.id,
                    "purpose": request.purpose,
                },
            )
        )
