"""The control-plane guard: the FastAPI dependency that enforces the sequence.

    CONTROL-PLANE REQUEST
            |
            v
    AUTHENTICATION      ControlPlaneAuthenticator   -> WHO is calling?
            |
            v
    AUTHORIZATION       PDP -> OPA -> Rego          -> MAY they do this?
            |
            v
    OPERATION           the route handler runs

The route handler only ever runs on the far side of both. There is no branch
here that lets a request through on an error, a timeout, an unreachable policy
engine or an unrecognised operation: every one of those raises.

WHAT THIS FILE DELIBERATELY DOES NOT CONTAIN: any rule about who may do what.
Not one. The guard collects an authenticated principal and asks the PDP. If a
privilege check ever appears in this file, policy has escaped OPA into
middleware where nobody reviews it -- and the audit trail would stop being able
to name the policy that decided.

DURABILITY OF REFUSALS. A rejected request raises, and FastAPI's session
dependency rolls back on an exception -- which would erase the record of the
refusal, exactly when it matters most. So the proof row and its audit event are
COMMITTED before the exception is raised. An attacker cannot make their own
failed attempts disappear by ensuring the request ends in an error.
"""
from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import HTTPException, Request

from app.api.deps import KeyStoreDep, SessionDep
from app.audit.service import AuditService
from app.authorization.pdp import PolicyDecisionPoint
from app.controlplane.authenticator import (
    ControlPlaneAuthenticator,
    ControlPlanePrincipalView,
)
from app.controlplane.contracts import (
    ControlPlaneClass,
    ControlPlaneDecision,
    ControlPlaneOperation,
    new_request_id,
)
from app.controlplane.proof import AuthReason
from app.core.config import get_settings
from app.core.logging import get_logger
from app.monitoring.events import Event, EventType

log = get_logger("controlplane.guard")

# operation name -> what it is and how sensitive. The catalogue is data, so the
# inventory in docs/CONTROL_PLANE_SECURITY.md can be checked against the code
# by a test rather than by a reader's memory.
OPERATIONS: dict[str, ControlPlaneOperation] = {
    "ans_heartbeat": ControlPlaneOperation(
        "ans_heartbeat", ControlPlaneClass.AUTHENTICATED_MUTATION,
        "Report liveness for a registered agent.", "ans_registration",
    ),
    "ans_deregister": ControlPlaneOperation(
        "ans_deregister", ControlPlaneClass.AUTHORIZED_MUTATION,
        "Remove an agent from discovery.", "ans_registration",
    ),
    "ans_sweep": ControlPlaneOperation(
        "ans_sweep", ControlPlaneClass.AUTHORIZED_MUTATION,
        "Force a liveness sweep across the whole registry.", "ans_registry",
    ),
    "pdp_query": ControlPlaneOperation(
        "pdp_query", ControlPlaneClass.AUTHENTICATED_MUTATION,
        "Ask the PDP for an authorization decision about a subject.", "subject",
    ),
    "aem_enforce": ControlPlaneOperation(
        "aem_enforce", ControlPlaneClass.AUTHORIZED_MUTATION,
        "Attempt a protected tool call through the enforcement boundary.", "subject",
    ),
    "policy_reload": ControlPlaneOperation(
        "policy_reload", ControlPlaneClass.HIGH_RISK_ADMINISTRATION,
        "Push the declared policy set into the engine.", "policy_set",
    ),
    "policy_activate": ControlPlaneOperation(
        "policy_activate", ControlPlaneClass.HIGH_RISK_ADMINISTRATION,
        "Load a policy into the engine.", "policy",
    ),
    "policy_deactivate": ControlPlaneOperation(
        "policy_deactivate", ControlPlaneClass.HIGH_RISK_ADMINISTRATION,
        "Remove a policy from the engine.", "policy",
    ),
    "identity_sign": ControlPlaneOperation(
        "identity_sign", ControlPlaneClass.HIGH_RISK_ADMINISTRATION,
        "Sign an arbitrary message with a registry-custodied agent key.", "identity",
    ),

    # --- Phase 5: HITL, and the S-7 closure ------------------------------
    "approval_decide": ControlPlaneOperation(
        "approval_decide", ControlPlaneClass.AUTHORIZED_MUTATION,
        "Approve or reject a specific agent action as a human.", "approval",
    ),
    "approval_view": ControlPlaneOperation(
        "approval_view", ControlPlaneClass.AUTHENTICATED_READ,
        "Read a pending approval, including what the agent wants to do.", "approval",
    ),
    "approval_cancel": ControlPlaneOperation(
        "approval_cancel", ControlPlaneClass.AUTHORIZED_MUTATION,
        "Withdraw a pending approval request.", "approval",
    ),
    # S-7. These were open to anyone who could reach the port until Phase 5.
    # Unauthenticated credential issuance was the sharpest of them: a caller
    # could mint itself a capability credential and receive ALLOW from the PDP.
    "agent_create": ControlPlaneOperation(
        "agent_create", ControlPlaneClass.HIGH_RISK_ADMINISTRATION,
        "Create a new agent identity, with a DID and key material.", "identity",
    ),
    "agent_status_change": ControlPlaneOperation(
        "agent_status_change", ControlPlaneClass.HIGH_RISK_ADMINISTRATION,
        "Suspend, reactivate or terminate an agent identity.", "identity",
    ),
    "credential_issue": ControlPlaneOperation(
        "credential_issue", ControlPlaneClass.HIGH_RISK_ADMINISTRATION,
        "Mint a verifiable credential from an issuing authority.", "credential",
    ),
    "credential_revoke": ControlPlaneOperation(
        "credential_revoke", ControlPlaneClass.AUTHORIZED_MUTATION,
        "Revoke a credential, making it invalid everywhere at once.", "credential",
    ),
    "credential_present": ControlPlaneOperation(
        "credential_present", ControlPlaneClass.AUTHORIZED_MUTATION,
        "Produce a holder proof using a registry-custodied agent key.", "credential",
    ),
    "audit_ingest": ControlPlaneOperation(
        "audit_ingest", ControlPlaneClass.AUTHENTICATED_MUTATION,
        "Write an event into the audit trail from outside this process.", "audit",
    ),

    # --- Phase 5.5 --------------------------------------------------------
    # Changing which key attests that a human approved something. HIGH RISK for
    # the obvious reason: whoever controls the signing key controls what an
    # approval means. Requires a machine administrator with a key of its own --
    # no human role reaches it.
    "approval_key_rotate": ControlPlaneOperation(
        "approval_key_rotate", ControlPlaneClass.HIGH_RISK_ADMINISTRATION,
        "Retire the approval authority's signing key and start signing with a "
        "new one.", "approval_authority",
    ),
    # Amending a loan amount. Authorized because the amount is an
    # AUTHORIZATION INPUT: whoever can change it can change which band a
    # request falls in, and therefore how many humans it needs. No human role
    # reaches it -- an officer who could amend an amount and then approve it
    # would defeat the amount policy and maker-checker in one move.
    "loan_amend": ControlPlaneOperation(
        "loan_amend", ControlPlaneClass.AUTHORIZED_MUTATION,
        "Change the amount on a loan application.", "loan_application",
    ),

    # --- Phase 6: JIT temporary access -----------------------------------
    # Asking for a mandate. AUTHENTICATED rather than AUTHORIZED because the
    # real gate is not here: issuance runs the FULL data-plane PDP evaluation
    # for the action being mandated, so an agent can only ever obtain a mandate
    # for something it could already do. This operation answers the narrower
    # question of whether the caller may use the endpoint at all -- and an
    # agent may ask about ITSELF, exactly as `pdp_query` already permits.
    "jit_request": ControlPlaneOperation(
        "jit_request", ControlPlaneClass.AUTHENTICATED_MUTATION,
        "Ask for a time-bounded, use-bounded mandate for an action the PDP "
        "already permits.", "subject",
    ),
    # Killing a mandate early. AUTHORIZED, and deliberately asymmetric with
    # issuance: containing a live temporary authority is an operator action,
    # and an agent must not be the only thing that can end its own mandate.
    # This is also the integration point Phase 10 and Phase 12 will call.
    "jit_revoke": ControlPlaneOperation(
        "jit_revoke", ControlPlaneClass.AUTHORIZED_MUTATION,
        "Revoke a live JIT mandate before it expires.", "jit_grant",
    ),
    # Changing the key that attests what a mandate means. HIGH RISK for the
    # same reason approval_key_rotate is: whoever controls the signing key
    # controls what a mandate is.
    "jit_key_rotate": ControlPlaneOperation(
        "jit_key_rotate", ControlPlaneClass.HIGH_RISK_ADMINISTRATION,
        "Retire the JIT authority's signing key and start signing with a new "
        "one.", "jit_authority",
    ),

    # --- Phase 7: secure A2A transactions --------------------------------
    # Submitting an inbound transaction envelope. AUTHENTICATED rather than
    # AUTHORIZED because the real gate is not here: the envelope is verified
    # and then the FULL data-plane PDP evaluation runs with the SENDER as
    # subject, so nothing is permitted that the sender could not do itself.
    #
    # THE TARGET IS THE ENVELOPE'S `receiverDid`, and that is what makes this
    # operation carry the receiver binding. `agent_self.rego` requires
    # `target.id == principal.did`, so an agent may submit only an envelope
    # ADDRESSED TO ITSELF -- and the replay-toward-another-receiver attack is
    # refused by a rule that already existed.
    #
    # NO ADMINISTRATOR HOLDS THIS OPERATION (see administration.rego). An
    # administrator with it would be a privileged bypass of exactly that
    # binding.
    "a2a_submit": ControlPlaneOperation(
        "a2a_submit", ControlPlaneClass.AUTHENTICATED_MUTATION,
        "Submit a signed agent-to-agent transaction addressed to yourself.",
        "a2a_transaction",
    ),
    # Housekeeping over the transaction ledger: sweeping expired
    # transactions. AUTHORIZED, and deliberately asymmetric with submission,
    # exactly as jit_revoke is with jit_request.
    "a2a_administer": ControlPlaneOperation(
        "a2a_administer", ControlPlaneClass.AUTHORIZED_MUTATION,
        "Administer the A2A transaction ledger.", "a2a_ledger",
    ),
}

# A resolver returns either a bare id, or a dict of target attributes when
# policy needs more than an identifier. "May this human approve THIS?" cannot
# be answered from an approval id alone -- the ACTION being approved is what
# separates a loan officer from an IAM administrator.
TargetResolver = Callable[
    [Request, Any], "Awaitable[str | dict | None] | str | dict | None"
]


async def _body_target(request: Request, body: Any, *path: str) -> str | None:
    """Pull a target DID out of a JSON body by key path. Never raises."""
    node = body
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node if isinstance(node, str) else None


def body_key(*path: str) -> TargetResolver:
    async def resolve(request: Request, body: Any) -> str | None:
        return await _body_target(request, body, *path)
    return resolve


def attributes(**resolvers: TargetResolver) -> TargetResolver:
    """Combine resolvers into a target OBJECT for policy.

        attributes(id=path_param("approval_id"), action=approval_action)

    Every value still comes from a resolver, so nothing a caller puts in the
    request body reaches policy unless a resolver deliberately reads it -- and
    the ones that do read server-held state, not caller claims.
    """
    async def resolve(request: Request, body: Any) -> dict:
        target: dict[str, Any] = {}
        for name, resolver in resolvers.items():
            produced = resolver(request, body)
            if hasattr(produced, "__await__"):
                produced = await produced
            target[name] = produced
        return target
    return resolve


def path_param(name: str) -> TargetResolver:
    def resolve(request: Request, body: Any) -> str | None:
        value = request.path_params.get(name)
        return value if isinstance(value, str) else None
    return resolve


def fixed(value: str) -> TargetResolver:
    def resolve(request: Request, body: Any) -> str | None:
        return value
    return resolve


class _Guard:
    """The enforcement itself. Built by `ControlPlaneGuard()` below.

    Not used as a FastAPI dependency directly: FastAPI resolves a dependency's
    type hints against `call.__globals__`, which a class INSTANCE does not
    have. With `from __future__ import annotations` in force every annotation
    here is a string, so FastAPI could not resolve `SessionDep` and silently
    treated the session and keystore as query parameters -- every protected
    route answered 422 instead of authenticating. Hence the function factory.
    """

    def __init__(self, operation: str, *, target: TargetResolver) -> None:
        if operation not in OPERATIONS:
            # A route protected with an operation the catalogue does not
            # declare would be unreviewable, and Rego would deny it at runtime
            # with a confusing reason. Fail at import time instead.
            raise KeyError(
                f"Unknown control-plane operation {operation!r}. Declare it in "
                f"OPERATIONS (and give it a rule in policies/control_plane/) "
                f"before protecting a route with it."
            )
        self.operation = OPERATIONS[operation]
        self.target = target

    async def enforce(
        self, request: Request, session: SessionDep, keystore: KeyStoreDep
    ) -> ControlPlanePrincipalView:
        # `session` comes through normal dependency injection, so the guard and
        # the route handler share ONE transaction and one dependency-override
        # story in tests. Resolving it by hand would have meant a second
        # session, a second transaction, and a guard that could see a different
        # database state from the operation it is guarding.
        settings = get_settings()
        request_id = new_request_id()
        # Target resolvers may need to read server-side state (an approval's
        # ACTION lives in the database, not in the request). They get the
        # guard's own session, so they see exactly what the route will.
        request.state.control_plane_session = session
        raw_body = await request.body()
        try:
            parsed = json.loads(raw_body) if raw_body else None
        except ValueError:
            parsed = None

        resolved = self.target(request, parsed)
        resolved = await resolved if hasattr(resolved, "__await__") else resolved
        if isinstance(resolved, dict):
            target_attributes = {"type": self.operation.target_type, **resolved}
            target_id = target_attributes.get("id")
        else:
            target_attributes = {"type": self.operation.target_type, "id": resolved}
            target_id = resolved
        target_id = target_id if isinstance(target_id, str) else None

        # --- authentication ------------------------------------------------
        authenticator = ControlPlaneAuthenticator(session, settings)
        auth = await authenticator.authenticate(
            headers=dict(request.headers),
            method=request.method,
            path=request.url.path,
            body=raw_body,
            operation=self.operation.name,
            target=target_id,
            source_ip=request.client.host if request.client else None,
        )
        if not auth.authenticated:
            if auth.reason == AuthReason.NONCE_REPLAYED:
                await AuditService(session).record(
                    Event(
                        EventType.CONTROL_PLANE_REPLAY_DETECTED,
                        resource="control_plane", action=self.operation.name,
                        decision="REJECTED", reason=auth.reason,
                        metadata={"path": request.url.path, "target": target_id},
                    )
                )
            await self._operation_rejected(session, auth.reason, target_id, request_id)
            await session.commit()          # the refusal must survive the raise
            raise HTTPException(
                status_code=auth.http_status,
                detail={
                    "error": "CONTROL_PLANE_AUTHENTICATION_FAILED"
                             if auth.http_status == 401
                             else "CONTROL_PLANE_REQUEST_REFUSED",
                    "reason": auth.reason,
                    "detail": auth.detail,
                    "operation": self.operation.name,
                    "request_id": request_id,
                    "checks": auth.checks,
                },
            )

        # --- authorization -------------------------------------------------
        principal = auth.principal
        assert principal is not None                       # invariant of `authenticated`
        pdp = PolicyDecisionPoint(session, keystore, settings)
        decision = await pdp.decide_control_plane(
            principal=principal.to_dict(),
            operation=self.operation.name,
            target=target_attributes,
            request_id=request_id,
            classification=self.operation.classification.value,
        )
        decision.authentication_ms = auth.latency_ms

        if not decision.allowed:
            await self._emit(session, decision, allowed=False)
            await self._operation_rejected(
                session, decision.reason, target_id, request_id
            )
            await session.commit()
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "CONTROL_PLANE_REQUEST_REFUSED",
                    "reason": decision.reason,
                    "operation": self.operation.name,
                    "principal": principal.did,
                    "policy": decision.policy_ref,
                    "request_id": request_id,
                    "classification": self.operation.classification.value,
                },
            )

        await self._emit(session, decision, allowed=True)
        # Committing here makes the nonce genuinely spent, whatever the
        # operation does next. A proof is consumed by being PRESENTED, not by
        # the operation succeeding: releasing it when the handler errors would
        # hand an attacker a reusable proof.
        await session.commit()
        request.state.control_plane_principal = principal
        request.state.control_plane_decision = decision
        return principal

    # --- helpers ----------------------------------------------------------
    async def _emit(
        self, session, decision: ControlPlaneDecision, *, allowed: bool
    ) -> None:
        await AuditService(session).record(
            Event(
                EventType.CONTROL_PLANE_AUTHORIZED if allowed
                else EventType.CONTROL_PLANE_DENIED,
                agent_did=decision.principal_did,
                request_id=decision.request_id,
                resource="control_plane",
                action=decision.operation,
                decision=decision.decision.value,
                reason=decision.reason,
                metadata={
                    "policy": decision.policy_ref,
                    "principal_type": decision.principal_type,
                    "target": decision.target,
                    "classification": decision.classification,
                    "authentication_ms": round(decision.authentication_ms, 2),
                    "authorization_ms": round(decision.authorization_ms, 2),
                },
            )
        )

    async def _operation_rejected(
        self, session, reason: str, target: str | None, request_id: str
    ) -> None:
        """Emit the operation-specific refusal event named in the spec.

        Generic control-plane events are correlated by `operation`, but an
        operator watching the ANS wants ANS_HEARTBEAT_REJECTED in the stream,
        not a filter expression.
        """
        specific = {
            "ans_heartbeat": EventType.ANS_HEARTBEAT_REJECTED,
            "ans_deregister": EventType.ANS_DEREGISTRATION_REJECTED,
            "pdp_query": EventType.AUTHORIZATION_API_REJECTED,
            "aem_enforce": EventType.AUTHORIZATION_API_REJECTED,
        }.get(self.operation.name)
        if specific is None:
            return
        await AuditService(session).record(
            Event(specific, agent_did=target, request_id=request_id,
                  resource="control_plane", action=self.operation.name,
                  decision="REJECTED", reason=reason,
                  metadata={"target": target,
                            "classification": self.operation.classification.value})
        )


def ControlPlaneGuard(  # noqa: N802 - reads as a type at the call site
    operation: str, *, target: TargetResolver
):
    """Build the FastAPI dependency that protects one route.

        @router.post("/heartbeat", dependencies=[Depends(
            ControlPlaneGuard("ans_heartbeat", target=body_key("did")))])

    A plain async function rather than a callable object, so FastAPI can
    resolve `SessionDep` and `KeyStoreDep` from this module's globals and the
    guard shares the request's session with the route it guards.
    """
    guard = _Guard(operation, target=target)

    async def dependency(
        request: Request, session: SessionDep, keystore: KeyStoreDep
    ) -> ControlPlanePrincipalView:
        return await guard.enforce(request, session, keystore)

    dependency.__name__ = f"control_plane_guard_{operation}"
    dependency.guard = guard          # exposed so tests can read the catalogue
    return dependency
