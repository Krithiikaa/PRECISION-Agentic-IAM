"""Event taxonomy and in-process event bus.

The full event catalogue from the architecture is declared here so every phase
uses the same names. Only the events a phase actually implements are ever
emitted -- nothing publishes an event for a mechanism that does not exist yet.

Emitted as of Phase 1: the AGENT_* / DID_* / KEY_* / SIGNATURE_* families.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class EventType:
    # --- Phase 1: identity lifecycle (implemented) ---
    AGENT_CREATED = "AGENT_CREATED"
    AGENT_ACTIVATED = "AGENT_ACTIVATED"
    AGENT_SUSPENDED = "AGENT_SUSPENDED"
    AGENT_TERMINATED = "AGENT_TERMINATED"
    DID_ASSIGNED = "DID_ASSIGNED"
    DID_DOCUMENT_PUBLISHED = "DID_DOCUMENT_PUBLISHED"
    KEY_GENERATED = "KEY_GENERATED"
    SIGNATURE_CREATED = "SIGNATURE_CREATED"
    SIGNATURE_VERIFIED = "SIGNATURE_VERIFIED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    AGENT_TASK_STARTED = "AGENT_TASK_STARTED"
    AGENT_TASK_COMPLETED = "AGENT_TASK_COMPLETED"
    AGENT_TASK_FAILED = "AGENT_TASK_FAILED"
    LLM_CALL = "LLM_CALL"

    # --- Phase 2: verifiable credentials (implemented) ---
    CREDENTIAL_ISSUED = "CREDENTIAL_ISSUED"
    CREDENTIAL_STORED = "CREDENTIAL_STORED"
    CREDENTIAL_PRESENTED = "CREDENTIAL_PRESENTED"
    CREDENTIAL_VERIFICATION_STARTED = "CREDENTIAL_VERIFICATION_STARTED"
    CREDENTIAL_VERIFIED = "CREDENTIAL_VERIFIED"
    CREDENTIAL_VERIFICATION_FAILED = "CREDENTIAL_VERIFICATION_FAILED"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    CREDENTIAL_REVOKED_REJECTED = "CREDENTIAL_REVOKED_REJECTED"
    CREDENTIAL_SUBJECT_MISMATCH = "CREDENTIAL_SUBJECT_MISMATCH"
    CREDENTIAL_SIGNATURE_INVALID = "CREDENTIAL_SIGNATURE_INVALID"
    CREDENTIAL_ISSUER_UNKNOWN = "CREDENTIAL_ISSUER_UNKNOWN"
    PRESENTATION_VERIFIED = "PRESENTATION_VERIFIED"
    PRESENTATION_VERIFICATION_FAILED = "PRESENTATION_VERIFICATION_FAILED"
    ISSUER_REGISTERED = "ISSUER_REGISTERED"

    # --- Phase 3: agent naming service (implemented) ---
    ANS_AGENT_REGISTERED = "ANS_AGENT_REGISTERED"
    ANS_AGENT_UPDATED = "ANS_AGENT_UPDATED"
    ANS_REGISTRATION_REJECTED = "ANS_REGISTRATION_REJECTED"
    ANS_SIGNATURE_INVALID = "ANS_SIGNATURE_INVALID"
    ANS_HEARTBEAT_RECEIVED = "ANS_HEARTBEAT_RECEIVED"
    ANS_AGENT_STALE = "ANS_AGENT_STALE"
    ANS_AGENT_OFFLINE = "ANS_AGENT_OFFLINE"
    ANS_AGENT_REVOKED = "ANS_AGENT_REVOKED"
    ANS_AGENT_RESOLVED = "ANS_AGENT_RESOLVED"
    ANS_DISCOVERY_STARTED = "ANS_DISCOVERY_STARTED"
    ANS_DISCOVERY_MATCH = "ANS_DISCOVERY_MATCH"
    ANS_DISCOVERY_REJECTED = "ANS_DISCOVERY_REJECTED"
    ANS_DISCOVERY_NO_MATCH = "ANS_DISCOVERY_NO_MATCH"
    ANS_AGENT_SELECTED = "ANS_AGENT_SELECTED"
    COORDINATOR_CAPABILITY_RESOLVED = "COORDINATOR_CAPABILITY_RESOLVED"
    COORDINATOR_DISCOVERY_COMPLETE = "COORDINATOR_DISCOVERY_COMPLETE"
    COORDINATOR_DISCOVERY_FAILED = "COORDINATOR_DISCOVERY_FAILED"

    # --- Phase 4: authorization. EMITTED. ---
    AUTHORIZATION_REQUESTED = "AUTHORIZATION_REQUESTED"
    PIP_CONTEXT_COLLECTED = "PIP_CONTEXT_COLLECTED"
    PDP_EVALUATION = "PDP_EVALUATION"
    OPA_DECISION = "OPA_DECISION"
    POLICY_ALLOW = "POLICY_ALLOW"
    POLICY_DENY = "POLICY_DENY"
    # The decision value only. Phase 4 does NOT implement the approval flow,
    # an approval artifact, or a human principal -- those are HITL.
    POLICY_HUMAN_APPROVAL_REQUIRED = "POLICY_HUMAN_APPROVAL_REQUIRED"
    AUTHORIZATION_UNAVAILABLE = "AUTHORIZATION_UNAVAILABLE"
    AEM_INTERCEPT = "AEM_INTERCEPT"
    AEM_ALLOWED = "AEM_ALLOWED"
    AEM_BLOCKED = "AEM_BLOCKED"
    AEM_BYPASS_ATTEMPT = "AEM_BYPASS_ATTEMPT"
    POLICY_LOADED = "POLICY_LOADED"
    # Policy CONFIGURATION -- the numbers a rule reads. A separate event from
    # POLICY_LOADED because thresholds and rules change for different reasons
    # and an auditor needs to see which one moved.
    POLICY_DATA_LOADED = "POLICY_DATA_LOADED"
    POLICY_ACTIVATED = "POLICY_ACTIVATED"
    POLICY_DEACTIVATED = "POLICY_DEACTIVATED"

    # --- Phase 4.5: control-plane hardening. EMITTED. ---
    # Authentication: did the caller prove control of the identity it claimed?
    CONTROL_PLANE_AUTHENTICATED = "CONTROL_PLANE_AUTHENTICATED"
    CONTROL_PLANE_REJECTED = "CONTROL_PLANE_REJECTED"
    # Authorization: was the proven principal permitted this operation? A
    # separate pair of events on purpose -- "we could not tell who you are" and
    # "we know exactly who you are and you may not do that" are different
    # incidents, and an operator must be able to distinguish them at a glance.
    CONTROL_PLANE_AUTHORIZED = "CONTROL_PLANE_AUTHORIZED"
    CONTROL_PLANE_DENIED = "CONTROL_PLANE_DENIED"
    CONTROL_PLANE_PRINCIPAL_REGISTERED = "CONTROL_PLANE_PRINCIPAL_REGISTERED"
    # Named separately from CONTROL_PLANE_REJECTED because a replay is
    # evidence of a captured proof, not of a misconfigured client.
    CONTROL_PLANE_REPLAY_DETECTED = "CONTROL_PLANE_REPLAY_DETECTED"
    ANS_HEARTBEAT_ACCEPTED = "ANS_HEARTBEAT_ACCEPTED"
    ANS_HEARTBEAT_REJECTED = "ANS_HEARTBEAT_REJECTED"
    ANS_DEREGISTRATION_ACCEPTED = "ANS_DEREGISTRATION_ACCEPTED"
    ANS_DEREGISTRATION_REJECTED = "ANS_DEREGISTRATION_REJECTED"
    AUTHORIZATION_API_REJECTED = "AUTHORIZATION_API_REJECTED"

    # --- Phase 5: human-in-the-loop. EMITTED. ---
    # Authentication and approval are separate events on purpose: "Keycloak
    # says this is Priya" and "Priya approved this loan" are different facts,
    # and an auditor must never have to infer the second from the first.
    HUMAN_AUTHENTICATED = "HUMAN_AUTHENTICATED"
    HUMAN_AUTHENTICATION_FAILED = "HUMAN_AUTHENTICATION_FAILED"
    HUMAN_PRINCIPAL_REGISTERED = "HUMAN_PRINCIPAL_REGISTERED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    # Evidence the decision was INFORMED: an approval nobody opened is a very
    # different thing from one somebody read.
    APPROVAL_VIEWED = "APPROVAL_VIEWED"
    APPROVAL_APPROVED = "APPROVAL_APPROVED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_CANCELLED = "APPROVAL_CANCELLED"
    APPROVAL_CONSUMED = "APPROVAL_CONSUMED"
    APPROVAL_REPLAY_REJECTED = "APPROVAL_REPLAY_REJECTED"
    # The PDP asked again, WITH the approval. This is the event that proves a
    # human decision did not become an ALLOW on its own.
    AUTHORIZATION_REEVALUATED = "AUTHORIZATION_REEVALUATED"

    # --- Phase 5.5: HITL hardening. EMITTED. ---
    # One person's sign-off. Distinct from APPROVAL_APPROVED, which fires when
    # the approval as a whole becomes usable: under dual control the first
    # sign-off changes nothing about whether the action may proceed, and an
    # audit trail that could not tell them apart could not answer "who was the
    # second person?".
    APPROVAL_SIGNOFF_RECORDED = "APPROVAL_SIGNOFF_RECORDED"
    # The same human reaching for the second approval. Its own event because it
    # is an attempt to defeat two-person control, not a validation error.
    APPROVAL_DUPLICATE_APPROVER_REJECTED = "APPROVAL_DUPLICATE_APPROVER_REJECTED"
    # The person who submitted the application trying to sign it off.
    APPROVAL_SELF_APPROVAL_REJECTED = "APPROVAL_SELF_APPROVAL_REJECTED"
    # Every required sign-off is in, and the artifact was signed.
    APPROVAL_DUAL_CONTROL_SATISFIED = "APPROVAL_DUAL_CONTROL_SATISFIED"
    # Policy escalated, and said how many people it wants. Carries the tier so
    # "why was this sent to two humans?" is answerable from the trail alone.
    POLICY_ESCALATED = "POLICY_ESCALATED"
    # Signing-key lifecycle. Rotation keeps history verifiable; revocation does
    # not, and the two are never the same event.
    APPROVAL_KEY_ROTATED = "APPROVAL_KEY_ROTATED"
    APPROVAL_KEY_REVOKED = "APPROVAL_KEY_REVOKED"
    # A loan amount changed. Its own event because it is the trigger for the
    # binding mismatch an operator will be looking at a moment later, and
    # correlating "why did this approval stop applying?" from a generic
    # mutation record would be slow at exactly the wrong time.
    LOAN_AMOUNT_AMENDED = "LOAN_AMOUNT_AMENDED"

    # --- Phase 6: JIT temporary access (implemented) ---
    # A grant is a MANDATE, not a permission: it carries an expensive
    # precondition forward within a bounded window, and every use is still
    # decided by the PDP. These events exist so that whole arc -- asked for,
    # issued, each use, and how it ended -- is reconstructible from the trail
    # by `grant_id`, which is what makes a temporary authority auditable at all.
    JIT_REQUESTED = "JIT_REQUESTED"
    JIT_DENIED = "JIT_DENIED"
    JIT_ISSUED = "JIT_ISSUED"
    JIT_USED = "JIT_USED"
    # A grant presented after it was spent, expired or revoked. Its own event
    # rather than a generic denial, for the reason APPROVAL_REPLAY_REJECTED is:
    # an operator filtering for reuse of a dead mandate should not have to
    # reconstruct it from decision rows.
    JIT_REPLAY_BLOCKED = "JIT_REPLAY_BLOCKED"
    JIT_EXPIRED = "JIT_EXPIRED"
    JIT_EXHAUSTED = "JIT_EXHAUSTED"
    JIT_REVOKED = "JIT_REVOKED"
    JIT_KEY_ROTATED = "JIT_KEY_ROTATED"
    JIT_KEY_REVOKED = "JIT_KEY_REVOKED"

    # --- Phase 7: secure A2A transactions (implemented) ---
    # A transaction is a signed INSTRUCTION, not a permission: verifying it
    # establishes who sent it and that it has not changed, and the PDP is then
    # asked exactly as it would be for any other action. These events exist so
    # that whole arc -- received, verified, decided, escalated, executed, or
    # refused -- is reconstructible from the trail by
    # `request_id = a2a-{transaction_id}`, which is what makes an
    # agent-to-agent instruction auditable at all.
    #
    # DELIBERATELY ABSENT: A2A-specific authorization events. The PDP already
    # emits AUTHORIZATION_REQUESTED, PIP_CONTEXT_COLLECTED, OPA_DECISION,
    # PDP_EVALUATION and POLICY_ALLOW/POLICY_DENY, all carrying that same
    # request_id. Duplicating them would create two records of one decision
    # that can disagree.
    A2A_REQUEST = "A2A_REQUEST"
    A2A_SIGNATURE_VERIFIED = "A2A_SIGNATURE_VERIFIED"
    A2A_REJECTED = "A2A_REJECTED"
    # A duplicate, or a transaction id reused to carry different content. Its
    # own event rather than a generic denial, for the reason
    # APPROVAL_REPLAY_REJECTED and JIT_REPLAY_BLOCKED are.
    A2A_REPLAY_BLOCKED = "A2A_REPLAY_BLOCKED"
    # The signed amount, the server's amount, the authorized amount and the
    # executed amount must all agree. A disagreement is an incident, not a
    # validation error, so it is findable on its own.
    A2A_AMOUNT_MISMATCH = "A2A_AMOUNT_MISMATCH"
    A2A_EXPIRED = "A2A_EXPIRED"
    A2A_EXECUTED = "A2A_EXECUTED"
    A2A_FAILED = "A2A_FAILED"
    A2A_RESPONSE = "A2A_RESPONSE"

    # --- Declared for later phases; NOT emitted yet ---
    MCP_REQUEST = "MCP_REQUEST"                   # Phase 8
    # NOTE: TOOL_EXECUTED has been emitted by the AEM since Phase 4. It was
    # listed under Phase 8 here by a comment that was never corrected when the
    # enforcement boundary landed; the name and value are unchanged.
    TOOL_EXECUTED = "TOOL_EXECUTED"
    SESSION_CREATED = "SESSION_CREATED"           # Phase 9
    SESSION_REVOKED = "SESSION_REVOKED"           # Phase 9
    SSS_UPDATED = "SSS_UPDATED"                   # Phase 9
    ANOMALY_DETECTED = "ANOMALY_DETECTED"         # Phase 10
    TRUST_UPDATED = "TRUST_UPDATED"               # Phase 10
    A2A_SESSION_TERMINATED = "A2A_SESSION_TERMINATED"   # Phase 11
    MCP_SESSION_TERMINATED = "MCP_SESSION_TERMINATED"   # Phase 11


@dataclass(frozen=True)
class Event:
    event_type: str
    agent_did: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    resource: str | None = None
    action: str | None = None
    decision: str | None = None
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.occurred_at.isoformat(),
            "event_type": self.event_type,
            "agent_did": self.agent_did,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "resource": self.resource,
            "action": self.action,
            "decision": self.decision,
            "reason": self.reason,
            "metadata": self.metadata,
        }


class EventBus:
    """Fan-out to live subscribers. Persistence is handled by the audit service.

    Subscribers are bounded queues: a slow consumer drops events rather than
    stalling the request path.
    """

    def __init__(self, queue_size: int = 512) -> None:
        self._subscribers: set[asyncio.Queue[Event]] = set()
        self._queue_size = queue_size

    def publish(self, event: Event) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def subscribe(self) -> AsyncIterator[Event]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=self._queue_size)
        self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


event_bus = EventBus()
