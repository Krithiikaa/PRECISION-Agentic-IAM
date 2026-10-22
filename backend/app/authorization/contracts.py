"""Phase 4 authorization contracts: the request and the decision.

Two rules shape everything in this module.

1. AUTHORIZATION IS CONTEXTUAL. A decision is never `agent == X` or
   `capability == Y`. It is a function of subject, action, resource, purpose,
   credential state and context together. The request type therefore refuses to
   exist without all of those.

2. A DECISION IS NEVER A BARE BOOLEAN. It carries the policy that produced it,
   its version, a machine-readable reason and the evaluation detail -- the same
   "explain every check" discipline the Phase 2 verifier already uses. A caller
   that cannot see *why* it was denied cannot fix the cause, and an auditor
   cannot review it.
"""
from __future__ import annotations

import enum
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class Decision(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    # Phase 4 introduced this VALUE only; Phase 5 gave it a flow.
    #
    # PHASE 5.5 DELIBERATELY DID NOT ADD A FOURTH VALUE. Dual control is
    # carried as the REASON `DUAL_APPROVAL_REQUIRED` plus `required_approvals`
    # on the policy document, on this same verdict. "How many humans" is a
    # property of the escalation, not a new kind of answer -- and a fourth
    # value would have to be understood by the AEM, the API, the console and
    # every existing consumer before any of them behaved correctly.
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"


class Reason:
    """Machine-readable decision reasons.

    Deliberately coarse: a reason tells the caller which *class* of condition
    failed, never which record, claim value or internal identifier was involved.
    """

    # ALLOW
    POLICY_MATCH = "VALID_CREDENTIAL_AND_POLICY_MATCH"

    # DENY -- credential state (the Phase 2 verifier's verdict, not re-derived)
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    CREDENTIAL_INVALID = "CREDENTIAL_INVALID"
    MISSING_CAPABILITY = "MISSING_CAPABILITY"

    # DENY -- scope
    RESOURCE_NOT_ALLOWED = "RESOURCE_NOT_ALLOWED"
    PURPOSE_NOT_ALLOWED = "PURPOSE_NOT_ALLOWED"
    ACTION_NOT_ALLOWED = "ACTION_NOT_ALLOWED"

    # DENY -- context / subject
    INVALID_CONTEXT = "INVALID_CONTEXT"
    UNKNOWN_SUBJECT = "UNKNOWN_SUBJECT"

    # DENY -- fail-closed paths. None of these may ever become ALLOW.
    NO_MATCHING_POLICY = "NO_MATCHING_POLICY"
    AUTHORIZATION_UNAVAILABLE = "AUTHORIZATION_UNAVAILABLE"
    MALFORMED_REQUEST = "MALFORMED_REQUEST"

    # HUMAN_APPROVAL_REQUIRED
    SENSITIVE_ACTION_REQUIRES_HUMAN = "SENSITIVE_ACTION_REQUIRES_HUMAN"
    # Phase 5.5. The SAME decision value, escalated for a different reason and
    # to a different number of people. A fourth decision value was deliberately
    # not introduced: every consumer of a verdict already handles these three,
    # and "how many humans" is a property of the escalation, not a new kind of
    # answer. `required_approvals` on the policy document carries the count.
    DUAL_APPROVAL_REQUIRED = "DUAL_APPROVAL_REQUIRED"

    # DENY -- human approval (Phase 5). Each names ONE thing that was wrong,
    # because "approval invalid" tells an operator nothing actionable.
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_ALREADY_CONSUMED = "APPROVAL_ALREADY_CONSUMED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_BINDING_MISMATCH = "APPROVAL_BINDING_MISMATCH"
    APPROVAL_SIGNATURE_INVALID = "APPROVAL_SIGNATURE_INVALID"
    APPROVAL_AUTHORITY_UNKNOWN = "APPROVAL_AUTHORITY_UNKNOWN"
    APPROVAL_DOMAIN_MISMATCH = "APPROVAL_DOMAIN_MISMATCH"
    APPROVAL_MALFORMED = "APPROVAL_MALFORMED"

    # DENY -- Phase 5.5. Dual control and signing-key lifecycle. Each names ONE
    # thing, for the same reason the Phase 5 set does.
    APPROVAL_INSUFFICIENT_APPROVALS = "APPROVAL_INSUFFICIENT_APPROVALS"
    APPROVAL_APPROVERS_NOT_DISTINCT = "APPROVAL_APPROVERS_NOT_DISTINCT"
    APPROVAL_KEY_RETIRED = "APPROVAL_KEY_RETIRED"
    APPROVAL_KEY_UNKNOWN = "APPROVAL_KEY_UNKNOWN"
    APPROVAL_KEY_REVOKED = "APPROVAL_KEY_REVOKED"

    # DENY -- Phase 5.5. The amount boundary.
    # The thresholds are not loaded in the engine. An unknown limit is not an
    # absent one: this denies rather than falling through.
    LOAN_POLICY_UNCONFIGURED = "LOAN_POLICY_UNCONFIGURED"
    # The amount cannot be established from server-side state. Nobody should be
    # asked to approve a figure nobody can state, and no agent should act on one.
    RESOURCE_ATTRIBUTES_UNAVAILABLE = "RESOURCE_ATTRIBUTES_UNAVAILABLE"

    # ALLOW -- Phase 5.5. Below the configured autonomous limit, on the agent's
    # own valid, scoped credential. Named distinctly from POLICY_MATCH so an
    # auditor can find every decision a human was NOT asked about.
    WITHIN_AGENT_APPROVAL_AUTHORITY = "WITHIN_AGENT_APPROVAL_AUTHORITY"

    # --- Phase 6: JIT temporary access ---------------------------------
    # ISSUANCE refusals. A grant is refused for a reason that names ONE thing,
    # for the same reason every other family here does.
    JIT_POLICY_UNCONFIGURED = "JIT_POLICY_UNCONFIGURED"
    JIT_ACTION_NOT_ELIGIBLE = "JIT_ACTION_NOT_ELIGIBLE"
    JIT_TTL_EXCEEDS_POLICY_MAXIMUM = "JIT_TTL_EXCEEDS_POLICY_MAXIMUM"
    JIT_USES_EXCEED_POLICY_MAXIMUM = "JIT_USES_EXCEED_POLICY_MAXIMUM"
    JIT_SCOPE_EXCEEDS_DECISION = "JIT_SCOPE_EXCEEDS_DECISION"
    JIT_MALFORMED_REQUEST = "JIT_MALFORMED_REQUEST"

    # USE refusals. Each names one failed binding or lifecycle condition.
    JIT_GRANT_EXPIRED = "JIT_GRANT_EXPIRED"
    JIT_GRANT_REVOKED = "JIT_GRANT_REVOKED"
    JIT_GRANT_EXHAUSTED = "JIT_GRANT_EXHAUSTED"
    JIT_GRANT_BINDING_MISMATCH = "JIT_GRANT_BINDING_MISMATCH"
    JIT_GRANT_SIGNATURE_INVALID = "JIT_GRANT_SIGNATURE_INVALID"
    JIT_GRANT_PROOF_PURPOSE_INVALID = "JIT_GRANT_PROOF_PURPOSE_INVALID"
    JIT_GRANT_DOMAIN_MISMATCH = "JIT_GRANT_DOMAIN_MISMATCH"
    JIT_GRANT_MALFORMED = "JIT_GRANT_MALFORMED"
    JIT_GRANT_UNKNOWN = "JIT_GRANT_UNKNOWN"
    JIT_GRANT_NOT_YET_VALID = "JIT_GRANT_NOT_YET_VALID"
    JIT_AUTHORITY_UNKNOWN = "JIT_AUTHORITY_UNKNOWN"
    JIT_KEY_RETIRED = "JIT_KEY_RETIRED"
    JIT_KEY_UNKNOWN = "JIT_KEY_UNKNOWN"
    JIT_KEY_REVOKED = "JIT_KEY_REVOKED"
    JIT_CONSTRAINT_VIOLATED = "JIT_CONSTRAINT_VIOLATED"

    # ALLOW -- the mandate carried a human decision forward. Named distinctly
    # from POLICY_MATCH so an auditor can find every action taken under a
    # standing mandate rather than a fresh per-action approval.
    WITHIN_JIT_GRANT = "WITHIN_JIT_GRANT"

    # --- Phase 7: secure A2A transactions -------------------------------
    # ENVELOPE refusals. Each names ONE thing, for the same reason every other
    # family here does. These are AUTHENTICATION failures surfaced as
    # authorization reasons: the A2A service refuses them before the PDP is
    # asked, and policy asserts them independently so the refusal is
    # reviewable in Rego rather than emergent from Python control flow.
    A2A_ENVELOPE_MISSING = "A2A_ENVELOPE_MISSING"
    A2A_ENVELOPE_MALFORMED = "A2A_ENVELOPE_MALFORMED"
    A2A_PROTOCOL_UNSUPPORTED = "A2A_PROTOCOL_UNSUPPORTED"
    A2A_PROOF_PURPOSE_INVALID = "A2A_PROOF_PURPOSE_INVALID"
    A2A_SIGNATURE_INVALID = "A2A_SIGNATURE_INVALID"
    A2A_DOMAIN_MISMATCH = "A2A_DOMAIN_MISMATCH"
    A2A_RECEIVER_MISMATCH = "A2A_RECEIVER_MISMATCH"
    A2A_SENDER_UNKNOWN = "A2A_SENDER_UNKNOWN"
    A2A_SENDER_NOT_ELIGIBLE = "A2A_SENDER_NOT_ELIGIBLE"
    A2A_SENDER_NOT_RESOLVABLE = "A2A_SENDER_NOT_RESOLVABLE"
    A2A_KEY_UNKNOWN = "A2A_KEY_UNKNOWN"
    A2A_KEY_RETIRED = "A2A_KEY_RETIRED"
    A2A_KEY_REVOKED = "A2A_KEY_REVOKED"
    A2A_TRANSACTION_STALE = "A2A_TRANSACTION_STALE"
    A2A_TRANSACTION_EXPIRED = "A2A_TRANSACTION_EXPIRED"
    A2A_TRANSACTION_NOT_YET_VALID = "A2A_TRANSACTION_NOT_YET_VALID"
    A2A_TTL_EXCEEDS_MAXIMUM = "A2A_TTL_EXCEEDS_MAXIMUM"

    # REPLAY. Two different events, and collapsing them would hide an attack
    # inside an ordinary retry: one is a client that did not see a response,
    # the other is a reused id carrying different content.
    A2A_REPLAY_BLOCKED = "A2A_REPLAY_BLOCKED"
    A2A_TRANSACTION_ID_REUSE = "A2A_TRANSACTION_ID_REUSE"

    # MONEY. The amount the sender signed, the amount the server holds, the
    # amount policy authorized and the amount actually moved must all agree.
    A2A_AMOUNT_MISMATCH = "A2A_AMOUNT_MISMATCH"
    A2A_AMOUNT_UNAVAILABLE = "A2A_AMOUNT_UNAVAILABLE"

    # POLICY refusals for a transaction that verified perfectly.
    A2A_POLICY_UNCONFIGURED = "A2A_POLICY_UNCONFIGURED"
    A2A_ACTION_NOT_ELIGIBLE = "A2A_ACTION_NOT_ELIGIBLE"
    A2A_NO_ENFORCEMENT_PATH = "A2A_NO_ENFORCEMENT_PATH"
    A2A_EXECUTION_FAILED = "A2A_EXECUTION_FAILED"

    # ALLOW -- named distinctly from POLICY_MATCH so an auditor can find every
    # action taken on another agent's instruction rather than on the agent's
    # own initiative.
    A2A_TRANSACTION_AUTHORIZED = "A2A_TRANSACTION_AUTHORIZED"
    A2A_HUMAN_APPROVED_AND_POLICY_MATCH = "A2A_HUMAN_APPROVED_AND_POLICY_MATCH"
    A2A_DUAL_CONTROL_SATISFIED = "A2A_DUAL_CONTROL_SATISFIED"

    # HUMAN_APPROVAL_REQUIRED -- the payment bands. DUAL_APPROVAL_REQUIRED is
    # reused verbatim from Phase 5.5 rather than given an A2A-specific twin:
    # it means exactly the same thing, and a second spelling would be a second
    # thing for the console and the queue to understand.
    A2A_PAYMENT_REQUIRES_HUMAN = "A2A_PAYMENT_REQUIRES_HUMAN"


# Reasons that indicate the authorization layer itself could not reach a
# policy-based verdict. They are denials, and they are recorded distinctly so an
# operator can tell "policy said no" from "the PDP could not ask".
FAIL_CLOSED_REASONS = frozenset({
    Reason.AUTHORIZATION_UNAVAILABLE,
    Reason.MALFORMED_REQUEST,
})


class MalformedAuthorizationRequest(ValueError):
    """The request could not be understood, so it was never evaluated.

    Distinct from a DENY: a denial means policy was consulted and said no. A
    malformed request means no meaningful question could be asked at all.
    """


_DID_RE = re.compile(r"^did:[a-z0-9]+:[a-z0-9]+:[a-zA-Z0-9._%-]+$")
_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


def new_request_id() -> str:
    return f"authz-{uuid.uuid4().hex[:16]}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Subject:
    """Who is asking. Phase 4 knows only agents.

    `type` exists so a future HITL phase can introduce a human principal
    WITHOUT reshaping this contract -- but no human principal type is
    implemented here, and `agent` is the only accepted value.
    """

    did: str
    type: str = "agent"

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "did": self.did}


@dataclass(frozen=True)
class Resource:
    """What is being acted on."""

    type: str
    id: str | None = None
    classification: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "id": self.id, "classification": self.classification}


@dataclass
class AuthorizationRequest:
    action: str
    resource: Resource
    subject: Subject
    purpose: str
    request_id: str = field(default_factory=new_request_id)
    # Credential ids the subject offers. Empty means "use everything the
    # subject holds"; either way the PIP VERIFIES them, and an id offered here
    # is a claim, never evidence.
    credentials: list[str] = field(default_factory=list)
    # Caller-supplied and therefore UNTRUSTED. It is passed to policy as
    # `input.context` for rules that legitimately need it, but nothing in it is
    # treated as an assertion about permission -- see `strip_decision_claims`.
    context: dict[str, Any] = field(default_factory=dict)
    # Phase 9 owns sessions. Explicitly None rather than absent, so policy can
    # tell "no session layer exists" from "session lookup failed".
    session: dict[str, Any] | None = None
    # Audience binding for a presentation-based request, preserving the Phase 2
    # S-2 protection. When set it is passed to the presentation verifier.
    expected_domain: str | None = None
    # Phase 5. An approval id the caller OFFERS. A claim, never evidence: the
    # PIP looks the approval up, verifies its signature against the approval
    # authority, and checks that it is bound to THIS request. Offering an id
    # narrows which approval is considered; it can never make one apply.
    #
    # When absent, the PIP looks one up BY BINDING, so an approval granted for
    # a different action is not found rather than found-and-rejected.
    approval_id: str | None = None
    # Phase 6. A JIT grant id the caller OFFERS. A claim, never evidence, and
    # handled exactly as `approval_id` is: the PIP loads the grant, verifies
    # its signature against the JIT authority's DID Document, and checks that
    # THIS request falls inside the mandate's scope. Offering an id narrows
    # which grant is considered; it can never make one apply.
    jit_grant_id: str | None = None

    def validate(self) -> None:
        """Reject anything that cannot be meaningfully evaluated.

        A malformed request must never reach OPA: an under-specified input
        document could match a policy for the wrong reason.
        """
        problems: list[str] = []
        if self.subject.type != "agent":
            problems.append(
                f"subject.type {self.subject.type!r} is not supported; Phase 4 "
                f"authorizes agents only (human principals are HITL)"
            )
        if not self.subject.did or not _DID_RE.match(self.subject.did):
            problems.append(f"subject.did {self.subject.did!r} is not a well-formed DID")
        if not self.action or not _TOKEN_RE.match(self.action):
            problems.append(f"action {self.action!r} must be a lower_snake_case token")
        if not self.resource.type or not _TOKEN_RE.match(self.resource.type):
            problems.append(f"resource.type {self.resource.type!r} must be a lower_snake_case token")
        if not self.purpose or not _TOKEN_RE.match(self.purpose):
            problems.append(
                f"purpose {self.purpose!r} must be a lower_snake_case token; purpose is "
                f"required because an action name alone does not describe why it is being taken"
            )
        if not isinstance(self.context, dict):
            problems.append("context must be an object")
        if problems:
            raise MalformedAuthorizationRequest("; ".join(problems))

    def strip_decision_claims(self) -> dict[str, Any]:
        """Context with any self-asserted verdict removed.

        An agent that sends `{"allow": true}` or `{"decision": "ALLOW"}` is
        making an assertion it has no authority to make. Rather than trusting
        it, or quietly ignoring it, these keys are removed before the context
        reaches policy and the removal is reported in the decision's evaluation
        detail so the attempt is visible in the audit trail.
        """
        return {
            k: v for k, v in self.context.items()
            if k.lower() not in _SELF_ASSERTED_KEYS
        }

    def rejected_context_keys(self) -> list[str]:
        return sorted(k for k in self.context if k.lower() in _SELF_ASSERTED_KEYS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "subject": self.subject.to_dict(),
            "action": self.action,
            "resource": self.resource.to_dict(),
            "purpose": self.purpose,
            "credentials": list(self.credentials),
            "context": dict(self.context),
            "session": self.session,
            "approval_id": self.approval_id,
            "jit_grant_id": self.jit_grant_id,
        }


# Keys a subject must never be able to influence the decision with.
_SELF_ASSERTED_KEYS = frozenset({
    "allow", "allowed", "decision", "authorized", "authorised",
    "permit", "permitted", "grant", "granted", "policy_id", "policy_version",
    "override", "bypass", "trust_score",
    # Phase 5: an agent supplying its own "approval" is asserting the very
    # thing a human is supposed to decide.
    "approval", "approved", "approval_id", "approver", "human_approved",
    # Phase 6: an agent supplying its own "grant" is asserting the very thing
    # the JIT authority exists to attest to. A requested TTL is deliberately
    # NOT stripped -- asking for a duration is a legitimate request, and policy
    # is what caps it. Only self-asserted GRANTS are removed.
    "jit", "jit_grant", "jit_grant_id", "grant_id", "mandate",
})


@dataclass
class Stage:
    """One measured step of the evaluation. Timings are real, not modelled."""

    name: str
    ok: bool
    detail: str
    duration_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass
class AuthorizationDecision:
    decision: Decision
    request_id: str
    reason: str
    policy_id: str | None = None
    policy_version: str | None = None
    subject_did: str | None = None
    action: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    purpose: str | None = None
    stages: list[Stage] = field(default_factory=list)
    evaluation: dict[str, Any] = field(default_factory=dict)
    decided_at: datetime = field(default_factory=utcnow)

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def total_latency_ms(self) -> float:
        return round(sum(s.duration_ms for s in self.stages), 2)

    @property
    def policy_ref(self) -> str | None:
        if not self.policy_id:
            return None
        return f"{self.policy_id}:{self.policy_version}" if self.policy_version else self.policy_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "request_id": self.request_id,
            "reason": self.reason,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy": self.policy_ref,
            "subject": self.subject_did,
            "action": self.action,
            "resource": {"type": self.resource_type, "id": self.resource_id},
            "purpose": self.purpose,
            "stages": [s.to_dict() for s in self.stages],
            "latency_ms": self.total_latency_ms,
            "evaluation": self.evaluation,
            "decided_at": self.decided_at.isoformat(),
        }

    @classmethod
    def denied(
        cls,
        request_id: str,
        reason: str,
        *,
        detail: str = "",
        request: AuthorizationRequest | None = None,
        stages: list[Stage] | None = None,
    ) -> "AuthorizationDecision":
        """Construct a denial. Every fail-closed path routes through here."""
        return cls(
            decision=Decision.DENY,
            request_id=request_id,
            reason=reason,
            subject_did=request.subject.did if request else None,
            action=request.action if request else None,
            resource_type=request.resource.type if request else None,
            resource_id=request.resource.id if request else None,
            purpose=request.purpose if request else None,
            stages=stages or [],
            evaluation={"detail": detail} if detail else {},
        )
