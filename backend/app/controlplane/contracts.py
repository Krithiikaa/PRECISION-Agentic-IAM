"""Control-plane authorization contracts.

Deliberately NOT reusing `app.authorization.contracts.AuthorizationRequest`.
That type models a data-plane question -- subject, action, RESOURCE, PURPOSE,
credentials -- and validates that the subject is an agent. A control-plane
question has none of those shapes: there is no resource being read, no purpose
of processing, no credential being presented, and the principal is frequently
not an agent at all.

Bending one type to cover both would have meant relaxing the data-plane
validation (`subject.type != "agent"` is currently a hard rejection) to admit
administrators. That validation is a real control, and loosening it to save a
dataclass would have been the wrong trade.
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class ControlPlaneDecisionValue(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    # No HUMAN_APPROVAL_REQUIRED. Routing an administrative operation to a
    # human approval flow is HITL, and no such flow exists.


class ControlPlaneClass(str, enum.Enum):
    """Sensitivity classes (§14). Recorded on every decision so an operator can
    filter the audit trail by how much a refused request was reaching for."""

    PUBLIC_READ = "PUBLIC_READ"
    AUTHENTICATED_READ = "AUTHENTICATED_READ"
    AUTHENTICATED_MUTATION = "AUTHENTICATED_MUTATION"
    AUTHORIZED_MUTATION = "AUTHORIZED_MUTATION"
    HIGH_RISK_ADMINISTRATION = "HIGH_RISK_ADMINISTRATION"


@dataclass(frozen=True)
class ControlPlaneOperation:
    """One protected operation, declared where the route is mounted.

    `name` is what Rego matches on, so adding a route without adding a rule
    fails closed with `UNKNOWN_CONTROL_PLANE_OPERATION` rather than slipping
    through.
    """

    name: str
    classification: ControlPlaneClass
    description: str
    target_type: str


def new_request_id() -> str:
    return f"cp-{uuid.uuid4().hex[:16]}"


@dataclass
class ControlPlaneDecision:
    decision: ControlPlaneDecisionValue
    request_id: str
    reason: str
    operation: str
    policy_id: str | None = None
    policy_version: str | None = None
    principal_did: str | None = None
    principal_type: str | None = None
    target: str | None = None
    classification: str | None = None
    authentication_ms: float = 0.0
    authorization_ms: float = 0.0
    evaluation: dict[str, Any] = field(default_factory=dict)
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def allowed(self) -> bool:
        return self.decision is ControlPlaneDecisionValue.ALLOW

    @property
    def total_latency_ms(self) -> float:
        return round(self.authentication_ms + self.authorization_ms, 2)

    @property
    def policy_ref(self) -> str | None:
        if not self.policy_id:
            return None
        return (f"{self.policy_id}:{self.policy_version}"
                if self.policy_version else self.policy_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "request_id": self.request_id,
            "reason": self.reason,
            "operation": self.operation,
            "policy": self.policy_ref,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "principal": self.principal_did,
            "principal_type": self.principal_type,
            "target": self.target,
            "classification": self.classification,
            "authentication_ms": round(self.authentication_ms, 2),
            "authorization_ms": round(self.authorization_ms, 2),
            "latency_ms": self.total_latency_ms,
            "evaluation": self.evaluation,
            "decided_at": self.decided_at.isoformat(),
        }

    @classmethod
    def denied(cls, request_id: str, operation: str, reason: str, **kw: Any
               ) -> "ControlPlaneDecision":
        """Every fail-closed path routes through here.

        There is no corresponding `allowed()` constructor: an ALLOW can only be
        built from a decision document OPA actually returned.
        """
        return cls(decision=ControlPlaneDecisionValue.DENY, request_id=request_id,
                   reason=reason, operation=operation, **kw)
