"""Core types shared by every agent runtime."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Protocol


@dataclass(frozen=True)
class AgentIdentity:
    """The identity an agent runtime carries into every interaction."""

    did: str
    slug: str
    name: str
    kid: str
    public_key_multibase: str
    controller_did: str
    endpoint: str | None = None
    capabilities: tuple[str, ...] = ()
    parent_did: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "did": self.did,
            "slug": self.slug,
            "name": self.name,
            "verification_method": self.kid,
            "public_key_multibase": self.public_key_multibase,
            "controller": self.controller_did,
            "endpoint": self.endpoint,
            "capabilities": list(self.capabilities),
            "parent_did": self.parent_did,
        }


@dataclass
class TaskRequest:
    """A unit of work handed to an agent."""

    instruction: str
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str | None = None
    sender_did: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
    # Marks a deliberately adversarial input in the Phase 11 security demo.
    # It changes nothing about how the request is processed or authorized; it
    # exists only so the audit trail can distinguish a drill from an incident.
    injected: bool = False


@dataclass
class TaskResult:
    task_id: str
    agent_did: str
    status: str                       # COMPLETED | FAILED
    output: str
    reasoning: str | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    llm: dict[str, Any] | None = None
    error: str | None = None
    signature: str | None = None
    verification_method: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent_did": self.agent_did,
            "status": self.status,
            "output": self.output,
            "reasoning": self.reasoning,
            "tool_calls": self.tool_calls,
            "llm": self.llm,
            "error": self.error,
            "signature": self.signature,
            "verification_method": self.verification_method,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    # The capability the agent must hold to call this tool. Holding the
    # capability is necessary but never sufficient: from Phase 4 the AEM/PDP
    # decide every actual invocation.
    required_capability: str
    resource: str
    action: str


class Tool(Protocol):
    spec: ToolSpec

    async def __call__(self, **kwargs: Any) -> Any: ...


EventSink = Callable[[str, dict[str, Any]], Awaitable[None]]
