"""AgentRuntime: the real execution core every agent process runs on.

An agent is not a database row and not a UI node. It is an instance of this
class living in its own process, holding:

    identity   - DID, key id, capabilities (app.agents.base.AgentIdentity)
    memory     - bounded working state that survives across turns
    llm        - an LLMProvider it genuinely calls
    tools      - a registry of callables it may select from
    telemetry  - an event sink every step reports to

What this class deliberately does NOT do: decide whether an action is
authorized. It proposes; the IAM plane (AEM -> PDP, Phase 4) disposes. Keeping
that separation here is what makes "the LLM cannot bypass IAM" true rather
than aspirational.
"""
from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from app.agents.base import AgentIdentity, EventSink, TaskRequest, TaskResult, Tool, ToolSpec
from app.core.errors import LLMUnavailableError
from app.core.logging import get_logger
from app.identity.signer import Signer
from app.llm.provider import LLMProvider
from app.monitoring.events import EventType

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance
    from app.agents.wallet import CredentialWallet

log = get_logger("agent.runtime")


@dataclass
class AgentMemory:
    """Bounded working memory. Real state, not a transcript prop."""

    max_turns: int = 20
    turns: deque = field(default_factory=deque)
    facts: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.turns = deque(self.turns, maxlen=self.max_turns)

    def remember_turn(self, role: str, content: str, **extra: Any) -> None:
        self.turns.append(
            {
                "role": role,
                "content": content,
                "at": datetime.now(timezone.utc).isoformat(),
                **extra,
            }
        )

    def remember_fact(self, key: str, value: Any) -> None:
        self.facts[key] = value

    def recent(self, n: int = 6) -> list[dict[str, Any]]:
        return list(self.turns)[-n:]

    def snapshot(self) -> dict[str, Any]:
        return {"turns": list(self.turns), "facts": dict(self.facts)}


class ToolRegistry:
    """Tools an agent may select from.

    Phase 1 ships the mechanism with an empty registry for every agent: the
    banking tools arrive in Phase 5 and only become reachable through the MCP
    gateway + AEM in Phase 8. An empty registry is the honest state, not a stub.
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.spec.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def specs(self) -> list[ToolSpec]:
        return [t.spec for t in self._tools.values()]

    def describe(self) -> str:
        if not self._tools:
            return "(no tools are currently available to you)"
        return "\n".join(
            f"- {t.spec.name}({', '.join(t.spec.parameters.get('properties', {}))}): "
            f"{t.spec.description}"
            for t in self._tools.values()
        )

    def __len__(self) -> int:
        return len(self._tools)


class AgentRuntime:
    def __init__(
        self,
        *,
        identity: AgentIdentity,
        llm: LLMProvider,
        system_prompt: str,
        signer: Signer | None = None,
        tools: ToolRegistry | None = None,
        event_sink: EventSink | None = None,
        memory: AgentMemory | None = None,
        wallet: "CredentialWallet | None" = None,
    ) -> None:
        self.identity = identity
        # Credentials the agent HOLDS (Phase 2). Holding one is not permission
        # to act; it is evidence an authority attested something. Authorisation
        # remains the PDP's job in Phase 4.
        self.wallet = wallet
        self.llm = llm
        self.system_prompt = system_prompt
        self.signer = signer
        self.tools = tools or ToolRegistry()
        self.memory = memory or AgentMemory()
        self._event_sink = event_sink
        self.started_at = datetime.now(timezone.utc)
        self.tasks_completed = 0
        self.tasks_failed = 0
        # Real, observed load: reported to the ANS in heartbeats and used as a
        # ranking signal when several agents offer the same capability.
        self.tasks_in_flight = 0
        self.last_activity_at: datetime | None = None

    # --- telemetry -------------------------------------------------------
    async def emit(self, event_type: str, **metadata: Any) -> None:
        log.info(event_type.lower(), agent=self.identity.did, **metadata)
        if self._event_sink is not None:
            await self._event_sink(event_type, {"agent_did": self.identity.did, **metadata})

    # --- prompting -------------------------------------------------------
    def build_system_prompt(self) -> str:
        """The agent is told its own identity, declared scope and attested scope.

        Note this is guidance to the model, not a security control. An agent
        that ignores every word of it is still stopped by the enforcement
        plane, which is the whole point of the architecture.
        """
        attested = self.wallet.attested_capabilities() if self.wallet else []
        return (
            f"{self.system_prompt.strip()}\n\n"
            f"YOUR IDENTITY\n"
            f"  Name: {self.identity.name}\n"
            f"  DID: {self.identity.did}\n"
            f"  Declared capabilities: {', '.join(self.identity.capabilities) or 'none'}\n"
            f"  Capabilities attested by a credential: {', '.join(attested) or 'none'}\n\n"
            f"AVAILABLE TOOLS\n{self.tools.describe()}\n\n"
            f"Every action you take is independently authorized by an external "
            f"policy layer. Requesting something outside your declared "
            f"capabilities will be denied and recorded."
        )

    def build_task_prompt(self, request: TaskRequest) -> str:
        parts: list[str] = []
        recent = self.memory.recent()
        if recent:
            parts.append("RECENT CONTEXT")
            parts.extend(f"  [{t['role']}] {t['content'][:400]}" for t in recent)
            parts.append("")
        if self.memory.facts:
            parts.append(f"KNOWN FACTS\n{json.dumps(self.memory.facts, default=str)[:1500]}\n")
        if request.context:
            parts.append(f"TASK CONTEXT\n{json.dumps(request.context, default=str)[:3000]}\n")
        if request.sender_did:
            parts.append(f"REQUEST FROM: {request.sender_did}\n")
        parts.append(f"TASK\n{request.instruction}")
        return "\n".join(parts)

    # --- execution -------------------------------------------------------
    async def execute_task(self, request: TaskRequest) -> TaskResult:
        result = TaskResult(
            task_id=request.task_id,
            agent_did=self.identity.did,
            status="FAILED",
            output="",
        )
        await self.emit(
            EventType.AGENT_TASK_STARTED,
            task_id=request.task_id,
            sender_did=request.sender_did,
            injected=request.injected,
        )
        self.memory.remember_turn("task", request.instruction, task_id=request.task_id)

        self.tasks_in_flight += 1
        try:
            llm_result = await self.llm.generate(
                self.build_task_prompt(request),
                system=self.build_system_prompt(),
            )
        except LLMUnavailableError as exc:
            # No fallback text. If the model did not run, the caller is told.
            self.tasks_in_flight -= 1
            self.tasks_failed += 1
            result.error = str(exc)
            result.completed_at = datetime.now(timezone.utc)
            await self.emit(
                EventType.AGENT_TASK_FAILED, task_id=request.task_id, error=str(exc)
            )
            return result

        result.status = "COMPLETED"
        result.output = llm_result.text.strip()
        result.llm = {
            "provider": llm_result.provider,
            "model": llm_result.model,
            "latency_ms": round(llm_result.latency_ms, 1),
            "prompt_tokens": llm_result.prompt_tokens,
            "completion_tokens": llm_result.completion_tokens,
        }
        result.completed_at = datetime.now(timezone.utc)
        self.tasks_in_flight -= 1
        self.tasks_completed += 1
        self.last_activity_at = result.completed_at
        self.memory.remember_turn("agent", result.output, task_id=request.task_id)

        await self.emit(
            EventType.LLM_CALL,
            task_id=request.task_id,
            model=llm_result.model,
            latency_ms=round(llm_result.latency_ms, 1),
            completion_tokens=llm_result.completion_tokens,
        )

        # The agent signs its own output with its own key: a consumer can prove
        # which agent produced this result without trusting the transport.
        if self.signer is not None:
            signature = self.signer.sign(self.identity.kid, self.signing_payload(result))
            result.signature = signature.signature_b64
            result.verification_method = self.identity.kid

        await self.emit(
            EventType.AGENT_TASK_COMPLETED,
            task_id=request.task_id,
            signed=result.signature is not None,
        )
        return result

    @staticmethod
    def signing_payload(result: TaskResult) -> str:
        """Deterministic bytes to sign. Sorted keys so a verifier can rebuild it."""
        return json.dumps(
            {
                "task_id": result.task_id,
                "agent_did": result.agent_did,
                "status": result.status,
                "output": result.output,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    # --- introspection ---------------------------------------------------
    def status(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_public_dict(),
            "started_at": self.started_at.isoformat(),
            "uptime_seconds": round(
                (datetime.now(timezone.utc) - self.started_at).total_seconds(), 1
            ),
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "tasks_in_flight": self.tasks_in_flight,
            "last_activity_at": (
                self.last_activity_at.isoformat() if self.last_activity_at else None
            ),
            "tools_registered": len(self.tools),
            "memory": {"turns": len(self.memory.turns), "facts": len(self.memory.facts)},
            "wallet": self.wallet.status() if self.wallet else None,
        }
