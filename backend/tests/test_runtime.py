"""AgentRuntime behaviour.

A stub LLMProvider is used here so the assertions are deterministic. That is a
test double, not a product code path: the shipped OllamaProvider is the only
provider bound at runtime, and app/agents/service.py refuses to serve tasks
when it is unavailable.
"""
from __future__ import annotations

import pytest

from app.agents.base import AgentIdentity, TaskRequest
from app.agents.runtime import AgentMemory, AgentRuntime
from app.core.errors import LLMUnavailableError
from app.identity.signer import Signer, verify_signature
from app.llm.provider import LLMHealth, LLMProvider, LLMResult

IDENTITY = AgentIdentity(
    did="did:poc:agent:risk-001",
    slug="risk-001",
    name="Credit Risk Analysis Agent",
    kid="did:poc:agent:risk-001#key-1",
    public_key_multibase="",
    controller_did="did:poc:organization:bank-demo",
    capabilities=("credit_analysis",),
)


class StubLLM(LLMProvider):
    name = "stub"

    def __init__(self, text="Assessment: moderate risk.", fail=False):
        self.text, self.fail, self.calls = text, fail, []

    @property
    def model(self) -> str:
        return "stub-model"

    async def generate(self, prompt, *, system=None, **kwargs) -> LLMResult:
        self.calls.append({"prompt": prompt, "system": system})
        if self.fail:
            raise LLMUnavailableError("Ollama at http://localhost:11434 is unreachable")
        return LLMResult(
            text=self.text, model=self.model, provider=self.name,
            latency_ms=12.0, prompt_tokens=10, completion_tokens=5,
        )

    async def health(self) -> LLMHealth:
        return LLMHealth(not self.fail, self.name, self.model, "stub://", "OK")


def _runtime(llm, keystore=None):
    signer = None
    identity = IDENTITY
    if keystore is not None:
        handle = keystore.generate_key(IDENTITY.kid)
        identity = AgentIdentity(**{**IDENTITY.__dict__,
                                    "public_key_multibase": handle.public_key_multibase})
        signer = Signer(keystore)
    return AgentRuntime(
        identity=identity, llm=llm, system_prompt="You are the Credit Risk Analysis Agent.",
        signer=signer,
    )


class TestTaskExecution:
    async def test_executes_and_records_llm_metadata(self):
        llm = StubLLM()
        result = await _runtime(llm).execute_task(TaskRequest(instruction="Assess USER-007."))

        assert result.status == "COMPLETED"
        assert result.output == "Assessment: moderate risk."
        assert result.llm["model"] == "stub-model"
        assert result.llm["completion_tokens"] == 5
        assert len(llm.calls) == 1

    async def test_system_prompt_carries_identity_and_capabilities(self):
        llm = StubLLM()
        await _runtime(llm).execute_task(TaskRequest(instruction="Assess USER-007."))
        system = llm.calls[0]["system"]
        assert "did:poc:agent:risk-001" in system
        assert "credit_analysis" in system
        assert "authorized by an external" in system

    async def test_llm_failure_produces_no_output(self):
        """No fabricated result when the model did not run."""
        result = await _runtime(StubLLM(fail=True)).execute_task(
            TaskRequest(instruction="Assess USER-007.")
        )
        assert result.status == "FAILED"
        assert result.output == ""
        assert "unreachable" in result.error

    async def test_result_is_signed_and_verifiable(self, keystore):
        runtime = _runtime(StubLLM(), keystore)
        result = await runtime.execute_task(TaskRequest(instruction="Assess USER-007."))

        assert result.verification_method == IDENTITY.kid
        verification = verify_signature(
            runtime.identity.public_key_multibase,
            AgentRuntime.signing_payload(result),
            result.signature,
        )
        assert verification.valid

    async def test_tampering_with_a_signed_result_is_detectable(self, keystore):
        runtime = _runtime(StubLLM(), keystore)
        result = await runtime.execute_task(TaskRequest(instruction="Assess USER-007."))
        result.output = "Assessment: no risk whatsoever."
        assert not verify_signature(
            runtime.identity.public_key_multibase,
            AgentRuntime.signing_payload(result),
            result.signature,
        ).valid

    async def test_events_are_emitted_for_every_stage(self):
        seen = []

        async def sink(event_type, metadata):
            seen.append(event_type)

        runtime = AgentRuntime(
            identity=IDENTITY, llm=StubLLM(), system_prompt="x", event_sink=sink
        )
        await runtime.execute_task(TaskRequest(instruction="Assess USER-007."))
        assert seen == ["AGENT_TASK_STARTED", "LLM_CALL", "AGENT_TASK_COMPLETED"]


class TestMemory:
    async def test_memory_accumulates_and_reaches_the_next_prompt(self):
        llm = StubLLM()
        runtime = _runtime(llm)
        await runtime.execute_task(TaskRequest(instruction="First task."))
        await runtime.execute_task(TaskRequest(instruction="Second task."))

        assert len(runtime.memory.turns) == 4          # task + agent, twice
        assert "First task." in llm.calls[1]["prompt"]
        assert runtime.status()["tasks_completed"] == 2

    def test_memory_is_bounded(self):
        memory = AgentMemory(max_turns=3)
        for i in range(10):
            memory.remember_turn("task", f"turn {i}")
        assert len(memory.turns) == 3
        assert memory.turns[-1]["content"] == "turn 9"
