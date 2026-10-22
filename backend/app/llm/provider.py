"""LLM provider abstraction.

Agents call `LLMProvider.generate(...)`. Nothing in the agent runtime talks to
Ollama directly, so swapping in another provider is a single binding change.

Hard rule enforced by this layer: if the model did not run, the caller gets an
exception. There is no canned-response fallback anywhere -- a fabricated answer
would make every downstream claim about "real LLM reasoning" false.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LLMResult:
    text: str
    model: str
    provider: str
    latency_ms: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    finish_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LLMHealth:
    available: bool
    provider: str
    model: str
    base_url: str
    detail: str
    models_present: list[str] = field(default_factory=list)


class LLMProvider(abc.ABC):
    name: str = "abstract"

    @property
    @abc.abstractmethod
    def model(self) -> str: ...

    @abc.abstractmethod
    async def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResult: ...

    @abc.abstractmethod
    async def health(self) -> LLMHealth: ...

    async def aclose(self) -> None:  # pragma: no cover - default no-op
        return None
