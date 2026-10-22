"""Ollama provider: real HTTP calls to a local Ollama daemon."""
from __future__ import annotations

import time
from typing import Any

import httpx

from app.core.errors import LLMUnavailableError
from app.llm.provider import LLMHealth, LLMProvider, LLMResult


# Distinct marker for "the model is pulled but cannot be loaded right now",
# which is an environment problem rather than a misconfiguration.
MODEL_CANNOT_LOAD = "MODEL_CANNOT_LOAD"


def _model_matches(configured: str, available: str) -> bool:
    """`llama3` should match `llama3:latest`; `llama3:8b` must not."""
    if configured == available:
        return True
    return ":" not in configured and available.split(":", 1)[0] == configured


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(
        self,
        base_url: str,
        model: str,
        timeout: float = 120.0,
        default_temperature: float = 0.1,
    ) -> None:
        if not model:
            raise ValueError("OLLAMA_MODEL must be configured; it is never defaulted silently")
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._default_temperature = default_temperature
        self._client = httpx.AsyncClient(base_url=self._base_url, timeout=timeout)

    @property
    def model(self) -> str:
        return self._model

    @property
    def base_url(self) -> str:
        return self._base_url

    async def list_models(self) -> list[str]:
        response = await self._client.get("/api/tags")
        response.raise_for_status()
        return [m["name"] for m in response.json().get("models", [])]

    async def health(self) -> LLMHealth:
        try:
            models = await self.list_models()
        except Exception as exc:  # noqa: BLE001
            return LLMHealth(
                available=False,
                provider=self.name,
                model=self._model,
                base_url=self._base_url,
                detail=f"OLLAMA_UNREACHABLE: {type(exc).__name__}: {exc}",
            )
        if not any(_model_matches(self._model, m) for m in models):
            return LLMHealth(
                available=False,
                provider=self.name,
                model=self._model,
                base_url=self._base_url,
                detail=(
                    f"MODEL_NOT_AVAILABLE: {self._model!r} is not pulled. "
                    f"Run: ollama pull {self._model}"
                ),
                models_present=models,
            )
        return LLMHealth(
            available=True,
            provider=self.name,
            model=self._model,
            base_url=self._base_url,
            detail="OK",
            models_present=models,
        )

    async def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResult:
        options: dict[str, Any] = {
            "temperature": self._default_temperature if temperature is None else temperature
        }
        if max_tokens is not None:
            options["num_predict"] = max_tokens

        payload: dict[str, Any] = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": options,
        }
        if system:
            payload["system"] = system
        if json_mode:
            payload["format"] = "json"

        started = time.perf_counter()
        try:
            response = await self._client.post("/api/generate", json=payload)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:300]
            # Ollama answers /api/tags happily while still being unable to load
            # the model, so this only surfaces at generation time. Give it a
            # distinct prefix: "the host is out of RAM" needs a different
            # operator response from "the daemon is down".
            if "more system memory" in body or "requires more system memory" in body:
                raise LLMUnavailableError(
                    f"{MODEL_CANNOT_LOAD}: the host does not have enough free memory to "
                    f"load {self._model!r}. Ollama said: {body}"
                ) from exc
            raise LLMUnavailableError(
                f"Ollama returned {exc.response.status_code}: {body}"
            ) from exc
        except httpx.HTTPError as exc:
            raise LLMUnavailableError(
                f"Ollama at {self._base_url} is unreachable: {type(exc).__name__}: {exc}"
            ) from exc

        latency_ms = (time.perf_counter() - started) * 1000
        body = response.json()
        return LLMResult(
            text=body.get("response", ""),
            model=body.get("model", self._model),
            provider=self.name,
            latency_ms=latency_ms,
            prompt_tokens=body.get("prompt_eval_count"),
            completion_tokens=body.get("eval_count"),
            finish_reason=body.get("done_reason"),
            metadata={
                "total_duration_ns": body.get("total_duration"),
                "eval_duration_ns": body.get("eval_duration"),
            },
        )

    async def aclose(self) -> None:
        await self._client.aclose()


def build_llm_provider(settings) -> LLMProvider:
    """Factory. Another provider is bound here, not inside the agent runtime."""
    return OllamaProvider(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        timeout=settings.llm_timeout_seconds,
        default_temperature=settings.llm_temperature,
    )
