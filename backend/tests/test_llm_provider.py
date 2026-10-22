"""LLM provider contract, including the live-Ollama path.

The tests marked `llm` genuinely call Ollama. They skip (loudly) when it is not
reachable rather than passing against a fake.
"""
from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.core.errors import LLMUnavailableError
from app.llm.ollama import MODEL_CANNOT_LOAD, OllamaProvider, _model_matches


@pytest.mark.parametrize(
    ("configured", "available", "expected"),
    [
        ("llama3", "llama3:latest", True),
        ("llama3:latest", "llama3:latest", True),
        ("llama3:8b", "llama3:latest", False),
        ("mistral", "llama3:latest", False),
    ],
)
def test_model_matching(configured, available, expected):
    assert _model_matches(configured, available) is expected


def test_model_must_be_configured():
    with pytest.raises(ValueError, match="never defaulted"):
        OllamaProvider(base_url="http://localhost:11434", model="")


async def test_unreachable_daemon_is_reported_not_faked():
    provider = OllamaProvider("http://127.0.0.1:1", "llama3:latest", timeout=2.0)
    health = await provider.health()
    assert not health.available
    assert health.detail.startswith("OLLAMA_UNREACHABLE")

    with pytest.raises(LLMUnavailableError, match="unreachable"):
        await provider.generate("hello")
    await provider.aclose()


@pytest.mark.llm
async def test_missing_model_is_reported_clearly():
    settings = get_settings()
    provider = OllamaProvider(settings.ollama_base_url, "definitely-not-pulled:v9", timeout=10.0)
    health = await provider.health()
    if health.detail.startswith("OLLAMA_UNREACHABLE"):
        pytest.skip("Ollama is not running")
    assert not health.available
    assert health.detail.startswith("MODEL_NOT_AVAILABLE")
    assert "ollama pull" in health.detail
    await provider.aclose()


@pytest.mark.llm
async def test_real_generation():
    settings = get_settings()
    provider = OllamaProvider(
        settings.ollama_base_url, settings.ollama_model, timeout=settings.llm_timeout_seconds
    )
    health = await provider.health()
    if not health.available:
        pytest.skip(f"Ollama unavailable: {health.detail}")

    try:
        result = await provider.generate(
            "Reply with exactly one word: READY",
            system="You are a terse test probe.",
            max_tokens=10,
        )
    except LLMUnavailableError as exc:
        # Skip only for the specific, verifiable environment condition where
        # the host cannot load the model. Any other failure is a real failure
        # and must not be swallowed.
        if MODEL_CANNOT_LOAD in str(exc):
            await provider.aclose()
            pytest.skip(f"Host cannot load {settings.ollama_model}: {exc}")
        raise
    assert result.text.strip()
    assert result.model.startswith(settings.ollama_model.split(":")[0])
    assert result.latency_ms > 0
    assert result.completion_tokens is not None    # proves a real generation happened
    await provider.aclose()
