"""Domain errors shared across the backend."""
from __future__ import annotations


class AgenticIAMError(Exception):
    """Base class for all domain errors."""


class NotFoundError(AgenticIAMError):
    pass


class ConflictError(AgenticIAMError):
    pass


class KeyStoreError(AgenticIAMError):
    pass


class IdentityError(AgenticIAMError):
    pass


class LLMUnavailableError(AgenticIAMError):
    """Raised when the configured LLM provider or model is not usable.

    Never swallowed into a fabricated response: if the LLM did not run,
    the caller is told so.
    """
