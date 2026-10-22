"""FastAPI dependencies."""
from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.registry import AgentRegistry
from app.core.config import Settings, get_settings
from app.db.database import get_session
from app.identity.keys import KeyStore, build_keystore
from app.llm.ollama import build_llm_provider
from app.llm.provider import LLMProvider


@lru_cache(maxsize=1)
def get_keystore() -> KeyStore:
    return build_keystore(get_settings())


@lru_cache(maxsize=1)
def get_llm_provider() -> LLMProvider:
    return build_llm_provider(get_settings())


SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
KeyStoreDep = Annotated[KeyStore, Depends(get_keystore)]
LLMDep = Annotated[LLMProvider, Depends(get_llm_provider)]


def get_registry(
    session: SessionDep, keystore: KeyStoreDep, settings: SettingsDep
) -> AgentRegistry:
    return AgentRegistry(session, keystore, settings)


RegistryDep = Annotated[AgentRegistry, Depends(get_registry)]
