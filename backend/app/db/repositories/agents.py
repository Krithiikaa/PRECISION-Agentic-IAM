"""Data access for agent identity."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.agent import (
    Agent,
    AgentKey,
    AgentRelationship,
    AgentStatus,
    AgentType,
    DIDDocument,
    KeyStatus,
)


class AgentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # --- reads -----------------------------------------------------------
    async def get_by_id(self, agent_id: uuid.UUID) -> Agent | None:
        return await self.session.get(Agent, agent_id)

    async def get_by_did(self, did: str) -> Agent | None:
        result = await self.session.execute(select(Agent).where(Agent.did == did))
        return result.scalar_one_or_none()

    async def get_by_slug(self, slug: str) -> Agent | None:
        result = await self.session.execute(select(Agent).where(Agent.slug == slug))
        return result.scalar_one_or_none()

    async def list_agents(
        self,
        *,
        status: AgentStatus | None = None,
        agent_type: AgentType | None = None,
        capability: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Agent]:
        stmt = select(Agent).order_by(Agent.created_at)
        if status is not None:
            stmt = stmt.where(Agent.status == status)
        if agent_type is not None:
            stmt = stmt.where(Agent.agent_type == agent_type)
        result = await self.session.execute(stmt.limit(limit).offset(offset))
        agents = list(result.scalars().all())
        if capability:
            # Capability filtering in Python keeps the query portable across
            # PostgreSQL/SQLite. The ANS (Phase 3) will index this properly.
            agents = [a for a in agents if capability in (a.capabilities or [])]
        return agents

    async def count(self) -> int:
        from sqlalchemy import func

        result = await self.session.execute(select(func.count()).select_from(Agent))
        return int(result.scalar_one())

    async def get_did_document(self, did: str) -> DIDDocument | None:
        result = await self.session.execute(
            select(DIDDocument).where(DIDDocument.did == did)
        )
        return result.scalar_one_or_none()

    async def get_active_key(self, agent_id: uuid.UUID) -> AgentKey | None:
        result = await self.session.execute(
            select(AgentKey).where(
                AgentKey.agent_id == agent_id, AgentKey.status == KeyStatus.ACTIVE
            )
        )
        return result.scalars().first()

    async def get_key_by_kid(self, kid: str) -> AgentKey | None:
        result = await self.session.execute(select(AgentKey).where(AgentKey.kid == kid))
        return result.scalar_one_or_none()

    # --- writes ----------------------------------------------------------
    async def add_agent(self, agent: Agent) -> Agent:
        self.session.add(agent)
        await self.session.flush()
        return agent

    async def add_key(self, key: AgentKey) -> AgentKey:
        self.session.add(key)
        await self.session.flush()
        return key

    async def upsert_did_document(
        self, agent_id: uuid.UUID, did: str, document: dict
    ) -> DIDDocument:
        existing = await self.get_did_document(did)
        if existing is None:
            record = DIDDocument(agent_id=agent_id, did=did, document=document, version=1)
            self.session.add(record)
            await self.session.flush()
            return record
        existing.document = document
        existing.version += 1
        await self.session.flush()
        return existing

    async def add_relationship(
        self,
        parent_agent_id: uuid.UUID,
        child_agent_id: uuid.UUID,
        relationship_type: str = "DELEGATES",
        expires_at: datetime | None = None,
    ) -> AgentRelationship:
        rel = AgentRelationship(
            parent_agent_id=parent_agent_id,
            child_agent_id=child_agent_id,
            relationship_type=relationship_type,
            expires_at=expires_at,
        )
        self.session.add(rel)
        await self.session.flush()
        return rel

    async def set_status(
        self, agent: Agent, status: AgentStatus, terminated_at: datetime | None = None
    ) -> Agent:
        agent.status = status
        if terminated_at is not None:
            agent.terminated_at = terminated_at
        await self.session.flush()
        return agent

    async def touch_activity(self, agent: Agent, when: datetime) -> None:
        agent.last_activity_at = when
        await self.session.flush()
