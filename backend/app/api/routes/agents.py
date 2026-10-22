"""Agent identity endpoints."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, status

from app.agents.registry import AgentSpec
from app.api.deps import RegistryDep, SessionDep
from app.api.schemas import (
    AgentCredentialSummary,
    AgentResponse,
    CreateAgentRequest,
    SignRequest,
    SignResponse,
    StatusChangeRequest,
)
from app.controlplane.guard import ControlPlaneGuard, body_key, path_param
from app.db.models.agent import Agent, AgentStatus, AgentType
from app.db.models.credential import CredentialStatusValue
from app.db.repositories.credentials import CredentialRepository

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


async def _credential_inventory(session, subject_did: str) -> list[AgentCredentialSummary]:
    """Credentials held by an agent, with effective (wall-clock) status."""
    now = datetime.now(timezone.utc)
    records = await CredentialRepository(session).list_credentials(subject_did=subject_did)
    inventory: list[AgentCredentialSummary] = []
    for record in records:
        stored = record.status_record.status if record.status_record else None
        effective = stored.value if stored else "UNKNOWN"
        if effective == CredentialStatusValue.ACTIVE.value and record.expires_at <= now:
            effective = CredentialStatusValue.EXPIRED.value
        inventory.append(
            AgentCredentialSummary(
                credential_id=record.credential_id,
                credential_type=record.credential_type,
                issuer=record.issuer_did,
                status=effective,
                issued_at=record.issued_at,
                expires_at=record.expires_at,
                seconds_remaining=max(0, int((record.expires_at - now).total_seconds())),
            )
        )
    return inventory


async def _with_credentials(session, agent: Agent) -> AgentResponse:
    response = AgentResponse.from_model(agent)
    response.credentials = await _credential_inventory(session, agent.did)
    return response


@router.post("", response_model=AgentResponse, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(
                 ControlPlaneGuard("agent_create", target=body_key("slug")))])
async def create_agent(body: CreateAgentRequest, registry: RegistryDep) -> AgentResponse:
    """Register an agent: assigns a DID, binds a key and publishes a DID Document."""
    agent = await registry.create_agent(
        AgentSpec(
            slug=body.slug,
            name=body.name,
            agent_type=body.agent_type,
            purpose=body.purpose,
            capabilities=body.capabilities,
            endpoint=body.endpoint,
            owner=body.owner,
            controller_did=body.controller_did,
            metadata=body.metadata,
            parent_did=body.parent_did,
            ttl_seconds=body.ttl_seconds,
            public_key_multibase=body.public_key_multibase,
        )
    )
    return AgentResponse.from_model(agent)


@router.get("", response_model=list[AgentResponse])
async def list_agents(
    registry: RegistryDep,
    agent_status: AgentStatus | None = Query(default=None, alias="status"),
    agent_type: AgentType | None = None,
    capability: str | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
) -> list[AgentResponse]:
    agents = await registry.list_agents(
        status=agent_status,
        agent_type=agent_type,
        capability=capability,
        limit=limit,
        offset=offset,
    )
    return [AgentResponse.from_model(a) for a in agents]


@router.get("/did/{did}", response_model=AgentResponse)
async def get_agent_by_did(did: str, registry: RegistryDep, session: SessionDep) -> AgentResponse:
    return await _with_credentials(session, await registry.get_agent(did))


@router.get("/did/{did}/credentials")
async def credentials_by_did(did: str, registry: RegistryDep, session: SessionDep,
                             include_document: bool = False) -> list[dict]:
    """Credentials held by an agent. Used by agent processes to load their wallet."""
    agent = await registry.get_agent(did)
    inventory = await _credential_inventory(session, agent.did)
    if not include_document:
        return [entry.model_dump(mode="json") for entry in inventory]
    repo = CredentialRepository(session)
    result = []
    for entry in inventory:
        record = await repo.get(entry.credential_id)
        result.append(
            {**entry.model_dump(mode="json"),
             "credential": record.document if record else None}
        )
    return result


@router.get("/did/{did}/did-document")
async def get_did_document_by_did(did: str, registry: RegistryDep) -> dict:
    """Resolve the DID Document. This is the public trust anchor for the agent."""
    return await registry.resolve_did_document(did)


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: uuid.UUID, registry: RegistryDep, session: SessionDep
) -> AgentResponse:
    return await _with_credentials(session, await registry.get_agent_by_id(agent_id))


@router.get("/{agent_id}/credentials")
async def agent_credentials(
    agent_id: uuid.UUID, registry: RegistryDep, session: SessionDep
) -> list[dict]:
    agent = await registry.get_agent_by_id(agent_id)
    return [e.model_dump(mode="json") for e in await _credential_inventory(session, agent.did)]


@router.get("/{agent_id}/did-document")
async def get_did_document(agent_id: uuid.UUID, registry: RegistryDep) -> dict:
    agent = await registry.get_agent_by_id(agent_id)
    return await registry.resolve_did_document(agent.did)


@router.post("/{agent_id}/sign", response_model=SignResponse, dependencies=[Depends(
    ControlPlaneGuard("identity_sign", target=path_param("agent_id")))])
async def sign_as_agent(
    agent_id: uuid.UUID, body: SignRequest, registry: RegistryDep
) -> SignResponse:
    """Sign a message with the agent's key.

    Only works for registry-custodied keys. Agents that hold their own key
    (the running agent services) must be asked to sign on their own endpoint --
    the registry does not have their private key and says so.

    PHASE 4.5 -- S-6: this signs an ARBITRARY message with an agent's key, so
    unauthenticated it forges any DID proof in the system, including the
    control-plane proofs that protect the ANS. It now requires the
    `identity_admin` role. See app/api/routes/identity.py for the full path.
    """
    agent = await registry.get_agent_by_id(agent_id)
    return SignResponse(**await registry.sign_as_agent(agent.did, body.message))


@router.post("/{agent_id}/status", response_model=AgentResponse, dependencies=[Depends(
    ControlPlaneGuard("agent_status_change", target=path_param("agent_id")))])
async def change_status(
    agent_id: uuid.UUID, body: StatusChangeRequest, registry: RegistryDep
) -> AgentResponse:
    agent = await registry.get_agent_by_id(agent_id)
    if body.status == AgentStatus.TERMINATED:
        updated = await registry.terminate(agent.did, body.reason or "OPERATOR_REQUEST")
    else:
        updated = await registry.set_status(agent.did, body.status, body.reason)
    return AgentResponse.from_model(updated)


@router.get("/{agent_id}/audit")
async def agent_audit(agent_id: uuid.UUID, registry: RegistryDep, limit: int = 100) -> list[dict]:
    agent = await registry.get_agent_by_id(agent_id)
    return await registry.audit.query(agent_did=agent.did, limit=limit)
