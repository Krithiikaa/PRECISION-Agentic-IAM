"""Agent identity endpoints."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.agents.delegation import (
    DelegatedScope,
    DelegationKind,
    DelegationRefused,
    DelegationService,
    SpawnRequest,
)
from app.agents.registry import AgentSpec
from app.api.deps import KeyStoreDep, RegistryDep, SessionDep
from app.api.schemas import (
    AgentCredentialSummary,
    AgentResponse,
    CreateAgentRequest,
    SignRequest,
    SignResponse,
    StatusChangeRequest,
)
from app.controlplane.guard import ControlPlaneGuard, body_key, fixed, path_param
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


@router.get("", response_model=list[AgentResponse], dependencies=[Depends(
    ControlPlaneGuard("identity_read", target=fixed("agent_registry")))])
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


@router.get("/did/{did}", response_model=AgentResponse, dependencies=[Depends(
    ControlPlaneGuard("identity_read", target=path_param("did")))])
async def get_agent_by_did(did: str, registry: RegistryDep, session: SessionDep) -> AgentResponse:
    return await _with_credentials(session, await registry.get_agent(did))


@router.get("/did/{did}/credentials", dependencies=[Depends(
    ControlPlaneGuard("credential_read", target=path_param("did")))])
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


@router.get("/{agent_id}", response_model=AgentResponse, dependencies=[Depends(
    ControlPlaneGuard("identity_read", target=path_param("agent_id")))])
async def get_agent(
    agent_id: uuid.UUID, registry: RegistryDep, session: SessionDep
) -> AgentResponse:
    return await _with_credentials(session, await registry.get_agent_by_id(agent_id))


@router.get("/{agent_id}/credentials", dependencies=[Depends(
    ControlPlaneGuard("credential_read", target=path_param("agent_id")))])
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


@router.get("/{agent_id}/audit", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=path_param("agent_id")))])
async def agent_audit(agent_id: uuid.UUID, registry: RegistryDep, limit: int = 100) -> list[dict]:
    agent = await registry.get_agent_by_id(agent_id)
    return await registry.audit.query(agent_did=agent.did, limit=limit)


# --- Delegated identities (CSA paper Table 3, R-63/64/65, R-94) -----------
class DelegatedScopeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capability: str = Field(min_length=1, max_length=64)
    actions: list[str] | None = Field(default=None, max_length=32)
    resources: list[str] | None = Field(default=None, max_length=32)


class SpawnIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: DelegationKind
    task: str = Field(min_length=3, max_length=500)
    scopes: list[DelegatedScopeIn] = Field(default_factory=list, max_length=16)
    ttl_seconds: int | None = Field(default=None, ge=30)
    name: str | None = Field(default=None, max_length=128)


@router.post("/did/{did}/delegations", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(ControlPlaneGuard("agent_spawn", target=path_param("did")))])
async def spawn_delegated_agent(did: str, body: SpawnIn, request: Request,
                                session: SessionDep, keystore: KeyStoreDep) -> dict:
    """Create a sub-agent, ephemeral agent or fork of `did`.

    The child gets its own DID and key, a provenance credential naming its
    parent, and capability credentials that are narrowing copies of the
    parent's VERIFIED credentials. A refusal is committed (it is audited and
    feeds the anomaly detector) before the error is returned.
    """
    service = DelegationService(session, keystore)
    try:
        result = await service.spawn(SpawnRequest(
            parent_did=did, kind=body.kind, task=body.task,
            scopes=[DelegatedScope(s.capability, s.actions, s.resources) for s in body.scopes],
            ttl_seconds=body.ttl_seconds, name=body.name,
        ), requested_by=request.state.control_plane_principal.did)
    except DelegationRefused:
        await session.commit()
        raise
    return result.to_dict()


@router.get("/did/{did}/lineage", dependencies=[Depends(
    ControlPlaneGuard("identity_read", target=path_param("did")))])
async def lineage(did: str, session: SessionDep, keystore: KeyStoreDep) -> dict:
    """Ancestors and children of an agent: the delegation chain, both ways."""
    return await DelegationService(session, keystore).lineage(did)


class ProfileIn(BaseModel):
    """The inputs to an Agent ID profile. The SERVER computes the model hash."""
    model_config = ConfigDict(extra="forbid")
    creator: str = Field(max_length=255)
    deployer: str = Field(max_length=255)
    model: str | None = Field(default=None, max_length=128)
    model_digest: str | None = Field(default=None, max_length=128)
    system_prompt: str | None = Field(default=None, max_length=8000)
    scope_of_behavior: dict = Field(default_factory=dict)
    toolset: list[str] = Field(default_factory=list, max_length=64)
    expected_outcomes: str | None = Field(default=None, max_length=1000)
    limitations: str | None = Field(default=None, max_length=1000)


@router.put("/did/{did}/profile", dependencies=[Depends(
    ControlPlaneGuard("agent_profile_publish", target=path_param("did")))])
async def publish_profile(did: str, body: ProfileIn, registry: RegistryDep) -> dict:
    """Publish the rich Agent ID profile (CSA paper section 3.2) into the DID Document."""
    from app.core.config import get_settings
    from app.identity.profile import build_agent_profile

    agent = await registry.get_agent(did)
    settings = get_settings()
    profile = build_agent_profile(
        creator=body.creator, deployer=body.deployer, owner=agent.owner,
        controller=agent.controller_did, software_version=settings.agent_software_version,
        model=body.model, model_digest=body.model_digest, system_prompt=body.system_prompt,
        scope_of_behavior=body.scope_of_behavior, toolset=body.toolset,
        created_at=agent.created_at, expires_at=agent.expires_at,
        expected_outcomes=body.expected_outcomes, limitations=body.limitations)
    version = await registry.update_profile(did, profile, reason="profile published")
    return {"did": did, "document_version": version,
            "model_hash": profile["model"]["hash"]}


class EndpointIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint: str = Field(pattern=r"^https?://[^\s]{3,500}$")


@router.put("/did/{did}/endpoint", dependencies=[Depends(
    ControlPlaneGuard("agent_status_change", target=path_param("did")))])
async def update_endpoint(did: str, body: EndpointIn, registry: RegistryDep) -> dict:
    """Set the agent's service endpoint in its DID Document.

    Guarded as `agent_status_change`: redirecting where an agent is reached
    is as consequential as suspending it, and it is the same administrator.
    """
    version = await registry.update_endpoint(did, body.endpoint, reason="endpoint updated")
    return {"did": did, "endpoint": body.endpoint, "document_version": version}
