"""API request/response contracts.

Note what is absent by construction: there is no field anywhere in this module
that can carry a private key. The API cannot leak one because it has no shape
to put it in.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.db.models.agent import Agent, AgentKey, AgentStatus, AgentType


class CreateAgentRequest(BaseModel):
    slug: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
    name: str = Field(min_length=1, max_length=128)
    agent_type: AgentType
    purpose: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    endpoint: str | None = None
    owner: str | None = None
    controller_did: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    parent_did: str | None = Field(
        default=None,
        description="DID of the delegating agent, for ephemeral helper agents.",
    )
    ttl_seconds: int | None = Field(
        default=None, ge=1, description="Lifetime for ephemeral agents."
    )
    public_key_multibase: str | None = Field(
        default=None,
        description=(
            "Supply when the agent generated its own key pair and is registering "
            "only the public half. Omit to have the registry generate the key."
        ),
    )


class KeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    kid: str
    algorithm: str
    public_key_multibase: str
    public_key_b64: str
    keystore_backend: str
    status: str

    @classmethod
    def from_model(cls, key: AgentKey) -> "KeyResponse":
        return cls(
            kid=key.kid,
            algorithm=key.algorithm,
            public_key_multibase=key.public_key_multibase,
            public_key_b64=key.public_key_b64,
            keystore_backend=key.keystore_backend,
            status=key.status.value,
        )


class AgentCredentialSummary(BaseModel):
    """Credential inventory entry on an agent. Never carries key material."""

    credential_id: str
    credential_type: str
    issuer: str
    status: str
    issued_at: datetime
    expires_at: datetime
    seconds_remaining: int


class AgentResponse(BaseModel):
    id: uuid.UUID
    slug: str
    did: str
    name: str
    agent_type: AgentType
    purpose: str | None
    controller_did: str
    owner: str | None
    status: AgentStatus
    endpoint: str | None
    capabilities: list[str]
    metadata: dict[str, Any]
    parent_did: str | None
    active_key: KeyResponse | None
    credentials: list[AgentCredentialSummary] | None = Field(
        default=None,
        description="Populated on the detail endpoints; omitted from list responses.",
    )
    created_at: datetime
    expires_at: datetime | None
    terminated_at: datetime | None
    last_activity_at: datetime | None

    @classmethod
    def from_model(cls, agent: Agent) -> "AgentResponse":
        active = agent.active_key
        return cls(
            id=agent.id,
            slug=agent.slug,
            did=agent.did,
            name=agent.name,
            agent_type=agent.agent_type,
            purpose=agent.purpose,
            controller_did=agent.controller_did,
            owner=agent.owner,
            status=agent.status,
            endpoint=agent.endpoint,
            capabilities=list(agent.capabilities or []),
            metadata=dict(agent.agent_metadata or {}),
            parent_did=agent.parent.did if agent.parent else None,
            active_key=KeyResponse.from_model(active) if active else None,
            created_at=agent.created_at,
            expires_at=agent.expires_at,
            terminated_at=agent.terminated_at,
            last_activity_at=agent.last_activity_at,
        )


class SignRequest(BaseModel):
    message: str = Field(min_length=1, max_length=100_000)


class SignResponse(BaseModel):
    did: str
    verification_method: str
    algorithm: str
    message: str
    signature: str
    signed_at: str


class VerifyRequest(BaseModel):
    did: str
    message: str
    signature: str


class VerifyResponse(BaseModel):
    valid: bool
    reason: str
    did: str
    verification_method: str | None = None
    verified_at: str


class StatusChangeRequest(BaseModel):
    status: AgentStatus
    reason: str | None = None


class AuditEventIn(BaseModel):
    """Ingest contract for events emitted by agent processes."""

    event_type: str = Field(min_length=1, max_length=64)
    agent_did: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    resource: str | None = None
    action: str | None = None
    decision: str | None = None
    reason: str | None = None
    timestamp: str | None = None
    model_config = ConfigDict(extra="allow")


class ErrorResponse(BaseModel):
    error: str
    detail: str
