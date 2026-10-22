"""Agent Registry: the identity lifecycle authority for agents.

Every agent that exists anywhere in this system is created here, which is what
guarantees the invariant that an agent always has a DID, a key pair held in the
KeyStore and a published DID Document before it can do anything.

Lifecycle:
    CREATE -> DID ASSIGNMENT -> KEY GENERATION -> DID DOCUMENT -> ACTIVE
                                                              -> SUSPENDED
                                                              -> TERMINATED
"""
from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.errors import ConflictError, IdentityError, NotFoundError
from app.db.models.agent import Agent, AgentKey, AgentStatus, AgentType, KeyStatus
from app.db.repositories.agents import AgentRepository
from app.identity.did import build_agent_did, key_id, validate_slug
from app.identity.did_document import build_did_document, public_key_from_document
from app.identity.keys import KeyStore
from app.identity.multibase import decode_ed25519_public_key
from app.identity.signer import Signer, VerificationResult, verify_signature
from app.monitoring.events import Event, EventType


@dataclass(frozen=True)
class _KeyMaterial:
    """Public key facts the registry persists, whoever generated the key."""

    kid: str
    algorithm: str
    public_key_multibase: str
    public_key_b64: str
    keystore_backend: str
    keystore_ref: str


@dataclass
class AgentSpec:
    slug: str
    name: str
    agent_type: AgentType
    purpose: str | None = None
    capabilities: list[str] = field(default_factory=list)
    endpoint: str | None = None
    owner: str | None = None
    controller_did: str | None = None
    metadata: dict = field(default_factory=dict)
    parent_did: str | None = None
    ttl_seconds: int | None = None
    # When set, the agent generated its own key pair in its own keystore and is
    # registering only the public half. The registry then never holds, and never
    # could hold, that agent's private key.
    public_key_multibase: str | None = None


class AgentRegistry:
    def __init__(
        self,
        session: AsyncSession,
        keystore: KeyStore,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.keystore = keystore
        self.settings = settings or get_settings()
        self.repo = AgentRepository(session)
        self.audit = AuditService(session)
        self.signer = Signer(keystore)

    # --- creation --------------------------------------------------------
    async def create_agent(self, spec: AgentSpec) -> Agent:
        validate_slug(spec.slug)
        if await self.repo.get_by_slug(spec.slug) is not None:
            raise ConflictError(f"An agent with slug {spec.slug!r} already exists")

        did = build_agent_did(spec.slug, self.settings.did_method)
        if await self.repo.get_by_did(did) is not None:
            raise ConflictError(f"DID {did} is already registered")

        parent: Agent | None = None
        if spec.parent_did:
            parent = await self.repo.get_by_did(spec.parent_did)
            if parent is None:
                raise NotFoundError(f"Parent agent {spec.parent_did} not found")

        controller = spec.controller_did or self.settings.organization_did
        kid = key_id(did)

        if spec.public_key_multibase:
            # Agent-held key: validate the encoding, store the public half only.
            try:
                decode_ed25519_public_key(spec.public_key_multibase)
            except Exception as exc:  # noqa: BLE001
                raise IdentityError(f"Invalid publicKeyMultibase: {exc}") from exc
            key_material = _KeyMaterial(
                kid=kid,
                algorithm="Ed25519",
                public_key_multibase=spec.public_key_multibase,
                public_key_b64=base64.b64encode(
                    decode_ed25519_public_key(spec.public_key_multibase)
                ).decode(),
                keystore_backend="external",
                keystore_ref=f"external://{spec.slug}",
            )
            rollback_key = False
        else:
            # Registry-held key: generated before persistence, removed again if
            # the transaction fails so a retry can succeed.
            if self.keystore.exists(kid):
                raise ConflictError(f"Key material for {kid} already exists in the keystore")
            handle = self.keystore.generate_key(kid)
            key_material = _KeyMaterial(
                kid=handle.kid,
                algorithm=handle.algorithm,
                public_key_multibase=handle.public_key_multibase,
                public_key_b64=handle.public_key_b64,
                keystore_backend=self.keystore.backend_name,
                keystore_ref=handle.keystore_ref,
            )
            rollback_key = True

        try:
            expires_at = (
                datetime.now(timezone.utc) + timedelta(seconds=spec.ttl_seconds)
                if spec.ttl_seconds
                else None
            )
            agent = Agent(
                slug=spec.slug,
                did=did,
                name=spec.name,
                agent_type=spec.agent_type,
                purpose=spec.purpose,
                controller_did=controller,
                owner=spec.owner,
                status=AgentStatus.PROVISIONING,
                endpoint=spec.endpoint,
                capabilities=list(spec.capabilities),
                agent_metadata=dict(spec.metadata),
                parent_agent_id=parent.id if parent else None,
                expires_at=expires_at,
            )
            await self.repo.add_agent(agent)

            await self.repo.add_key(
                AgentKey(
                    agent_id=agent.id,
                    kid=key_material.kid,
                    algorithm=key_material.algorithm,
                    public_key_multibase=key_material.public_key_multibase,
                    public_key_b64=key_material.public_key_b64,
                    keystore_backend=key_material.keystore_backend,
                    keystore_ref=key_material.keystore_ref,
                    status=KeyStatus.ACTIVE,
                )
            )

            document = build_did_document(
                did=did,
                controller=controller,
                kid=key_material.kid,
                public_key_multibase=key_material.public_key_multibase,
                service_endpoint=spec.endpoint,
                agent_name=spec.name,
                agent_type=spec.agent_type.value,
                capabilities=list(spec.capabilities),
                status=AgentStatus.ACTIVE.value,
                parent_did=parent.did if parent else None,
            )
            await self.repo.upsert_did_document(agent.id, did, document)

            if parent is not None:
                await self.repo.add_relationship(
                    parent_agent_id=parent.id,
                    child_agent_id=agent.id,
                    relationship_type="DELEGATES",
                    expires_at=expires_at,
                )

            agent.status = AgentStatus.ACTIVE
            await self.session.flush()
            # Load the relationships eagerly: callers (and the API serialisers)
            # run outside the async IO context and must not trigger lazy loads.
            await self.session.refresh(agent, ["keys", "did_document", "parent"])

            base = {"agent_id": str(agent.id), "name": spec.name}
            await self.audit.record(
                Event(EventType.AGENT_CREATED, agent_did=did,
                      metadata={**base, "agent_type": spec.agent_type.value,
                                "capabilities": list(spec.capabilities),
                                "parent_did": parent.did if parent else None})
            )
            await self.audit.record(
                Event(EventType.DID_ASSIGNED, agent_did=did,
                      metadata={**base, "controller": controller})
            )
            await self.audit.record(
                Event(EventType.KEY_GENERATED, agent_did=did,
                      metadata={**base, "kid": key_material.kid,
                                "algorithm": key_material.algorithm,
                                "keystore_backend": key_material.keystore_backend,
                                "key_custody": "agent" if spec.public_key_multibase else "registry"})
            )
            await self.audit.record(
                Event(EventType.DID_DOCUMENT_PUBLISHED, agent_did=did,
                      metadata={**base, "version": 1})
            )
            await self.audit.record(
                Event(EventType.AGENT_ACTIVATED, agent_did=did, metadata=base)
            )
            return agent
        except IntegrityError as exc:
            if rollback_key:
                self.keystore.delete(key_material.kid)
            raise ConflictError(f"Agent {spec.slug!r} could not be registered: {exc.orig}") from exc
        except Exception:
            if rollback_key:
                self.keystore.delete(key_material.kid)
            raise

    # --- resolution ------------------------------------------------------
    async def get_agent(self, did: str) -> Agent:
        agent = await self.repo.get_by_did(did)
        if agent is None:
            raise NotFoundError(f"No agent registered for DID {did}")
        return agent

    async def get_agent_by_id(self, agent_id: uuid.UUID) -> Agent:
        agent = await self.repo.get_by_id(agent_id)
        if agent is None:
            raise NotFoundError(f"No agent with id {agent_id}")
        return agent

    async def resolve_did_document(self, did: str) -> dict:
        record = await self.repo.get_did_document(did)
        if record is None:
            raise NotFoundError(f"No DID Document published for {did}")
        return record.document

    # --- lifecycle -------------------------------------------------------
    async def set_status(self, did: str, status: AgentStatus, reason: str | None = None) -> Agent:
        agent = await self.get_agent(did)
        terminated_at = datetime.now(timezone.utc) if status == AgentStatus.TERMINATED else None
        await self.repo.set_status(agent, status, terminated_at)

        record = await self.repo.get_did_document(did)
        if record is not None:
            document = dict(record.document)
            metadata = dict(document.get("agentMetadata") or {})
            metadata["status"] = status.value
            document["agentMetadata"] = metadata
            await self.repo.upsert_did_document(agent.id, did, document)

        event_type = {
            AgentStatus.ACTIVE: EventType.AGENT_ACTIVATED,
            AgentStatus.SUSPENDED: EventType.AGENT_SUSPENDED,
            AgentStatus.TERMINATED: EventType.AGENT_TERMINATED,
        }.get(status)
        if event_type:
            await self.audit.record(
                Event(event_type, agent_did=did, reason=reason,
                      metadata={"agent_id": str(agent.id), "status": status.value})
            )
        return agent

    async def terminate(self, did: str, reason: str = "OPERATOR_REQUEST") -> Agent:
        """Terminate the agent and destroy its signing key.

        Key destruction is what makes termination meaningful: a terminated
        agent cannot produce a valid signature again even if its record is
        later resurrected.
        """
        agent = await self.get_agent(did)
        for key in agent.keys:
            if key.status == KeyStatus.ACTIVE:
                key.status = KeyStatus.REVOKED
                self.keystore.delete(key.kid)
        await self.session.flush()
        return await self.set_status(did, AgentStatus.TERMINATED, reason)

    # --- cryptographic operations ---------------------------------------
    async def sign_as_agent(self, did: str, message: str) -> dict:
        agent = await self.get_agent(did)
        if agent.status != AgentStatus.ACTIVE:
            raise IdentityError(
                f"Agent {did} is {agent.status.value}; only ACTIVE agents may sign"
            )
        key = await self.repo.get_active_key(agent.id)
        if key is None:
            raise IdentityError(f"Agent {did} has no active key")
        if key.keystore_backend == "external":
            raise IdentityError(
                f"Agent {did} holds its own key ({key.keystore_ref}); the registry "
                "cannot sign on its behalf. Ask the agent service to sign."
            )

        result = self.signer.sign(key.kid, message)
        await self.repo.touch_activity(agent, datetime.now(timezone.utc))
        await self.audit.record(
            Event(EventType.SIGNATURE_CREATED, agent_did=did,
                  metadata={"kid": key.kid, "message_length": len(message)})
        )
        return {
            "did": did,
            "verification_method": key.kid,
            "algorithm": result.algorithm,
            "message": message,
            "signature": result.signature_b64,
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def verify_agent_signature(
        self, did: str, message: str, signature_b64: str
    ) -> VerificationResult:
        """Verify against the public key published in the agent's DID Document.

        Deliberately resolves through the DID Document rather than the key
        table: that is the path a third party would take, so this exercises the
        same trust chain the A2A layer will use in Phase 7.
        """
        record = await self.repo.get_did_document(did)
        if record is None:
            result = VerificationResult(False, f"DID_NOT_RESOLVABLE: {did}")
        else:
            try:
                public_key = public_key_from_document(record.document)
            except ValueError as exc:
                result = VerificationResult(False, f"NO_VERIFICATION_METHOD: {exc}")
            else:
                kid = record.document["verificationMethod"][0]["id"]
                result = verify_signature(public_key, message, signature_b64, kid)

        await self.audit.record(
            Event(
                EventType.SIGNATURE_VERIFIED if result.valid else EventType.SIGNATURE_INVALID,
                agent_did=did,
                decision="VALID" if result.valid else "INVALID",
                reason=result.reason,
                metadata={"verification_method": result.verification_method},
            )
        )
        return result

    async def list_agents(self, **kwargs) -> list[Agent]:
        return await self.repo.list_agents(**kwargs)
