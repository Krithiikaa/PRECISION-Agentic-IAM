"""ANS registry: registration, liveness, resolution, deregistration.

Responsibility boundary, kept deliberately narrow:

    ANS answers  "WHICH AGENT SHOULD I CONTACT?"
    ANS does NOT answer  "IS THIS REQUEST AUTHORIZED?"   <- Phase 4 (PDP/AEM)

Nothing in this module grants access to anything. A discovery result is a
routing hint that the caller must still authenticate and authorize.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ans.proof import (
    ProofReason,
    RegistrationPayload,
    capabilities_are_valid,
    endpoint_is_valid,
    timestamp_is_fresh,
)
from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.errors import IdentityError, NotFoundError
from app.core.logging import get_logger
from app.credentials.vc import parse_iso
from app.db.models.agent import AgentStatus
from app.db.models.ans import (
    ANSAgent,
    ANSAgentCredential,
    ANSCapability,
    ANSHeartbeat,
    ANSRegistrationProof,
    ANSStatus,
)
from app.db.models.credential import Credential, CredentialStatusValue
from app.db.repositories.agents import AgentRepository
from app.identity.did import is_agent_did
from app.identity.did_document import public_key_from_document
from app.identity.signer import verify_signature
from app.monitoring.events import Event, EventType

log = get_logger("ans.registry")

# Identity states that make an agent ineligible to be in the registry at all.
INELIGIBLE_IDENTITY_STATES = (AgentStatus.TERMINATED, AgentStatus.SUSPENDED)


@dataclass
class RegistrationResult:
    accepted: bool
    reason: str
    detail: str
    agent: ANSAgent | None = None
    checks: list[dict[str, Any]] = None  # type: ignore[assignment]

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "detail": self.detail,
            "checks": self.checks or [],
            "agent": describe_agent(self.agent) if self.agent else None,
        }


def describe_agent(agent: ANSAgent, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    age = (now - agent.last_seen).total_seconds() if agent.last_seen else None
    return {
        "did": agent.did,
        "name": agent.name,
        "agent_type": agent.agent_type,
        "endpoint": agent.endpoint,
        "status": agent.status.value,
        "organization": agent.organization_did,
        "purpose": agent.purpose,
        "capabilities": agent.capability_names,
        "credentials": [
            {
                "credential_id": c.credential_id,
                "credential_type": c.credential_type,
                "status": c.status,
                "expires_at": c.expires_at.isoformat() if c.expires_at else None,
            }
            for c in agent.credentials
        ],
        "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
        "seconds_since_heartbeat": round(age, 1) if age is not None else None,
        "registered_at": agent.registered_at.isoformat(),
        "active_tasks": agent.active_tasks,
        "health": {
            "ok": agent.last_health_ok,
            "latency_ms": agent.health_latency_ms,
            "checked_at": agent.last_health_at.isoformat() if agent.last_health_at else None,
        },
        # NULL until Phase 10 owns a trust engine; not invented here.
        "trust_score": agent.trust_score,
        "metadata": agent.agent_metadata,
    }


class ANSRegistry:
    def __init__(self, session: AsyncSession, settings: Settings | None = None) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.agents = AgentRepository(session)
        self.audit = AuditService(session)

    # --- lookups ---------------------------------------------------------
    async def get(self, did: str) -> ANSAgent | None:
        result = await self.session.execute(select(ANSAgent).where(ANSAgent.did == did))
        return result.scalar_one_or_none()

    async def list_agents(
        self, *, status: ANSStatus | None = None, capability: str | None = None
    ) -> list[ANSAgent]:
        stmt = select(ANSAgent).order_by(ANSAgent.did)
        if status is not None:
            stmt = stmt.where(ANSAgent.status == status)
        if capability:
            stmt = stmt.join(ANSCapability, ANSCapability.agent_did == ANSAgent.did).where(
                ANSCapability.capability == capability
            )
        result = await self.session.execute(stmt)
        return list(result.scalars().unique().all())

    async def capability_catalogue(self) -> list[dict[str, Any]]:
        """Every capability the registry knows about, with who offers it."""
        result = await self.session.execute(
            select(
                ANSCapability.capability,
                func.count(ANSCapability.agent_did).label("providers"),
            ).group_by(ANSCapability.capability).order_by(ANSCapability.capability)
        )
        catalogue = []
        for capability, providers in result.all():
            agents = await self.session.execute(
                select(ANSAgent.did, ANSAgent.status)
                .join(ANSCapability, ANSCapability.agent_did == ANSAgent.did)
                .where(ANSCapability.capability == capability)
            )
            rows = agents.all()
            catalogue.append({
                "capability": capability,
                "providers": providers,
                "active_providers": sum(1 for _, s in rows if s == ANSStatus.ACTIVE),
                "agents": [did for did, _ in rows],
            })
        return catalogue

    # --- registration ----------------------------------------------------
    async def register(
        self,
        payload: RegistrationPayload,
        signature_b64: str,
        *,
        source_ip: str | None = None,
        now: datetime | None = None,
    ) -> RegistrationResult:
        """Register or update an agent, only on a valid proof of DID control."""
        now = now or datetime.now(timezone.utc)
        checks: list[dict[str, Any]] = []

        def check(name: str, passed: bool, detail: str) -> bool:
            checks.append({"name": name, "passed": passed, "detail": detail})
            return passed

        async def reject(reason: str, detail: str) -> RegistrationResult:
            await self._record_proof(payload, signature_b64, None, False, reason,
                                     detail, source_ip, now)
            await self.audit.record(
                Event(
                    EventType.ANS_REGISTRATION_REJECTED,
                    agent_did=payload.did,
                    resource="ans_registry",
                    action="REGISTER",
                    decision="REJECTED",
                    reason=reason,
                    metadata={"detail": detail, "endpoint": payload.endpoint,
                              "checks": checks, "source_ip": source_ip},
                )
            )
            if reason == ProofReason.INVALID_PROOF:
                await self.audit.record(
                    Event(EventType.ANS_SIGNATURE_INVALID, agent_did=payload.did,
                          decision="REJECTED", reason=reason,
                          metadata={"endpoint": payload.endpoint})
                )
            log.warning("ans_registration_rejected", did=payload.did, reason=reason,
                        detail=detail)
            return RegistrationResult(False, reason, detail, checks=checks)

        # 1. DID syntax
        if not is_agent_did(payload.did):
            check("did_format", False, f"{payload.did!r} is not a well-formed agent DID")
            return await reject(ProofReason.MALFORMED, f"malformed DID {payload.did!r}")
        check("did_format", True, payload.did)

        # 2/3. The identity must already exist in the Phase 1 registry. ANS
        # never mints identities; it only names ones that were issued properly.
        agent_record = await self.agents.get_by_did(payload.did)
        if agent_record is None:
            check("did_registered", False, "not present in the agent registry")
            return await reject(ProofReason.DID_UNKNOWN,
                                f"{payload.did} is not a registered agent identity")
        check("did_registered", True, f"identity status {agent_record.status.value}")

        if agent_record.status in INELIGIBLE_IDENTITY_STATES:
            check("identity_eligible", False,
                  f"identity is {agent_record.status.value}")
            return await reject(
                ProofReason.AGENT_NOT_ELIGIBLE,
                f"{payload.did} is {agent_record.status.value} and may not be registered",
            )
        check("identity_eligible", True, agent_record.status.value)

        # 4. Public key from the published DID Document -- the same trust path
        # a third party would take.
        document = await self.agents.get_did_document(payload.did)
        if document is None:
            check("did_document", False, "no DID Document published")
            return await reject(ProofReason.DID_NOT_RESOLVABLE,
                                f"no DID Document for {payload.did}")
        try:
            public_key = public_key_from_document(document.document)
            verification_method = document.document["verificationMethod"][0]["id"]
        except (ValueError, KeyError, IndexError) as exc:
            check("did_document", False, f"unusable DID Document: {exc}")
            return await reject(ProofReason.DID_NOT_RESOLVABLE, str(exc))
        check("did_document", True, f"public key from {verification_method}")

        # 5/6. Shape of what is being claimed.
        ok, detail = endpoint_is_valid(payload.endpoint)
        if not check("endpoint", ok, detail):
            return await reject(ProofReason.ENDPOINT_INVALID, detail)
        ok, detail = capabilities_are_valid(payload.capabilities)
        if not check("capabilities", ok, detail):
            return await reject(ProofReason.CAPABILITIES_INVALID, detail)

        # 7. Freshness, so an old captured registration cannot be replayed
        # after the nonce table is pruned.
        ok, detail = timestamp_is_fresh(
            payload.timestamp, now=now,
            window_seconds=self.settings.ans_registration_freshness_seconds,
        )
        if not check("timestamp", ok, detail):
            return await reject(ProofReason.STALE_TIMESTAMP, detail)

        # 8. Nonce single-use. Only accepted registrations consume one.
        used = await self.session.execute(
            select(ANSRegistrationProof).where(
                ANSRegistrationProof.agent_did == payload.did,
                ANSRegistrationProof.nonce == payload.nonce,
                ANSRegistrationProof.accepted.is_(True),
            )
        )
        if used.scalar_one_or_none() is not None:
            check("nonce", False, "this nonce was already used for a registration")
            return await reject(ProofReason.NONCE_REPLAYED,
                                f"nonce {payload.nonce} has already been used")
        check("nonce", True, "unused")

        # 9. The proof itself. This is what stops an attacker pointing an
        # existing DID at an endpoint they control.
        result = verify_signature(public_key, payload.signing_bytes(), signature_b64,
                                  verification_method)
        if not check("registration_proof", result.valid,
                     "signature verifies against the DID Document"
                     if result.valid else result.reason):
            return await reject(ProofReason.INVALID_PROOF, result.reason)

        # --- accepted -----------------------------------------------------
        existing = await self.get(payload.did)
        is_update = existing is not None
        agent = existing or ANSAgent(
            did=payload.did,
            name=agent_record.name,
            registered_at=now,
        )
        agent.name = agent_record.name
        agent.agent_type = agent_record.agent_type.value
        agent.purpose = agent_record.purpose
        agent.endpoint = payload.endpoint
        agent.organization_did = payload.organization or agent_record.controller_did
        agent.status = ANSStatus.ACTIVE
        agent.last_seen = now
        if not is_update:
            self.session.add(agent)
        await self.session.flush()

        await self._replace_capabilities(payload.did, payload.capabilities, now)
        indexed = await self._index_credentials(payload.did, now)

        await self._record_proof(payload, signature_b64, verification_method, True,
                                 ProofReason.VALID, "registration accepted", source_ip, now)
        await self.session.flush()
        await self.session.refresh(agent, ["capabilities", "credentials"])

        await self.audit.record(
            Event(
                EventType.ANS_AGENT_UPDATED if is_update else EventType.ANS_AGENT_REGISTERED,
                agent_did=payload.did,
                resource="ans_registry",
                action="REGISTER",
                decision="ACCEPTED",
                metadata={
                    "endpoint": payload.endpoint,
                    "capabilities": payload.capabilities,
                    "organization": agent.organization_did,
                    "credentials_indexed": indexed,
                    "update": is_update,
                },
            )
        )
        log.info("ans_registration_accepted", did=payload.did,
                 endpoint=payload.endpoint, update=is_update)
        return RegistrationResult(True, ProofReason.VALID,
                                  "registration accepted", agent, checks)

    async def _replace_capabilities(
        self, did: str, capabilities: list[str], now: datetime
    ) -> None:
        await self.session.execute(
            delete(ANSCapability).where(ANSCapability.agent_did == did)
        )
        for capability in sorted(set(capabilities)):
            self.session.add(
                ANSCapability(agent_did=did, capability=capability, created_at=now)
            )
        await self.session.flush()

    async def _index_credentials(self, did: str, now: datetime) -> int:
        """Refresh the credential index from live Phase 2 state.

        This is an index for fast filtering, never a verdict: discovery
        re-verifies with the Phase 2 verifier before returning an agent for a
        credential-constrained query.
        """
        await self.session.execute(
            delete(ANSAgentCredential).where(ANSAgentCredential.agent_did == did)
        )
        result = await self.session.execute(
            select(Credential).where(Credential.subject_did == did)
        )
        count = 0
        for credential in result.scalars().unique().all():
            stored = credential.status_record.status if credential.status_record else None
            status = stored.value if stored else "UNKNOWN"
            if status == CredentialStatusValue.ACTIVE.value and credential.expires_at <= now:
                status = CredentialStatusValue.EXPIRED.value
            self.session.add(
                ANSAgentCredential(
                    agent_did=did,
                    credential_id=credential.credential_id,
                    credential_type=credential.credential_type,
                    status=status,
                    expires_at=credential.expires_at,
                    indexed_at=now,
                )
            )
            count += 1
        await self.session.flush()
        return count

    async def _record_proof(
        self, payload: RegistrationPayload, signature: str, verification_method: str | None,
        accepted: bool, reason: str, detail: str, source_ip: str | None, now: datetime,
    ) -> None:
        self.session.add(
            ANSRegistrationProof(
                agent_did=payload.did,
                nonce=payload.nonce,
                payload=payload.to_dict(),
                signature=signature[:256],
                verification_method=verification_method,
                accepted=accepted,
                reason=reason,
                detail=detail,
                source_ip=source_ip,
                created_at=now,
            )
        )
        await self.session.flush()

    # --- liveness --------------------------------------------------------
    async def heartbeat(
        self,
        did: str,
        *,
        status: ANSStatus = ANSStatus.ACTIVE,
        endpoint: str | None = None,
        active_tasks: int | None = None,
        now: datetime | None = None,
    ) -> ANSAgent:
        now = now or datetime.now(timezone.utc)
        agent = await self.get(did)
        if agent is None:
            raise NotFoundError(f"{did} is not registered with the ANS")

        # A heartbeat may report liveness and load; it may NOT move the
        # endpoint. Changing where traffic goes requires a fresh signed
        # registration, otherwise the proof would be bypassable.
        if endpoint and endpoint != agent.endpoint:
            raise IdentityError(
                f"Heartbeat cannot change the endpoint for {did}. "
                f"Re-register with a signed proof to move from "
                f"{agent.endpoint!r} to {endpoint!r}."
            )

        if agent.status in (ANSStatus.REVOKED, ANSStatus.TERMINATED):
            raise IdentityError(
                f"{did} is {agent.status.value} in the registry and cannot heartbeat"
            )

        previous = agent.status
        agent.status = status
        agent.last_seen = now
        if active_tasks is not None:
            agent.active_tasks = active_tasks

        # Every heartbeat is persisted here: this is the durable liveness
        # record, and the sweeper and ranking both depend on it.
        self.session.add(
            ANSHeartbeat(agent_did=did, occurred_at=now, status=status.value,
                         endpoint=agent.endpoint, active_tasks=active_tasks)
        )
        await self.session.flush()

        # Only INFORMATIVE heartbeats become audit events. Seven agents
        # reporting every 15s produced 60% of the entire audit trail, burying
        # the events an operator actually needs and pushing them out of any
        # bounded query. A routine "still alive" carries no information; a
        # status change does.
        if previous != status:
            await self.audit.record(
                Event(EventType.ANS_HEARTBEAT_RECEIVED, agent_did=did,
                      reason="STATUS_CHANGED",
                      metadata={"status": status.value,
                                "previous_status": previous.value,
                                "active_tasks": active_tasks,
                                "recovered": previous in (ANSStatus.STALE,
                                                          ANSStatus.DEGRADED,
                                                          ANSStatus.OFFLINE)})
            )
        return agent

    async def sweep(self, now: datetime | None = None) -> dict[str, list[str]]:
        """Demote agents whose heartbeats have stopped.

        Liveness is observed, not asserted: an agent is STALE or OFFLINE
        because it stopped reporting, regardless of what it last claimed.
        """
        now = now or datetime.now(timezone.utc)
        stale_after = now - timedelta(seconds=self.settings.ans_agent_timeout_seconds)
        offline_after = now - timedelta(seconds=self.settings.ans_agent_offline_seconds)
        moved: dict[str, list[str]] = {"stale": [], "offline": []}

        result = await self.session.execute(
            select(ANSAgent).where(
                ANSAgent.status.notin_(
                    [ANSStatus.OFFLINE, ANSStatus.REVOKED, ANSStatus.TERMINATED]
                )
            )
        )
        for agent in result.scalars().unique().all():
            last = agent.last_seen or agent.registered_at
            if last <= offline_after:
                agent.status = ANSStatus.OFFLINE
                moved["offline"].append(agent.did)
                await self.audit.record(
                    Event(EventType.ANS_AGENT_OFFLINE, agent_did=agent.did,
                          reason="HEARTBEAT_TIMEOUT",
                          metadata={"last_seen": last.isoformat(),
                                    "threshold_seconds":
                                        self.settings.ans_agent_offline_seconds})
                )
            elif last <= stale_after and agent.status != ANSStatus.STALE:
                agent.status = ANSStatus.STALE
                moved["stale"].append(agent.did)
                await self.audit.record(
                    Event(EventType.ANS_AGENT_STALE, agent_did=agent.did,
                          reason="HEARTBEAT_OVERDUE",
                          metadata={"last_seen": last.isoformat(),
                                    "threshold_seconds":
                                        self.settings.ans_agent_timeout_seconds})
                )
        await self.session.flush()
        return moved

    async def reconcile_identities(self, now: datetime | None = None) -> list[str]:
        """Mirror upstream identity revocation into the registry.

        A terminated or suspended identity must stop being handed out promptly,
        without waiting for its heartbeat to lapse.
        """
        now = now or datetime.now(timezone.utc)
        revoked: list[str] = []
        result = await self.session.execute(
            select(ANSAgent).where(
                ANSAgent.status.notin_([ANSStatus.REVOKED, ANSStatus.TERMINATED])
            )
        )
        for agent in result.scalars().unique().all():
            identity = await self.agents.get_by_did(agent.did)
            if identity is None or identity.status in INELIGIBLE_IDENTITY_STATES:
                state = identity.status.value if identity else "MISSING"
                agent.status = (
                    ANSStatus.TERMINATED
                    if identity and identity.status == AgentStatus.TERMINATED
                    else ANSStatus.REVOKED
                )
                revoked.append(agent.did)
                await self.audit.record(
                    Event(EventType.ANS_AGENT_REVOKED, agent_did=agent.did,
                          reason="IDENTITY_NOT_ELIGIBLE",
                          metadata={"identity_status": state,
                                    "ans_status": agent.status.value})
                )
        await self.session.flush()
        return revoked

    # --- health probing --------------------------------------------------
    async def probe(self, did: str, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
        """Actually call the agent's /health. Registry claims vs observed reality."""
        import time

        agent = await self.get(did)
        if agent is None:
            raise NotFoundError(f"{did} is not registered with the ANS")

        owns_client = client is None
        client = client or httpx.AsyncClient(
            timeout=self.settings.ans_health_probe_timeout_seconds
        )
        started = time.perf_counter()
        ok, detail, body = False, "", None
        try:
            response = await client.get(f"{agent.endpoint.rstrip('/')}/health")
            latency = (time.perf_counter() - started) * 1000
            ok = response.status_code == 200
            detail = f"HTTP {response.status_code}"
            if ok:
                body = response.json()
                # The endpoint must answer for the DID it is registered under:
                # a healthy service at the wrong identity is not this agent.
                if body.get("did") and body["did"] != did:
                    ok, detail = False, (
                        f"endpoint answers for {body['did']}, not {did}"
                    )
        except httpx.HTTPError as exc:
            latency = (time.perf_counter() - started) * 1000
            detail = f"{type(exc).__name__}: {exc}"
        finally:
            if owns_client:
                await client.aclose()

        now = datetime.now(timezone.utc)
        agent.last_health_ok = ok
        agent.health_latency_ms = round(latency, 1)
        agent.last_health_at = now
        if not ok and agent.status == ANSStatus.ACTIVE:
            agent.status = ANSStatus.DEGRADED
        await self.session.flush()

        return {"did": did, "endpoint": agent.endpoint, "healthy": ok,
                "detail": detail, "latency_ms": round(latency, 1),
                "status": agent.status.value, "agent_health": body}

    # --- deregistration --------------------------------------------------
    async def unregister(self, did: str, reason: str = "GRACEFUL_SHUTDOWN") -> ANSAgent:
        agent = await self.get(did)
        if agent is None:
            raise NotFoundError(f"{did} is not registered with the ANS")
        agent.status = ANSStatus.OFFLINE
        agent.active_tasks = 0
        await self.session.flush()
        await self.audit.record(
            Event(EventType.ANS_AGENT_OFFLINE, agent_did=did, action="UNREGISTER",
                  decision="OFFLINE", reason=reason,
                  metadata={"endpoint": agent.endpoint})
        )
        log.info("ans_agent_unregistered", did=did, reason=reason)
        return agent

    # --- resolution ------------------------------------------------------
    async def resolve(self, did: str) -> dict[str, Any]:
        """Resolve a DID to everything needed to contact the agent.

        The DID Document comes from the Phase 1 registry -- ANS does not keep a
        second copy and cannot disagree with the identity authority about what
        an agent's public key is.
        """
        agent = await self.get(did)
        if agent is None:
            raise NotFoundError(f"{did} is not registered with the ANS")
        document = await self.agents.get_did_document(did)
        identity = await self.agents.get_by_did(did)

        await self.audit.record(
            Event(EventType.ANS_AGENT_RESOLVED, agent_did=did, action="RESOLVE",
                  metadata={"endpoint": agent.endpoint, "status": agent.status.value})
        )
        return {
            **describe_agent(agent),
            "did_document": document.document if document else None,
            "identity_status": identity.status.value if identity else "UNKNOWN",
        }
