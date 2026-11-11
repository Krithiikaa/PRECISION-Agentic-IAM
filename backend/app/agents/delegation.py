"""Delegated agent identities: sub-agents, ephemeral agents and forks.

CSA paper Table 3 and section 3.4: R-63 (ephemeral agents get a new unique
ID per execution), R-64 (a fork is a distinct instance whose provenance is
part of its identity), R-65 (a sub-agent has a verifiable link to its parent,
e.g. through a VC), R-94 (the secure protocol for assuming runtime IDs:
request -> issuer verifies the primary DID and policy -> time-bound,
scope-limited credential -> use -> expiry or revocation), R-61 (no dormant
identities), R-253 (spawn-rate limits) and R-254 (delegation scoping and
re-delegation limits).

THE INVARIANT this module exists to hold:

    a child's authority  is a SUBSET of  what the parent can PROVE right now

"What the parent can prove" means capability credentials that pass the Phase 2
verifier at the moment of spawning -- not the capabilities the parent
DECLARES, which any agent can claim. Each delegated credential is a narrowing
copy of one verified parent credential: same capability, a subset of its
actions and resources, the same purpose, and an expiry no later than the
parent credential's own. A child therefore cannot:

  * gain a capability its parent does not hold         DELEGATION_EXCEEDS_PARENT
  * widen an action or resource set                      DELEGATION_EXCEEDS_PARENT
  * outlive the parent, or the credential it came from   (expiry is clamped)
  * re-delegate past the configured depth                DELEGATION_DEPTH_EXCEEDED
  * be spawned by a suspended, locked-out or untrusted parent
                                                         DELEGATION_PARENT_NOT_ELIGIBLE
  * be spawned faster than the configured rate           DELEGATION_RATE_EXCEEDED

Every refusal is audited as AGENT_SPAWN_REFUSED with one of those reasons,
and the anomaly detector treats a DELEGATION_* refusal as a delegation-
escalation attempt (a trust signal against the parent).

WHERE AUTHORIZATION IS DECIDED: whether a caller may spawn at all is a
control-plane operation (`agent_spawn`) decided in Rego by the same guard as
every other mutation. This module does not decide who may spawn; it enforces
what a spawn may contain. The child then holds ordinary credentials, so
everything it later does is decided by the same PDP as any other agent.

Parent containment cascades to children (app/sessions/authority.py), so a
sub-agent never outlives its parent's compromise.
"""
from __future__ import annotations

import enum
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.registry import AgentRegistry, AgentSpec
from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.errors import ConflictError
from app.core.logging import get_logger
from app.credentials.issuer import CredentialIssuer, IssueRequest
from app.credentials.vc import CredentialType, credential_claims
from app.credentials.verifier import CredentialVerifier
from app.db.models.agent import Agent, AgentStatus, AgentType
from app.db.models.audit import AuditEvent
from app.db.models.credential import Credential, CredentialStatus, CredentialStatusValue
from app.db.models.security import SessionState, TrustLevel
from app.identity.keys import KeyStore
from app.identity.profile import build_agent_profile
from app.monitoring.events import Event, EventType
from app.sessions.sss import SessionStateSynchronizer
from app.trust.engine import TrustEngine

log = get_logger("agents.delegation")

PROVENANCE_CREDENTIAL = CredentialType.AGENT_PROVENANCE


class DelegationKind(str, enum.Enum):
    SUB_AGENT = "SUB_AGENT"       # hierarchical: works for the parent
    EPHEMERAL = "EPHEMERAL"       # one task, short-lived, then gone
    FORK = "FORK"                 # a copy: same software and model, own identity


class DelegationRefused(ConflictError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass
class DelegatedScope:
    """One capability the parent wants to hand down, optionally narrowed."""
    capability: str
    actions: list[str] | None = None      # None = all of the parent's
    resources: list[str] | None = None    # None = all of the parent's


@dataclass
class SpawnRequest:
    parent_did: str
    kind: DelegationKind
    task: str
    scopes: list[DelegatedScope] = field(default_factory=list)
    ttl_seconds: int | None = None
    name: str | None = None


@dataclass
class SpawnResult:
    child: Agent
    depth: int
    expires_at: datetime
    delegated_credentials: list[str]
    provenance_credential: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "child_did": self.child.did, "slug": self.child.slug,
            "kind": self.child.agent_metadata.get("delegation", {}).get("kind"),
            "parent_did": self.child.agent_metadata.get("delegation", {}).get("parent_did"),
            "depth": self.depth, "expires_at": self.expires_at.isoformat(),
            "delegated_credentials": self.delegated_credentials,
            "provenance_credential": self.provenance_credential,
        }


class DelegationService:
    def __init__(self, session: AsyncSession, keystore: KeyStore,
                 settings: Settings | None = None) -> None:
        self.session = session
        self.keystore = keystore
        self.settings = settings or get_settings()
        self.registry = AgentRegistry(session, keystore, self.settings)
        self.issuer = CredentialIssuer(session, keystore, self.settings)
        self.verifier = CredentialVerifier(session, keystore, self.settings)
        self.audit = AuditService(session)

    async def spawn(self, request: SpawnRequest, *, requested_by: str) -> SpawnResult:
        now = datetime.now(timezone.utc)
        try:
            return await self._spawn(request, requested_by, now)
        except DelegationRefused as refusal:
            await self.audit.record(Event(
                EventType.AGENT_SPAWN_REFUSED, agent_did=request.parent_did,
                decision="REFUSED", reason=refusal.reason,
                metadata={"kind": request.kind.value, "detail": refusal.detail,
                          "requested_by": requested_by,
                          "requested_scopes": [s.__dict__ for s in request.scopes]}))
            await self.session.flush()
            raise

    async def _spawn(self, request: SpawnRequest, requested_by: str, now: datetime) -> SpawnResult:
        parent = await self.registry.get_agent(request.parent_did)
        await self._parent_is_eligible(parent, now)

        depth = int((parent.agent_metadata or {}).get("delegation", {}).get("depth", 0)) + 1
        if depth > self.settings.delegation_max_depth:
            raise DelegationRefused(
                "DELEGATION_DEPTH_EXCEEDED",
                f"depth {depth} exceeds the maximum of {self.settings.delegation_max_depth}")

        await self._within_spawn_rate(parent.did, now)

        verified = await self._verified_parent_credentials(parent.did, now)
        grants = self._narrow(request.scopes, verified)

        # Lifetime: requested (or the kind's default), clamped by every bound.
        requested = request.ttl_seconds or (
            self.settings.ephemeral_default_ttl_seconds
            if request.kind == DelegationKind.EPHEMERAL
            else self.settings.delegation_max_ttl_seconds)
        expires_at = now + timedelta(seconds=min(requested, self.settings.delegation_max_ttl_seconds))
        if parent.expires_at:
            expires_at = min(expires_at, parent.expires_at)
        for _, parent_cred in grants:
            expires_at = min(expires_at, parent_cred.expires_at)
        ttl = int((expires_at - now).total_seconds())
        if ttl < 30:
            raise DelegationRefused("DELEGATION_LIFETIME_TOO_SHORT",
                                    "the parent or its credentials expire too soon to delegate")

        token = secrets.token_hex(3)
        slug = f"{parent.slug[:40]}-{request.kind.value[:3].lower()}-{token}"
        delegation = {
            "kind": request.kind.value, "parent_did": parent.did, "depth": depth,
            "task": request.task[:300], "requested_by": requested_by,
            "spawned_at": now.isoformat(),
            "delegated_capabilities": sorted({g["capability"] for g, _ in grants}),
        }
        parent_profile = ((parent.agent_metadata or {}).get("profile") or {})
        child_tools = sorted({t for t in (parent_profile.get("toolset") or [])})
        profile = build_agent_profile(
            creator=parent.did, deployer=requested_by, owner=parent.owner,
            controller=parent.controller_did,
            software_version=(parent_profile.get("software") or {}).get(
                "version", self.settings.agent_software_version),
            model=(parent_profile.get("model") or {}).get("name"),
            model_digest=(parent_profile.get("model") or {}).get("runtimeDigest"),
            system_prompt=None,
            scope_of_behavior={
                "task": request.task[:300],
                "capabilities": delegation["delegated_capabilities"],
                "inherits": "nothing implicitly; only the credentials listed as delegated",
            },
            toolset=child_tools if request.kind == DelegationKind.FORK else [],
            created_at=now, expires_at=expires_at, delegation=delegation)

        child = await self.registry.create_agent(AgentSpec(
            slug=slug, name=request.name or f"{parent.name} ({request.kind.value.lower()})",
            agent_type=AgentType.HELPER, purpose=request.task[:500],
            capabilities=delegation["delegated_capabilities"],
            owner=parent.owner, controller_did=parent.controller_did,
            metadata={"delegation": delegation, "profile": profile},
            parent_did=parent.did, ttl_seconds=ttl, profile=profile,
            relationship_type="FORKED_FROM" if request.kind == DelegationKind.FORK
                              else "DELEGATES"))

        # The verifiable parent link (paper R-65, R-87 "SpawnedBy" provenance VC).
        provenance = await self.issuer.issue(IssueRequest(
            issuer_did=self.settings.organization_did, subject_did=child.did,
            credential_type=PROVENANCE_CREDENTIAL,
            claims={"spawnedBy": parent.did, "relationship": request.kind.value,
                    "depth": depth, "spawnedAt": now.isoformat(), "task": request.task[:300]},
            ttl_seconds=ttl))

        issued: list[str] = []
        for grant, parent_cred in grants:
            vc = await self.issuer.issue(IssueRequest(
                issuer_did=parent_cred.issuer_did, subject_did=child.did,
                credential_type=CredentialType.AGENT_CAPABILITY,
                claims={**grant, "delegatedBy": parent.did,
                        "delegatedFrom": parent_cred.credential_id},
                ttl_seconds=ttl))
            issued.append(vc.credential_id)

        await self.audit.record(Event(
            EventType.AGENT_SPAWNED, agent_did=child.did, decision="SPAWNED",
            metadata={**delegation, "child_did": child.did,
                      "expires_at": expires_at.isoformat(),
                      "delegated_credentials": issued,
                      "provenance_credential": provenance.credential_id}))
        await self.session.flush()
        log.info("agent_spawned", parent=parent.did, child=child.did,
                 kind=request.kind.value, depth=depth, ttl=ttl)
        return SpawnResult(child, depth, expires_at, issued, provenance.credential_id)

    # -------------------------------------------------------------- checks
    async def _parent_is_eligible(self, parent: Agent, now: datetime) -> None:
        if parent.status != AgentStatus.ACTIVE:
            raise DelegationRefused("DELEGATION_PARENT_NOT_ELIGIBLE",
                                    f"parent is {parent.status.value}")
        if parent.expires_at and parent.expires_at <= now:
            raise DelegationRefused("DELEGATION_PARENT_NOT_ELIGIBLE", "parent has expired")
        session = await SessionStateSynchronizer(self.session, self.settings).fact(parent.did)
        if session["state"] == SessionState.TERMINATED_IMMEDIATE_SECURITY_LOCKOUT.value:
            raise DelegationRefused("DELEGATION_PARENT_NOT_ELIGIBLE",
                                    "parent's session is locked out")
        trust = await TrustEngine(self.session, self.settings).assess(parent.did, now=now)
        if trust.level != TrustLevel.TRUSTED:
            # A degraded agent minting new identities is exactly the
            # "abusing ephemeral agents to mask activity" threat (Table 5 #3).
            raise DelegationRefused("DELEGATION_PARENT_NOT_ELIGIBLE",
                                    f"parent trust is {trust.level.value} ({trust.score})")

    async def _within_spawn_rate(self, parent_did: str, now: datetime) -> None:
        window = self.settings.delegation_spawn_window_seconds
        recent = (await self.session.execute(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.event_type == EventType.AGENT_SPAWNED,
                AuditEvent.event_metadata["parent_did"].as_string() == parent_did,
                AuditEvent.occurred_at > now - timedelta(seconds=window))
        )).scalar_one()
        if recent >= self.settings.delegation_max_spawns:
            raise DelegationRefused(
                "DELEGATION_RATE_EXCEEDED",
                f"{recent} spawns in the last {window}s (limit {self.settings.delegation_max_spawns})")

    async def _verified_parent_credentials(self, parent_did: str, now: datetime) -> list[Credential]:
        rows = (await self.session.execute(
            select(Credential)
            .join(CredentialStatus, CredentialStatus.credential_id == Credential.credential_id)
            .where(Credential.subject_did == parent_did,
                   Credential.credential_type == CredentialType.AGENT_CAPABILITY,
                   CredentialStatus.status == CredentialStatusValue.ACTIVE,
                   Credential.expires_at > now)
        )).scalars().all()
        verified = []
        for row in rows:
            # The Phase 2 verifier, used verbatim. Nothing here re-checks a
            # signature, expiry or status list itself.
            report = await self.verifier.verify(row.document, expected_subject=parent_did,
                                                verifier="delegation", record_event=False)
            if report.valid:
                verified.append(row)
        return verified

    def _narrow(self, scopes: list[DelegatedScope],
                verified: list[Credential]) -> list[tuple[dict[str, Any], Credential]]:
        grants: list[tuple[dict[str, Any], Credential]] = []
        for scope in scopes:
            candidates = [c for c in verified
                          if credential_claims(c.document).get("capability") == scope.capability]
            if not candidates:
                raise DelegationRefused(
                    "DELEGATION_EXCEEDS_PARENT",
                    f"parent holds no verified credential for capability {scope.capability!r}")
            chosen = None
            for cred in candidates:
                claims = credential_claims(cred.document)
                p_actions = set(claims.get("allowedActions") or [])
                p_resources = set(claims.get("allowedResources") or [])
                actions = set(scope.actions) if scope.actions is not None else p_actions
                resources = set(scope.resources) if scope.resources is not None else p_resources
                if actions <= p_actions and resources <= p_resources and actions and resources:
                    chosen = (cred, sorted(actions), sorted(resources), claims)
                    break
            if chosen is None:
                raise DelegationRefused(
                    "DELEGATION_EXCEEDS_PARENT",
                    f"requested actions/resources for {scope.capability!r} are not a "
                    f"non-empty subset of any verified parent credential")
            cred, actions, resources, claims = chosen
            grants.append(({"capability": scope.capability, "allowedActions": actions,
                            "allowedResources": resources, "purpose": claims.get("purpose")},
                           cred))
        return grants

    # ----------------------------------------------------------- lifecycle
    async def expire_due(self, now: datetime | None = None) -> list[str]:
        """Terminate delegated identities whose lifetime is over (paper R-61).

        Termination destroys the signing key, so an expired ephemeral agent
        can never sign again. Enforcement does not wait for this sweep: the
        PIP treats an agent past `expires_at` as inactive the moment it
        expires. The sweep exists so no dormant identity lingers.
        """
        now = now or datetime.now(timezone.utc)
        due = (await self.session.execute(
            select(Agent).where(Agent.expires_at.is_not(None), Agent.expires_at <= now,
                                Agent.status.in_([AgentStatus.ACTIVE, AgentStatus.SUSPENDED]))
        )).scalars().all()
        expired = []
        for agent in due:
            await self.registry.terminate(agent.did, reason="EXPIRED")
            await self.audit.record(Event(
                EventType.AGENT_EXPIRED, agent_did=agent.did, decision="TERMINATED",
                reason="EXPIRED", metadata={"expired_at": agent.expires_at.isoformat()}))
            expired.append(agent.did)
        return expired

    async def lineage(self, did: str) -> dict[str, Any]:
        agent = await self.registry.get_agent(did)
        ancestors = []
        cursor = agent
        while cursor.parent is not None and len(ancestors) < 16:
            cursor = cursor.parent
            ancestors.append({"did": cursor.did, "status": cursor.status.value})
        children = (await self.session.execute(
            select(Agent).where(Agent.parent_agent_id == agent.id))).scalars().all()
        return {
            "did": agent.did, "status": agent.status.value,
            "delegation": (agent.agent_metadata or {}).get("delegation"),
            "expires_at": agent.expires_at.isoformat() if agent.expires_at else None,
            "ancestors": ancestors,
            "children": [{"did": c.did, "status": c.status.value,
                          "kind": (c.agent_metadata or {}).get("delegation", {}).get("kind"),
                          "expires_at": c.expires_at.isoformat() if c.expires_at else None}
                         for c in children],
        }
