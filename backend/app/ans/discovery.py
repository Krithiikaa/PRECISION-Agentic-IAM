"""Capability-aware discovery.

Given a query, ANS finds candidates, evaluates each one against every
constraint, explains the outcome per candidate, ranks the survivors
deterministically, and records the whole thing.

Two rules this module never breaks:

1. **It never falls back.** If nothing satisfies the query, the answer is an
   empty result set with a reason. Silently returning a "close enough" agent
   would be worse than failing, because the caller would route real work to it.

2. **It never authorizes.** Matching a credential requirement means the agent
   *holds* a valid credential of that type. Whether it may then perform the
   action is the PDP's decision in Phase 4.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ans.registry import ANSRegistry, describe_agent
from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.credentials.verifier import CredentialVerifier
from app.db.models.agent import AgentStatus
from app.db.models.ans import (
    NEVER_DISCOVERABLE,
    ANSAgent,
    ANSCapability,
    ANSDiscoveryRequest,
    ANSDiscoveryResult,
    ANSStatus,
)
from app.db.models.credential import Credential
from app.db.repositories.agents import AgentRepository
from app.identity.keys import KeyStore
from app.monitoring.events import Event, EventType


class DiscoveryReason:
    MATCH = "MATCH"
    NO_MATCHING_AGENT = "NO_MATCHING_AGENT"
    CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
    STATUS_NOT_DISCOVERABLE = "STATUS_NOT_DISCOVERABLE"
    IDENTITY_NOT_ELIGIBLE = "IDENTITY_NOT_ELIGIBLE"
    HEARTBEAT_STALE = "HEARTBEAT_STALE"
    ORGANIZATION_MISMATCH = "ORGANIZATION_MISMATCH"
    CREDENTIAL_MISSING = "CREDENTIAL_MISSING"
    CREDENTIAL_INVALID = "CREDENTIAL_INVALID"
    TRUST_TOO_LOW = "TRUST_TOO_LOW"
    ENDPOINT_UNHEALTHY = "ENDPOINT_UNHEALTHY"


@dataclass
class DiscoveryQuery:
    capability: str | None = None
    capabilities: list[str] = field(default_factory=list)
    required_credentials: list[str] = field(default_factory=list)
    organization: str | None = None
    status: list[ANSStatus] | None = None
    purpose: str | None = None
    min_trust_score: int | None = None
    require_healthy_endpoint: bool = False
    requester_did: str | None = None
    limit: int = 20

    def all_capabilities(self) -> list[str]:
        wanted = list(self.capabilities)
        if self.capability:
            wanted.append(self.capability)
        return sorted(set(wanted))

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "capabilities": self.capabilities,
            "required_credentials": self.required_credentials,
            "organization": self.organization,
            "status": [s.value for s in self.status] if self.status else None,
            "purpose": self.purpose,
            "min_trust_score": self.min_trust_score,
            "require_healthy_endpoint": self.require_healthy_endpoint,
            "requester_did": self.requester_did,
        }


@dataclass
class Candidate:
    agent: ANSAgent
    matched: bool = True
    reason_code: str = DiscoveryReason.MATCH
    reasons: list[dict[str, Any]] = field(default_factory=list)
    score: float = 0.0
    rank: int | None = None

    def note(self, name: str, passed: bool, detail: str) -> bool:
        self.reasons.append({"name": name, "passed": passed, "detail": detail})
        return passed

    def fail(self, code: str) -> None:
        self.matched = False
        self.reason_code = code

    def to_dict(self) -> dict[str, Any]:
        return {
            **describe_agent(self.agent),
            "matched": self.matched,
            "reason_code": self.reason_code,
            "match_reasons": self.reasons,
            "score": round(self.score, 2),
            "rank": self.rank,
        }


@dataclass
class DiscoveryOutcome:
    request_id: str
    query: DiscoveryQuery
    results: list[Candidate]
    rejected: list[Candidate]
    reason: str
    latency_ms: float

    @property
    def selected(self) -> Candidate | None:
        return self.results[0] if self.results else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "query": self.query.to_dict(),
            "results": [c.to_dict() for c in self.results],
            "rejected": [c.to_dict() for c in self.rejected],
            "candidate_count": len(self.results) + len(self.rejected),
            "matched_count": len(self.results),
            "reason": self.reason,
            "selected": self.selected.to_dict() if self.selected else None,
            "ans_latency_ms": round(self.latency_ms, 2),
        }


class DiscoveryEngine:
    def __init__(
        self,
        session: AsyncSession,
        keystore: KeyStore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.registry = ANSRegistry(session, self.settings)
        self.agents = AgentRepository(session)
        self.audit = AuditService(session)
        # Credential checks reuse the Phase 2 verifier verbatim. No second
        # implementation of expiry, revocation or signature checking exists.
        self.verifier = CredentialVerifier(session, keystore, self.settings)

    async def discover(self, query: DiscoveryQuery) -> DiscoveryOutcome:
        started = time.perf_counter()
        request_id = f"ans-{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)

        await self.audit.record(
            Event(EventType.ANS_DISCOVERY_STARTED, agent_did=query.requester_did,
                  request_id=request_id, action="DISCOVER",
                  metadata={"query": query.to_dict()})
        )

        candidates = [Candidate(agent=a) for a in await self._candidate_agents(query)]
        for candidate in candidates:
            await self._evaluate(candidate, query, now)

        matched = [c for c in candidates if c.matched]
        rejected = [c for c in candidates if not c.matched]

        for candidate in matched:
            candidate.score = self._score(candidate)
        # Deterministic: score descending, then DID ascending so equal
        # candidates always order the same way across runs.
        matched.sort(key=lambda c: (-c.score, c.agent.did))
        for index, candidate in enumerate(matched[: query.limit], start=1):
            candidate.rank = index
        matched = matched[: query.limit]

        latency_ms = (time.perf_counter() - started) * 1000
        reason = DiscoveryReason.MATCH if matched else DiscoveryReason.NO_MATCHING_AGENT
        outcome = DiscoveryOutcome(request_id, query, matched, rejected, reason, latency_ms)

        await self._persist(outcome, now)
        await self._emit(outcome)
        return outcome

    # --- candidate selection ---------------------------------------------
    async def _candidate_agents(self, query: DiscoveryQuery) -> list[ANSAgent]:
        """Narrow in SQL using the capability index, not by scanning the table."""
        stmt = select(ANSAgent)
        wanted = query.all_capabilities()
        if wanted:
            stmt = stmt.join(
                ANSCapability, ANSCapability.agent_did == ANSAgent.did
            ).where(ANSCapability.capability.in_(wanted))
        if query.organization:
            stmt = stmt.where(ANSAgent.organization_did == query.organization)
        # These are never handed out, whatever the caller asks for.
        stmt = stmt.where(ANSAgent.status.notin_(list(NEVER_DISCOVERABLE)))
        result = await self.session.execute(stmt.order_by(ANSAgent.did))
        return list(result.scalars().unique().all())

    # --- per-candidate evaluation ----------------------------------------
    async def _evaluate(
        self, candidate: Candidate, query: DiscoveryQuery, now: datetime
    ) -> None:
        agent = candidate.agent

        # 1. capability
        wanted = query.all_capabilities()
        if wanted:
            held = set(agent.capability_names)
            missing = [c for c in wanted if c not in held]
            if not candidate.note(
                "capability", not missing,
                f"provides {', '.join(wanted)}" if not missing
                else f"does not provide {', '.join(missing)}",
            ):
                return candidate.fail(DiscoveryReason.CAPABILITY_MISMATCH)

        # 2. registry status
        allowed = query.status or [ANSStatus.ACTIVE]
        if not candidate.note(
            "status", agent.status in allowed,
            f"{agent.status.value}" if agent.status in allowed
            else f"{agent.status.value}, query requires "
                 f"{', '.join(s.value for s in allowed)}",
        ):
            return candidate.fail(DiscoveryReason.STATUS_NOT_DISCOVERABLE)

        # 3. upstream identity -- the registry must not outlive a revocation
        identity = await self.agents.get_by_did(agent.did)
        eligible = identity is not None and identity.status == AgentStatus.ACTIVE
        if not candidate.note(
            "identity", eligible,
            f"identity {identity.status.value}" if identity
            else "identity not found in the agent registry",
        ):
            return candidate.fail(DiscoveryReason.IDENTITY_NOT_ELIGIBLE)

        # 4. liveness
        last = agent.last_seen or agent.registered_at
        age = (now - last).total_seconds()
        fresh = age <= self.settings.ans_agent_timeout_seconds
        if not candidate.note(
            "liveness", fresh,
            f"heartbeat {int(age)}s ago" if fresh
            else f"last heartbeat {int(age)}s ago, over the "
                 f"{self.settings.ans_agent_timeout_seconds}s threshold",
        ):
            return candidate.fail(DiscoveryReason.HEARTBEAT_STALE)

        # 5. organization
        if query.organization:
            ok = agent.organization_did == query.organization
            if not candidate.note("organization", ok,
                                  agent.organization_did or "none"):
                return candidate.fail(DiscoveryReason.ORGANIZATION_MISMATCH)

        # 6. purpose
        if query.purpose:
            ok = bool(agent.purpose and query.purpose.lower() in agent.purpose.lower())
            if not candidate.note("purpose", ok, agent.purpose or "none declared"):
                return candidate.fail(DiscoveryReason.CAPABILITY_MISMATCH)

        # 7. credentials -- verified live, never read from the index
        for credential_type in query.required_credentials:
            code = await self._check_credential(candidate, credential_type)
            if code is not None:
                return candidate.fail(code)

        # 8. trust score (NULL until Phase 10 supplies one)
        if query.min_trust_score is not None:
            score = agent.trust_score
            ok = score is not None and score >= query.min_trust_score
            if not candidate.note(
                "trust", ok,
                f"trust {score} >= {query.min_trust_score}" if ok
                else (f"trust score is {score}" if score is not None
                      else "no trust score recorded (Phase 10 supplies these)"),
            ):
                return candidate.fail(DiscoveryReason.TRUST_TOO_LOW)

        # 9. endpoint health, as last observed
        if query.require_healthy_endpoint:
            ok = agent.last_health_ok is True
            if not candidate.note(
                "endpoint_health", ok,
                f"healthy, {agent.health_latency_ms}ms" if ok
                else ("never probed" if agent.last_health_ok is None
                      else "last probe failed"),
            ):
                return candidate.fail(DiscoveryReason.ENDPOINT_UNHEALTHY)

    async def _check_credential(
        self, candidate: Candidate, credential_type: str
    ) -> str | None:
        """Verify the agent actually holds a valid credential of this type.

        Delegates entirely to the Phase 2 verifier, so expiry, revocation and
        signature validity are decided by one implementation, not two.
        """
        result = await self.session.execute(
            select(Credential).where(
                Credential.subject_did == candidate.agent.did,
                Credential.credential_type == credential_type,
            )
        )
        held = list(result.scalars().unique().all())
        if not held:
            candidate.note(f"credential:{credential_type}", False,
                           "agent holds no credential of this type")
            return DiscoveryReason.CREDENTIAL_MISSING

        failures: list[str] = []
        for credential in held:
            report = await self.verifier.verify(
                credential.document,
                expected_subject=candidate.agent.did,
                verifier="ans-discovery",
                record_event=False,   # discovery emits its own events
            )
            if report.valid:
                candidate.note(f"credential:{credential_type}", True,
                               f"valid, expires {report.expires_at}")
                return None
            failures.append(f"{credential.credential_id[9:17]}: {report.reason}")

        candidate.note(f"credential:{credential_type}", False,
                       "; ".join(failures))
        return DiscoveryReason.CREDENTIAL_INVALID

    # --- ranking ----------------------------------------------------------
    def _score(self, candidate: Candidate) -> float:
        """Deterministic ranking over signals ANS genuinely observes.

        Order of influence matches the specification: status, then credential
        satisfaction, then trust, then load, then latency. No ML, no
        randomness, and nothing hardcoded to favour a particular agent.
        """
        agent = candidate.agent
        score = 0.0

        score += 40.0 if agent.status == ANSStatus.ACTIVE else 0.0
        # Every credential requirement that was checked and passed.
        score += 10.0 * sum(
            1 for r in candidate.reasons
            if r["name"].startswith("credential:") and r["passed"]
        )
        # Trust contributes only when Phase 10 has actually supplied a score.
        if agent.trust_score is not None:
            score += agent.trust_score / 10.0
        # Load: each task in flight makes the agent slightly less attractive.
        score -= 2.0 * max(0, agent.active_tasks)
        # Observed health and latency.
        if agent.last_health_ok is True:
            score += 10.0
            if agent.health_latency_ms is not None:
                score -= min(agent.health_latency_ms / 100.0, 10.0)
        return score

    # --- persistence and events -------------------------------------------
    async def _persist(self, outcome: DiscoveryOutcome, now: datetime) -> None:
        selected = outcome.selected
        self.session.add(
            ANSDiscoveryRequest(
                request_id=outcome.request_id,
                requester_did=outcome.query.requester_did,
                query=outcome.query.to_dict(),
                candidate_count=len(outcome.results) + len(outcome.rejected),
                matched_count=len(outcome.results),
                selected_did=selected.agent.did if selected else None,
                reason=outcome.reason,
                latency_ms=outcome.latency_ms,
                created_at=now,
            )
        )
        for candidate in outcome.results + outcome.rejected:
            self.session.add(
                ANSDiscoveryResult(
                    request_id=outcome.request_id,
                    candidate_did=candidate.agent.did,
                    matched=candidate.matched,
                    rank=candidate.rank,
                    score=round(candidate.score, 2) if candidate.matched else None,
                    reasons=candidate.reasons,
                    reason_code=candidate.reason_code,
                )
            )
        await self.session.flush()

    async def _emit(self, outcome: DiscoveryOutcome) -> None:
        for candidate in outcome.results:
            await self.audit.record(
                Event(EventType.ANS_DISCOVERY_MATCH,
                      agent_did=candidate.agent.did,
                      request_id=outcome.request_id, decision="MATCH",
                      metadata={"rank": candidate.rank, "score": round(candidate.score, 2),
                                "endpoint": candidate.agent.endpoint,
                                "reasons": candidate.reasons,
                                "requester": outcome.query.requester_did})
            )
        for candidate in outcome.rejected:
            await self.audit.record(
                Event(EventType.ANS_DISCOVERY_REJECTED,
                      agent_did=candidate.agent.did,
                      request_id=outcome.request_id, decision="REJECTED",
                      reason=candidate.reason_code,
                      metadata={"reasons": candidate.reasons,
                                "requester": outcome.query.requester_did})
            )
        if outcome.selected:
            await self.audit.record(
                Event(EventType.ANS_AGENT_SELECTED,
                      agent_did=outcome.selected.agent.did,
                      request_id=outcome.request_id, decision="SELECTED",
                      metadata={"endpoint": outcome.selected.agent.endpoint,
                                "score": round(outcome.selected.score, 2),
                                "ans_latency_ms": round(outcome.latency_ms, 2),
                                "requester": outcome.query.requester_did})
            )
        else:
            await self.audit.record(
                Event(EventType.ANS_DISCOVERY_NO_MATCH,
                      agent_did=outcome.query.requester_did,
                      request_id=outcome.request_id, decision="NO_MATCH",
                      reason=DiscoveryReason.NO_MATCHING_AGENT,
                      metadata={"query": outcome.query.to_dict(),
                                "candidates_checked": len(outcome.rejected),
                                "rejections": [
                                    {"did": c.agent.did, "reason": c.reason_code}
                                    for c in outcome.rejected
                                ]})
            )

    async def get_request(self, request_id: str) -> dict[str, Any] | None:
        result = await self.session.execute(
            select(ANSDiscoveryRequest).where(
                ANSDiscoveryRequest.request_id == request_id
            )
        )
        record = result.scalar_one_or_none()
        if record is None:
            return None
        return {
            "request_id": record.request_id,
            "requester_did": record.requester_did,
            "query": record.query,
            "candidate_count": record.candidate_count,
            "matched_count": record.matched_count,
            "selected_did": record.selected_did,
            "reason": record.reason,
            "ans_latency_ms": record.latency_ms,
            "created_at": record.created_at.isoformat(),
            "results": [
                {"candidate_did": r.candidate_did, "matched": r.matched, "rank": r.rank,
                 "score": r.score, "reason_code": r.reason_code, "reasons": r.reasons}
                for r in sorted(record.results, key=lambda r: (r.rank or 999, r.candidate_did))
            ],
        }
