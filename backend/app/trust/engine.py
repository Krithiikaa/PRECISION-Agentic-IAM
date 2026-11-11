"""Trust & Risk Engine: a continuous, explainable trust score per agent.

CSA paper R-127 ("dynamic trust scores based on behaviour, history and
security posture"), R-128 (continuous risk assessment adjusting permissions)
and R-209/R-210 (trust score inputs; risk-adaptive enforcement).

THE MODEL IS DELIBERATELY SIMPLE AND FULLY DERIVABLE:

    score = max(0, 100 - sum(weight of every UNEXPIRED signal))

    score >= TRUST_REDUCED_BELOW      TRUSTED
    score >= TRUST_UNTRUSTED_BELOW    REDUCED     (sensitive actions -> human)
    otherwise                         UNTRUSTED   (PDP denies)

Every point of a score is accounted for by a row in `trust_signals`, each
citing the alert that produced it. An operator asking "why is this agent at
45?" gets a list, not a model output. That is what a POC can honestly claim;
an ML-weighted score would be harder to audit and is not what is built here.

Signals expire, so an agent that stops misbehaving recovers without anyone
editing anything. Containment is NOT a trust level: it is a Session Authority
state that only a human lifts (see app/sessions/authority.py), so a contained
agent does not drift back to trusted when its signals age out.

WHAT POLICY DOES WITH THE LEVEL is Rego's business (policies/security/trust.rego).
This module computes a fact; it never allows or denies anything.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.db.models.security import AgentTrust, TrustLevel, TrustSignal
from app.monitoring.events import Event, EventType

FULL_TRUST = 100


@dataclass(frozen=True)
class TrustAssessment:
    agent_did: str
    score: int
    level: TrustLevel
    active_signals: int
    computed_at: datetime
    previous_level: TrustLevel | None = None

    @property
    def changed_level(self) -> bool:
        return self.previous_level is not None and self.previous_level != self.level

    def to_fact(self) -> dict[str, Any]:
        return {"score": self.score, "level": self.level.value,
                "active_signals": self.active_signals}


class TrustEngine:
    def __init__(self, session: AsyncSession, settings: Settings | None = None) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.audit = AuditService(session)

    def level_for(self, score: int) -> TrustLevel:
        if score >= self.settings.trust_reduced_below:
            return TrustLevel.TRUSTED
        if score >= self.settings.trust_untrusted_below:
            return TrustLevel.REDUCED
        return TrustLevel.UNTRUSTED

    async def record_signal(
        self,
        agent_did: str,
        signal_type: str,
        weight: int,
        *,
        alert_id: str | None = None,
        detail: str | None = None,
        now: datetime | None = None,
        observed_at: datetime | None = None,
    ) -> TrustAssessment:
        """Record one signal. `observed_at` is when the BEHAVIOUR happened;
        the signal expires a TTL after that, not after it was recorded."""
        if weight <= 0:
            raise ValueError("a trust signal must carry a positive weight")
        now = now or datetime.now(timezone.utc)
        observed = observed_at or now
        self.session.add(TrustSignal(
            agent_did=agent_did, signal_type=signal_type, weight=weight,
            alert_id=alert_id, detail=(detail or "")[:512] or None,
            observed_at=observed,
            expires_at=observed + timedelta(seconds=self.settings.trust_signal_ttl_seconds),
        ))
        await self.session.flush()
        return await self.recompute(agent_did, now=now, cause=signal_type)

    async def compute(self, agent_did: str, *, now: datetime | None = None) -> tuple[int, int]:
        now = now or datetime.now(timezone.utc)
        total, count = (await self.session.execute(
            select(func.coalesce(func.sum(TrustSignal.weight), 0), func.count(TrustSignal.id))
            .where(TrustSignal.agent_did == agent_did, TrustSignal.expires_at > now)
        )).one()
        return max(0, FULL_TRUST - int(total)), int(count)

    async def recompute(
        self, agent_did: str, *, now: datetime | None = None, cause: str | None = None
    ) -> TrustAssessment:
        """Recompute from signals and store the result. Emits TRUST_UPDATED on change."""
        now = now or datetime.now(timezone.utc)
        score, count = await self.compute(agent_did, now=now)
        level = self.level_for(score)
        row = (await self.session.execute(
            select(AgentTrust).where(AgentTrust.agent_did == agent_did).with_for_update()
        )).scalar_one_or_none()
        previous_level = row.level if row else TrustLevel.TRUSTED
        previous_score = row.score if row else FULL_TRUST
        if row is None:
            row = AgentTrust(agent_did=agent_did, score=score, level=level,
                             active_signals=count, computed_at=now)
            self.session.add(row)
        else:
            row.score, row.level, row.active_signals, row.computed_at = score, level, count, now
        await self.session.flush()

        if score != previous_score or level != previous_level:
            await self.audit.record(Event(
                EventType.TRUST_UPDATED, agent_did=agent_did, decision=level.value,
                reason=cause,
                metadata={"score": score, "previous_score": previous_score,
                          "level": level.value, "previous_level": previous_level.value,
                          "active_signals": count},
            ))
        return TrustAssessment(agent_did, score, level, count, now, previous_level)

    async def assess(self, agent_did: str, *, now: datetime | None = None) -> TrustAssessment:
        """The current trust of one agent, computed live. Used by the PIP.

        Computed from the signals rather than read from `agent_trust`, so an
        expired signal stops counting the instant it expires even if nothing
        has recomputed the cached row since. Read-only: the PIP never writes.
        """
        now = now or datetime.now(timezone.utc)
        score, count = await self.compute(agent_did, now=now)
        return TrustAssessment(agent_did, score, self.level_for(score), count, now)

    async def signals(self, agent_did: str, *, include_expired: bool = False) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        query = select(TrustSignal).where(TrustSignal.agent_did == agent_did)
        if not include_expired:
            query = query.where(TrustSignal.expires_at > now)
        rows = (await self.session.execute(query.order_by(TrustSignal.observed_at.desc()))).scalars()
        return [{
            "signal_type": r.signal_type, "weight": r.weight, "alert_id": r.alert_id,
            "detail": r.detail, "observed_at": r.observed_at.isoformat(),
            "expires_at": r.expires_at.isoformat(), "active": r.expires_at > now,
        } for r in rows]

    async def overview(self) -> list[dict[str, Any]]:
        rows = (await self.session.execute(
            select(AgentTrust).order_by(AgentTrust.score.asc())
        )).scalars()
        return [{"agent_did": r.agent_did, "score": r.score, "level": r.level.value,
                 "active_signals": r.active_signals,
                 "computed_at": r.computed_at.isoformat()} for r in rows]
