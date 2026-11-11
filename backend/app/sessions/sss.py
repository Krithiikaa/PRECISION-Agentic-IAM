"""Session State Synchronizer (SSS): the global session ledger and its push.

CSA paper R-159: "a highly available, low-latency distributed store that keeps
a real-time ledger of global sessions ... the source of truth for AEMs".

TWO HALVES, and only one of them is authoritative.

  The LEDGER is the `agent_session_states` table. The PIP reads it inside
  every authorization evaluation, so a lockout written here takes effect on
  the next decision in every worker of every process -- nothing has to be
  told. This is the half that enforces.

  The PUSH is a Redis pub/sub message carrying (did, state, version). It
  exists for processes that hold LOCAL state the database cannot reach into:
  an agent runtime with an open task, the ANS discovery cache. They act on it
  immediately instead of at their next poll. This half only shortens latency.

If Redis is unreachable the push is reported as not delivered and the
lockout is STILL enforced, because the ledger is. The reverse design -- the
lockout living in Redis -- would turn "Redis is down" into "every contained
agent is free", which is the failure mode this split exists to rule out.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.models.security import AgentSessionState, SessionState
from app.monitoring.events import Event, EventType

log = get_logger("sessions.sss")


@dataclass(frozen=True)
class SessionChange:
    agent_did: str
    state: SessionState
    version: int
    incident_id: str | None
    reason: str | None
    changed_at: datetime

    def to_message(self) -> str:
        return json.dumps({
            "agent_did": self.agent_did,
            "state": self.state.value,
            "version": self.version,
            "incident_id": self.incident_id,
            "reason": self.reason,
            "changed_at": self.changed_at.isoformat(),
        }, sort_keys=True)


def session_fact(row: AgentSessionState | None) -> dict[str, Any]:
    """The shape the PIP places in the input document under `pip.session`.

    An agent with no row has never had its session state changed, which is
    ACTIVE -- the true state, not a default standing in for an unknown one.
    """
    if row is None:
        return {"state": SessionState.ACTIVE.value, "version": 0,
                "incident_id": None, "reason": None}
    return {"state": row.state.value, "version": row.version,
            "incident_id": row.incident_id, "reason": row.reason}


class SessionStateSynchronizer:
    def __init__(self, session: AsyncSession, settings: Settings | None = None) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.audit = AuditService(session)

    async def get(self, agent_did: str) -> AgentSessionState | None:
        return (await self.session.execute(
            select(AgentSessionState).where(AgentSessionState.agent_did == agent_did)
        )).scalar_one_or_none()

    async def fact(self, agent_did: str) -> dict[str, Any]:
        return session_fact(await self.get(agent_did))

    async def set_state(
        self,
        agent_did: str,
        state: SessionState,
        *,
        reason: str | None,
        changed_by: str,
        incident_id: str | None = None,
        now: datetime | None = None,
    ) -> SessionChange:
        """Write a new global state. Locks the row so concurrent writers serialise.

        The version is what lets a subscriber discard a stale message, so it
        must increase strictly; `FOR UPDATE` makes the read-increment-write
        atomic against a second Session Authority call for the same agent.
        """
        now = now or datetime.now(timezone.utc)
        row = (await self.session.execute(
            select(AgentSessionState)
            .where(AgentSessionState.agent_did == agent_did)
            .with_for_update()
        )).scalar_one_or_none()
        previous = row.state.value if row else SessionState.ACTIVE.value
        if row is None:
            row = AgentSessionState(agent_did=agent_did, state=state, version=1)
            self.session.add(row)
        else:
            row.state = state
            row.version = row.version + 1
        row.reason = reason
        row.incident_id = incident_id
        row.changed_by = changed_by
        row.changed_at = now
        await self.session.flush()

        await self.audit.record(Event(
            # `decision` is a 32-character column; the paper's lockout state
            # name is 37. The full name is in metadata.
            EventType.SSS_UPDATED, agent_did=agent_did,
            decision=("LOCKED_OUT" if state == SessionState.TERMINATED_IMMEDIATE_SECURITY_LOCKOUT
                      else state.value),
            reason=reason,
            metadata={"previous_state": previous, "state": state.value,
                      "version": row.version, "incident_id": incident_id,
                      "changed_by": changed_by},
        ))
        return SessionChange(agent_did, state, row.version, incident_id, reason, now)

    async def publish(self, change: SessionChange) -> dict[str, Any]:
        """Push one change. Call AFTER the ledger write is committed.

        Returns what happened rather than raising: a failed push is a latency
        problem, not a security one, and the caller reports it to the operator.
        """
        try:
            import redis.asyncio as redis

            client = redis.from_url(
                self.settings.redis_url,
                socket_timeout=self.settings.ratelimit_redis_timeout_seconds,
                socket_connect_timeout=self.settings.ratelimit_redis_timeout_seconds,
            )
            try:
                receivers = await client.publish(self.settings.sss_channel, change.to_message())
            finally:
                await client.aclose()
            return {"delivered": True, "channel": self.settings.sss_channel,
                    "subscribers": int(receivers)}
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed silently
            log.warning("sss_push_failed", agent=change.agent_did,
                        error=f"{type(exc).__name__}: {exc}")
            return {"delivered": False, "channel": self.settings.sss_channel,
                    "error": f"{type(exc).__name__}",
                    "note": "the lockout is enforced by the ledger regardless"}
