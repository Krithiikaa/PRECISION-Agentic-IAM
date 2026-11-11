"""The receiving end of the Session State Synchronizer push (paper R-157, R-161).

Each agent runtime subscribes and keeps a LOCAL view of which DIDs are locked
out. It acts on that view at its own boundary, before any network call:

  * its OWN DID locked out   -> it refuses all work and its workflow runner
                                stops claiming. "Connections terminated" in
                                the architecture diagram, done by the agent.
  * a PEER's DID locked out  -> it refuses that peer's instructions outright.

This is FAST FAILURE, not the control. The control is the ledger the PDP
reads on every decision (app/sessions/sss.py), so an agent that never receives
a push -- Redis down, subscriber reconnecting -- is still denied centrally.
Messages carry a version; a stale one never overrides a newer one.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from app.core.config import Settings
from app.core.logging import get_logger

log = get_logger("sessions.subscriber")

LOCKOUT = "TERMINATED_IMMEDIATE_SECURITY_LOCKOUT"


@dataclass
class LocalSessionView:
    versions: dict[str, int] = field(default_factory=dict)
    locked: set[str] = field(default_factory=set)
    received: int = 0

    def apply(self, message: dict[str, Any]) -> bool:
        did, version = message.get("agent_did"), int(message.get("version") or 0)
        if not did or version <= self.versions.get(did, 0):
            return False                       # stale or malformed: ignore
        self.versions[did] = version
        self.received += 1
        if message.get("state") == LOCKOUT:
            self.locked.add(did)
        else:
            self.locked.discard(did)
        return True

    def is_locked(self, did: str | None) -> bool:
        return bool(did) and did in self.locked


async def subscribe(settings: Settings, view: LocalSessionView, stop: asyncio.Event) -> None:
    """Follow the SSS channel until stopped, reconnecting after failures."""
    import redis.asyncio as redis

    while not stop.is_set():
        client = redis.from_url(settings.redis_url)
        try:
            pubsub = client.pubsub()
            await pubsub.subscribe(settings.sss_channel)
            log.info("sss_subscribed", channel=settings.sss_channel)
            while not stop.is_set():
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message.get("type") == "message":
                    try:
                        payload = json.loads(message["data"])
                    except (ValueError, TypeError):
                        continue
                    if view.apply(payload):
                        log.warning("sss_change_applied", agent=payload.get("agent_did"),
                                    state=payload.get("state"), version=payload.get("version"))
            await pubsub.aclose()
        except Exception as exc:  # noqa: BLE001 - reconnect, never crash the agent
            log.warning("sss_subscription_lost", error=f"{type(exc).__name__}: {exc}")
            try:
                await asyncio.wait_for(stop.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
        finally:
            await client.aclose()
