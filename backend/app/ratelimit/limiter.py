"""Distributed rate limiting (Phase 10).

WHY REDIS AND NOT A DICTIONARY. A counter in process memory limits one
worker. Run four of them behind a load balancer and the effective limit is
four times what the operator configured — and nothing says so. Redis makes
the counter shared, which is the only version of this control that means
what it claims in a deployment with more than one instance.

Redis is already a declared dependency (`redis==5.2.1` in requirements.txt)
and already runs in docker-compose. Phase 9 recorded it as "an unused but
mandatory startup dependency"; this is what uses it.

THE WINDOW IS A SLIDING LOG, NOT A FIXED BUCKET. A fixed window lets a
caller spend its whole allowance at 11:59:59 and the next window's at
12:00:00 — twice the limit in two seconds, which is exactly the burst the
limit exists to stop. A sorted set keyed by timestamp costs one more Redis
structure and does not have that edge.

EVERY DECISION IS ONE ATOMIC SCRIPT. Read-then-write from Python would let
concurrent requests each read "under the limit" before any of them writes.
The Lua below runs on the Redis server with nothing interleaved, so N
concurrent requests produce exactly N increments and the (N+1)th is refused.

ON REDIS BEING UNAVAILABLE -- the policy is explicit, configurable and
never silent. See `RedisUnavailablePolicy`.
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass
from typing import Any

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

log = get_logger("ratelimit")


class RedisUnavailablePolicy(str, enum.Enum):
    """What to do when the shared counter cannot be reached.

    There is no third option in which the request is allowed and nothing is
    said about it. An abuse control that disappears quietly is worse than
    one that was never installed, because the dashboards still show it.
    """

    # Refuse the request. Correct for production: a rate limit that is not
    # being enforced is an open door, and a 503 is an incident an operator
    # can see.
    FAIL_CLOSED = "fail_closed"
    # Allow the request, count it in process memory, and log a WARNING every
    # time. Correct for single-instance development, where the alternative
    # is that nothing runs without Redis. NEVER correct for a multi-instance
    # deployment, and `Settings` refuses this combination in production.
    FAIL_OPEN_LOCAL = "fail_open_local"


@dataclass(frozen=True)
class RateLimitRule:
    """A limit, named so an operator can see which one refused a request."""

    name: str
    limit: int
    window_seconds: int

    def describe(self) -> str:
        return f"{self.limit}/{self.window_seconds}s"


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    rule: RateLimitRule
    remaining: int
    retry_after: int
    # True when the shared counter was unreachable and the configured policy
    # allowed the request anyway. Surfaced so the caller can log it and a
    # test can assert the fallback actually happened.
    degraded: bool = False

    def headers(self) -> dict[str, str]:
        """Standard rate-limit headers.

        `Retry-After` is only sent on a refusal: advertising it on every
        response invites a client to poll at exactly the limit.
        """
        out = {
            "RateLimit-Limit": str(self.rule.limit),
            "RateLimit-Remaining": str(max(0, self.remaining)),
            "RateLimit-Reset": str(self.retry_after),
            "RateLimit-Policy": f"{self.rule.limit};w={self.rule.window_seconds}",
        }
        if not self.allowed:
            out["Retry-After"] = str(self.retry_after)
        return out


# Sliding-window log, atomically.
#
#   KEYS[1]  the bucket
#   ARGV[1]  now, in milliseconds
#   ARGV[2]  window, in milliseconds
#   ARGV[3]  limit
#   ARGV[4]  a unique member for this request
#
# Returns {allowed, count}. The expiry is reset on every call so an idle
# bucket disappears on its own and the keyspace does not grow without bound.
_SLIDING_WINDOW = """
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)
local count = redis.call('ZCARD', KEYS[1])

if count < limit then
  redis.call('ZADD', KEYS[1], now, ARGV[4])
  redis.call('PEXPIRE', KEYS[1], window)
  return {1, count + 1}
end

redis.call('PEXPIRE', KEYS[1], window)
return {0, count}
"""


class RateLimiter:
    """Counts requests against a shared window.

    DECIDES NOTHING ABOUT AUTHORIZATION. A rate limit answers "has this
    caller asked too often?", never "may this caller do this?" -- the second
    question belongs to the PDP, and conflating them would make an abuse
    control into an access control that policy cannot see.
    """

    def __init__(self, settings: Settings | None = None, client: Any = None) -> None:
        self.settings = settings or get_settings()
        self._client = client
        self._script = None
        # The degraded-mode counter. Deliberately simple and deliberately
        # per-process: it is a development convenience, not a distributed
        # limiter, and pretending otherwise is the mistake this guards.
        self._local: dict[str, list[float]] = {}

    async def client(self):
        if self._client is None:
            import redis.asyncio as redis

            self._client = redis.from_url(
                self.settings.redis_url,
                socket_timeout=self.settings.ratelimit_redis_timeout_seconds,
                socket_connect_timeout=self.settings.ratelimit_redis_timeout_seconds,
                decode_responses=True,
            )
        return self._client

    async def check(self, key: str, rule: RateLimitRule) -> RateLimitDecision:
        """Count one request against `key` and say whether it may proceed."""
        now_ms = int(time.time() * 1000)
        window_ms = rule.window_seconds * 1000
        bucket = f"ratelimit:{rule.name}:{key}"
        member = f"{now_ms}-{time.perf_counter_ns()}"

        try:
            client = await self.client()
            allowed, count = await client.eval(
                _SLIDING_WINDOW, 1, bucket,
                str(now_ms), str(window_ms), str(rule.limit), member,
            )
            return RateLimitDecision(
                allowed=bool(allowed), rule=rule,
                remaining=max(0, rule.limit - int(count)),
                retry_after=rule.window_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - any Redis fault lands here
            return self._unavailable(key, rule, exc)

    def _unavailable(self, key, rule, exc) -> RateLimitDecision:
        """The shared counter could not be reached.

        LOUD IN BOTH DIRECTIONS. Whichever policy is configured, this logs --
        a rate limiter that silently stopped limiting is the failure mode
        this whole module exists to avoid.
        """
        policy = self.settings.ratelimit_redis_policy

        if policy == RedisUnavailablePolicy.FAIL_CLOSED.value:
            log.error(
                "ratelimit_backend_unavailable_failing_closed",
                rule=rule.name, error=type(exc).__name__,
                detail="refusing the request: an unenforced rate limit is an "
                       "open door, and this must be visible as an incident",
            )
            return RateLimitDecision(
                allowed=False, rule=rule, remaining=0,
                retry_after=rule.window_seconds, degraded=True,
            )

        log.warning(
            "ratelimit_backend_unavailable_degraded_to_local",
            rule=rule.name, error=type(exc).__name__,
            detail="counting in process memory only; this limits ONE worker "
                   "and is not a distributed limit",
        )
        allowed, remaining = self._local_check(key, rule)
        return RateLimitDecision(
            allowed=allowed, rule=rule, remaining=remaining,
            retry_after=rule.window_seconds, degraded=True,
        )

    def _local_check(self, key: str, rule: RateLimitRule) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - rule.window_seconds
        seen = [t for t in self._local.get(key, []) if t > cutoff]
        if len(seen) >= rule.limit:
            self._local[key] = seen
            return False, 0
        seen.append(now)
        self._local[key] = seen
        return True, max(0, rule.limit - len(seen))

    async def reset(self, key: str, rule: RateLimitRule) -> None:
        """Clear one bucket. For tests and for an operator unblocking a
        caller that was refused for a reason since corrected."""
        self._local.pop(key, None)
        try:
            client = await self.client()
            await client.delete(f"ratelimit:{rule.name}:{key}")
        except Exception:  # noqa: BLE001 - nothing to clear if it is down
            pass

    async def aclose(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:  # noqa: BLE001
                pass
            self._client = None
