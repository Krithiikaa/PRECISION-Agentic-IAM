"""Distributed rate limiting (Phase 10).

Redis-backed, because a counter in process memory limits one worker and
says nothing about that. See `limiter.py` for the window and the
Redis-unavailable policy, and `middleware.py` for the tier map and how a
caller is identified without trusting a header.
"""
from app.ratelimit.limiter import (
    RateLimitDecision,
    RateLimiter,
    RateLimitRule,
    RedisUnavailablePolicy,
)
from app.ratelimit.middleware import RateLimitMiddleware, tier_for

__all__ = [
    "RateLimitDecision",
    "RateLimitMiddleware",
    "RateLimitRule",
    "RateLimiter",
    "RedisUnavailablePolicy",
    "tier_for",
]
