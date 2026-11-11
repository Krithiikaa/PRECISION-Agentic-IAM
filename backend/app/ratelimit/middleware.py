"""Rate-limit middleware and the tier map (Phase 10).

WHY MIDDLEWARE AND NOT A PER-ROUTE DEPENDENCY. A dependency has to be
remembered on every new route, and the one somebody forgets is the one that
gets hammered. Middleware covers the whole table by construction: a route
added tomorrow is limited the moment it exists, at the default tier, without
anyone deciding to protect it.

The cost is that tiers are resolved by path rather than declared at the
route. That is a real trade, and `test_rate_limiting.py` asserts the tier map
against the live route table so a path that stops matching is caught rather
than silently falling to the default.

WHAT THE KEY IS, AND WHY IT IS NOT JUST THE IP.

    authenticated caller  ->  their identity
    everyone else         ->  the TCP peer address

Keying only on IP punishes everyone behind one NAT for one abuser, and lets
one abuser with many addresses through. Keying on identity where we have one
is both fairer and tighter. An unauthenticated caller has no identity, which
is exactly why the unauthenticated tiers are the strictest.

SPOOFING. The peer address comes from `request.client.host`, which is the
socket's remote address, NOT a header. `X-Forwarded-For` is read ONLY when
the request arrives from an address the operator configured as a trusted
proxy; otherwise it is ignored entirely. Without that rule a caller sets one
header and gets a fresh allowance per request, which is not a rate limit.
"""
from __future__ import annotations

import ipaddress

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.ratelimit.limiter import RateLimiter, RateLimitRule

log = get_logger("ratelimit.middleware")

# Paths exempt from limiting. Liveness probes are polled by orchestrators at
# a fixed, high rate by design; limiting them turns a healthy service into an
# unhealthy one under exactly the load the limiter is supposed to survive.
EXEMPT_PATHS = frozenset({"/health", "/ready"})


def tier_for(path: str, method: str) -> str:
    """Which limit applies. Most specific first.

    `auth` is tightest because those endpoints are where credentials are
    tried: an attacker guessing tokens or replaying assertions hits these,
    and a generous limit there is a generous limit on guessing.
    """
    if path.startswith("/mcp") or path.endswith("/oauth-protected-resource"):
        return "auth"
    if path.startswith("/api/v1/credentials/challenge"):
        return "auth"
    if path.startswith("/api/v1/credentials/verify") or path.endswith("/verify-presentation"):
        return "auth"
    if path.startswith("/api/v1/identity/"):
        return "auth"

    # Expensive: each runs a full policy evaluation, and `enforce` may
    # execute a protected tool.
    if path.startswith(("/api/v1/enforce", "/api/v1/authorize")) and method == "POST":
        return "expensive"
    if path.startswith("/api/v1/a2a/transactions") and method == "POST":
        return "expensive"
    if path.startswith("/api/v1/jit/request"):
        return "expensive"

    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return "mutation"
    return "read"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings | None = None,
                 limiter: RateLimiter | None = None) -> None:
        super().__init__(app)
        self.settings = settings or get_settings()
        self.limiter = limiter or RateLimiter(self.settings)

    def _trusted_proxy(self, host: str | None) -> bool:
        if not host:
            return False
        networks = self.settings.trusted_proxy_networks
        if not networks:
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        for cidr in networks:
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def client_identifier(self, request) -> str:
        """Who is being counted.

        THE ORDER MATTERS AND THE FALLBACK IS DELIBERATE. An authenticated
        identity is preferred because it is the thing an abuser cannot
        cheaply change. Only when there is none do we fall back to the peer
        address -- and `X-Forwarded-For` is consulted ONLY behind a
        configured trusted proxy, because otherwise it is attacker-supplied.
        """
        principal = getattr(request.state, "control_plane_principal", None)
        identity = getattr(principal, "did", None) or getattr(principal, "username", None)
        if identity:
            return f"id:{identity}"

        # An MCP caller authenticates with a bearer token the transport
        # validates later. Counting the token's holder is not possible here
        # without validating it twice, so these fall to the peer address --
        # and the `auth` tier applied to /mcp is tight for that reason.
        peer = request.client.host if request.client else None
        if self._trusted_proxy(peer):
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                # Left-most is the originating client per RFC 7239 usage.
                return f"ip:{forwarded.split(',')[0].strip()}"
        return f"ip:{peer or 'unknown'}"

    async def dispatch(self, request, call_next):
        if not self.settings.ratelimit_enabled:
            return await call_next(request)

        path = request.url.path
        if path in EXEMPT_PATHS:
            return await call_next(request)

        tier = tier_for(path, request.method)
        limit, window = self.settings.ratelimit_tiers[tier]
        rule = RateLimitRule(name=tier, limit=limit, window_seconds=window)

        key = self.client_identifier(request)
        decision = await self.limiter.check(key, rule)

        if not decision.allowed:
            log.warning(
                "rate_limit_exceeded", tier=tier, path=path,
                method=request.method, degraded=decision.degraded,
                # The KEY is logged, never a token or a header value. An
                # identity or a peer address is what an operator needs to
                # act; anything more would put credentials in the log.
                client=key,
            )
            detail = (
                "rate limit exceeded"
                if not decision.degraded
                else "rate limiting backend unavailable; refusing rather than "
                     "serving an unenforced limit"
            )
            return JSONResponse(
                status_code=429 if not decision.degraded else 503,
                content={"error": "rate_limited", "detail": detail,
                         "policy": rule.describe()},
                headers=decision.headers(),
            )

        response = await call_next(request)
        for header, value in decision.headers().items():
            response.headers[header] = value
        return response
