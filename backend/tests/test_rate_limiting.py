"""Rate limiting (Phase 10).

WHY THE SUITE DISABLES RATE LIMITING AND THIS FILE TURNS IT BACK ON. The
suite drives thousands of requests at machine speed through one client,
which is exactly the shape the limiter refuses — leaving it on would make
unrelated tests fail with 429 at a point that depends on ordering. So
`conftest.py` sets `RATELIMIT_ENABLED=false`, and everything here constructs
the limiter explicitly. The convenience cannot reach production: `Settings`
refuses to start with the limiter disabled when `ENV=production`, and
`test_production_configuration.py` asserts that.

WHAT IS AND IS NOT TESTED AGAINST REAL REDIS. The window, the atomicity and
the concurrency tests run against the REAL Redis that docker-compose
provides — a fake would prove nothing about a Lua script that exists
precisely to be atomic on a real server. The unavailability tests point the
limiter at a dead address, which is the honest way to simulate an outage.
"""
from __future__ import annotations

import asyncio
import uuid

import pytest

from app.core.config import Settings, get_settings
from app.ratelimit.limiter import RateLimiter, RateLimitRule
from app.ratelimit.middleware import tier_for

pytestmark = pytest.mark.integration


def _key() -> str:
    """A fresh bucket per test. Tests that shared one would pass or fail
    depending on order, which is the least useful kind of rate-limit test."""
    return f"test-{uuid.uuid4().hex}"


@pytest.fixture
async def limiter():
    instance = RateLimiter(get_settings())
    try:
        await (await instance.client()).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"Redis is not reachable at {get_settings().redis_url}: "
            f"{type(exc).__name__}. Start it with "
            f"`docker compose up -d redis`. SKIPPED rather than faked: a "
            f"stubbed limiter would assert nothing about the Lua script."
        )
    yield instance
    await instance.aclose()


class TestTheWindow:
    async def test_requests_under_the_limit_are_allowed(self, limiter):
        rule = RateLimitRule("test", limit=5, window_seconds=60)
        key = _key()
        for _ in range(5):
            assert (await limiter.check(key, rule)).allowed is True

    async def test_the_request_over_the_limit_is_refused(self, limiter):
        rule = RateLimitRule("test", limit=3, window_seconds=60)
        key = _key()
        for _ in range(3):
            assert (await limiter.check(key, rule)).allowed is True
        assert (await limiter.check(key, rule)).allowed is False

    async def test_remaining_counts_down_and_stops_at_zero(self, limiter):
        rule = RateLimitRule("test", limit=3, window_seconds=60)
        key = _key()
        assert (await limiter.check(key, rule)).remaining == 2
        assert (await limiter.check(key, rule)).remaining == 1
        assert (await limiter.check(key, rule)).remaining == 0
        assert (await limiter.check(key, rule)).remaining == 0

    async def test_the_window_resets(self, limiter):
        """A ONE-SECOND window, so the test takes a second rather than a
        minute. The mechanism is identical at any width."""
        rule = RateLimitRule("test", limit=2, window_seconds=1)
        key = _key()
        assert (await limiter.check(key, rule)).allowed is True
        assert (await limiter.check(key, rule)).allowed is True
        assert (await limiter.check(key, rule)).allowed is False

        await asyncio.sleep(1.2)
        assert (await limiter.check(key, rule)).allowed is True

    async def test_it_is_a_sliding_window_not_a_fixed_bucket(self, limiter):
        """A fixed window lets a caller spend its whole allowance at the end
        of one period and the next period's at the start of the following
        one — twice the limit in a moment, which is the burst the limit
        exists to stop. After a partial wait, only the aged-out slots
        return."""
        rule = RateLimitRule("test", limit=2, window_seconds=2)
        key = _key()
        await limiter.check(key, rule)
        await asyncio.sleep(1.2)
        await limiter.check(key, rule)
        # Both slots are in flight; the third must fail.
        assert (await limiter.check(key, rule)).allowed is False
        # After the FIRST ages out, exactly one slot frees up.
        await asyncio.sleep(1.0)
        assert (await limiter.check(key, rule)).allowed is True

    async def test_different_keys_do_not_share_an_allowance(self, limiter):
        rule = RateLimitRule("test", limit=1, window_seconds=60)
        a, b = _key(), _key()
        assert (await limiter.check(a, rule)).allowed is True
        assert (await limiter.check(b, rule)).allowed is True

    async def test_different_rules_do_not_share_a_bucket(self, limiter):
        """The bucket name includes the rule, so exhausting `auth` must not
        exhaust `read` for the same caller."""
        key = _key()
        auth = RateLimitRule("auth", limit=1, window_seconds=60)
        read = RateLimitRule("read", limit=1, window_seconds=60)
        assert (await limiter.check(key, auth)).allowed is True
        assert (await limiter.check(key, auth)).allowed is False
        assert (await limiter.check(key, read)).allowed is True


class TestConcurrency:
    async def test_concurrent_requests_cannot_exceed_the_limit(self, limiter):
        """THE REASON THE COUNTER IS A LUA SCRIPT.

        Read-then-write from Python would let twenty concurrent callers each
        observe "under the limit" before any of them wrote. Exactly five may
        pass.
        """
        rule = RateLimitRule("test", limit=5, window_seconds=60)
        key = _key()
        results = await asyncio.gather(
            *(limiter.check(key, rule) for _ in range(20))
        )
        allowed = [r for r in results if r.allowed]
        assert len(allowed) == 5, f"{len(allowed)} of 20 passed a limit of 5"

    async def test_concurrent_distinct_identities_each_get_their_own(
        self, limiter
    ):
        rule = RateLimitRule("test", limit=2, window_seconds=60)
        keys = [_key() for _ in range(5)]
        results = await asyncio.gather(
            *(limiter.check(k, rule) for k in keys for _ in range(2))
        )
        assert all(r.allowed for r in results)


class TestRedisUnavailable:
    """An outage must not silently disable the control."""

    @pytest.fixture
    def dead(self):
        settings = Settings(
            # A port nothing listens on. An honest outage, not a mock.
            redis_url="redis://127.0.0.1:1/0",
            ratelimit_redis_timeout_seconds=0.05,
        )
        return settings

    async def test_fail_closed_refuses_the_request(self, dead):
        settings = dead.model_copy(update={"ratelimit_redis_policy": "fail_closed"})
        limiter = RateLimiter(settings)
        decision = await limiter.check(_key(), RateLimitRule("t", 100, 60))
        assert decision.allowed is False
        assert decision.degraded is True

    async def test_fail_open_local_still_limits_within_one_process(self, dead):
        """Degraded is not absent. The local counter is a development
        convenience and still refuses a flood — it simply cannot coordinate
        across workers, which is why production forbids it."""
        settings = dead.model_copy(
            update={"ratelimit_redis_policy": "fail_open_local"}
        )
        limiter = RateLimiter(settings)
        rule = RateLimitRule("t", limit=2, window_seconds=60)
        key = _key()
        assert (await limiter.check(key, rule)).allowed is True
        assert (await limiter.check(key, rule)).allowed is True
        third = await limiter.check(key, rule)
        assert third.allowed is False
        assert third.degraded is True

    async def test_every_degraded_decision_is_marked(self, dead):
        """`degraded` is what lets the middleware answer 503 instead of 429
        and what lets an operator tell "you asked too often" from "the
        limiter is blind"."""
        for policy in ("fail_closed", "fail_open_local"):
            limiter = RateLimiter(dead.model_copy(
                update={"ratelimit_redis_policy": policy}))
            assert (await limiter.check(_key(), RateLimitRule("t", 100, 60))).degraded


class TestTheTierMap:
    """Tiers are resolved by PATH, which is the cost of using middleware
    instead of a per-route dependency. These assert the map against the real
    route table so a path that stops matching is caught."""

    @pytest.mark.parametrize(
        "path,method,expected",
        [
            ("/mcp", "POST", "auth"),
            ("/api/v1/credentials/challenge", "GET", "auth"),
            ("/api/v1/credentials/verify", "POST", "auth"),
            ("/api/v1/identity/sign", "POST", "auth"),
            ("/api/v1/enforce", "POST", "expensive"),
            ("/api/v1/authorize", "POST", "expensive"),
            ("/api/v1/jit/request", "POST", "expensive"),
            ("/api/v1/agents", "POST", "mutation"),
            ("/api/v1/audit", "GET", "read"),
            ("/api/v1/agents", "GET", "read"),
        ],
    )
    def test_a_path_lands_in_the_expected_tier(self, path, method, expected):
        assert tier_for(path, method) == expected

    def test_the_auth_tier_is_the_tightest(self):
        tiers = get_settings().ratelimit_tiers
        auth_rate = tiers["auth"][0] / tiers["auth"][1]
        for name in ("expensive", "mutation", "read"):
            rate = tiers[name][0] / tiers[name][1]
            assert auth_rate <= rate, (
                f"the {name} tier is tighter than auth; credential and token "
                f"endpoints are where guessing happens and must be strictest"
            )

    def test_every_served_path_resolves_to_a_declared_tier(self):
        """A path that fell through to an undeclared tier would raise a
        KeyError on a live request."""
        from fastapi.routing import APIRoute

        from app.main import create_app

        tiers = get_settings().ratelimit_tiers
        for route in create_app().routes:
            if not isinstance(route, APIRoute):
                continue
            for method in route.methods - {"HEAD", "OPTIONS"}:
                assert tier_for(route.path, method) in tiers


class TestHeaders:
    async def test_an_allowed_response_advertises_the_policy(self, limiter):
        decision = await limiter.check(_key(), RateLimitRule("t", 10, 60))
        headers = decision.headers()
        assert headers["RateLimit-Limit"] == "10"
        assert "RateLimit-Policy" in headers

    async def test_retry_after_appears_only_on_a_refusal(self, limiter):
        rule = RateLimitRule("t", limit=1, window_seconds=60)
        key = _key()
        allowed = await limiter.check(key, rule)
        refused = await limiter.check(key, rule)
        assert "Retry-After" not in allowed.headers()
        assert "Retry-After" in refused.headers()


class TestSpoofedClientAddresses:
    """`X-Forwarded-For` is attacker-supplied unless a trusted proxy set it.

    Honouring it unconditionally would hand every caller a fresh allowance
    per request simply by changing a header, which is not a rate limit.
    """

    def _middleware(self, **overrides):
        from app.ratelimit.middleware import RateLimitMiddleware

        settings = Settings(**overrides)
        return RateLimitMiddleware(app=None, settings=settings)

    def _request(self, peer: str, forwarded: str | None = None):
        class _Client:
            host = peer

        class _Request:
            client = _Client()
            headers = {"x-forwarded-for": forwarded} if forwarded else {}
            state = type("S", (), {})()

        return _Request()

    def test_a_forwarded_header_is_ignored_without_a_trusted_proxy(self):
        middleware = self._middleware(trusted_proxy_networks_raw="")
        key = middleware.client_identifier(self._request("10.0.0.5", "1.2.3.4"))
        assert key == "ip:10.0.0.5", (
            "the forwarded header was believed from an untrusted peer: a "
            "caller could mint a fresh allowance per request"
        )

    def test_changing_the_header_does_not_change_the_bucket(self):
        middleware = self._middleware(trusted_proxy_networks_raw="")
        keys = {
            middleware.client_identifier(self._request("10.0.0.5", str(n)))
            for n in range(5)
        }
        assert keys == {"ip:10.0.0.5"}

    def test_a_trusted_proxy_is_believed(self):
        middleware = self._middleware(trusted_proxy_networks_raw="10.0.0.0/8")
        key = middleware.client_identifier(self._request("10.0.0.5", "1.2.3.4"))
        assert key == "ip:1.2.3.4"

    def test_a_peer_outside_the_trusted_range_is_not(self):
        middleware = self._middleware(trusted_proxy_networks_raw="10.0.0.0/8")
        key = middleware.client_identifier(self._request("192.168.1.1", "1.2.3.4"))
        assert key == "ip:192.168.1.1"

    def test_an_authenticated_identity_outranks_any_address(self):
        """Identity is preferred because it is the thing an abuser cannot
        cheaply change — and it makes the limit fairer behind one NAT."""
        middleware = self._middleware(trusted_proxy_networks_raw="10.0.0.0/8")
        request = self._request("10.0.0.5", "1.2.3.4")
        request.state.control_plane_principal = type(
            "P", (), {"did": "did:poc:agent:risk-001", "username": None}
        )()
        assert middleware.client_identifier(request) == "id:did:poc:agent:risk-001"


class TestIdentityKeyingActuallyRuns:
    """REGRESSION. The limiter runs before authentication, so the 'keyed on
    identity' rule never fired: every caller on one host shared ONE bucket and
    nine agents starved each other. The test above sets the principal by hand,
    which is how the defect stayed hidden."""

    def _app(self, limit=3, multiplier=2):
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from app.ratelimit.limiter import RateLimiter
        from app.ratelimit.middleware import RateLimitMiddleware

        # The real Redis, with a unique client address and unique identities
        # per test, so buckets never leak between tests or runs.
        settings = Settings(ratelimit_enabled=True, ratelimit_read=f"{limit},60",
                            ratelimit_address_multiplier=multiplier,
                            ratelimit_redis_policy="fail_closed")
        app = FastAPI()

        @app.get("/api/v1/agents")
        async def agents():
            return []

        app.add_middleware(RateLimitMiddleware, settings=settings)
        self.run = uuid.uuid4().hex[:8]
        address = f"10.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}"
        return AsyncClient(transport=ASGITransport(app=app, client=(address, 1234)),
                           base_url="http://t")

    async def get(self, client, did=None):
        did = did.replace("did:poc:agent:", f"did:poc:agent:{self.run}-") if did and did.startswith("did:") else did
        headers = {"X-CP-Principal": did} if did else {}
        return (await client.get("/api/v1/agents", headers=headers)).status_code

    async def test_two_identities_on_one_host_do_not_share_a_bucket(self):
        async with self._app(limit=3, multiplier=10) as client:
            a = [await self.get(client, "did:poc:agent:a") for _ in range(3)]
            b = [await self.get(client, "did:poc:agent:b") for _ in range(3)]
        assert a == [200] * 3 and b == [200] * 3

    async def test_one_identity_is_still_limited(self):
        async with self._app(limit=3, multiplier=10) as client:
            codes = [await self.get(client, "did:poc:agent:a") for _ in range(4)]
        assert codes == [200, 200, 200, 429]

    async def test_inventing_identities_is_bounded_by_the_address_ceiling(self):
        """An unverified claim buys at most limit x multiplier from one address."""
        async with self._app(limit=2, multiplier=2) as client:
            codes = [await self.get(client, f"did:poc:agent:x{i}") for i in range(6)]
        assert codes.count(200) == 4 and codes[-1] == 429

    async def test_a_malformed_claim_is_counted_by_address(self):
        async with self._app(limit=2, multiplier=10) as client:
            codes = [await self.get(client, "not a did <script>") for _ in range(3)]
        assert codes == [200, 200, 429]
