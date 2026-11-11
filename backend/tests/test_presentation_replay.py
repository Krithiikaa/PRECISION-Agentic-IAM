"""Presentation replay protection (Phase 10).

THE GAP THIS CLOSES was documented in this codebase from Phase 2 and was
still open at the end of Phase 9: `challenge` was compared for equality but
never recorded, so a captured presentation replayed cleanly against any
verifier that reused one. `app/credentials/presentation.py` said so in its
own docstring for seven phases.

WHAT "CLOSED" MEANS HERE, stated precisely because it is easy to overclaim:
a challenge is now unpredictable, recorded at issue, bound to its verifier,
expiring, and spendable exactly once under concurrency. It does NOT make a
presentation unforgeable — that was already the holder proof's job, and
every one of those checks still runs. A fresh challenge on a revoked
credential is still refused.
"""
from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import get_settings
from app.credentials.challenge import ChallengeReason, ChallengeService

pytestmark = pytest.mark.integration


@pytest.fixture
def challenges(session):
    return ChallengeService(session, get_settings())


class TestAChallengeIsSpentExactlyOnce:
    async def test_a_fresh_challenge_is_accepted(self, challenges):
        record = await challenges.issue()
        outcome = await challenges.spend(record.challenge)
        assert outcome.spent is True
        assert outcome.reason is ChallengeReason.OK

    async def test_the_same_challenge_cannot_be_spent_twice(self, challenges):
        """THE CENTRAL TEST. This is the replay, in its simplest form."""
        record = await challenges.issue()
        first = await challenges.spend(record.challenge)
        second = await challenges.spend(record.challenge)

        assert first.spent is True
        assert second.spent is False
        assert second.reason is ChallengeReason.ALREADY_USED

    async def test_a_challenge_this_verifier_never_issued_is_refused(
        self, challenges
    ):
        """Recording at ISSUE time is what makes this possible. If challenges
        were only remembered once used, an attacker could invent one and have
        it accepted precisely because it had never been seen before."""
        outcome = await challenges.spend("i-made-this-up")
        assert outcome.spent is False
        assert outcome.reason is ChallengeReason.UNKNOWN

    async def test_an_expired_challenge_is_refused(self, challenges, session):
        from datetime import datetime, timedelta, timezone

        record = await challenges.issue()
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.flush()

        outcome = await challenges.spend(record.challenge)
        assert outcome.spent is False
        assert outcome.reason is ChallengeReason.EXPIRED

    async def test_an_expired_challenge_is_not_marked_spent(
        self, challenges, session
    ):
        """Expiry is checked BEFORE the atomic claim, deliberately. If
        presenting an expired challenge burned it, a holder racing the clock
        would lose a challenge it could have been told to refresh."""
        from datetime import datetime, timedelta, timezone

        record = await challenges.issue()
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.flush()
        await challenges.spend(record.challenge)
        await session.refresh(record)
        assert record.consumed_at is None

    async def test_a_challenge_issued_for_another_verifier_is_refused(
        self, challenges
    ):
        """The ledger enforces the audience binding too, so a verifier that
        forgot to pass `expected_domain` is still protected."""
        record = await challenges.issue(domain="loan-service")
        outcome = await challenges.spend(record.challenge, domain="payment-service")
        assert outcome.spent is False
        assert outcome.reason is ChallengeReason.DOMAIN_MISMATCH

    async def test_the_matching_verifier_may_spend_it(self, challenges):
        record = await challenges.issue(domain="loan-service")
        assert (await challenges.spend(record.challenge, domain="loan-service")).spent

    async def test_who_spent_it_is_recorded(self, challenges, session):
        """A challenge consumed by a holder nobody expected is the visible
        half of a stolen presentation, so the trail has to name them."""
        record = await challenges.issue()
        await challenges.spend(
            record.challenge, holder="did:poc:agent:risk-001",
            presentation_id="urn:uuid:abc",
        )
        await session.refresh(record)
        assert record.consumed_by == "did:poc:agent:risk-001"
        assert record.presentation_id == "urn:uuid:abc"
        assert record.consumed_at is not None


class TestConcurrentReplay:
    """REAL CONCURRENT TASKS ON REAL CONNECTIONS.

    A replay attacker does not wait politely for the first presentation to
    finish. Two tasks sharing one session could not even see each other's
    uncommitted rows, so this uses separate sessions and commits — the same
    construction test_a2a_concurrency.py uses, for the same reason.
    """

    async def test_twenty_concurrent_presentations_spend_it_once(
        self, engine, session
    ):
        service = ChallengeService(session, get_settings())
        record = await service.issue()
        value = record.challenge
        await session.commit()

        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def spend(n: int):
            async with maker() as s:
                outcome = await ChallengeService(s, get_settings()).spend(
                    value, holder=f"holder-{n}",
                )
                await s.commit()
                return outcome.spent

        results = await asyncio.gather(
            *(spend(n) for n in range(20)), return_exceptions=True
        )
        winners = [r for r in results if r is True]
        assert len(winners) == 1, (
            f"{len(winners)} concurrent presentations spent one challenge"
        )

    async def test_two_different_challenges_both_spend(self, engine, session):
        """The control is single-use, NOT serialisation. A mechanism that
        blocked a second, unrelated challenge would be a correctness bug
        wearing a safety property's clothes."""
        service = ChallengeService(session, get_settings())
        a = (await service.issue()).challenge
        b = (await service.issue()).challenge
        await session.commit()

        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def spend(value):
            async with maker() as s:
                outcome = await ChallengeService(s, get_settings()).spend(value)
                await s.commit()
                return outcome.spent

        assert await asyncio.gather(spend(a), spend(b)) == [True, True]


class TestTheEndpointIssuesRealChallenges:
    async def test_the_endpoint_reports_single_use_enforced(self, client):
        body = (await client.get("/api/v1/credentials/challenge")).json()
        assert body["single_use_enforced"] is True
        assert body["challenge"]
        assert body["expires_at"]

    async def test_two_calls_return_different_challenges(self, client):
        a = (await client.get("/api/v1/credentials/challenge")).json()["challenge"]
        b = (await client.get("/api/v1/credentials/challenge")).json()["challenge"]
        assert a != b

    async def test_the_challenge_is_recorded_and_therefore_spendable(
        self, client, challenges, session
    ):
        """Issued over HTTP, spent through the service. If the endpoint did
        not persist, this would come back UNKNOWN — which is exactly what
        the pre-Phase-10 endpoint would have done."""
        value = (await client.get("/api/v1/credentials/challenge")).json()["challenge"]
        assert (await challenges.spend(value)).spent is True

    async def test_a_challenge_can_be_bound_to_a_verifier_at_issue(
        self, client, challenges
    ):
        body = (await client.get(
            "/api/v1/credentials/challenge?domain=loan-service")).json()
        assert body["domain"] == "loan-service"
        wrong = await challenges.spend(body["challenge"], domain="payment-service")
        assert wrong.spent is False


class TestHousekeepingIsNotTheControl:
    async def test_sweeping_removes_spent_and_expired_rows(
        self, challenges, session
    ):
        from datetime import datetime, timedelta, timezone

        spent = await challenges.issue()
        await challenges.spend(spent.challenge)
        stale = await challenges.issue()
        stale.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        live = await challenges.issue()
        await session.flush()

        removed = await challenges.sweep()
        assert removed >= 2
        # The live one survives, and is still spendable.
        assert (await challenges.spend(live.challenge)).spent is True

    async def test_an_expired_challenge_is_refused_even_without_a_sweep(
        self, challenges, session
    ):
        """Sweeping is housekeeping, not enforcement. If expiry only took
        effect once a sweep ran, a verifier that never swept would accept
        arbitrarily old challenges."""
        from datetime import datetime, timedelta, timezone

        record = await challenges.issue()
        record.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await session.flush()
        assert (await challenges.spend(record.challenge)).reason is ChallengeReason.EXPIRED
