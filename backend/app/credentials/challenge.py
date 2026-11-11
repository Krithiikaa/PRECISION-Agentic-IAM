"""Issuing and spending presentation challenges (Phase 10).

A CHALLENGE IS A VERIFIER'S QUESTION, and the point of asking it is that the
answer cannot have been prepared earlier. That requires three things, and
before Phase 10 this system had only the first:

    unpredictable   `secrets.token_urlsafe` -- already true
    fresh           bounded lifetime, checked against the SERVER clock
    single-use      spent exactly once, atomically, across every worker

THE CONSUMPTION IS ONE STATEMENT. A read-then-write would let two concurrent
presentations of the same challenge both observe "unspent" before either
writes, which is precisely the race a replay attacker creates on purpose.
`UPDATE ... WHERE consumed_at IS NULL RETURNING` resolves it in the
database: exactly one caller gets a row back.

WHAT THIS DOES NOT DO. It does not verify a signature, check a credential's
status, or decide anything about authorization. A spent challenge means
"this presentation is not a replay" and nothing else -- every other check in
`PresentationVerifier` still runs, and a fresh challenge on a revoked
credential is still refused.
"""
from __future__ import annotations

import enum
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.models.challenge import PresentationChallenge

log = get_logger("credentials.challenge")


class ChallengeReason(str, enum.Enum):
    """Why a challenge could not be spent.

    Each names ONE condition, for the reason every other reason family in
    this system does: "challenge invalid" tells an operator nothing they can
    act on, and tells an attacker just as much.
    """

    OK = "CHALLENGE_ACCEPTED"
    UNKNOWN = "CHALLENGE_UNKNOWN"
    ALREADY_USED = "CHALLENGE_ALREADY_USED"
    EXPIRED = "CHALLENGE_EXPIRED"
    DOMAIN_MISMATCH = "CHALLENGE_DOMAIN_MISMATCH"


@dataclass(frozen=True)
class ChallengeOutcome:
    spent: bool
    reason: ChallengeReason
    detail: str | None = None


class ChallengeService:
    """Issues verifier challenges and spends them exactly once."""

    def __init__(self, session: AsyncSession, settings: Settings | None = None) -> None:
        self.session = session
        self.settings = settings or get_settings()

    async def issue(
        self, *, domain: str | None = None, now: datetime | None = None
    ) -> PresentationChallenge:
        """Mint and RECORD a challenge.

        Recording at issue time rather than at first use is what makes
        `CHALLENGE_UNKNOWN` meaningful: a value this verifier never issued is
        refused, so an attacker cannot invent challenges and have them
        accepted merely because they have not been seen before.
        """
        now = now or datetime.now(timezone.utc)
        record = PresentationChallenge(
            challenge=secrets.token_urlsafe(32),
            domain=domain,
            issued_at=now,
            expires_at=now + timedelta(seconds=self.settings.challenge_ttl_seconds),
        )
        self.session.add(record)
        await self.session.flush()
        return record

    async def spend(
        self,
        challenge: str,
        *,
        domain: str | None = None,
        holder: str | None = None,
        presentation_id: str | None = None,
        now: datetime | None = None,
    ) -> ChallengeOutcome:
        """Consume a challenge, or say precisely why it cannot be.

        THE ORDER OF CHECKS MATTERS. Expiry and domain are settled BEFORE the
        atomic claim, so an expired or misaddressed challenge is refused
        without being marked spent -- otherwise presenting an expired
        challenge would burn it, and a legitimate holder racing the clock
        would lose a challenge it could have been told to refresh.
        """
        now = now or datetime.now(timezone.utc)

        record = (
            await self.session.execute(
                select(PresentationChallenge).where(
                    PresentationChallenge.challenge == challenge
                )
            )
        ).scalar_one_or_none()

        if record is None:
            return ChallengeOutcome(
                False, ChallengeReason.UNKNOWN,
                "this verifier did not issue that challenge",
            )
        if record.consumed_at is not None:
            log.warning(
                "presentation_challenge_replayed",
                domain=record.domain, holder=holder,
                detail="a challenge was presented twice; the second is refused",
            )
            return ChallengeOutcome(
                False, ChallengeReason.ALREADY_USED,
                "this challenge has already been used",
            )
        if record.expires_at <= now:
            return ChallengeOutcome(
                False, ChallengeReason.EXPIRED, "this challenge has expired",
            )
        if record.domain is not None and domain is not None and record.domain != domain:
            return ChallengeOutcome(
                False, ChallengeReason.DOMAIN_MISMATCH,
                "this challenge was issued for a different verifier",
            )

        # THE ATOMIC CLAIM. Everything above is advisory -- it produces a
        # precise reason for the common cases. THIS is the control: under
        # concurrency, two callers both reach it and exactly one matches
        # `consumed_at IS NULL`.
        result = await self.session.execute(
            update(PresentationChallenge)
            .where(
                PresentationChallenge.challenge == challenge,
                PresentationChallenge.consumed_at.is_(None),
            )
            .values(
                consumed_at=now, consumed_by=holder, presentation_id=presentation_id,
            )
        )
        await self.session.flush()

        if (result.rowcount or 0) == 0:
            # Lost the race. Another presentation of this same challenge
            # committed first -- which is a replay, however close together
            # the two arrived.
            log.warning(
                "presentation_challenge_lost_race", holder=holder,
                detail="a concurrent presentation spent this challenge first",
            )
            return ChallengeOutcome(
                False, ChallengeReason.ALREADY_USED,
                "a concurrent presentation used this challenge first",
            )

        return ChallengeOutcome(True, ChallengeReason.OK)

    async def sweep(self, *, now: datetime | None = None) -> int:
        """Delete spent and expired challenges.

        Housekeeping, not a control: an expired challenge is already refused
        by `spend`. This stops the table growing without bound.
        """
        from sqlalchemy import delete, or_

        now = now or datetime.now(timezone.utc)
        result = await self.session.execute(
            delete(PresentationChallenge).where(
                or_(
                    PresentationChallenge.consumed_at.is_not(None),
                    PresentationChallenge.expires_at <= now,
                )
            )
        )
        await self.session.flush()
        return int(result.rowcount or 0)
