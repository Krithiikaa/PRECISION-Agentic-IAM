"""Presentation challenge ledger (Phase 10).

THE GAP THIS CLOSES, documented in this codebase since Phase 2 and still
open at the end of Phase 9: `challenge` was compared for equality when a
verifier supplied an expected value, but used challenges were never
recorded. A captured presentation could therefore be replayed against any
verifier that reused a challenge, and nothing would notice.

Every other path in this system that needed replay protection already built
exactly this: `control_plane_proofs` has a nonce ledger,
`ans_registration_proofs` has one, `a2a_transactions` has one, and
`mcp_invocations` has a request-id ledger. This is the same pattern for the
one path that was left without it.

WHY A DATABASE ROW AND NOT REDIS. A challenge must be consumed EXACTLY once
across every worker, and the consumption has to be atomic with respect to
concurrent presentations of the same challenge. A conditional
`UPDATE ... WHERE consumed_at IS NULL RETURNING` gives that in one
statement, on the store that is already the arbiter for every other
exactly-once property here. Redis would be a second store to keep
consistent with the first, for a volume measured in challenges per minute.

WHAT IS STORED: the challenge value, what it was issued for, and whether it
has been spent. NOT the presentation, not a credential, not key material. A
challenge is a public, single-use nonce -- it is worthless to whoever reads
it, which is why it can be handed out unauthenticated.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class PresentationChallenge(Base, TimestampMixin):
    """One verifier-issued nonce, and whether it has been spent.

    THE UNIQUE CONSTRAINT ON `challenge` IS THE CONTROL. Two concurrent
    presentations of the same challenge both reach the conditional UPDATE
    and exactly one wins it; the loser sees zero rows affected and is
    refused. Application code cannot get this wrong because it never
    decides -- the database does.
    """

    __tablename__ = "presentation_challenges"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    # The nonce itself. UNIQUE, because the whole point is that one value is
    # spendable once.
    challenge: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )

    # The audience this challenge was issued for. A challenge minted for one
    # verifier must not be spendable at another, which is the same binding
    # `domain` already gives the signed presentation -- restated here so the
    # LEDGER enforces it too, and a verifier that forgot to pass
    # `expected_domain` is still protected.
    domain: Mapped[str | None] = mapped_column(String(128), index=True)

    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Freshness, enforced against the SERVER clock. A challenge with no
    # expiry would be a permanent one-use token, which is a strictly worse
    # thing to leak than a short-lived one.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # NULL means unspent. The conditional UPDATE keys on exactly this.
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Who spent it. Recorded for the audit trail: a challenge consumed by a
    # holder nobody expected is the visible half of a stolen presentation.
    consumed_by: Mapped[str | None] = mapped_column(String(255))
    # Which presentation spent it, for correlation with the verification
    # event. A digest would do; the id is already non-secret.
    presentation_id: Mapped[str | None] = mapped_column(String(128))

    __table_args__ = (
        Index("ix_presentation_challenges_unspent", "expires_at", "consumed_at"),
    )
