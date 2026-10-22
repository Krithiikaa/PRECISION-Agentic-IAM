"""Replay, idempotency and exactly-once execution.

THE SEMANTIC UNDER TEST:

    Exactly-once EXECUTION, with idempotent replay of the previously
    determined RESULT.

Not "single-use": a sender that did not see the response must be able to ask
again and learn what happened, without a second payment. And not "just retry":
the same id carrying DIFFERENT content is an attack, not a retry, and gets its
own refusal.

The arbiter is the DATABASE, never Python. `UNIQUE (sender_did,
transaction_id)` decides who processes an instruction, and a conditional
`UPDATE ... WHERE status = 'AUTHORIZED'` decides who executes it.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db.models.a2a import A2ATransaction, A2ATransactionAttempt
from app.enforcement.resources import (
    payment_execution_count,
    payment_instruction_status,
)
from app.protocols.a2a.envelope import A2AReason

pytestmark = pytest.mark.asyncio


class TestIdempotentReplay:
    async def test_the_same_envelope_twice_executes_once(
        self, submit_a2a, a2a_envelope
    ):
        envelope = a2a_envelope(resource_id="pay-3310")
        first = await submit_a2a(envelope)
        second = await submit_a2a(envelope)

        assert first.executed is True
        assert first.idempotent is False
        assert second.executed is True          # it DID execute -- once
        assert second.idempotent is True
        # THE ASSERTION THAT MATTERS. Not the response: the record.
        assert payment_execution_count("pay-3310") == 1

    async def test_the_replay_returns_the_recorded_outcome(
        self, submit_a2a, a2a_envelope
    ):
        envelope = a2a_envelope()
        first = await submit_a2a(envelope)
        second = await submit_a2a(envelope)
        assert second.status == first.status == "EXECUTED"
        assert second.transaction_id == first.transaction_id
        assert second.result is not None

    async def test_a_replay_is_not_re_decided(self, submit_a2a, a2a_envelope):
        """A retry must not get a different answer for something that settled.

        The amount band, the credential state or an approval could all have
        moved since. Re-evaluating would mean a transaction that already
        executed could be reported as denied.
        """
        envelope = a2a_envelope()
        await submit_a2a(envelope)
        second = await submit_a2a(envelope)
        assert second.idempotent is True
        assert second.decision is None, (
            "an idempotent replay must return the RECORDED outcome, not a "
            "fresh PDP decision"
        )

    async def test_ten_replays_still_execute_once(self, submit_a2a, a2a_envelope):
        envelope = a2a_envelope(resource_id="pay-3310")
        for _ in range(10):
            await submit_a2a(envelope)
        assert payment_execution_count("pay-3310") == 1

    async def test_only_one_transaction_row_exists(
        self, submit_a2a, a2a_envelope, session
    ):
        envelope = a2a_envelope()
        await submit_a2a(envelope)
        await submit_a2a(envelope)
        rows = (await session.execute(select(A2ATransaction))).scalars().all()
        assert len(rows) == 1

    async def test_the_replay_is_recorded_as_an_attempt(
        self, submit_a2a, a2a_envelope, session
    ):
        envelope = a2a_envelope()
        await submit_a2a(envelope)
        await submit_a2a(envelope)
        attempts = (await session.execute(
            select(A2ATransactionAttempt))).scalars().all()
        assert any(a.reason == A2AReason.REPLAY_BLOCKED for a in attempts)


class TestTransactionIdReuse:
    async def test_the_same_id_with_a_different_amount_is_refused(
        self, submit_a2a, a2a_envelope
    ):
        """THE DANGEROUS CASE, and it is not a retry.

        An attacker reusing an id already accepted, to smuggle different
        content behind a record that exists. It gets its own reason so an
        operator is not told 'duplicate' about an attack.
        """
        first = await submit_a2a(a2a_envelope(transaction_id="txn-fixed",
                                              resource_id="pay-3310"))
        assert first.executed

        second = await submit_a2a(a2a_envelope(transaction_id="txn-fixed",
                                               resource_id="pay-3311",
                                               amount_inr=500_000))
        assert second.accepted is False
        assert second.reason == A2AReason.TRANSACTION_ID_REUSE
        assert payment_instruction_status("pay-3311") == "AWAITING_EXECUTION"

    async def test_the_same_id_with_a_different_payload_is_refused(
        self, submit_a2a, a2a_envelope
    ):
        await submit_a2a(a2a_envelope(transaction_id="txn-fixed",
                                      payload={"note": "one"}))
        second = await submit_a2a(a2a_envelope(transaction_id="txn-fixed",
                                               payload={"note": "two"}))
        assert second.reason == A2AReason.TRANSACTION_ID_REUSE

    async def test_the_same_id_from_a_DIFFERENT_sender_is_allowed(
        self, submit_a2a, a2a_envelope, fraud_agent, session
    ):
        """Uniqueness is COMPOSITE, and this is why.

        A global unique on transaction_id would let one sender squat on
        another's id namespace: pre-register `txn-0001` and the legitimate
        holder of that id is denied forever. The id belongs to the sender.
        """
        await submit_a2a(a2a_envelope(transaction_id="txn-0001"))
        other = await submit_a2a(
            a2a_envelope(transaction_id="txn-0001", sender=fraud_agent.did,
                         signing_agent=fraud_agent,
                         sender_kid=fraud_agent.active_key.kid))
        # fraud-001 holds no payment credential, so it is DENIED on policy --
        # but it is NOT refused as a duplicate, which is the point.
        assert other.reason != A2AReason.TRANSACTION_ID_REUSE
        rows = (await session.execute(select(A2ATransaction))).scalars().all()
        assert len(rows) == 2


class TestForgeriesDoNotBurnATransactionId:
    async def test_a_forged_submission_writes_no_transaction_row(
        self, submit_a2a, a2a_envelope, session
    ):
        """The ordering property: the signature verifies BEFORE the ledger.

        If a forged envelope could write a row, an attacker could burn a
        legitimate sender's transaction id with a unique-constraint
        collision.
        """
        forged = a2a_envelope(
            transaction_id="txn-precious",
            tamper=lambda e: e["transaction"].__setitem__("amountInr", 1))
        result = await submit_a2a(forged)
        assert result.accepted is False
        rows = (await session.execute(select(A2ATransaction))).scalars().all()
        assert rows == []

    async def test_the_legitimate_sender_can_still_use_that_id(
        self, submit_a2a, a2a_envelope
    ):
        for _ in range(5):
            await submit_a2a(a2a_envelope(
                transaction_id="txn-precious",
                tamper=lambda e: e["transaction"].__setitem__("amountInr", 1)))
        genuine = await submit_a2a(a2a_envelope(transaction_id="txn-precious"))
        assert genuine.executed is True, (
            "forged attempts must not consume a legitimate sender's id"
        )

    async def test_forged_attempts_are_still_recorded(
        self, submit_a2a, a2a_envelope, session
    ):
        """A refusal nobody can see is a refusal nobody can respond to."""
        for _ in range(3):
            await submit_a2a(a2a_envelope(
                tamper=lambda e: e["transaction"].__setitem__("amountInr", 1)))
        attempts = (await session.execute(
            select(A2ATransactionAttempt))).scalars().all()
        assert len(attempts) == 3
        assert all(a.accepted is False for a in attempts)
        assert all(a.submitted_by for a in attempts), (
            "the authenticated submitter is the one attributable fact"
        )

    async def test_a_rejected_attempt_does_not_attribute_to_the_claimed_sender(
        self, submit_a2a, a2a_envelope, session
    ):
        """On a forged envelope the sender is an ASSERTION, not a fact.

        The columns are named `claimed_*` so a reader cannot mistake a
        failed claim for an attribution.
        """
        await submit_a2a(a2a_envelope(
            tamper=lambda e: e["transaction"].__setitem__("amountInr", 1)))
        attempt = (await session.execute(
            select(A2ATransactionAttempt))).scalars().first()
        assert hasattr(attempt, "claimed_sender_did")
        assert not hasattr(attempt, "sender_did")


class TestTheNonceLedger:
    async def test_a_reused_nonce_under_a_fresh_id_is_refused(
        self, submit_a2a, a2a_envelope
    ):
        """The second, independent replay ledger.

        The transaction id already stops an exact replay. This stops a
        captured nonce being reused under a new id.
        """
        await submit_a2a(a2a_envelope(transaction_id="txn-a", nonce="shared-nonce"))
        second = await submit_a2a(
            a2a_envelope(transaction_id="txn-b", nonce="shared-nonce"))
        assert second.accepted is False
        assert second.reason == A2AReason.REPLAY_BLOCKED

    async def test_rejected_submissions_do_not_consume_a_nonce(
        self, submit_a2a, a2a_envelope
    ):
        """PARTIAL unique index: only a verified submission consumes one, so
        an attacker cannot burn a legitimate sender's nonces."""
        await submit_a2a(a2a_envelope(
            nonce="mine", transaction_id="txn-a",
            tamper=lambda e: e["transaction"].__setitem__("amountInr", 1)))
        genuine = await submit_a2a(a2a_envelope(nonce="mine",
                                                transaction_id="txn-a"))
        assert genuine.executed is True


class TestStaleAndExpired:
    async def test_an_expired_envelope_never_reaches_the_pdp(
        self, submit_a2a, a2a_envelope, backdate_key, risk_agent
    ):
        """An envelope whose window closed is refused BEFORE the PDP.

        The key is aged first: in a fresh database a 200-second-old envelope
        also predates its own key, and the key-window check fires first --
        correctly, but it would make this test assert the wrong thing.
        """
        from datetime import datetime, timedelta, timezone

        await backdate_key(risk_agent)
        past = datetime.now(timezone.utc) - timedelta(seconds=200)
        result = await submit_a2a(a2a_envelope(moment=past, ttl_seconds=60))
        assert result.accepted is False
        assert result.decision is None, "verification refused it before the PDP"
        assert result.reason == A2AReason.EXPIRED

    async def test_the_sweep_moves_overdue_transactions(
        self, submit_a2a, a2a_envelope, a2a_service, session
    ):
        """HOUSEKEEPING, not enforcement: an overdue transaction was already
        unusable. The sweep makes the stored status match reality."""
        from datetime import datetime, timedelta, timezone

        await submit_a2a(a2a_envelope(resource_id="pay-3311",
                                      amount_inr=500_000))
        record = (await session.execute(select(A2ATransaction))).scalars().first()
        assert record.status.value == "PENDING_APPROVAL"
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.flush()

        expired = await a2a_service.sweep_expired()
        assert record.transaction_id in expired
        await session.refresh(record)
        assert record.status.value == "EXPIRED"
