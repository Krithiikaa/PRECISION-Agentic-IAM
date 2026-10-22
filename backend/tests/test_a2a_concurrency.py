"""Exactly-once execution under genuine concurrency.

REAL CONCURRENT TASKS ON REAL CONNECTIONS. A test that awaits one coroutine
at a time is not testing a race, and a "race" whose tasks share one session
cannot even see each other's uncommitted rows -- which would prove nothing.
Every test here commits, so the contention is real.

THE ASSERTION THAT MATTERS IS ALWAYS THE RECORD, never a response. A test
that only checked responses could not tell one execution from two that both
reported success.
"""
from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import get_settings
from app.db.models.a2a import A2ATransaction, A2ATransactionStatus
from app.enforcement.aem import AdapterEnforcementMiddleware
from app.enforcement.resources import (
    payment_execution_count,
    payment_instruction_status,
)
from app.protocols.a2a.envelope import A2AReason
from app.protocols.a2a.service import A2ATransactionService, InvalidTransactionTransition

pytestmark = pytest.mark.asyncio


class TestConcurrentDuplicateSubmission:
    """Matrix items 7 and 8: concurrent replay, duplicate financial execution."""

    async def test_twenty_concurrent_submissions_execute_exactly_once(
        self, engine, session, keystore, a2a_envelope, payments_agent,
        payment_credential, a2a_policy_loaded, opa_client,
    ):
        """THE CENTRAL FINANCIAL PROPERTY.

        Twenty callers present the SAME signed instruction at the same
        instant. The database decides: `UNIQUE (sender_did, transaction_id)`
        admits one processing path, and the conditional UPDATE admits one
        execution. Nineteen are answered idempotently.
        """
        await session.commit()
        envelope = a2a_envelope(resource_id="pay-3310", amount_inr=50_000)
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def submit(n: int):
            async with maker() as s:
                from app.authorization.pdp import PolicyDecisionPoint
                aem = AdapterEnforcementMiddleware(
                    s, keystore, get_settings(),
                    pdp=PolicyDecisionPoint(s, keystore, get_settings(),
                                            opa=opa_client),
                )
                result = await aem.enforce_a2a(
                    envelope=envelope, submitted_by=payments_agent.did)
                await s.commit()
                return result

        results = await asyncio.gather(*(submit(n) for n in range(20)),
                                       return_exceptions=True)
        errors = [r for r in results if isinstance(r, Exception)]
        assert not errors, f"submissions raised: {errors}"

        # THE MONEY MOVED ONCE. Read from the record, not from a response.
        assert payment_execution_count("pay-3310") == 1
        assert payment_instruction_status("pay-3310") == "EXECUTED"

        # Exactly one transaction row, and it is EXECUTED.
        async with maker() as s:
            rows = (await s.execute(select(A2ATransaction))).scalars().all()
            assert len(rows) == 1
            assert rows[0].status is A2ATransactionStatus.EXECUTED

        # Exactly one caller processed it; the rest were idempotent.
        processed = [r for r in results if not r.idempotent]
        idempotent = [r for r in results if r.idempotent]
        assert len(processed) == 1, (
            f"expected one processing path, got {len(processed)}")
        assert len(idempotent) == 19
        assert all(r.accepted for r in results)

    async def test_concurrent_submissions_of_DIFFERENT_transactions_all_succeed(
        self, engine, session, keystore, a2a_envelope, payments_agent,
        payment_credential, a2a_policy_loaded, opa_client,
    ):
        """No false serialisation.

        Exactly-once must not become one-at-a-time: five distinct
        instructions against five distinct records must all proceed.
        """
        await session.commit()
        envelopes = [a2a_envelope(transaction_id=f"txn-distinct-{n}",
                                  resource_id="pay-3310")
                     for n in range(5)]
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def submit(envelope):
            async with maker() as s:
                from app.authorization.pdp import PolicyDecisionPoint
                aem = AdapterEnforcementMiddleware(
                    s, keystore, get_settings(),
                    pdp=PolicyDecisionPoint(s, keystore, get_settings(),
                                            opa=opa_client),
                )
                result = await aem.enforce_a2a(
                    envelope=envelope, submitted_by=payments_agent.did)
                await s.commit()
                return result

        results = await asyncio.gather(*(submit(e) for e in envelopes),
                                       return_exceptions=True)
        errors = [r for r in results if isinstance(r, Exception)]
        assert not errors, f"submissions raised: {errors}"
        assert all(r.accepted for r in results)
        assert all(not r.idempotent for r in results), (
            "five distinct transactions must not be treated as retries")

        async with maker() as s:
            count = (await s.execute(
                select(func.count()).select_from(A2ATransaction))).scalar_one()
            assert count == 5

    async def test_exactly_one_execution_event_is_emitted(
        self, engine, session, keystore, a2a_envelope, payments_agent,
        payment_credential, a2a_policy_loaded, opa_client,
    ):
        """An audit trail that recorded two executions for one payment would
        be worse than useless during an incident."""
        from app.db.models.audit import AuditEvent

        await session.commit()
        envelope = a2a_envelope(resource_id="pay-3310")
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def submit(n):
            async with maker() as s:
                from app.authorization.pdp import PolicyDecisionPoint
                aem = AdapterEnforcementMiddleware(
                    s, keystore, get_settings(),
                    pdp=PolicyDecisionPoint(s, keystore, get_settings(),
                                            opa=opa_client),
                )
                r = await aem.enforce_a2a(envelope=envelope,
                                          submitted_by=payments_agent.did)
                await s.commit()
                return r

        await asyncio.gather(*(submit(n) for n in range(10)),
                             return_exceptions=True)
        async with maker() as s:
            executed = (await s.execute(
                select(func.count()).select_from(AuditEvent)
                .where(AuditEvent.event_type == "A2A_EXECUTED"))).scalar_one()
            assert executed == 1


class TestTheExecutionClaimIsAtomic:
    async def test_the_claim_can_only_be_won_once(
        self, engine, session, a2a_envelope, a2a_service, payments_agent
    ):
        """The SECOND independent layer, behind the unique INSERT.

        Even a single processing path cannot enter execution twice.
        """
        report = await a2a_service.verify(
            a2a_envelope(), expected_receiver_did=payments_agent.did)
        outcome = await a2a_service.register(
            a2a_envelope(transaction_id=report.transaction_id), report,
            submitted_by=payments_agent.did)
        record = outcome.record
        await a2a_service.mark_verified(record, server_amount_inr=50_000,
                                        amount_reconciled=True)
        await a2a_service.mark_decided(
            record, decision="ALLOW", reason="TEST", policy_id="p",
            policy_version="v1", authorized_amount_inr=50_000)
        await session.commit()

        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def claim(n):
            async with maker() as s:
                service = A2ATransactionService(s, get_settings())
                fresh = await service.get(record.sender_did, record.transaction_id)
                won = await service.claim_execution(fresh)
                await s.commit()
                return won

        results = await asyncio.gather(*(claim(n) for n in range(10)),
                                       return_exceptions=True)
        assert len([r for r in results if r is True]) == 1, results

    async def test_an_expired_transaction_cannot_be_claimed(
        self, session, a2a_envelope, a2a_service, payments_agent
    ):
        """Expiry is folded into the SAME atomic condition, so there is no
        window between the check and the execution."""
        from datetime import datetime, timedelta, timezone

        report = await a2a_service.verify(
            a2a_envelope(), expected_receiver_did=payments_agent.did)
        outcome = await a2a_service.register(
            a2a_envelope(transaction_id=report.transaction_id), report,
            submitted_by=payments_agent.did)
        record = outcome.record
        await a2a_service.mark_verified(record, server_amount_inr=50_000,
                                        amount_reconciled=True)
        await a2a_service.mark_decided(record, decision="ALLOW", reason="TEST",
                                       policy_id="p", policy_version="v1")
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.flush()
        assert await a2a_service.claim_execution(record) is False


class TestTerminalStatesAreTerminal:
    """Every terminal state has an EMPTY transition set, so nothing can bring
    a settled transaction back. Refused BY NAME, not by nobody having written
    the code."""

    @pytest.mark.parametrize("terminal", [
        A2ATransactionStatus.EXECUTED,
        A2ATransactionStatus.DENIED,
        A2ATransactionStatus.REJECTED,
        A2ATransactionStatus.FAILED,
        A2ATransactionStatus.EXPIRED,
    ])
    async def test_nothing_moves_out_of_a_terminal_state(
        self, session, a2a_envelope, a2a_service, payments_agent, terminal
    ):
        report = await a2a_service.verify(
            a2a_envelope(), expected_receiver_did=payments_agent.did)
        outcome = await a2a_service.register(
            a2a_envelope(transaction_id=report.transaction_id), report,
            submitted_by=payments_agent.did)
        record = outcome.record
        record.status = terminal
        await session.flush()
        for target in (A2ATransactionStatus.VERIFIED,
                       A2ATransactionStatus.AUTHORIZED,
                       A2ATransactionStatus.EXECUTING,
                       A2ATransactionStatus.EXECUTED):
            with pytest.raises(InvalidTransactionTransition):
                a2a_service._assert_transition(record, target)

    async def test_an_executed_transaction_cannot_execute_again(
        self, session, a2a_envelope, a2a_service, payments_agent
    ):
        report = await a2a_service.verify(
            a2a_envelope(), expected_receiver_did=payments_agent.did)
        outcome = await a2a_service.register(
            a2a_envelope(transaction_id=report.transaction_id), report,
            submitted_by=payments_agent.did)
        record = outcome.record
        record.status = A2ATransactionStatus.EXECUTED
        await session.flush()
        assert await a2a_service.claim_execution(record) is False
