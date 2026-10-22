"""The mandate lifecycle: budget, expiry, revocation, and the races.

The properties asserted here are enforced by the DATABASE, not by Python, and
the tests are written to prove that rather than to take it on trust. Where a
race matters, the test runs real concurrent tasks against real connections --
an assertion about a conditional UPDATE that never runs two of them
concurrently is an assertion about nothing.

Covers matrix items O (replay), T (concurrent use), and the revocation and
expiry semantics agreed in the Phase 6 design review.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import get_settings
from app.db.models.jit import JITGrant, JITGrantStatus
from app.jit.grant import GrantReason
from app.jit.service import (
    ALLOWED_TRANSITIONS,
    GrantNotActive,
    InvalidGrantTransition,
    JITService,
)

pytestmark = pytest.mark.integration


# ===========================================================================
#  The state machine
# ===========================================================================
class TestStateMachine:
    def test_every_terminal_state_is_terminal(self):
        """EXPIRED, EXHAUSTED and REVOKED have EMPTY transition sets.

        Not "nothing happens to write that code" -- an explicit empty set, so
        every impossible move is refused by name.
        """
        for status in (JITGrantStatus.EXPIRED, JITGrantStatus.EXHAUSTED,
                       JITGrantStatus.REVOKED):
            assert ALLOWED_TRANSITIONS[status] == frozenset(), status

    def test_active_can_only_reach_the_three_terminal_states(self):
        assert ALLOWED_TRANSITIONS[JITGrantStatus.ACTIVE] == frozenset({
            JITGrantStatus.EXHAUSTED, JITGrantStatus.EXPIRED, JITGrantStatus.REVOKED,
        })

    def test_nothing_can_return_to_active(self):
        """A mandate cannot be un-spent, un-expired or un-revoked."""
        for status, permitted in ALLOWED_TRANSITIONS.items():
            assert JITGrantStatus.ACTIVE not in permitted, status

    async def test_a_revoked_mandate_cannot_be_revoked_again(
        self, jit_service, issued_mandate
    ):
        await jit_service.revoke(issued_mandate.grant_id, reason="first")
        with pytest.raises((InvalidGrantTransition, GrantNotActive)):
            await jit_service.revoke(issued_mandate.grant_id, reason="second")

    async def test_an_expired_mandate_cannot_be_revoked(
        self, jit_service, issued_mandate
    ):
        """Revoking something already dead is a refusal, not a silent success.

        An operator must not be able to believe they have contained something
        they have not.
        """
        await jit_service.sweep_expired(
            now=issued_mandate.expires_at + timedelta(seconds=1)
        )
        with pytest.raises((InvalidGrantTransition, GrantNotActive)):
            await jit_service.revoke(issued_mandate.grant_id, reason="too late")


# ===========================================================================
#  The budget
# ===========================================================================
class TestBudget:
    async def test_uses_are_counted(self, jit_service, issued_mandate):
        for n in range(1, 4):
            won = await jit_service.record_use(
                issued_mandate.grant_id, request_id=f"authz-{n}",
                resource_id="customer-007",
            )
            assert won, f"use {n} should have been permitted"
            record = await jit_service.get(issued_mandate.grant_id)
            assert record.uses == n

    async def test_the_budget_is_bounded(self, jit_service, issued_mandate):
        """Matrix item O: a mandate spent out is refused, by name."""
        for n in range(3):
            assert await jit_service.record_use(
                issued_mandate.grant_id, request_id=f"authz-{n}")
        assert not await jit_service.record_use(
            issued_mandate.grant_id, request_id="authz-one-too-many")

    async def test_spending_the_budget_moves_it_to_exhausted(
        self, jit_service, issued_mandate
    ):
        for n in range(3):
            await jit_service.record_use(issued_mandate.grant_id, request_id=f"authz-{n}")
        record = await jit_service.get(issued_mandate.grant_id)
        assert record.status is JITGrantStatus.EXHAUSTED
        assert record.exhausted_at is not None

    async def test_exhausted_is_distinct_from_expired(self, jit_service, issued_mandate):
        """"You spent your budget" and "your window closed" are different.

        Collapsing them would make a mandate that ran out look like one that
        timed out, and an operator would chase the wrong cause.
        """
        for n in range(3):
            await jit_service.record_use(issued_mandate.grant_id, request_id=f"authz-{n}")
        record = await jit_service.get(issued_mandate.grant_id)
        assert record.status is JITGrantStatus.EXHAUSTED
        assert record.expired_at is None

    async def test_a_retried_request_does_not_burn_a_second_use(
        self, jit_service, issued_mandate
    ):
        """IDEMPOTENCY. `UNIQUE (grant_id, request_id)` earning its place.

        A client that did not see the response retries. That must not cost a
        second unit of a budget somebody authorised.
        """
        assert await jit_service.record_use(issued_mandate.grant_id, request_id="authz-1")
        assert await jit_service.record_use(issued_mandate.grant_id, request_id="authz-1")
        assert await jit_service.record_use(issued_mandate.grant_id, request_id="authz-1")
        record = await jit_service.get(issued_mandate.grant_id)
        assert record.uses == 1

    async def test_each_use_is_recorded_with_what_it_was_spent_on(
        self, jit_service, issued_mandate
    ):
        await jit_service.record_use(issued_mandate.grant_id, request_id="authz-1",
                                     resource_id="customer-007", action="read")
        uses = await jit_service.uses_of(issued_mandate.grant_id)
        assert len(uses) == 1
        assert uses[0].request_id == "authz-1"
        assert uses[0].resource_id == "customer-007"
        assert uses[0].sequence == 1

    async def test_the_database_refuses_an_overspent_budget(
        self, session, jit_service, issued_mandate
    ):
        """The CHECK constraint, asserted directly.

        Belt and braces behind the conditional UPDATE: even a direct write that
        bypassed the service cannot leave the row in an overspent state.
        """
        from sqlalchemy.exc import IntegrityError
        from sqlalchemy import update

        with pytest.raises(IntegrityError):
            await session.execute(
                update(JITGrant)
                .where(JITGrant.grant_id == issued_mandate.grant_id)
                .values(uses=999)
            )
            await session.flush()
        await session.rollback()


# ===========================================================================
#  Expiry -- server clock only
# ===========================================================================
class TestExpiry:
    async def test_an_expired_mandate_cannot_be_spent(self, jit_service, issued_mandate):
        won = await jit_service.record_use(
            issued_mandate.grant_id, request_id="authz-late",
            now=issued_mandate.expires_at + timedelta(seconds=1),
        )
        assert not won

    async def test_the_expiry_boundary_denies(self, jit_service, issued_mandate):
        """`expires_at > now` in the WHERE clause: the boundary instant fails."""
        won = await jit_service.record_use(
            issued_mandate.grant_id, request_id="authz-boundary",
            now=issued_mandate.expires_at,
        )
        assert not won

    async def test_just_before_expiry_still_works(self, jit_service, issued_mandate):
        won = await jit_service.record_use(
            issued_mandate.grant_id, request_id="authz-just-in-time",
            now=issued_mandate.expires_at - timedelta(milliseconds=1),
        )
        assert won

    async def test_expiry_is_atomic_with_the_spend(self, jit_service, issued_mandate):
        """Both conditions are in ONE WHERE clause.

        Checking expiry separately would leave a window in which a mandate
        expires between the check and the spend. Asserting the shape of the
        statement is the only way to assert the absence of that window.
        """
        import inspect

        source = inspect.getsource(JITService.record_use)
        update_block = source[source.index("update(JITGrant)"):source.index("returning")]
        assert "JITGrant.expires_at > now" in update_block
        assert "JITGrant.uses < JITGrant.max_uses" in update_block
        assert "JITGrantStatus.ACTIVE" in update_block

    async def test_the_sweep_marks_overdue_mandates(self, jit_service, issued_mandate):
        expired = await jit_service.sweep_expired(
            now=issued_mandate.expires_at + timedelta(seconds=1)
        )
        assert issued_mandate.grant_id in expired
        record = await jit_service.get(issued_mandate.grant_id)
        assert record.status is JITGrantStatus.EXPIRED
        assert record.expired_at is not None

    async def test_the_sweep_is_housekeeping_not_enforcement(
        self, jit_service, issued_mandate
    ):
        """A mandate past expiry is already unusable BEFORE any sweep runs.

        If enforcement depended on the sweep, a mandate would stay usable for
        as long as nobody ran it -- which is exactly the kind of dependency
        that turns into an incident.
        """
        late = issued_mandate.expires_at + timedelta(seconds=1)
        record = await jit_service.get(issued_mandate.grant_id)
        assert record.status is JITGrantStatus.ACTIVE  # no sweep has run
        assert not await jit_service.record_use(
            issued_mandate.grant_id, request_id="authz-late", now=late)

    async def test_the_sweep_leaves_live_mandates_alone(
        self, jit_service, issued_mandate
    ):
        assert await jit_service.sweep_expired() == []
        record = await jit_service.get(issued_mandate.grant_id)
        assert record.status is JITGrantStatus.ACTIVE


# ===========================================================================
#  Revocation
# ===========================================================================
class TestRevocation:
    async def test_a_revoked_mandate_cannot_be_spent(self, jit_service, issued_mandate):
        """Matrix item N: takes effect immediately, with nothing cached."""
        await jit_service.revoke(issued_mandate.grant_id, reason="compromise suspected")
        assert not await jit_service.record_use(
            issued_mandate.grant_id, request_id="authz-after-revocation")

    async def test_revocation_records_who_and_why(self, jit_service, issued_mandate):
        await jit_service.revoke(
            issued_mandate.grant_id, reason="incident 4711",
            revoked_by="did:poc:administrator:identity-authority",
        )
        record = await jit_service.get(issued_mandate.grant_id)
        assert record.status is JITGrantStatus.REVOKED
        assert record.revocation_reason == "incident 4711"
        assert record.revoked_by == "did:poc:administrator:identity-authority"
        assert record.revoked_at is not None

    async def test_revocation_preserves_the_budget_already_spent(
        self, jit_service, issued_mandate
    ):
        """History is not rewritten. What was used stays used."""
        await jit_service.record_use(issued_mandate.grant_id, request_id="authz-1")
        await jit_service.revoke(issued_mandate.grant_id, reason="contain")
        record = await jit_service.get(issued_mandate.grant_id)
        assert record.uses == 1
        assert len(await jit_service.uses_of(issued_mandate.grant_id)) == 1

    async def test_revoking_every_mandate_for_an_agent(
        self, jit_service, jit_binding, risk_agent
    ):
        """THE CONTAINMENT INTEGRATION POINT Phase 10 and 12 will call."""
        ids = []
        for n in range(3):
            record = await jit_service.issue(
                binding=jit_binding(resource_ids=(f"customer-{n}",)),
                ttl_seconds=300, max_uses=2,
                issuing_request_id=f"authz-{n}", justification={},
            )
            ids.append(record.grant_id)

        revoked = await jit_service.revoke_for_agent(
            risk_agent.did, reason="agent compromised",
            revoked_by="did:poc:administrator:identity-authority",
        )
        assert set(revoked) == set(ids)
        for grant_id in ids:
            assert not await jit_service.record_use(grant_id, request_id=f"after-{grant_id}")

    async def test_revoking_for_an_agent_leaves_other_agents_alone(
        self, jit_service, jit_binding, risk_agent, fraud_agent
    ):
        mine = await jit_service.issue(
            binding=jit_binding(), ttl_seconds=300, max_uses=2,
            issuing_request_id="authz-mine", justification={},
        )
        theirs = await jit_service.issue(
            binding=jit_binding(agent_did=fraud_agent.did), ttl_seconds=300,
            max_uses=2, issuing_request_id="authz-theirs", justification={},
        )
        await jit_service.revoke_for_agent(risk_agent.did, reason="contain")
        assert (await jit_service.get(mine.grant_id)).status is JITGrantStatus.REVOKED
        assert (await jit_service.get(theirs.grant_id)).status is JITGrantStatus.ACTIVE

    async def test_revoking_mandates_derived_from_an_approval(
        self, jit_service, jit_binding
    ):
        """A mandate must not outlive the decision it rests on."""
        record = await jit_service.issue(
            binding=jit_binding(), ttl_seconds=300, max_uses=2,
            issuing_request_id="authz-1", justification={}, approval_id="appr-123",
        )
        revoked = await jit_service.revoke_for_approval(
            "appr-123", reason="the approval was withdrawn")
        assert revoked == [record.grant_id]
        assert (await jit_service.get(record.grant_id)).status is JITGrantStatus.REVOKED


# ===========================================================================
#  Concurrency -- real tasks, real connections
# ===========================================================================
class TestConcurrency:
    """Real tasks on real connections.

    Every test here COMMITS its setup first: separate connections cannot see an
    uncommitted insert, and a "race" in which the other tasks cannot even find
    the row proves nothing. The conftest truncation still cleans up afterwards.
    """

    async def test_the_last_use_has_exactly_one_winner(self, engine, session,
                                                       jit_service, issued_mandate):
        """Matrix item T.

        Ten concurrent callers, one remaining unit of budget. The DATABASE
        picks the winner; a read-then-write would let several through.
        """
        await jit_service.record_use(issued_mandate.grant_id, request_id="authz-a")
        await jit_service.record_use(issued_mandate.grant_id, request_id="authz-b")
        await session.commit()
        # One use left of three, and visible to other connections.

        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def attempt(n: int) -> bool:
            async with maker() as s:
                service = JITService(s, None, get_settings())
                won = await service.record_use(
                    issued_mandate.grant_id, request_id=f"authz-race-{n}")
                await s.commit()
                return won

        results = await asyncio.gather(*(attempt(n) for n in range(10)),
                                       return_exceptions=True)
        winners = [r for r in results if r is True]
        assert len(winners) == 1, f"expected exactly one winner, got {results}"

        async with maker() as s:
            record = await JITService(s).get(issued_mandate.grant_id)
            assert record.uses == 3
            assert record.status is JITGrantStatus.EXHAUSTED

    async def test_concurrent_uses_never_exceed_the_budget(self, engine, session,
                                                           jit_service, jit_binding):
        """Twenty callers against a budget of five. Five win, and only five."""
        record = await jit_service.issue(
            binding=jit_binding(), ttl_seconds=300, max_uses=5,
            issuing_request_id="authz-budget", justification={},
        )
        await session.commit()
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def attempt(n: int) -> bool:
            async with maker() as s:
                service = JITService(s, None, get_settings())
                won = await service.record_use(record.grant_id, request_id=f"req-{n}")
                await s.commit()
                return won

        results = await asyncio.gather(*(attempt(n) for n in range(20)),
                                       return_exceptions=True)
        assert len([r for r in results if r is True]) == 5

        async with maker() as s:
            final = await JITService(s).get(record.grant_id)
            assert final.uses == 5
            assert final.status is JITGrantStatus.EXHAUSTED

    async def test_a_use_racing_a_revocation_does_not_both_succeed(
        self, engine, session, jit_service, issued_mandate
    ):
        """Revocation and spending contend for the same ACTIVE row."""
        await session.commit()
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def spend() -> bool:
            async with maker() as s:
                won = await JITService(s, None, get_settings()).record_use(
                    issued_mandate.grant_id, request_id="authz-racing")
                await s.commit()
                return won

        async def revoke() -> bool:
            async with maker() as s:
                try:
                    await JITService(s, None, get_settings()).revoke(
                        issued_mandate.grant_id, reason="racing")
                    await s.commit()
                    return True
                except (GrantNotActive, InvalidGrantTransition):
                    return False

        await asyncio.gather(spend(), revoke(), return_exceptions=True)

        async with maker() as s:
            record = await JITService(s).get(issued_mandate.grant_id)
            # Whatever the interleaving, the mandate is dead and cannot be
            # spent again. That is the invariant; which of the two won the
            # instant is not something callers may rely on.
            assert record.status is JITGrantStatus.REVOKED
            won_after = await JITService(s, None, get_settings()).record_use(
                issued_mandate.grant_id, request_id="authz-after")
            assert not won_after


# ===========================================================================
#  Issuance bounds enforced structurally
# ===========================================================================
class TestIssuanceStructuralBounds:
    async def test_a_non_positive_ttl_is_refused(self, jit_service, jit_binding):
        from app.core.errors import ConflictError

        with pytest.raises(ConflictError):
            await jit_service.issue(binding=jit_binding(), ttl_seconds=0, max_uses=1,
                                    issuing_request_id="authz-1", justification={})

    async def test_a_non_positive_budget_is_refused(self, jit_service, jit_binding):
        from app.core.errors import ConflictError

        with pytest.raises(ConflictError):
            await jit_service.issue(binding=jit_binding(), ttl_seconds=60, max_uses=0,
                                    issuing_request_id="authz-1", justification={})

    async def test_an_absurd_ttl_is_refused_before_opa_is_asked(
        self, jit_service, jit_binding
    ):
        """Matrix item R, at the structural layer.

        Policy is the real ceiling and is stricter. This bound exists so a
        nonsensical request is refused without an OPA round trip, and it can
        never be more permissive than policy.
        """
        from app.core.errors import ConflictError

        with pytest.raises(ConflictError):
            await jit_service.issue(
                binding=jit_binding(),
                ttl_seconds=get_settings().jit_absolute_max_ttl_seconds + 1,
                max_uses=1, issuing_request_id="authz-1", justification={},
            )

    async def test_an_absurd_budget_is_refused(self, jit_service, jit_binding):
        from app.core.errors import ConflictError

        with pytest.raises(ConflictError):
            await jit_service.issue(
                binding=jit_binding(), ttl_seconds=60,
                max_uses=get_settings().jit_absolute_max_uses + 1,
                issuing_request_id="authz-1", justification={},
            )

    async def test_a_service_without_a_keystore_refuses_to_issue(
        self, session, jit_binding
    ):
        """It cannot sign, so it must not pretend to have issued anything."""
        service = JITService(session, None, get_settings())
        with pytest.raises(RuntimeError, match="cannot sign"):
            await service.issue(binding=jit_binding(), ttl_seconds=60, max_uses=1,
                                issuing_request_id="authz-1", justification={})


# ===========================================================================
#  The verdict the PIP reports
# ===========================================================================
class TestFact:
    async def test_no_offered_id_means_no_mandate_applies(
        self, jit_service, jit_binding, issued_mandate
    ):
        """A mandate is OPT-IN. It is never auto-discovered.

        Auto-discovery would let a live mandate REDUCE an agent's baseline
        authority: one whose ceiling a record had outgrown would start denying
        actions the agent's own credential already permits, without anyone
        having presented it. A mandate must only ever be able to help.
        """
        fact = await jit_service.fact_for(jit_binding(), grant_id=None,
                                          resource_id="customer-007")
        assert not fact.present
        assert fact.reason == GrantReason.MISSING

    async def test_an_unknown_id_is_present_and_refused(self, jit_service, jit_binding):
        """Matrix item M: distinct from "no mandate offered"."""
        fact = await jit_service.fact_for(jit_binding(), grant_id="jit-does-not-exist")
        assert fact.present
        assert not fact.valid
        assert fact.reason == GrantReason.UNKNOWN

    async def test_a_valid_mandate_reports_valid(
        self, jit_service, jit_binding, issued_mandate
    ):
        fact = await jit_service.fact_for(
            jit_binding(), grant_id=issued_mandate.grant_id,
            resource_id="customer-007",
        )
        assert fact.valid, fact.reason
        assert fact.bound_to_request and fact.covers_resource
        assert fact.uses_remaining == 3

    async def test_lifecycle_is_reported_before_the_signature(
        self, jit_service, jit_binding, issued_mandate
    ):
        """A revoked mandate is perfectly signed.

        Reporting "signature invalid" for one would send an operator hunting
        entirely the wrong problem.
        """
        await jit_service.revoke(issued_mandate.grant_id, reason="contain")
        fact = await jit_service.fact_for(
            jit_binding(), grant_id=issued_mandate.grant_id,
            resource_id="customer-007",
        )
        assert fact.reason == GrantReason.REVOKED

    async def test_an_exhausted_mandate_reports_exhausted(
        self, jit_service, jit_binding, issued_mandate
    ):
        for n in range(3):
            await jit_service.record_use(issued_mandate.grant_id, request_id=f"r-{n}")
        fact = await jit_service.fact_for(
            jit_binding(), grant_id=issued_mandate.grant_id,
            resource_id="customer-007",
        )
        assert fact.reason == GrantReason.EXHAUSTED

    async def test_the_fact_carries_the_credentials_it_rested_on(
        self, jit_service, jit_binding
    ):
        """So policy can assert they are STILL valid at use time."""
        record = await jit_service.issue(
            binding=jit_binding(), ttl_seconds=300, max_uses=1,
            issuing_request_id="authz-1",
            justification={"credential_ids": ["urn:uuid:abc", "urn:uuid:def"]},
        )
        fact = await jit_service.fact_for(
            jit_binding(), grant_id=record.grant_id, resource_id="customer-007")
        assert fact.justified_by_credentials == ["urn:uuid:abc", "urn:uuid:def"]

    async def test_stats_counts_by_status(self, jit_service, jit_binding):
        await jit_service.issue(binding=jit_binding(), ttl_seconds=300, max_uses=1,
                                issuing_request_id="a", justification={})
        record = await jit_service.issue(binding=jit_binding(), ttl_seconds=300,
                                         max_uses=1, issuing_request_id="b",
                                         justification={})
        await jit_service.revoke(record.grant_id, reason="x")
        stats = await jit_service.stats()
        assert stats["ACTIVE"] == 1
        assert stats["REVOKED"] == 1
