"""Deactivating a policy stays deactivated (Phase 9).

THE DEFECT THIS FILE EXISTS TO PREVENT COMING BACK.

`policies/manifest.json` declares what every policy IS -- owner, purpose,
shipped version -- and every entry in it reads `"status": "ACTIVE"`, because
the file describes the SHIPPED set. The RUNNING state is different: an
operator can switch a policy off through
`POST /api/v1/policies/{id}/deactivate`, which deletes the module from OPA
and records INACTIVE in the database.

`reconcile()` and `load_all()` both read only the manifest. So a policy an
operator had deliberately switched off looked, to the reconciler, exactly
like a policy missing because OPA had restarted -- and it was pushed back
in. `main.py` runs that reconciler **every 15 seconds**, and its log line
says `policy_set_incomplete ... reloading`, which reads like recovery rather
than reversion.

The consequence was that **policy deactivation silently did not hold**. An
operator disabling a rule to stop an incident would have watched it come
back within fifteen seconds, with nothing in the log that looked wrong.

It surfaced as an intermittent failure of the Phase 6 gate's policy-change
check -- whether that check passed depended on whether a reconciler tick
landed between the deactivate and the authorization. An intermittent test is
a bad way to learn this; these tests are the deterministic way.
"""
from __future__ import annotations

import pytest

from app.authorization.pap import PolicyAdministrationPoint
from app.core.config import get_settings
from app.db.models.authorization import PolicyStatus

pytestmark = pytest.mark.integration

# A data-plane policy with a single, obvious job, so a test that switches it
# off is switching off something whose absence is easy to assert.
TARGET = "loan-credit-read"
TARGET_MODULE = "agentic_iam/loan/credit"


@pytest.fixture
async def pap(session, opa_client, policies_loaded):
    return PolicyAdministrationPoint(session, get_settings(), opa=opa_client)


@pytest.fixture
async def restore_policy(pap):
    """Put the policy set back however the test leaves it.

    Not optional politeness: OPA is shared by the whole suite and by the
    gate scripts, so a test that left a policy deactivated would make
    unrelated things fail in a way that looks nothing like its own cause.
    """
    yield
    await pap.activate(TARGET)


class TestDeactivationSurvivesReconciliation:
    async def test_deactivate_removes_the_module_from_the_engine(
        self, pap, opa_client, restore_policy
    ):
        assert TARGET_MODULE in set(await opa_client.list_policies())
        await pap.deactivate(TARGET)
        assert TARGET_MODULE not in set(await opa_client.list_policies())

    async def test_the_reconciler_does_not_put_it_back(
        self, pap, opa_client, restore_policy
    ):
        """THE CENTRAL TEST.

        `reconcile()` is what `main.py` runs on a 15-second timer. Calling it
        directly, immediately after a deactivation, is exactly the race that
        used to lose.
        """
        await pap.deactivate(TARGET)

        outcome = await pap.reconcile()

        assert TARGET_MODULE not in set(await opa_client.list_policies()), (
            "the reconciler restored a policy an operator had deactivated"
        )
        # And it should report the set as intact, not as repaired: a
        # deliberately absent module is not a fault to be announced.
        assert outcome.get("reconciled") is False
        assert TARGET not in (outcome.get("restored") or [])

    async def test_reconciling_repeatedly_still_does_not_put_it_back(
        self, pap, opa_client, restore_policy
    ):
        """Three ticks, because the original defect would have fired on the
        first one and a fix that only debounced would pass a single call."""
        await pap.deactivate(TARGET)
        for _ in range(3):
            await pap.reconcile()
        assert TARGET_MODULE not in set(await opa_client.list_policies())

    async def test_a_full_reload_does_not_put_it_back_either(
        self, pap, opa_client, restore_policy
    ):
        """`reconcile()` repairs by calling `load_all()`. Fixing only the
        reconciler would have left the same bug reachable through
        `POST /api/v1/policies/reload`, and through every service restart."""
        await pap.deactivate(TARGET)

        result = await pap.load_all()

        assert TARGET_MODULE not in set(await opa_client.list_policies())
        assert TARGET in result.get("skipped", [])
        assert TARGET not in result.get("loaded", [])

    async def test_the_database_still_says_inactive_after_a_reload(
        self, pap, restore_policy
    ):
        """The state must not drift back either: a record flipped to ACTIVE
        would re-arm the defect on the NEXT reconcile."""
        await pap.deactivate(TARGET)
        await pap.load_all()

        record = await pap.get(TARGET)
        assert record.status is PolicyStatus.INACTIVE


class TestReactivationStillWorks:
    """A fix that made deactivation permanent would be a worse bug."""

    async def test_activate_puts_it_back(self, pap, opa_client):
        await pap.deactivate(TARGET)
        assert TARGET_MODULE not in set(await opa_client.list_policies())

        await pap.activate(TARGET)
        assert TARGET_MODULE in set(await opa_client.list_policies())

    async def test_and_a_reload_then_keeps_it(self, pap, opa_client):
        await pap.deactivate(TARGET)
        await pap.activate(TARGET)
        await pap.load_all()
        assert TARGET_MODULE in set(await opa_client.list_policies())

    async def test_an_untouched_policy_is_unaffected_throughout(
        self, pap, opa_client, restore_policy
    ):
        """Deactivating one policy must not disturb the rest of the set --
        the reconciler reloads EVERYTHING when it repairs, so a bug here
        would be wide."""
        before = set(await opa_client.list_policies())
        await pap.deactivate(TARGET)
        await pap.reconcile()
        after = set(await opa_client.list_policies())

        assert before - after == {TARGET_MODULE}, (
            f"deactivating {TARGET} changed more than itself: "
            f"{(before - after) - {TARGET_MODULE}} also disappeared"
        )


class TestTheEngineRestartCaseStillRecovers:
    """The reconciler exists for a real reason, and it must keep working.

    OPA holds policy in memory, so an OPA restart comes back empty and the
    default-deny combining algorithm then denies everything. Recovering from
    that automatically is the whole point of the reconciler; the fix above
    must not have cost it.
    """

    async def test_a_module_missing_for_any_other_reason_is_restored(
        self, pap, opa_client
    ):
        """Deleted straight out of the engine, WITHOUT going through
        `deactivate()` -- which is what an OPA restart looks like. Nothing
        recorded it as INACTIVE, so the reconciler should put it back."""
        await opa_client.delete_policy(TARGET_MODULE)
        assert TARGET_MODULE not in set(await opa_client.list_policies())

        outcome = await pap.reconcile()

        assert TARGET_MODULE in set(await opa_client.list_policies()), (
            "the reconciler no longer recovers from an engine restart"
        )
        assert outcome.get("reconciled") is True
