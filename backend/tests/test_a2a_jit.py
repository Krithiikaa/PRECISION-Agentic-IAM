"""A2A and JIT: a mandate is an INPUT, and it cannot authorize a payment.

TWO INDEPENDENT REFUSALS, for the reason `approve_loan` has two:

    1. `execute_payment` is absent from `jit_eligible_actions`
    2. `execute_payment` is named in `excluded_actions.actions`

A mandate carries an authorization forward across several actions. A human
who approved one payment did not approve five, and a mandate issued while an
instruction sat in the autonomous band could be spent on one that has since
moved into the dual-control band.

PHASE 7 ADDED NO JIT CODE. A mandate offered inside an envelope is handled by
the machinery Phase 6 already built: the PIP loads it, verifies it against the
JIT authority, and Rego decides what it means.
"""
from __future__ import annotations

import pytest

from app.authorization.contracts import Reason
from app.enforcement.resources import payment_execution_count

pytestmark = pytest.mark.asyncio


class TestAMandateCannotBeIssuedForAPayment:
    async def test_issuance_is_refused(
        self, a2a_aem, risk_agent, payment_credential, jit_policy_loaded,
        a2a_policy_loaded,
    ):
        """And it is refused by the STRONGER of the two available reasons.

        Issuance runs the FULL data-plane PDP evaluation first. Outside an
        A2A transaction there is no envelope, so `input.pip.a2a.present` is
        false, no A2A allow rule fires, and the action is simply not
        permitted -- so a mandate cannot be issued for something the agent
        could not do at that instant. The eligibility refusal below never
        even needs to be reached.
        """
        result = await a2a_aem.issue_jit_grant(
            subject_did=risk_agent.did, action="execute_payment",
            resource_type="payment_instructions", resource_ids=["pay-3310"],
            purpose="payment_settlement", ttl_seconds=300, max_uses=3,
        )
        assert result.issued is False
        assert result.reason == Reason.JIT_SCOPE_EXCEEDS_DECISION
        assert result.decision.decision.value == "DENY"

    async def test_the_eligibility_refusal_exists_independently(
        self, opa_client, jit_policy_loaded
    ):
        """THE SECOND, INDEPENDENT REFUSAL.

        Asked of the issuance package directly, with a fabricated clean
        ALLOW in the input -- which is the only way to reach the eligibility
        rule, precisely because the real PDP refuses first. If the action
        were ever permitted outside A2A, this is the rule that would still
        refuse the mandate.
        """
        from app.core.config import get_settings

        result = await opa_client.evaluate(
            {
                "request_id": "test",
                "decision": {"decision": "ALLOW", "reason": "FABRICATED"},
                "requested": {
                    "action": "execute_payment",
                    "resource_type": "payment_instructions",
                    "resource_ids": ["pay-3310"],
                    "ttl_seconds": 300, "max_uses": 3,
                },
                "pip": {},
            },
            decision_url=get_settings().jit_decision_url,
        )
        assert result.document["decision"] == "DENY"
        assert result.document["reason"] == Reason.JIT_ACTION_NOT_ELIGIBLE
        assert "excluded" in result.document.get("detail", "").lower()

    async def test_it_is_excluded_by_name_as_well_as_by_omission(self):
        import json
        import pathlib

        repo = pathlib.Path(__file__).resolve().parents[2]
        document = json.loads(
            (repo / "policies" / "data" / "jit_policy.json").read_text())
        assert "execute_payment" in document["excluded_actions"]["actions"]
        assert "execute_payment" not in document["jit_eligible_actions"]

    async def test_no_a2a_action_is_jit_eligible(self):
        """Phase 7 widened nothing. The eligible set is unchanged."""
        import json
        import pathlib

        repo = pathlib.Path(__file__).resolve().parents[2]
        jit = json.loads(
            (repo / "policies" / "data" / "jit_policy.json").read_text())
        a2a = json.loads(
            (repo / "policies" / "data" / "a2a_policy.json").read_text())
        actions = [a for a in a2a["a2a_eligible_actions"] if a != "_comment"]
        assert actions, "the A2A allow-list is empty"
        for action in actions:
            assert action not in jit["jit_eligible_actions"], (
                f"{action} became JIT-eligible; a mandate must not carry an "
                f"agent-to-agent instruction forward")
        assert a2a["jit"]["eligible"] is False


class TestAPresentedMandateCannotHelp:
    async def test_a_fabricated_grant_id_does_not_authorize(
        self, submit_a2a, a2a_envelope
    ):
        """An offered id is a CLAIM. The PIP looks it up and finds nothing."""
        result = await submit_a2a(a2a_envelope(
            resource_id="pay-3311", amount_inr=500_000,
            jit_grant_id="jit-i-made-this-up"))
        assert result.executed is False
        assert payment_execution_count("pay-3311") == 0

    async def test_a_genuine_mandate_for_ANOTHER_action_does_not_help(
        self, submit_a2a, a2a_envelope, issued_mandate
    ):
        """A real, signed, unexpired mandate -- over credit_records. It
        cannot move a payment, and the binding says why."""
        result = await submit_a2a(a2a_envelope(
            resource_id="pay-3311", amount_inr=500_000,
            jit_grant_id=issued_mandate.grant_id))
        assert result.executed is False
        assert payment_execution_count("pay-3311") == 0
        assert result.decision.reason == Reason.JIT_GRANT_BINDING_MISMATCH

    async def test_a_mandate_cannot_substitute_for_a_human(
        self, submit_a2a, a2a_envelope, issued_mandate
    ):
        """THE HITL BOUNDARY. A mandate is not a person."""
        result = await submit_a2a(a2a_envelope(
            resource_id="pay-3312", amount_inr=5_000_000,
            jit_grant_id=issued_mandate.grant_id))
        assert result.executed is False
        assert payment_execution_count("pay-3312") == 0

    async def test_a_mandate_id_cannot_be_added_by_the_relaying_receiver(
        self, submit_a2a, a2a_envelope, issued_mandate
    ):
        """`offered.jitGrantId` is inside the signature, so the agent
        carrying the instruction cannot add evidence to it."""
        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e["offered"].__setitem__(
                "jitGrantId", issued_mandate.grant_id)))
        assert result.accepted is False
        assert result.reason == "A2A_SIGNATURE_INVALID"


class TestJITRemainsAnInputNotADecision:
    async def test_the_autonomous_band_needs_no_mandate_at_all(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(resource_id="pay-3310"))
        assert result.executed is True
        assert result.decision.evaluation["pip"]["jit"]["present"] is False

    async def test_a_revoked_credential_beats_a_valid_mandate(
        self, submit_a2a, a2a_envelope, session, payment_credential,
        issued_mandate,
    ):
        """Phase 2's "revocation is invalid everywhere at once" still holds
        with a mandate in hand."""
        from app.credentials.status import CredentialStatusService

        await CredentialStatusService(session).revoke(
            payment_credential.credential_id, reason="compromised")
        result = await submit_a2a(a2a_envelope(
            resource_id="pay-3310", jit_grant_id=issued_mandate.grant_id))
        assert result.executed is False
        assert result.decision.decision.value == "DENY"
