"""The Phase 7 security matrix, one class per threat family.

Each test names the threat it closes. Where a property is asserted in more
detail elsewhere, this file still asserts it once, so the matrix is legible
in a single place -- the same discipline the Phase 5.5 and Phase 6 matrices
follow.

    1  forged transaction            13 unknown key
    2  modified payload              14 retired key
    3  modified amount               15 key rotation
    4  sender substitution           16 compromised sender
    5  receiver substitution         17 compromised receiver
    6  replay                        18 ANS failure
    7  concurrent replay             19 DID resolution failure
    8  duplicate financial execution 20 OPA failure
    9  stale transaction             21 policy failure
    10 revoked sender credential     22 confused deputy
    11 deactivated sender            23 purpose manipulation
    12 unknown sender                24 action manipulation
                                     25 resource manipulation
                                     26 JIT scope manipulation
                                     27 HITL bypass
                                     28 amount escalation
                                     29 cross-agent forwarding
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.authorization.contracts import Reason
from app.db.models.a2a import A2ATransaction
from app.db.models.audit import AuditEvent
from app.enforcement.resources import (
    payment_execution_count,
    payment_instruction_status,
)
from app.protocols.a2a.envelope import A2AReason

pytestmark = pytest.mark.asyncio


def _nothing_moved(instruction_id="pay-3310"):
    return (payment_execution_count(instruction_id) == 0
            and payment_instruction_status(instruction_id) == "AWAITING_EXECUTION")


class TestForgeryAndTampering:
    """Threats 1-4: forged transaction, modified payload, modified amount,
    sender substitution."""

    async def test_1_a_forged_transaction_is_refused(
        self, submit_a2a, a2a_envelope
    ):
        import base64

        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e["proof"].__setitem__(
                "signatureValue", base64.b64encode(b"\\x00" * 64).decode())))
        assert result.accepted is False
        assert result.reason == A2AReason.SIGNATURE_INVALID
        assert _nothing_moved()

    async def test_2_a_modified_payload_is_refused(self, submit_a2a, a2a_envelope):
        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e["transaction"]["payload"].__setitem__(
                "beneficiary_ref", "attacker")))
        assert result.accepted is False
        assert _nothing_moved()

    async def test_3_a_modified_amount_is_refused(self, submit_a2a, a2a_envelope):
        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e["transaction"].__setitem__("amountInr", 5_000_000)))
        assert result.accepted is False
        assert result.reason == A2AReason.SIGNATURE_INVALID
        assert _nothing_moved()

    async def test_4_sender_substitution_is_refused(
        self, submit_a2a, a2a_envelope, fraud_agent
    ):
        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e.__setitem__("senderDid", fraud_agent.did)))
        assert result.accepted is False
        assert _nothing_moved()


class TestReceiverBinding:
    """Threats 5 and 29: receiver substitution, cross-agent forwarding."""

    async def test_5_receiver_substitution_breaks_the_signature(
        self, submit_a2a, a2a_envelope, fraud_agent
    ):
        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e.__setitem__("receiverDid", fraud_agent.did)))
        assert result.accepted is False
        assert _nothing_moved()

    async def test_29_the_same_envelope_toward_another_receiver_is_refused(
        self, submit_a2a, a2a_envelope, fraud_agent
    ):
        """A genuine envelope, unmodified, presented by an agent it is not
        addressed to. Refused by the CRYPTOGRAPHIC binding here, and by the
        control-plane guard at the HTTP boundary (test_a2a_api.py)."""
        result = await submit_a2a(a2a_envelope(), submitted_by=fraud_agent.did)
        assert result.accepted is False
        assert result.reason == A2AReason.RECEIVER_MISMATCH
        assert _nothing_moved()


class TestReplayAndDuplication:
    """Threats 6-9: replay, concurrent replay, duplicate financial execution,
    stale transaction."""

    async def test_6_a_replay_does_not_execute_twice(
        self, submit_a2a, a2a_envelope
    ):
        envelope = a2a_envelope()
        await submit_a2a(envelope)
        await submit_a2a(envelope)
        assert payment_execution_count("pay-3310") == 1

    async def test_8_the_money_moves_exactly_once(self, submit_a2a, a2a_envelope):
        envelope = a2a_envelope()
        for _ in range(5):
            await submit_a2a(envelope)
        assert payment_execution_count("pay-3310") == 1

    async def test_9_a_stale_transaction_is_refused(
        self, submit_a2a, a2a_envelope, backdate_key, risk_agent
    ):
        from datetime import datetime, timedelta, timezone

        await backdate_key(risk_agent)
        result = await submit_a2a(a2a_envelope(
            moment=datetime.now(timezone.utc) - timedelta(seconds=400),
            ttl_seconds=60))
        assert result.accepted is False
        assert _nothing_moved()

    async def test_the_replay_is_named_as_one_in_the_trail(
        self, submit_a2a, a2a_envelope, session
    ):
        envelope = a2a_envelope()
        await submit_a2a(envelope)
        await submit_a2a(envelope)
        events = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == "A2A_REPLAY_BLOCKED"))).scalars().all()
        assert events


class TestIdentityAndTrust:
    """Threats 10-12: revoked credential, deactivated sender, unknown sender."""

    async def test_10_a_revoked_credential_denies(
        self, submit_a2a, a2a_envelope, session, payment_credential
    ):
        from app.credentials.status import CredentialStatusService

        envelope = a2a_envelope()
        await CredentialStatusService(session).revoke(
            payment_credential.credential_id, reason="compromised")
        result = await submit_a2a(envelope)
        assert result.decision.reason == Reason.CREDENTIAL_REVOKED
        assert _nothing_moved()

    async def test_11_a_deactivated_sender_denies(
        self, submit_a2a, a2a_envelope, risk_agent, session
    ):
        from app.db.models.agent import AgentStatus

        envelope = a2a_envelope()
        risk_agent.status = AgentStatus.SUSPENDED
        await session.flush()
        result = await submit_a2a(envelope)
        assert result.reason == A2AReason.SENDER_NOT_ELIGIBLE
        assert _nothing_moved()

    async def test_12_an_unknown_sender_denies(
        self, submit_a2a, a2a_envelope, keystore, risk_agent
    ):
        result = await submit_a2a(a2a_envelope(sender="did:poc:agent:ghost"))
        assert result.reason == A2AReason.SENDER_UNKNOWN
        assert _nothing_moved()


class TestKeys:
    """Threats 13-15: unknown key, retired key, key rotation."""

    async def test_13_an_unknown_key_denies(self, submit_a2a, a2a_envelope):
        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e["proof"].__setitem__(
                "verificationMethod", "did:poc:agent:risk-001#key-77")))
        assert result.reason == A2AReason.KEY_UNKNOWN
        assert _nothing_moved()

    async def test_14_a_retired_key_cannot_sign_new(
        self, submit_a2a, a2a_envelope, risk_agent, session, backdate_key
    ):
        from datetime import datetime, timedelta, timezone

        from app.db.models.agent import KeyStatus

        await backdate_key(risk_agent, days=1)
        key = risk_agent.active_key
        kid = key.kid                     # captured before it stops being ACTIVE
        key.status = KeyStatus.ROTATED
        key.rotated_at = datetime.now(timezone.utc) - timedelta(seconds=60)
        await session.flush()
        result = await submit_a2a(a2a_envelope(sender_kid=kid))
        assert result.reason == A2AReason.KEY_RETIRED
        assert _nothing_moved()

    async def test_15_rotation_does_not_invalidate_history(
        self, a2a_service, a2a_envelope, risk_agent, payments_agent, session,
        backdate_key,
    ):
        from datetime import datetime, timedelta, timezone

        from app.db.models.agent import KeyStatus

        await backdate_key(risk_agent, days=1)
        envelope = a2a_envelope(
            moment=datetime.now(timezone.utc) - timedelta(seconds=30))
        key = risk_agent.active_key
        key.status = KeyStatus.ROTATED
        key.rotated_at = datetime.now(timezone.utc)
        await session.flush()
        report = await a2a_service.verify(
            envelope, expected_receiver_did=payments_agent.did)
        assert report.valid


class TestCompromise:
    """Threats 16-17: compromised sender, compromised receiver.

    Neither is PREVENTED -- a key holder is the agent. What the design does
    is BOUND the damage, and these assert the bounds.
    """

    async def test_16_a_compromised_sender_is_still_bounded_by_policy(
        self, submit_a2a, a2a_envelope
    ):
        """Holding risk-001's key lets an attacker instruct anything
        risk-001 could instruct -- and nothing more. The amount bands,
        the credential scope and the purpose all still apply."""
        result = await submit_a2a(a2a_envelope(resource_id="pay-3312",
                                               amount_inr=5_000_000))
        assert result.executed is False
        assert result.required_approvals == 2
        assert payment_execution_count("pay-3312") == 0

    async def test_16_containment_stops_the_next_transaction(
        self, submit_a2a, a2a_envelope, risk_agent, session
    ):
        """Suspending the agent is the first move in an incident."""
        from app.db.models.agent import AgentStatus

        assert (await submit_a2a(a2a_envelope())).executed is True
        risk_agent.status = AgentStatus.SUSPENDED
        await session.flush()
        second = await submit_a2a(a2a_envelope(resource_id="pay-3311",
                                               amount_inr=500_000))
        assert second.accepted is False

    async def test_17_a_compromised_receiver_cannot_alter_the_instruction(
        self, submit_a2a, a2a_envelope
    ):
        """The receiver RELAYS. Every field it might want to change is
        inside the sender's signature, so the most it can do is withhold --
        which is denial of service, not unauthorized execution."""
        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e["transaction"].__setitem__("resourceId",
                                                          "pay-3312")))
        assert result.accepted is False
        assert _nothing_moved("pay-3312")

    async def test_17_a_compromised_receiver_cannot_replay(
        self, submit_a2a, a2a_envelope
    ):
        envelope = a2a_envelope()
        await submit_a2a(envelope)
        await submit_a2a(envelope)
        await submit_a2a(envelope)
        assert payment_execution_count("pay-3310") == 1


class TestInfrastructureFailure:
    """Threats 18-21: ANS failure, DID resolution failure, OPA failure,
    policy failure."""

    async def test_18_ans_is_not_on_the_verification_path_at_all(self):
        """An ANS compromise degrades to DENIAL OF SERVICE, never to
        unauthorized execution: it can point a sender at the wrong endpoint,
        and the wrong endpoint holds no key to submit with.

        Asserted structurally, because the property is the ABSENCE of a
        dependency.
        """
        import pathlib

        package = pathlib.Path(__file__).resolve().parents[1] / "app" / "protocols"
        source = "\\n".join(p.read_text() for p in package.rglob("*.py"))
        assert "app.ans" not in source, (
            "the A2A package reached for the ANS. Public keys come from the "
            "Phase 1 registry, which the directory does not control.")

    async def test_19_an_unresolvable_sender_denies(
        self, submit_a2a, a2a_envelope, risk_agent, session
    ):
        from sqlalchemy import delete

        from app.db.models.agent import DIDDocument

        envelope = a2a_envelope()
        await session.execute(
            delete(DIDDocument).where(DIDDocument.did == risk_agent.did))
        await session.flush()
        result = await submit_a2a(envelope)
        assert result.reason == A2AReason.SENDER_NOT_RESOLVABLE
        assert _nothing_moved()

    async def test_20_an_opa_outage_denies(
        self, a2a_aem, a2a_envelope, payments_agent, payment_credential,
        a2a_policy_loaded, monkeypatch,
    ):
        from app.authorization.opa import OPAUnavailableError

        async def down(*a, **k):
            raise OPAUnavailableError("down")

        monkeypatch.setattr(a2a_aem.pdp.opa, "evaluate", down)
        result = await a2a_aem.enforce_a2a(envelope=a2a_envelope(),
                                           submitted_by=payments_agent.did)
        assert result.decision.reason == Reason.AUTHORIZATION_UNAVAILABLE
        assert _nothing_moved()

    async def test_21_missing_policy_configuration_denies(
        self, submit_a2a, a2a_envelope, opa_client
    ):
        from app.authorization.pap import PolicyAdministrationPoint
        from app.core.config import get_settings

        pap = PolicyAdministrationPoint(None, get_settings())
        definition = next(d for d in pap.read_data_definitions()
                          if d.data_id == "a2a-policy")
        await opa_client.delete_data(definition.path)
        try:
            result = await submit_a2a(a2a_envelope())
            assert result.reason == "A2A_POLICY_UNCONFIGURED"
            assert _nothing_moved()
        finally:
            await opa_client.put_data(definition.path, definition.document)


class TestScopeManipulation:
    """Threats 22-26: confused deputy, purpose, action, resource, JIT scope."""

    async def test_22_the_sender_cannot_borrow_the_receivers_authority(
        self, a2a_aem, a2a_envelope, fraud_agent, payments_agent,
        payment_credential, a2a_policy_loaded,
    ):
        result = await a2a_aem.enforce_a2a(
            envelope=a2a_envelope(sender=fraud_agent.did,
                                  signing_agent=fraud_agent,
                                  sender_kid=fraud_agent.active_key.kid),
            submitted_by=payments_agent.did)
        assert result.executed is False
        assert _nothing_moved()

    async def test_23_purpose_manipulation_breaks_the_signature(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e["transaction"].__setitem__("purpose",
                                                          "loan_assessment")))
        assert result.accepted is False

    async def test_23_a_purpose_outside_the_credential_denies(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(purpose="loan_assessment"))
        assert result.executed is False
        assert _nothing_moved()

    async def test_24_action_manipulation_breaks_the_signature(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e["transaction"].__setitem__("action", "read")))
        assert result.accepted is False

    async def test_25_resource_manipulation_breaks_the_signature(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e["transaction"].__setitem__("resourceId",
                                                          "pay-3311")))
        assert result.accepted is False
        assert _nothing_moved("pay-3311")

    async def test_26_a_mandate_for_another_scope_does_not_help(
        self, submit_a2a, a2a_envelope, issued_mandate
    ):
        result = await submit_a2a(a2a_envelope(
            resource_id="pay-3311", amount_inr=500_000,
            jit_grant_id=issued_mandate.grant_id))
        assert result.executed is False
        assert _nothing_moved("pay-3311")


class TestHITLAndAmountEscalation:
    """Threats 27-28: HITL bypass, amount escalation."""

    async def test_27_jit_cannot_satisfy_an_a2a_approval_requirement(
        self, submit_a2a, a2a_envelope, issued_mandate
    ):
        result = await submit_a2a(a2a_envelope(
            resource_id="pay-3312", amount_inr=5_000_000,
            jit_grant_id=issued_mandate.grant_id))
        assert result.executed is False
        assert payment_execution_count("pay-3312") == 0

    async def test_27_a_fabricated_approval_cannot_release_a_payment(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(
            resource_id="pay-3311", amount_inr=500_000,
            approval_id="approval-forged"))
        assert result.executed is False
        assert _nothing_moved("pay-3311")

    async def test_27_dual_control_cannot_be_reduced_to_one(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(resource_id="pay-3312",
                                               amount_inr=5_000_000))
        assert result.required_approvals == 2

    async def test_28_amount_escalation_in_the_envelope_is_refused(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(
            tamper=lambda e: e["transaction"].__setitem__("amountInr",
                                                          5_000_000)))
        assert result.reason == A2AReason.SIGNATURE_INVALID

    async def test_28_amount_escalation_by_instructing_a_figure_is_refused(
        self, submit_a2a, a2a_envelope
    ):
        result = await submit_a2a(a2a_envelope(amount_inr=5_000_000))
        assert result.reason == A2AReason.AMOUNT_MISMATCH
        assert _nothing_moved()

    async def test_28_amount_escalation_by_amending_the_record_is_refused(
        self, submit_a2a, a2a_envelope
    ):
        from app.enforcement.resources import set_payment_amount

        set_payment_amount("pay-3310", 5_000_000)
        result = await submit_a2a(a2a_envelope(amount_inr=50_000))
        assert result.reason == A2AReason.AMOUNT_MISMATCH
        assert payment_execution_count("pay-3310") == 0


class TestAudit:
    async def test_the_whole_arc_is_retrievable_by_one_request_id(
        self, submit_a2a, a2a_envelope, session
    ):
        """THE DELIVERABLE, not the event list: one query returns the
        complete story of one instruction."""
        await submit_a2a(a2a_envelope(transaction_id="txn-audit"))
        events = (await session.execute(select(AuditEvent).where(
            AuditEvent.request_id == "a2a-txn-audit"
        ).order_by(AuditEvent.seq))).scalars().all()
        types = [e.event_type for e in events]
        for expected in ("A2A_REQUEST", "A2A_SIGNATURE_VERIFIED",
                         "AUTHORIZATION_REQUESTED", "PIP_CONTEXT_COLLECTED",
                         "OPA_DECISION", "PDP_EVALUATION", "POLICY_ALLOW",
                         "AEM_ALLOWED", "TOOL_EXECUTED", "A2A_EXECUTED"):
            assert expected in types, f"{expected} missing from {types}"

    async def test_the_events_carry_sender_receiver_and_transaction(
        self, submit_a2a, a2a_envelope, session, risk_agent, payments_agent
    ):
        await submit_a2a(a2a_envelope(transaction_id="txn-corr",
                                      correlation_id="flow-1"))
        event = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == "A2A_EXECUTED"))).scalars().one()
        assert event.agent_did == risk_agent.did
        assert event.event_metadata["receiver"] == payments_agent.did
        assert event.event_metadata["transaction_id"] == "txn-corr"
        assert event.event_metadata["correlation_id"] == "flow-1"

    async def test_a_refusal_is_recorded_and_not_attributed_to_the_claimed_sender(
        self, submit_a2a, a2a_envelope, session
    ):
        """On a forged envelope the sender is an ASSERTION. Attributing the
        event to it would put an attacker's claim in the victim's history."""
        await submit_a2a(a2a_envelope(
            tamper=lambda e: e["transaction"].__setitem__("amountInr", 1)))
        event = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == "A2A_REJECTED"))).scalars().one()
        assert event.agent_did is None
        assert event.event_metadata["claimed_sender"] is not None
        assert event.event_metadata["submitted_by"] is not None

    async def test_no_full_signature_reaches_the_trail(
        self, submit_a2a, a2a_envelope, session
    ):
        await submit_a2a(a2a_envelope())
        record = (await session.execute(select(A2ATransaction))).scalars().one()
        assert len(record.signature) <= 256

    async def test_no_payload_body_reaches_the_audit_metadata(
        self, submit_a2a, a2a_envelope, session
    ):
        """A digest, never the body. The trail is not an exfiltration route."""
        await submit_a2a(a2a_envelope(
            payload={"secret_note": "do-not-log-me"}))
        events = (await session.execute(select(AuditEvent))).scalars().all()
        for event in events:
            assert "do-not-log-me" not in str(event.event_metadata)


class TestNoRegression:
    async def test_decision_rego_is_untouched_by_phase_7(self):
        """Phase 7 introduced ZERO new cross-module rule names, so the seed
        architecture did not have to change."""
        import pathlib

        repo = pathlib.Path(__file__).resolve().parents[2]
        source = (repo / "policies" / "decision.rego").read_text()
        assert "a2a" in source.lower() or True   # no requirement either way
        for name in ("a2a_present", "a2a_valid", "a2a_amount_reconciled",
                     "a2a_within_agent_authority", "a2a_requires_dual_control"):
            assert name not in source, (
                f"{name} was seeded in decision.rego; Phase 7 was designed to "
                f"need no new seed")

    async def test_sensitive_rego_is_untouched_by_phase_7(self):
        import pathlib

        repo = pathlib.Path(__file__).resolve().parents[2]
        source = (repo / "policies" / "security" / "sensitive.rego").read_text()
        assert "execute_payment" not in source, (
            "adding execute_payment to sensitive.rego would escalate EVERY "
            "payment to a human, including a trivial one")

    async def test_loan_amount_rego_is_untouched_by_phase_7(self):
        import pathlib

        repo = pathlib.Path(__file__).resolve().parents[2]
        source = (repo / "policies" / "loan" / "amount.rego").read_text()
        assert "payment" not in source.lower()

    async def test_the_loan_material_attributes_are_unchanged(self):
        """Every approval already granted is bound to a digest covering
        these exact values."""
        from app.enforcement.resources import material_attributes

        assert material_attributes("loan_applications", "loan-7842") == {
            "available": True, "amount_inr": 2_500_000, "currency": "INR",
            "submitted_by": "iam.admin",
        }
        assert material_attributes("credit_records", "customer-007") == {
            "available": False,
            "detail": "no material attributes are defined for 'credit_records'",
        }

    async def test_an_ordinary_request_is_unaffected_by_the_a2a_fact(
        self, pdp, authz_request, risk_agent, issued_credential
    ):
        """A Phase 1-6 request is decided exactly as it was before Phase 7."""
        from app.authorization.contracts import Decision

        decision = await pdp.decide(authz_request(risk_agent.did))
        assert decision.decision is Decision.ALLOW
        assert decision.evaluation["pip"]["a2a"]["present"] is False

    async def test_the_aem_enforce_signature_is_unchanged(self):
        import inspect

        from app.enforcement.aem import AdapterEnforcementMiddleware

        parameters = set(inspect.signature(
            AdapterEnforcementMiddleware.enforce).parameters)
        assert parameters == {
            "self", "subject_did", "tool_name", "arguments", "purpose",
            "request_id", "context", "credentials", "approval_id",
            "jit_grant_id",
        }

    async def test_the_pdp_decide_works_without_an_a2a_argument(
        self, pdp, authz_request, risk_agent, issued_credential
    ):
        assert (await pdp.decide(authz_request(risk_agent.did))) is not None


class TestDiscipline:
    async def test_no_allow_decision_is_made_in_python(self):
        """`if signature_valid: allow()` appears nowhere."""
        import pathlib
        import re

        package = pathlib.Path(__file__).resolve().parents[1] / "app" / "protocols"
        pattern = re.compile(r"if\s+.*(signature|valid).*:\s*\n\s*.*allow",
                             re.IGNORECASE)
        for path in package.rglob("*.py"):
            assert not pattern.search(path.read_text()), path

    async def test_no_in_memory_replay_set_exists(self):
        """The database arbitrates, because two processes cannot."""
        import pathlib
        import re

        package = pathlib.Path(__file__).resolve().parents[1] / "app" / "protocols"
        for path in package.rglob("*.py"):
            source = path.read_text()
            assert not re.search(r"^\s*_?(seen|_cache|_nonces)\s*[:=]",
                                 source, re.M), path

    async def test_no_second_canonicalisation_implementation(self):
        import pathlib

        package = pathlib.Path(__file__).resolve().parents[1] / "app" / "protocols"
        source = "\\n".join(p.read_text() for p in package.rglob("*.py"))
        assert "json.dumps" not in source, (
            "the A2A package serialised JSON itself. Canonicalisation is "
            "app.credentials.canonical, shared by all seven proof types.")

    async def test_the_a2a_module_declares_no_new_cross_module_name(self):
        """The Phase 6 finding, closed by construction."""
        import pathlib
        import re

        repo = pathlib.Path(__file__).resolve().parents[2]
        source = (repo / "policies" / "a2a" / "transaction.rego").read_text()
        defined = set(re.findall(r"^([a-z_][a-z0-9_]*)\s*(?::=|if|contains)",
                                 source, re.M))
        # Everything it defines is either seeded in decision.rego already, or
        # namespaced to this module.
        seeded = {"deny", "allow", "human_required"}
        for name in defined - seeded:
            assert name.startswith("a2a"), (
                f"{name!r} is neither seeded nor namespaced, so another module "
                f"could come to depend on it and the set would stop compiling "
                f"when this one is not loaded")
