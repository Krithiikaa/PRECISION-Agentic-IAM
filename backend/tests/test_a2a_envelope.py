"""The A2A envelope: what it binds, and what breaks when any of it moves.

THE PROPERTY UNDER TEST, stated once:

    Sender, receiver, action, resource, purpose, amount and payload cannot
    change without the signature failing.

Every mutation below is applied AFTER signing, which is exactly the attack.
Nothing is stubbed: the signatures are produced by the real keystore with the
agents' real Phase 1 keys and verified by the real verifier.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import get_settings
from app.identity.signer import Signer
from app.protocols.a2a.client import build_signed_transaction
from app.protocols.a2a.envelope import (
    A2A_PROOF_PURPOSE,
    A2A_RESPONSE_PROOF_PURPOSE,
    A2AReason,
    A2ABinding,
    is_wellformed_amount,
    payload_digest,
    verify_envelope,
    verify_response,
)

pytestmark = pytest.mark.asyncio


@pytest.fixture
def verify(a2a_service, payments_agent):
    """Verify through the SERVICE, so sender resolution is real."""
    async def run(envelope, *, receiver=None, now=None):
        return await a2a_service.verify(
            envelope, expected_receiver_did=receiver or payments_agent.did, now=now,
        )
    return run


class TestAValidEnvelope:
    async def test_a_genuine_envelope_verifies(self, verify, a2a_envelope):
        report = await verify(a2a_envelope())
        assert report.valid, report.reason
        assert report.reason == A2AReason.VALID
        assert report.receiver_bound is True
        assert report.payload_verified is True

    async def test_every_check_is_reported_not_just_the_verdict(
        self, verify, a2a_envelope
    ):
        """A caller that cannot see WHICH check failed cannot fix the cause."""
        report = await verify(a2a_envelope())
        names = [c.name for c in report.checks]
        for expected in ("structure", "protocol", "proof_purpose",
                         "receiver_binding", "sender_document", "signing_key",
                         "signature", "domain", "validity_window",
                         "payload_digest", "binding_hash"):
            assert expected in names, f"{expected} was never checked"

    async def test_the_report_carries_the_bound_fields(self, verify, a2a_envelope,
                                                       risk_agent, payments_agent):
        report = await verify(a2a_envelope())
        assert report.sender_did == risk_agent.did
        assert report.receiver_did == payments_agent.did
        assert report.action == "execute_payment"
        assert report.resource_type == "payment_instructions"
        assert report.resource_id == "pay-3310"
        assert report.purpose == "payment_settlement"
        assert report.amount_inr == 50_000
        assert report.currency == "INR"

    async def test_key_order_does_not_matter(self, verify, a2a_envelope):
        """Canonicalisation sorts, so a relay may re-serialise freely.

        The envelope crosses a process boundary (A -> B -> IAM). If the
        signature depended on key order, any hop that deserialised and
        re-serialised it would break a genuine instruction.
        """
        envelope = a2a_envelope()
        shuffled = dict(reversed(list(envelope.items())))
        shuffled["transaction"] = dict(reversed(list(envelope["transaction"].items())))
        report = await verify(shuffled)
        assert report.valid, report.reason


class TestTamperingWithTheBoundFields:
    """Each of these is a substitution attack, and each must break the signature."""

    @pytest.mark.parametrize("field,value", [
        ("senderDid", "did:poc:agent:fraud-001"),
        ("receiverDid", "did:poc:agent:risk-002"),
        ("transactionId", "txn-somebody-elses"),
        ("nonce", "a-different-nonce"),
        ("domain", "another-service"),
        ("correlationId", "injected"),
        ("issuanceDate", "2020-01-01T00:00:00.000Z"),
        ("expirationDate", "2099-01-01T00:00:00.000Z"),
    ])
    async def test_top_level_field_tampering_is_refused(
        self, verify, a2a_envelope, field, value
    ):
        envelope = a2a_envelope(tamper=lambda e: e.__setitem__(field, value))
        report = await verify(envelope)
        assert not report.valid
        # The refusal may be the signature, or an earlier structural check
        # that the mutation happens to trip first. Either is correct; what
        # must never happen is acceptance.
        assert report.reason != A2AReason.VALID

    @pytest.mark.parametrize("field,value", [
        ("action", "read"),
        ("resourceType", "credit_records"),
        ("resourceId", "pay-3312"),
        ("purpose", "loan_assessment"),
        ("amountInr", 5_000_000),
        ("currency", "USD"),
    ])
    async def test_transaction_field_tampering_is_refused(
        self, verify, a2a_envelope, field, value
    ):
        envelope = a2a_envelope(
            tamper=lambda e: e["transaction"].__setitem__(field, value)
        )
        report = await verify(envelope)
        assert not report.valid
        assert report.reason != A2AReason.VALID

    async def test_modifying_the_payload_is_refused(self, verify, a2a_envelope):
        envelope = a2a_envelope(
            tamper=lambda e: e["transaction"]["payload"].__setitem__(
                "beneficiary_ref", "attacker-account")
        )
        report = await verify(envelope)
        assert not report.valid

    async def test_modifying_the_payload_and_its_digest_still_breaks(
        self, verify, a2a_envelope
    ):
        """The thorough attacker also updates the digest. The signature covers both."""
        def tamper(e):
            e["transaction"]["payload"] = {"beneficiary_ref": "attacker-account"}
            e["transaction"]["payloadSha256"] = payload_digest(
                e["transaction"]["payload"])
        report = await verify(a2a_envelope(tamper=tamper))
        assert not report.valid
        assert report.reason == A2AReason.SIGNATURE_INVALID

    async def test_the_most_thorough_attacker_rebuilds_the_binding_hash_too(
        self, verify, a2a_envelope
    ):
        """Amount raised, digest recomputed, bindingHash recomputed.

        Every derived field is consistent -- and the signature still fails,
        because the signature is over the bytes, not over the consistency.
        """
        def tamper(e):
            e["transaction"]["amountInr"] = 5_000_000
            e["transaction"]["bindingHash"] = A2ABinding.from_envelope(e).digest()
        report = await verify(a2a_envelope(tamper=tamper))
        assert not report.valid
        assert report.reason == A2AReason.SIGNATURE_INVALID

    async def test_offered_credentials_cannot_be_injected_by_a_relay(
        self, verify, a2a_envelope
    ):
        envelope = a2a_envelope(
            tamper=lambda e: e["offered"].__setitem__("credentialIds", ["urn:uuid:x"])
        )
        assert not (await verify(envelope)).valid

    async def test_an_approval_id_cannot_be_injected_by_a_relay(
        self, verify, a2a_envelope
    ):
        """The receiver relays the envelope. It must not be able to add
        evidence to the instruction it is carrying."""
        envelope = a2a_envelope(
            tamper=lambda e: e["offered"].__setitem__("approvalId", "approval-forged")
        )
        assert not (await verify(envelope)).valid

    async def test_a_jit_grant_id_cannot_be_injected_by_a_relay(
        self, verify, a2a_envelope
    ):
        envelope = a2a_envelope(
            tamper=lambda e: e["offered"].__setitem__("jitGrantId", "jit-forged")
        )
        assert not (await verify(envelope)).valid


class TestTheSignatureItself:
    async def test_a_forged_signature_is_refused(self, verify, a2a_envelope):
        forged = base64.b64encode(b"\x00" * 64).decode()
        envelope = a2a_envelope(
            tamper=lambda e: e["proof"].__setitem__("signatureValue", forged))
        report = await verify(envelope)
        assert not report.valid
        assert report.reason == A2AReason.SIGNATURE_INVALID

    async def test_an_empty_signature_is_refused(self, verify, a2a_envelope):
        envelope = a2a_envelope(
            tamper=lambda e: e["proof"].__setitem__("signatureValue", ""))
        assert (await verify(envelope)).reason == A2AReason.SIGNATURE_INVALID

    async def test_a_non_base64_signature_is_refused(self, verify, a2a_envelope):
        envelope = a2a_envelope(
            tamper=lambda e: e["proof"].__setitem__("signatureValue", "not base64!!"))
        assert (await verify(envelope)).reason == A2AReason.SIGNATURE_INVALID

    async def test_a_truncated_signature_is_refused(self, verify, a2a_envelope):
        def tamper(e):
            e["proof"]["signatureValue"] = e["proof"]["signatureValue"][:40]
        assert (await verify(a2a_envelope(tamper=tamper))).reason == \
            A2AReason.SIGNATURE_INVALID

    async def test_swapping_the_verification_method_is_refused(
        self, verify, a2a_envelope, fraud_agent
    ):
        """Pointing the proof at a different key does not redirect the verifier.

        `verificationMethod` is inside the signed payload, so changing it
        invalidates the signature rather than silently choosing another key.
        """
        envelope = a2a_envelope(
            tamper=lambda e: e["proof"].__setitem__(
                "verificationMethod", f"{fraud_agent.did}#key-1"))
        report = await verify(envelope)
        assert not report.valid
        assert report.reason in {A2AReason.KEY_UNKNOWN,
                                 A2AReason.SENDER_NOT_RESOLVABLE,
                                 A2AReason.SIGNATURE_INVALID}

    async def test_signing_with_another_agents_key_is_refused(
        self, verify, keystore, risk_agent, fraud_agent, payments_agent
    ):
        """fraud-001 signs, but the envelope claims to be from risk-001."""
        envelope = build_signed_transaction(
            Signer(keystore),
            sender_did=risk_agent.did,                    # the CLAIM
            sender_kid=fraud_agent.active_key.kid,        # the actual signer
            receiver_did=payments_agent.did,
            action="execute_payment", resource_type="payment_instructions",
            resource_id="pay-3310", purpose="payment_settlement",
            domain=get_settings().a2a_domain, amount_inr=50_000, currency="INR",
        )
        report = await verify(envelope)
        assert not report.valid
        assert report.reason == A2AReason.KEY_UNKNOWN


class TestTheSevenDomainSeparators:
    """A proof made for one purpose can never verify as another.

    This system now has SEVEN proof purposes over canonical JSON. The purpose
    is inside the signed payload, so there is no path where a credential
    proof, a holder proof, an ANS registration, a control-plane proof, a human
    approval, a JIT grant or an A2A RESPONSE becomes an A2A transaction.
    """

    @pytest.mark.parametrize("purpose", [
        "assertionMethod", "authentication", "ansRegistration",
        "controlPlaneRequest", "humanApproval", "jitGrant", "a2aResponse",
    ])
    async def test_another_proof_purpose_is_refused(
        self, verify, a2a_envelope, purpose
    ):
        envelope = a2a_envelope(
            tamper=lambda e: e["proof"].__setitem__("proofPurpose", purpose))
        report = await verify(envelope)
        assert not report.valid
        assert report.reason == A2AReason.PROOF_PURPOSE_INVALID

    async def test_the_transaction_purpose_is_the_one_that_works(self, a2a_envelope):
        assert a2a_envelope()["proof"]["proofPurpose"] == A2A_PROOF_PURPOSE

    async def test_a_jit_grant_presented_as_a_transaction_is_refused(
        self, verify, issued_mandate
    ):
        """A genuine, correctly signed JIT grant. Refused on SHAPE."""
        report = await verify(issued_mandate.artifact)
        assert not report.valid
        assert report.reason == A2AReason.MALFORMED

    async def test_a_credential_presented_as_a_transaction_is_refused(
        self, verify, issued_credential
    ):
        report = await verify(issued_credential.document)
        assert not report.valid
        assert report.reason == A2AReason.MALFORMED

    async def test_an_a2a_response_presented_as_a_transaction_is_refused(
        self, verify, keystore, payments_agent, risk_agent
    ):
        from app.protocols.a2a.client import build_signed_response

        response = build_signed_response(
            Signer(keystore), responder_did=payments_agent.did,
            responder_kid=payments_agent.active_key.kid,
            original_sender_did=risk_agent.did, transaction_id="txn-1",
            status="EXECUTED", domain=get_settings().a2a_domain,
        )
        report = await verify(response)
        assert not report.valid
        assert report.reason == A2AReason.MALFORMED


class TestStructure:
    async def test_no_envelope_at_all(self, verify):
        assert (await verify(None)).reason == A2AReason.MISSING

    async def test_an_empty_object(self, verify):
        assert (await verify({})).reason == A2AReason.MISSING

    async def test_a_document_that_is_not_a_transaction(self, verify):
        assert (await verify({"type": ["VerifiableCredential"], "transaction": {},
                              "proof": {}})).reason == A2AReason.MALFORMED

    async def test_a_missing_proof(self, verify, a2a_envelope):
        envelope = a2a_envelope(tamper=lambda e: e.pop("proof"))
        assert (await verify(envelope)).reason == A2AReason.MALFORMED

    async def test_an_unsupported_protocol(self, verify, a2a_envelope):
        envelope = a2a_envelope(tamper=lambda e: e.__setitem__("protocol", "other"))
        assert (await verify(envelope)).reason == A2AReason.PROTOCOL_UNSUPPORTED

    async def test_an_unsupported_protocol_version_is_refused_not_parsed(
        self, verify, a2a_envelope
    ):
        """A version this build does not understand may bind fields it does
        not check. Accepting it would silently downgrade every guarantee."""
        envelope = a2a_envelope(
            tamper=lambda e: e.__setitem__("protocolVersion", "99.0"))
        assert (await verify(envelope)).reason == A2AReason.PROTOCOL_UNSUPPORTED

    async def test_a_payload_digest_that_does_not_match_is_refused(
        self, verify, a2a_envelope
    ):
        envelope = a2a_envelope(
            tamper=lambda e: e["transaction"].__setitem__("payloadSha256", "0" * 64))
        assert (await verify(envelope)).reason in {A2AReason.SIGNATURE_INVALID,
                                                   A2AReason.MALFORMED}

    async def test_a_binding_hash_that_does_not_match_is_refused(
        self, verify, a2a_envelope
    ):
        envelope = a2a_envelope(
            tamper=lambda e: e["transaction"].__setitem__("bindingHash", "0" * 64))
        assert (await verify(envelope)).reason in {A2AReason.SIGNATURE_INVALID,
                                                   A2AReason.MALFORMED}


@pytest.mark.usefixtures()
class TestTheAmountIsWellFormed:
    """A DOMAIN check, not a risk threshold. See `is_wellformed_amount`."""

    async def test_whole_non_negative_integers_are_accepted(self):
        assert all(is_wellformed_amount(v) for v in (0, 1, 50_000, 10**12))

    async def test_negative_fractional_boolean_and_string_are_refused(self):
        assert not any(is_wellformed_amount(v)
                       for v in (-1, 1.5, True, False, "5", None, [5]))

    async def test_a_float_amount_cannot_be_signed_at_all(
        self, keystore, risk_agent, payments_agent
    ):
        """Canonical JSON refuses floats, so the refusal is at construction."""
        with pytest.raises(ValueError):
            build_signed_transaction(
                Signer(keystore), sender_did=risk_agent.did,
                sender_kid=risk_agent.active_key.kid,
                receiver_did=payments_agent.did, action="execute_payment",
                resource_type="payment_instructions", resource_id="pay-3310",
                purpose="payment_settlement", domain="d",
                amount_inr=50_000.5, currency="INR",
            )

    async def test_an_amount_without_a_currency_is_refused(
        self, keystore, risk_agent, payments_agent
    ):
        with pytest.raises(ValueError, match="together or not at all"):
            build_signed_transaction(
                Signer(keystore), sender_did=risk_agent.did,
                sender_kid=risk_agent.active_key.kid,
                receiver_did=payments_agent.did, action="execute_payment",
                resource_type="payment_instructions", resource_id="pay-3310",
                purpose="payment_settlement", domain="d",
                amount_inr=50_000, currency=None,
            )

    async def test_a_negative_amount_is_refused(
        self, keystore, risk_agent, payments_agent
    ):
        with pytest.raises(ValueError):
            build_signed_transaction(
                Signer(keystore), sender_did=risk_agent.did,
                sender_kid=risk_agent.active_key.kid,
                receiver_did=payments_agent.did, action="execute_payment",
                resource_type="payment_instructions", resource_id="pay-3310",
                purpose="payment_settlement", domain="d",
                amount_inr=-1, currency="INR",
            )

    async def test_a_transaction_with_no_amount_is_well_formed(
        self, verify, a2a_envelope
    ):
        """Not every action moves money. Absent is a fact, not zero."""
        report = await verify(a2a_envelope(amount_inr=None, currency=None,
                                           action="read",
                                           resource_type="credit_records",
                                           resource_id="customer-007",
                                           purpose="loan_assessment"))
        assert report.valid, report.reason
        assert report.amount_inr is None


class TestTime:
    async def test_an_expired_envelope_is_refused(self, verify, a2a_envelope):
        past = datetime.now(timezone.utc) - timedelta(seconds=120)
        report = await verify(a2a_envelope(moment=past, ttl_seconds=60))
        assert not report.valid
        assert report.reason == A2AReason.EXPIRED

    async def test_a_stale_envelope_is_refused(
        self, verify, a2a_envelope, backdate_key, risk_agent
    ):
        """Bounded freshness in BOTH directions, as the control-plane proof is."""
        await backdate_key(risk_agent)
        long_ago = datetime.now(timezone.utc) - timedelta(hours=2)
        report = await verify(a2a_envelope(moment=long_ago, ttl_seconds=300))
        assert not report.valid
        assert report.reason in {A2AReason.STALE, A2AReason.EXPIRED}

    async def test_an_envelope_dated_before_its_key_existed_is_refused(
        self, verify, a2a_envelope
    ):
        """A proof claiming to predate its own key is a forgery signal, and
        it is caught BEFORE freshness -- which is the right order, because
        "this key did not exist then" is the more specific fact."""
        long_ago = datetime.now(timezone.utc) - timedelta(hours=2)
        report = await verify(a2a_envelope(moment=long_ago, ttl_seconds=300))
        assert not report.valid
        assert report.reason == A2AReason.KEY_UNKNOWN

    async def test_a_future_dated_envelope_is_refused(
        self, verify, a2a_envelope
    ):
        """An envelope timestamped far ahead would stay valid as long as an
        attacker chose."""
        ahead = datetime.now(timezone.utc) + timedelta(hours=2)
        report = await verify(a2a_envelope(moment=ahead))
        assert not report.valid
        assert report.reason in {A2AReason.NOT_YET_VALID, A2AReason.STALE}

    async def test_a_ttl_beyond_the_ceiling_is_refused(self, verify, a2a_envelope):
        """A sender does not choose how long its own instruction lives.

        An envelope with a one-year window would be a standing instruction
        with a year to be stolen in.
        """
        report = await verify(a2a_envelope(ttl_seconds=86_400))
        assert not report.valid
        assert report.reason == A2AReason.TTL_EXCEEDS_MAXIMUM

    async def test_expiry_before_issuance_is_malformed(self, verify, a2a_envelope):
        envelope = a2a_envelope(
            tamper=lambda e: e.__setitem__("expirationDate", e["issuanceDate"]))
        assert not (await verify(envelope)).valid


class TestTheSender:
    async def test_an_unregistered_sender_is_refused(
        self, verify, keystore, payments_agent, risk_agent
    ):
        envelope = build_signed_transaction(
            Signer(keystore), sender_did="did:poc:agent:nobody-here",
            sender_kid=risk_agent.active_key.kid,
            receiver_did=payments_agent.did, action="execute_payment",
            resource_type="payment_instructions", resource_id="pay-3310",
            purpose="payment_settlement", domain=get_settings().a2a_domain,
            amount_inr=50_000, currency="INR",
        )
        report = await verify(envelope)
        assert not report.valid
        assert report.reason == A2AReason.SENDER_UNKNOWN

    async def test_a_suspended_sender_is_refused(
        self, verify, a2a_envelope, registry, risk_agent, session
    ):
        from app.db.models.agent import AgentStatus

        envelope = a2a_envelope()
        risk_agent.status = AgentStatus.SUSPENDED
        await session.flush()
        report = await verify(envelope)
        assert not report.valid
        assert report.reason == A2AReason.SENDER_NOT_ELIGIBLE

    async def test_a_terminated_sender_is_refused(
        self, verify, a2a_envelope, risk_agent, session
    ):
        from app.db.models.agent import AgentStatus

        envelope = a2a_envelope()
        risk_agent.status = AgentStatus.TERMINATED
        await session.flush()
        assert (await verify(envelope)).reason == A2AReason.SENDER_NOT_ELIGIBLE

    async def test_a_non_agent_did_is_refused(
        self, verify, keystore, payments_agent, approval_authority
    ):
        """The APPROVAL AUTHORITY tries to send a transaction.

        It holds a real key and signs real artifacts -- just not these. An
        A2A transaction attests to what an AGENT instructed.
        """
        envelope = build_signed_transaction(
            Signer(keystore), sender_did=approval_authority.did,
            sender_kid=f"{approval_authority.did}#key-1",
            receiver_did=payments_agent.did, action="execute_payment",
            resource_type="payment_instructions", resource_id="pay-3310",
            purpose="payment_settlement", domain=get_settings().a2a_domain,
            amount_inr=50_000, currency="INR",
        )
        report = await verify(envelope)
        assert not report.valid
        assert report.reason == A2AReason.SENDER_UNKNOWN


class TestReceiverBinding:
    async def test_an_envelope_for_b_is_refused_when_c_presents_it(
        self, verify, a2a_envelope, fraud_agent
    ):
        """THE REPLAY-TOWARD-ANOTHER-RECEIVER ATTACK.

        The envelope is genuine, correctly signed, fresh and unspent. It is
        simply not addressed to the agent presenting it, and the HTTP
        destination has no say in that.
        """
        envelope = a2a_envelope()          # addressed to payments-001
        report = await verify(envelope, receiver=fraud_agent.did)
        assert not report.valid
        assert report.reason == A2AReason.RECEIVER_MISMATCH

    async def test_the_sender_cannot_present_its_own_envelope(
        self, verify, a2a_envelope, risk_agent
    ):
        """If a sender could submit an envelope addressed to somebody else it
        would control both ends and the receiver's consent would not exist."""
        report = await verify(a2a_envelope(), receiver=risk_agent.did)
        assert report.reason == A2AReason.RECEIVER_MISMATCH

    async def test_the_addressed_receiver_is_accepted(
        self, verify, a2a_envelope, payments_agent
    ):
        assert (await verify(a2a_envelope(), receiver=payments_agent.did)).valid


class TestAudience:
    async def test_an_envelope_for_another_service_is_refused(
        self, verify, a2a_envelope
    ):
        """The Phase 2 S-2 protection, preserved: an envelope minted for this
        boundary cannot be relayed to another one."""
        report = await verify(a2a_envelope(domain="some-other-service"))
        assert not report.valid
        assert report.reason == A2AReason.DOMAIN_MISMATCH


class TestTheResponse:
    async def test_a_genuine_response_verifies(
        self, session, keystore, payments_agent, risk_agent
    ):
        from app.db.repositories.agents import AgentRepository
        from app.protocols.a2a.client import build_signed_response

        response = build_signed_response(
            Signer(keystore), responder_did=payments_agent.did,
            responder_kid=payments_agent.active_key.kid,
            original_sender_did=risk_agent.did, transaction_id="txn-abc",
            status="EXECUTED", decision="ALLOW", reason="A2A_TRANSACTION_AUTHORIZED",
            domain=get_settings().a2a_domain,
        )
        document = await AgentRepository(session).get_did_document(payments_agent.did)
        report = verify_response(
            response, expected_transaction_id="txn-abc",
            expected_responder_did=payments_agent.did,
            responder_document=document.document,
            expected_domain=get_settings().a2a_domain,
        )
        assert report.valid, report.reason

    async def test_a_fabricated_outcome_is_refused(
        self, session, keystore, payments_agent, risk_agent
    ):
        """Without a signed response a third party can fabricate 'your
        payment succeeded', and the sender has no way to tell."""
        from app.db.repositories.agents import AgentRepository
        from app.protocols.a2a.client import build_signed_response

        response = build_signed_response(
            Signer(keystore), responder_did=payments_agent.did,
            responder_kid=payments_agent.active_key.kid,
            original_sender_did=risk_agent.did, transaction_id="txn-abc",
            status="DENIED", domain=get_settings().a2a_domain,
        )
        response["outcome"]["status"] = "EXECUTED"          # the lie
        document = await AgentRepository(session).get_did_document(payments_agent.did)
        report = verify_response(
            response, expected_transaction_id="txn-abc",
            expected_responder_did=payments_agent.did,
            responder_document=document.document,
            expected_domain=get_settings().a2a_domain,
        )
        assert not report.valid
        assert report.reason == A2AReason.SIGNATURE_INVALID

    async def test_a_response_for_another_transaction_is_refused(
        self, session, keystore, payments_agent, risk_agent
    ):
        from app.db.repositories.agents import AgentRepository
        from app.protocols.a2a.client import build_signed_response

        response = build_signed_response(
            Signer(keystore), responder_did=payments_agent.did,
            responder_kid=payments_agent.active_key.kid,
            original_sender_did=risk_agent.did, transaction_id="txn-other",
            status="EXECUTED", domain=get_settings().a2a_domain,
        )
        document = await AgentRepository(session).get_did_document(payments_agent.did)
        report = verify_response(
            response, expected_transaction_id="txn-abc",
            expected_responder_did=payments_agent.did,
            responder_document=document.document,
            expected_domain=get_settings().a2a_domain,
        )
        assert not report.valid

    async def test_a_response_from_the_wrong_agent_is_refused(
        self, session, keystore, fraud_agent, risk_agent, payments_agent
    ):
        from app.db.repositories.agents import AgentRepository
        from app.protocols.a2a.client import build_signed_response

        response = build_signed_response(
            Signer(keystore), responder_did=fraud_agent.did,
            responder_kid=fraud_agent.active_key.kid,
            original_sender_did=risk_agent.did, transaction_id="txn-abc",
            status="EXECUTED", domain=get_settings().a2a_domain,
        )
        document = await AgentRepository(session).get_did_document(fraud_agent.did)
        report = verify_response(
            response, expected_transaction_id="txn-abc",
            expected_responder_did=payments_agent.did,
            responder_document=document.document,
            expected_domain=get_settings().a2a_domain,
        )
        assert not report.valid
        assert report.reason == A2AReason.RECEIVER_MISMATCH

    async def test_the_response_purpose_differs_from_the_request_purpose(self):
        assert A2A_RESPONSE_PROOF_PURPOSE != A2A_PROOF_PURPOSE
