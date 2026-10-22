"""A2A signing keys: rotation, revocation, and role separation.

TWO DISTINCTIONS THIS FILE EXISTS TO ENFORCE:

    ROTATION keeps history verifiable. A rotated key still verifies the
    envelopes it signed while active, and cannot sign anything new.
    REVOCATION does not. A compromised key's history is exactly what cannot
    be relied on.

    THE A2A SIGNING KEY IS THE AGENT'S OWN PHASE 1 KEY, and it is NOT the
    approval authority's, NOT the JIT authority's, and NOT an
    administrator's. An A2A transaction attests to what the SENDER
    instructed, and the sender is the only correct signer.

PHASE 7 IMPLEMENTS THE VERIFICATION SIDE OF THE KEY WINDOW, not an
operator-facing agent key-rotation flow. `KeyStatus.ROTATED` and
`AgentKey.rotated_at` have existed since Phase 1 and nothing sets them; the
columns' semantics are defined, so the window is checked and tested against
them here. Building the rotation OPERATION is Phase 1 identity-plane work
and is outside this phase -- recorded as a known gap rather than implied.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import get_settings
from app.db.models.agent import KeyStatus
from app.identity.signer import Signer
from app.protocols.a2a.client import build_signed_transaction
from app.protocols.a2a.envelope import A2AReason

pytestmark = pytest.mark.asyncio


@pytest.fixture
def verify(a2a_service, payments_agent):
    async def run(envelope, *, now=None):
        return await a2a_service.verify(
            envelope, expected_receiver_did=payments_agent.did, now=now)
    return run


class TestRotationPreservesHistory:
    async def test_an_envelope_signed_before_rotation_still_verifies(
        self, verify, a2a_envelope, risk_agent, session, backdate_key
    ):
        """Rotating must not invalidate what the key already signed."""
        await backdate_key(risk_agent, days=1)
        signed_at = datetime.now(timezone.utc) - timedelta(seconds=30)
        envelope = a2a_envelope(moment=signed_at)
        assert (await verify(envelope)).valid

        key = risk_agent.active_key
        key.status = KeyStatus.ROTATED
        key.rotated_at = datetime.now(timezone.utc)
        await session.flush()

        report = await verify(envelope)
        assert report.valid, (
            "a rotated key must keep verifying the envelopes it signed while "
            f"active; got {report.reason}")

    async def test_a_rotated_key_cannot_sign_anything_new(
        self, verify, a2a_envelope, risk_agent, session, backdate_key
    ):
        """An envelope DATED AFTER the retirement did not come from that key
        doing its job."""
        await backdate_key(risk_agent, days=1)
        key = risk_agent.active_key
        kid = key.kid                    # captured: once ROTATED it is no
        key.status = KeyStatus.ROTATED   # longer the ACTIVE key, which is
        key.rotated_at = datetime.now(timezone.utc) - timedelta(seconds=60)
        await session.flush()            # exactly the property under test

        # Signed NOW, after the retirement, with the retired key.
        report = await verify(a2a_envelope(sender_kid=kid))
        assert not report.valid
        assert report.reason == A2AReason.KEY_RETIRED


class TestRevocationDoesNotPreserveHistory:
    async def test_a_revoked_key_verifies_nothing_including_its_own_past(
        self, verify, a2a_envelope, risk_agent, session, backdate_key
    ):
        """THE DIFFERENCE BETWEEN ROTATION AND REVOCATION, in one test."""
        await backdate_key(risk_agent, days=1)
        envelope = a2a_envelope(
            moment=datetime.now(timezone.utc) - timedelta(seconds=30))
        assert (await verify(envelope)).valid

        risk_agent.active_key.status = KeyStatus.REVOKED
        await session.flush()


        report = await verify(envelope)
        assert not report.valid
        assert report.reason == A2AReason.KEY_REVOKED


class TestUnknownKeys:
    async def test_a_kid_nobody_registered_is_refused(
        self, verify, a2a_envelope
    ):
        envelope = a2a_envelope(
            tamper=lambda e: e["proof"].__setitem__(
                "verificationMethod", "did:poc:agent:risk-001#key-99"))
        report = await verify(envelope)
        assert not report.valid
        assert report.reason == A2AReason.KEY_UNKNOWN

    async def test_a_proof_dated_before_the_key_existed_is_refused(
        self, verify, a2a_envelope
    ):
        report = await verify(a2a_envelope(
            moment=datetime.now(timezone.utc) - timedelta(days=30)))
        assert not report.valid
        assert report.reason == A2AReason.KEY_UNKNOWN


class TestTheSigningKeyIsNotAnAuthorityKey:
    """An A2A transaction attests to what the SENDER instructed. Every other
    signing key in this system attests to something else, and a test asserts
    each one is refused."""

    async def test_the_approval_authority_cannot_sign_a_transaction(
        self, verify, keystore, payments_agent, approval_authority
    ):
        envelope = build_signed_transaction(
            Signer(keystore), sender_did=approval_authority.did,
            sender_kid=f"{approval_authority.did}#key-1",
            receiver_did=payments_agent.did, action="execute_payment",
            resource_type="payment_instructions", resource_id="pay-3310",
            purpose="payment_settlement", domain=get_settings().a2a_domain,
            amount_inr=50_000, currency="INR")
        assert (await verify(envelope)).reason == A2AReason.SENDER_UNKNOWN

    async def test_the_jit_authority_cannot_sign_a_transaction(
        self, verify, keystore, payments_agent, jit_authority
    ):
        envelope = build_signed_transaction(
            Signer(keystore), sender_did=jit_authority.did,
            sender_kid=f"{jit_authority.did}#key-1",
            receiver_did=payments_agent.did, action="execute_payment",
            resource_type="payment_instructions", resource_id="pay-3310",
            purpose="payment_settlement", domain=get_settings().a2a_domain,
            amount_inr=50_000, currency="INR")
        assert (await verify(envelope)).reason == A2AReason.SENDER_UNKNOWN

    async def test_an_administrator_cannot_sign_a_transaction(
        self, verify, keystore, payments_agent, control_plane
    ):
        did = "did:poc:administrator:identity-authority"
        envelope = build_signed_transaction(
            Signer(keystore), sender_did=did, sender_kid=f"{did}#key-1",
            receiver_did=payments_agent.did, action="execute_payment",
            resource_type="payment_instructions", resource_id="pay-3310",
            purpose="payment_settlement", domain=get_settings().a2a_domain,
            amount_inr=50_000, currency="INR")
        assert (await verify(envelope)).reason == A2AReason.SENDER_UNKNOWN

    async def test_the_three_authorities_hold_three_different_keys(
        self, session, keystore, risk_agent, approval_authority, jit_authority
    ):
        """Compromising one must not yield the others."""
        approval_key = (await approval_authority.require_active_key())
        jit_key = (await jit_authority.require_active_key())
        agent_key = risk_agent.active_key
        multibase = {approval_key.public_key_multibase,
                     jit_key.public_key_multibase,
                     agent_key.public_key_multibase}
        assert len(multibase) == 3, "two authorities share key material"

    async def test_phase_7_introduced_no_new_signing_authority(self):
        """A 'transaction authority' would attest to nothing the PDP
        decision and the audit row do not already record."""
        import pathlib

        package = pathlib.Path(__file__).resolve().parents[1] / "app" / "protocols"
        source = "\\n".join(p.read_text() for p in package.rglob("*.py"))
        assert "build_service_did" not in source, (
            "the A2A package created a service principal; the sender agent "
            "is the only correct signer of its own instruction")
        assert "generate_key" not in source, (
            "the A2A package generated key material")


class TestNoPrivateKeyIsEverExposed:
    async def test_the_stored_signature_is_truncated(
        self, submit_a2a, a2a_envelope, session
    ):
        """Enough to correlate two presentations, never enough to replay one."""
        from sqlalchemy import select

        from app.db.models.a2a import A2ATransaction

        await submit_a2a(a2a_envelope())
        record = (await session.execute(select(A2ATransaction))).scalars().one()
        assert len(record.signature) <= 256

    async def test_no_a2a_route_returns_key_material(self):
        import pathlib

        source = (pathlib.Path(__file__).resolve().parents[1]
                  / "app" / "api" / "routes" / "a2a.py").read_text()
        for forbidden in ("private_key", "keystore.sign(", "_load_private_key"):
            assert forbidden not in source
