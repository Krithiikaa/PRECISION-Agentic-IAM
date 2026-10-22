"""ANS registration: proving control of a DID before claiming a name.

The attack this defends against: registering an existing agent's DID with an
endpoint the attacker controls, so every coordinator that discovers "the risk
agent" is routed to them.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from app.ans.proof import ProofReason, RegistrationPayload
from app.db.models.agent import AgentStatus, AgentType
from app.db.models.ans import ANSStatus
from app.identity.signer import Signer

pytestmark = pytest.mark.integration


def checks_of(result) -> dict[str, bool]:
    return {c["name"]: c["passed"] for c in (result.checks or [])}


class TestValidRegistration:
    async def test_agent_registers_itself(self, ans_registry, sign_registration, risk_agent):
        payload, signature = sign_registration(
            risk_agent, endpoint="http://localhost:9003",
            capabilities=["credit_analysis", "risk_analysis"],
        )
        result = await ans_registry.register(payload, signature)

        assert result.accepted
        assert result.reason == ProofReason.VALID
        assert all(checks_of(result).values())
        assert result.agent.status == ANSStatus.ACTIVE
        assert result.agent.endpoint == "http://localhost:9003"
        assert result.agent.capability_names == ["credit_analysis", "risk_analysis"]

    async def test_registration_indexes_held_credentials(
        self, ans_registry, sign_registration, risk_agent, issued_credential
    ):
        payload, signature = sign_registration(risk_agent)
        result = await ans_registry.register(payload, signature)
        indexed = {c.credential_id for c in result.agent.credentials}
        assert issued_credential.credential_id in indexed

    async def test_reregistration_by_the_same_identity_updates(
        self, ans_registry, sign_registration, risk_agent
    ):
        first, sig1 = sign_registration(risk_agent, endpoint="http://localhost:9003")
        await ans_registry.register(first, sig1)

        second, sig2 = sign_registration(
            risk_agent, endpoint="http://localhost:9103",
            capabilities=["credit_analysis"],
        )
        result = await ans_registry.register(second, sig2)

        assert result.accepted
        assert result.agent.endpoint == "http://localhost:9103"
        assert result.agent.capability_names == ["credit_analysis"]
        assert len(await ans_registry.list_agents()) == 1   # updated, not duplicated

    async def test_capabilities_are_indexed_for_lookup(
        self, ans_registry, sign_registration, risk_agent
    ):
        payload, signature = sign_registration(
            risk_agent, capabilities=["credit_analysis", "risk_analysis"]
        )
        await ans_registry.register(payload, signature)
        catalogue = {e["capability"]: e for e in await ans_registry.capability_catalogue()}
        assert catalogue["credit_analysis"]["active_providers"] == 1


class TestSpoofingIsRejected:
    async def test_invalid_signature(self, ans_registry, sign_registration, risk_agent):
        """The mandatory spoofing test (spec section 57)."""
        payload, _ = sign_registration(risk_agent, endpoint="http://attacker:9999")
        forged = base64.b64encode(b"\x00" * 64).decode()

        result = await ans_registry.register(payload, forged)
        assert not result.accepted
        assert result.reason == ProofReason.INVALID_PROOF
        assert checks_of(result)["registration_proof"] is False
        # Everything before the proof check passed: only cryptography stops this.
        assert checks_of(result)["did_registered"] is True
        assert await ans_registry.get(risk_agent.did) is None

    async def test_endpoint_substitution_breaks_the_proof(
        self, ans_registry, sign_registration, risk_agent
    ):
        """A signature over one endpoint cannot be reused for another."""
        honest, signature = sign_registration(
            risk_agent, endpoint="http://localhost:9003"
        )
        swapped = RegistrationPayload.from_dict(
            {**honest.to_dict(), "endpoint": "http://attacker.invalid:9999"}
        )
        result = await ans_registry.register(swapped, signature)
        assert not result.accepted
        assert result.reason == ProofReason.INVALID_PROOF

    async def test_capability_escalation_breaks_the_proof(
        self, ans_registry, sign_registration, risk_agent
    ):
        honest, signature = sign_registration(risk_agent, capabilities=["credit_analysis"])
        escalated = RegistrationPayload.from_dict(
            {**honest.to_dict(), "capabilities": ["credit_analysis", "loan_decision"]}
        )
        result = await ans_registry.register(escalated, signature)
        assert not result.accepted
        assert result.reason == ProofReason.INVALID_PROOF

    async def test_another_agents_key_cannot_claim_this_did(
        self, ans_registry, keystore, risk_agent, fraud_agent
    ):
        """Holding *a* key is not holding *the* key."""
        payload = RegistrationPayload.build(
            did=risk_agent.did, endpoint="http://attacker:9999",
            capabilities=["credit_analysis"],
        )
        # Signed by the fraud agent, claiming the risk agent's DID.
        signature = Signer(keystore).sign(
            fraud_agent.active_key.kid, payload.signing_bytes()
        )
        result = await ans_registry.register(payload, signature.signature_b64)
        assert not result.accepted
        assert result.reason == ProofReason.INVALID_PROOF

    async def test_unknown_did_cannot_register(self, ans_registry):
        payload = RegistrationPayload.build(
            did="did:poc:agent:ghost-999", endpoint="http://localhost:9999",
            capabilities=["credit_analysis"],
        )
        result = await ans_registry.register(payload, base64.b64encode(b"\x00" * 64).decode())
        assert not result.accepted
        assert result.reason == ProofReason.DID_UNKNOWN

    async def test_malformed_did_is_rejected(self, ans_registry):
        payload = RegistrationPayload.build(
            did="not-a-did", endpoint="http://localhost:9999",
            capabilities=["credit_analysis"],
        )
        result = await ans_registry.register(payload, "AAAA")
        assert result.reason == ProofReason.MALFORMED


class TestReplayProtection:
    async def test_nonce_cannot_be_reused(self, ans_registry, sign_registration, risk_agent):
        payload, signature = sign_registration(risk_agent, nonce="fixed-nonce-1")
        first = await ans_registry.register(payload, signature)
        assert first.accepted

        second = await ans_registry.register(payload, signature)
        assert not second.accepted
        assert second.reason == ProofReason.NONCE_REPLAYED

    async def test_stale_timestamp_is_rejected(
        self, ans_registry, sign_registration, risk_agent
    ):
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        payload, signature = sign_registration(risk_agent, moment=old)
        result = await ans_registry.register(payload, signature)
        assert not result.accepted
        assert result.reason == ProofReason.STALE_TIMESTAMP

    async def test_rejected_attempts_do_not_burn_a_nonce(
        self, ans_registry, sign_registration, risk_agent
    ):
        """An attacker must not be able to consume nonces by spamming failures."""
        payload, signature = sign_registration(risk_agent, nonce="contested-nonce")
        bad = await ans_registry.register(payload, base64.b64encode(b"\x01" * 64).decode())
        assert not bad.accepted

        good = await ans_registry.register(payload, signature)
        assert good.accepted


class TestEligibility:
    async def test_terminated_identity_cannot_register(
        self, ans_registry, registry, sign_registration, risk_agent
    ):
        payload, signature = sign_registration(risk_agent)
        await registry.terminate(risk_agent.did, "COMPROMISED")

        result = await ans_registry.register(payload, signature)
        assert not result.accepted
        assert result.reason == ProofReason.AGENT_NOT_ELIGIBLE

    async def test_suspended_identity_cannot_register(
        self, ans_registry, registry, sign_registration, risk_agent
    ):
        payload, signature = sign_registration(risk_agent)
        await registry.set_status(risk_agent.did, AgentStatus.SUSPENDED, "anomaly")
        result = await ans_registry.register(payload, signature)
        assert result.reason == ProofReason.AGENT_NOT_ELIGIBLE

    @pytest.mark.parametrize(
        "endpoint", ["", "ftp://localhost:9003", "not a url", "http://"]
    )
    async def test_invalid_endpoint_is_rejected(
        self, ans_registry, sign_registration, risk_agent, endpoint
    ):
        payload, signature = sign_registration(risk_agent, endpoint=endpoint)
        result = await ans_registry.register(payload, signature)
        assert not result.accepted
        assert result.reason == ProofReason.ENDPOINT_INVALID

    @pytest.mark.parametrize("capabilities", [[], ["Bad Name"], ["x"]])
    async def test_invalid_capabilities_are_rejected(
        self, ans_registry, sign_registration, risk_agent, capabilities
    ):
        payload, signature = sign_registration(risk_agent, capabilities=capabilities)
        result = await ans_registry.register(payload, signature)
        assert not result.accepted
        assert result.reason == ProofReason.CAPABILITIES_INVALID


class TestAuditTrail:
    async def test_every_attempt_is_recorded(
        self, session, ans_registry, sign_registration, risk_agent
    ):
        from sqlalchemy import select
        from app.db.models.ans import ANSRegistrationProof

        payload, signature = sign_registration(risk_agent)
        await ans_registry.register(payload, base64.b64encode(b"\x00" * 64).decode())
        await ans_registry.register(payload, signature)

        result = await session.execute(
            select(ANSRegistrationProof).where(
                ANSRegistrationProof.agent_did == risk_agent.did
            )
        )
        rows = list(result.scalars().all())
        assert len(rows) == 2
        assert {r.accepted for r in rows} == {True, False}
