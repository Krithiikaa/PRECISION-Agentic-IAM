"""Agent registry: lifecycle, uniqueness, persistence, revocation."""
from __future__ import annotations

import base64
import os

import pytest
from sqlalchemy import select

from app.core.errors import ConflictError, IdentityError, NotFoundError
from app.db.models.agent import Agent, AgentStatus, AgentType, KeyStatus
from app.identity.multibase import encode_ed25519_public_key

pytestmark = pytest.mark.integration

MESSAGE = "I am the Risk Analysis Agent"
TAMPERED = "I am the Payroll Agent"


class TestCreation:
    async def test_creates_did_key_and_document(self, registry, agent_spec, session):
        agent = await registry.create_agent(agent_spec("risk-001"))

        assert agent.did == "did:poc:agent:risk-001"
        assert agent.status == AgentStatus.ACTIVE
        assert agent.controller_did == "did:poc:organization:bank-demo"

        key = agent.active_key
        assert key is not None
        assert key.algorithm == "Ed25519"
        assert key.kid == "did:poc:agent:risk-001#key-1"
        assert registry.keystore.exists(key.kid)

        document = await registry.resolve_did_document(agent.did)
        assert document["verificationMethod"][0]["publicKeyMultibase"] == key.public_key_multibase

    async def test_two_agents_get_different_identities(self, registry, agent_spec):
        """Phase 1 gate test 7."""
        first = await registry.create_agent(agent_spec("risk-001"))
        second = await registry.create_agent(agent_spec("fraud-001", name="Fraud Detection Agent"))
        assert first.did != second.did
        assert first.active_key.public_key_multibase != second.active_key.public_key_multibase

    async def test_duplicate_slug_is_rejected(self, registry, agent_spec):
        await registry.create_agent(agent_spec("risk-001"))
        with pytest.raises(ConflictError):
            await registry.create_agent(agent_spec("risk-001"))

    async def test_failed_creation_leaves_no_orphan_key(self, registry, agent_spec):
        """A rolled-back registration must not strand key material."""
        with pytest.raises(NotFoundError):
            await registry.create_agent(
                agent_spec("helper-001", parent_did="did:poc:agent:nobody-999")
            )
        assert not registry.keystore.exists("did:poc:agent:helper-001#key-1")

    async def test_ephemeral_agent_gets_its_own_identity_and_a_parent_link(
        self, registry, agent_spec, session
    ):
        parent = await registry.create_agent(agent_spec("risk-001"))
        helper = await registry.create_agent(
            agent_spec(
                "helper-001",
                name="Loan Document Processing Helper",
                agent_type=AgentType.HELPER,
                parent_did=parent.did,
                ttl_seconds=900,
            )
        )
        # Distinct identity, NOT the parent's.
        assert helper.did != parent.did
        assert helper.active_key.public_key_multibase != parent.active_key.public_key_multibase
        assert helper.parent_agent_id == parent.id
        assert helper.expires_at is not None

        document = await registry.resolve_did_document(helper.did)
        assert document["agentMetadata"]["delegatedBy"] == parent.did


class TestKeyCustody:
    async def test_agent_held_key_is_registered_without_the_private_half(
        self, registry, agent_spec
    ):
        """An agent may generate its own key and register only the public part."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        public_raw = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        multibase = encode_ed25519_public_key(public_raw)

        agent = await registry.create_agent(
            agent_spec("risk-001", public_key_multibase=multibase)
        )
        assert agent.active_key.public_key_multibase == multibase
        assert agent.active_key.keystore_backend == "external"
        # The registry generated nothing, so it holds nothing.
        assert not registry.keystore.exists(agent.active_key.kid)

    async def test_registry_refuses_to_sign_for_an_agent_held_key(self, registry, agent_spec):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        public_raw = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        agent = await registry.create_agent(
            agent_spec("risk-001", public_key_multibase=encode_ed25519_public_key(public_raw))
        )
        with pytest.raises(IdentityError, match="holds its own key"):
            await registry.sign_as_agent(agent.did, MESSAGE)

    async def test_invalid_public_key_is_rejected(self, registry, agent_spec):
        with pytest.raises(IdentityError, match="Invalid publicKeyMultibase"):
            await registry.create_agent(agent_spec("risk-001", public_key_multibase="zNOTAKEY"))


class TestSigning:
    async def test_sign_then_verify_through_the_did_document(self, registry, agent_spec):
        """Phase 1 gate tests 3 and 4."""
        agent = await registry.create_agent(agent_spec("risk-001"))
        signed = await registry.sign_as_agent(agent.did, MESSAGE)
        result = await registry.verify_agent_signature(agent.did, MESSAGE, signed["signature"])
        assert result.valid
        assert result.verification_method == "did:poc:agent:risk-001#key-1"

    async def test_tampered_message_is_rejected(self, registry, agent_spec):
        """Phase 1 gate test 5."""
        agent = await registry.create_agent(agent_spec("risk-001"))
        signed = await registry.sign_as_agent(agent.did, MESSAGE)
        result = await registry.verify_agent_signature(agent.did, TAMPERED, signed["signature"])
        assert not result.valid
        assert result.reason.startswith("SIGNATURE_MISMATCH")

    async def test_another_agents_signature_is_rejected(self, registry, agent_spec):
        risk = await registry.create_agent(agent_spec("risk-001"))
        fraud = await registry.create_agent(agent_spec("fraud-001", name="Fraud Detection Agent"))
        signed = await registry.sign_as_agent(fraud.did, MESSAGE)
        result = await registry.verify_agent_signature(risk.did, MESSAGE, signed["signature"])
        assert not result.valid

    async def test_unknown_did_does_not_verify(self, registry):
        result = await registry.verify_agent_signature("did:poc:agent:ghost-001", MESSAGE, "AAAA")
        assert not result.valid
        assert result.reason.startswith("DID_NOT_RESOLVABLE")


class TestLifecycle:
    async def test_suspended_agent_cannot_sign(self, registry, agent_spec):
        agent = await registry.create_agent(agent_spec("risk-001"))
        await registry.set_status(agent.did, AgentStatus.SUSPENDED, "anomaly")
        with pytest.raises(IdentityError, match="SUSPENDED"):
            await registry.sign_as_agent(agent.did, MESSAGE)

    async def test_termination_destroys_the_key(self, registry, agent_spec):
        agent = await registry.create_agent(agent_spec("risk-001"))
        kid = agent.active_key.kid
        await registry.terminate(agent.did, "COMPROMISED")

        assert agent.status == AgentStatus.TERMINATED
        assert agent.terminated_at is not None
        assert not registry.keystore.exists(kid)
        assert all(k.status == KeyStatus.REVOKED for k in agent.keys)

        with pytest.raises(IdentityError):
            await registry.sign_as_agent(agent.did, MESSAGE)

    async def test_previously_issued_signature_still_verifies_after_termination(
        self, registry, agent_spec
    ):
        """Termination stops NEW signatures. Old ones remain mathematically valid.

        This is why Phase 2 needs credential status and Phase 9 needs session
        revocation: the signature alone is not an authorisation.
        """
        agent = await registry.create_agent(agent_spec("risk-001"))
        signed = await registry.sign_as_agent(agent.did, MESSAGE)
        await registry.terminate(agent.did)
        result = await registry.verify_agent_signature(agent.did, MESSAGE, signed["signature"])
        assert result.valid


class TestPersistence:
    async def test_identity_survives_a_new_session(self, registry, agent_spec, engine):
        """Phase 1 gate test 6, at the data layer: a fresh connection sees it."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        agent = await registry.create_agent(agent_spec("risk-001"))
        await registry.session.commit()
        expected_key = agent.active_key.public_key_multibase

        async with async_sessionmaker(bind=engine, expire_on_commit=False)() as fresh:
            found = (
                await fresh.execute(select(Agent).where(Agent.did == "did:poc:agent:risk-001"))
            ).scalar_one()
            assert found.active_key.public_key_multibase == expected_key
            assert found.status == AgentStatus.ACTIVE
