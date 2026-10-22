"""DID syntax and DID Document structure."""
from __future__ import annotations

import pytest

from app.core.errors import IdentityError
from app.identity.did import build_agent_did, is_agent_did, key_id, parse_did
from app.identity.did_document import build_did_document, public_key_from_document
from app.identity.keys import InMemoryKeyStore


def test_agent_did_shape():
    assert build_agent_did("risk-001") == "did:poc:agent:risk-001"
    parsed = parse_did("did:poc:agent:risk-001")
    assert (parsed.method, parsed.kind, parsed.slug) == ("poc", "agent", "risk-001")


@pytest.mark.parametrize(
    "bad", ["", "risk-001", "did:poc:risk-001", "did:poc:agent:Risk_001", "did:poc:user:bob"]
)
def test_malformed_dids_are_rejected(bad):
    with pytest.raises(IdentityError):
        parse_did(bad)
    assert not is_agent_did(bad)


@pytest.mark.parametrize("bad", ["ab", "-risk", "risk-", "RISK", "risk_001"])
def test_invalid_slugs_are_rejected(bad):
    with pytest.raises(IdentityError):
        build_agent_did(bad)


def test_key_id_is_a_did_url():
    assert key_id("did:poc:agent:risk-001") == "did:poc:agent:risk-001#key-1"


def test_did_document_contains_the_required_elements():
    handle = InMemoryKeyStore().generate_key("did:poc:agent:risk-001#key-1")
    document = build_did_document(
        did="did:poc:agent:risk-001",
        controller="did:poc:organization:bank-demo",
        kid=handle.kid,
        public_key_multibase=handle.public_key_multibase,
        service_endpoint="http://localhost:9003",
        agent_name="Credit Risk Analysis Agent",
        agent_type="RISK",
        capabilities=["credit_analysis"],
        status="ACTIVE",
    )
    assert document["id"] == "did:poc:agent:risk-001"
    assert document["controller"] == "did:poc:organization:bank-demo"

    method = document["verificationMethod"][0]
    assert method["type"] == "Ed25519VerificationKey2020"
    assert method["publicKeyMultibase"] == handle.public_key_multibase
    assert document["authentication"] == [handle.kid]

    service = document["service"][0]
    assert service["type"] == "AgentService"
    assert service["serviceEndpoint"] == "http://localhost:9003"

    # Non-standard fields are namespaced, never mixed into DID Core properties.
    assert document["agentMetadata"]["capabilities"] == ["credit_analysis"]
    assert public_key_from_document(document, handle.kid) == handle.public_key_multibase


def test_document_never_carries_private_material():
    handle = InMemoryKeyStore().generate_key("did:poc:agent:risk-001#key-1")
    document = build_did_document(
        did="did:poc:agent:risk-001",
        controller="did:poc:organization:bank-demo",
        kid=handle.kid,
        public_key_multibase=handle.public_key_multibase,
    )
    import json

    assert "privateKey" not in json.dumps(document)
