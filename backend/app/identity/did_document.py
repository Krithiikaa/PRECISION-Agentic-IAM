"""DID Document construction.

POC scope note: the document shape follows the W3C DID Core structure
(`id`, `controller`, `verificationMethod`, `authentication`,
`assertionMethod`, `service`) so the same document could be served by a real
DID method later. It is *not* resolvable through the W3C universal resolver;
resolution happens against this backend's registry.
"""
from __future__ import annotations

from typing import Any

DID_CONTEXT = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
]

# W3C suite name for the key type we actually use.
VERIFICATION_KEY_TYPE = "Ed25519VerificationKey2020"


def build_did_document(
    *,
    did: str,
    controller: str,
    kid: str,
    public_key_multibase: str,
    service_endpoint: str | None = None,
    agent_name: str | None = None,
    agent_type: str | None = None,
    capabilities: list[str] | None = None,
    status: str | None = None,
    parent_did: str | None = None,
) -> dict[str, Any]:
    verification_method = {
        "id": kid,
        "type": VERIFICATION_KEY_TYPE,
        "controller": controller,
        "publicKeyMultibase": public_key_multibase,
    }
    document: dict[str, Any] = {
        "@context": DID_CONTEXT,
        "id": did,
        "controller": controller,
        "verificationMethod": [verification_method],
        # The agent authenticates with this key (A2A) and asserts with it (VCs).
        "authentication": [kid],
        "assertionMethod": [kid],
        "service": [],
    }
    if service_endpoint:
        document["service"].append(
            {
                "id": f"{did}#agent-api",
                "type": "AgentService",
                "serviceEndpoint": service_endpoint,
            }
        )
    # Non-standard metadata is namespaced so it cannot be confused with
    # W3C-defined DID Document properties.
    metadata: dict[str, Any] = {}
    if agent_name:
        metadata["name"] = agent_name
    if agent_type:
        metadata["agentType"] = agent_type
    if capabilities is not None:
        metadata["capabilities"] = capabilities
    if status:
        metadata["status"] = status
    if parent_did:
        metadata["delegatedBy"] = parent_did
    if metadata:
        document["agentMetadata"] = metadata
    return document


def public_key_from_document(document: dict[str, Any], kid: str | None = None) -> str:
    """Extract the publicKeyMultibase for `kid` (or the first method)."""
    methods = document.get("verificationMethod") or []
    if not methods:
        raise ValueError("DID Document has no verificationMethod")
    if kid is None:
        return methods[0]["publicKeyMultibase"]
    for method in methods:
        if method.get("id") == kid:
            return method["publicKeyMultibase"]
    raise ValueError(f"DID Document has no verification method {kid!r}")


def build_issuer_did_document(
    *,
    did: str,
    kid: str,
    public_key_multibase: str,
    name: str,
    service_endpoint: str | None = None,
) -> dict[str, Any]:
    """DID Document for a credential-issuing authority.

    An issuer is its own controller: nobody above it vouches for it in this
    POC, which is exactly the trust root a verifier has to accept. The
    verification method is listed under `assertionMethod` because that is the
    proof purpose an issuer uses when signing a credential.
    """
    document: dict[str, Any] = {
        "@context": DID_CONTEXT,
        "id": did,
        "controller": did,
        "verificationMethod": [
            {
                "id": kid,
                "type": VERIFICATION_KEY_TYPE,
                "controller": did,
                "publicKeyMultibase": public_key_multibase,
            }
        ],
        "assertionMethod": [kid],
        "authentication": [kid],
        "service": [],
        "issuerMetadata": {"name": name, "role": "CredentialIssuer"},
    }
    if service_endpoint:
        document["service"].append(
            {
                "id": f"{did}#credential-issuer",
                "type": "CredentialIssuerService",
                "serviceEndpoint": service_endpoint,
            }
        )
    return document
