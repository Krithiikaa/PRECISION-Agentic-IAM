"""The rich Agent ID profile published in the DID Document.

CSA paper section 3.2 (R-69 to R-82): an Agent ID is more than a key. Its DID
Document carries who created, deployed, owns and controls the agent; which
software and model it runs, bound by a cryptographic hash; its formal scope of
behaviour; its toolset; the protocols it speaks; and lifecycle timestamps.

THE MODEL HASH, and exactly what it commits to (R-70 asks for "a cryptographic
hash of the core model parameters and software version", SHA-3 family):

    SHA3-256( canonical JSON of {
        model,               e.g. "llama3:8b"
        model_digest,        the weights digest the model runtime REPORTS
                             (Ollama's sha256 of the model blob), or null
        software_version,    this codebase's agent runtime version
        system_prompt_sha3   SHA3-256 of the agent's system prompt
    })

It does NOT hash the weights itself -- this service never reads them. It binds
the identity to the runtime's own digest of the weights, plus the prompt and
software that shape behaviour, so a silent swap of any of them changes the
hash an auditor sees in the DID Document. Where the runtime digest is not
available the field is null and the profile says so, rather than inventing one.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

PROFILE_VERSION = "agent-id-profile/v1"
HASH_ALGORITHM = "SHA3-256"

# Protocols this POC's agent runtime actually speaks. Not aspirational.
RUNTIME_PROTOCOLS = ("https+signed-control-plane", "a2a-signed-envelope/v1", "mcp/2025-06-18")


def sha3_256(text: str) -> str:
    return hashlib.sha3_256(text.encode("utf-8")).hexdigest()


def model_hash(*, model: str | None, model_digest: str | None,
               software_version: str, system_prompt: str | None) -> str:
    payload = {
        "model": model,
        "model_digest": model_digest,
        "software_version": software_version,
        "system_prompt_sha3": sha3_256(system_prompt) if system_prompt else None,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha3_256(canonical)


def build_agent_profile(
    *,
    creator: str,
    deployer: str,
    owner: str | None,
    controller: str,
    software_version: str,
    model: str | None,
    model_digest: str | None,
    system_prompt: str | None,
    scope_of_behavior: dict[str, Any],
    toolset: list[str],
    created_at: datetime,
    expires_at: datetime | None,
    delegation: dict[str, Any] | None = None,
    expected_outcomes: str | None = None,
    limitations: str | None = None,
) -> dict[str, Any]:
    profile: dict[str, Any] = {
        "profileVersion": PROFILE_VERSION,
        "provenance": {
            "creator": creator, "deployer": deployer, "owner": owner,
            "controller": controller,
        },
        "software": {"version": software_version, "updateMechanism":
                     "re-provisioning by the identity administrator; every change "
                     "republishes this document with a new version number"},
        "model": {
            "name": model,
            "runtimeDigest": model_digest,
            "hash": {"algorithm": HASH_ALGORITHM,
                     "value": model_hash(model=model, model_digest=model_digest,
                                         software_version=software_version,
                                         system_prompt=system_prompt),
                     "commitsTo": ["model", "runtimeDigest", "software.version",
                                   "systemPrompt(SHA3-256)"]},
        },
        "scopeOfBehavior": scope_of_behavior,
        "toolset": sorted(set(toolset)),
        "protocols": list(RUNTIME_PROTOCOLS),
        "timestamps": {"created": created_at.isoformat(),
                       "expires": expires_at.isoformat() if expires_at else None},
    }
    if expected_outcomes or limitations:
        profile["expectedOutcomes"] = expected_outcomes
        profile["limitations"] = limitations
    if delegation:
        profile["delegation"] = delegation
    return profile
