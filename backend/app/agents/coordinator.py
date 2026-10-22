"""Coordinator logic: work out what capability a task needs, then find it.

This module is the reason Phase 3 exists. There is no table of agent
endpoints here, no `RISK_AGENT_URL`, and no mapping from task text to a
specific agent. The coordinator:

    1. asks ANS what capabilities the network currently offers
    2. asks the LLM to choose one, constrained to that live list
    3. asks ANS which agents provide it, under the required constraints
    4. VERIFIES the answer against the identity authority before trusting it
    5. selects the top-ranked candidate

Step 4 matters: ANS is a directory, not a trust anchor. If ANS were
compromised it could point `did:poc:agent:risk-001` at an attacker's endpoint.
The coordinator therefore cross-checks the endpoint against the DID Document
published by the Phase 1 registry, which ANS does not control.

Authorization is still absent. Discovering an agent says nothing about whether
the resulting request is permitted -- that is the PDP in Phase 4.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.agents.ans_client import ANSClient
from app.core.errors import LLMUnavailableError
from app.core.logging import get_logger
from app.llm.provider import LLMProvider

log = get_logger("agent.coordinator")


class CoordinationError(RuntimeError):
    """Coordination could not complete. Never resolved by guessing an agent."""


@dataclass
class CapabilityResolution:
    capability: str
    rationale: str
    catalogue: list[str]
    llm: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "rationale": self.rationale,
            "catalogue": self.catalogue,
            "llm": self.llm,
        }


@dataclass
class VerificationCheck:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class CoordinationOutcome:
    task: str
    capability: CapabilityResolution | None
    discovery: dict[str, Any] | None
    selected: dict[str, Any] | None
    verification: list[VerificationCheck] = field(default_factory=list)
    verified: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "capability": self.capability.to_dict() if self.capability else None,
            "discovery": self.discovery,
            "selected": self.selected,
            "verification": [c.to_dict() for c in self.verification],
            "verified": self.verified,
            "reason": self.reason,
            # Stated explicitly so nothing downstream mistakes discovery for a
            # permission decision.
            "authorization": {
                "evaluated": False,
                "note": "Discovery is not authorization. The PDP arrives in Phase 4.",
            },
        }


CAPABILITY_SYSTEM_PROMPT = """You route banking tasks to agent capabilities.

You are given the capabilities that are actually registered in the agent
network right now. Choose exactly one that the task requires.

Rules:
- You MUST choose from the provided list. Do not invent a capability name.
- If nothing in the list fits, return null for "capability".
- Respond with JSON only: {"capability": "<name or null>", "rationale": "<one sentence>"}"""


class Coordinator:
    def __init__(
        self,
        *,
        ans: ANSClient,
        llm: LLMProvider,
        iam_client: httpx.AsyncClient,
        did: str,
    ) -> None:
        self.ans = ans
        self.llm = llm
        self.iam = iam_client
        self.did = did

    # --- step 1 + 2: which capability does this task need? ----------------
    async def resolve_capability(self, task: str) -> CapabilityResolution:
        catalogue_entries = await self.ans.capabilities_catalogue()
        catalogue = [entry["capability"] for entry in catalogue_entries]
        if not catalogue:
            raise CoordinationError(
                "The ANS capability catalogue is empty; no agent has registered a "
                "capability, so no task can be routed."
            )

        listing = "\n".join(
            f"- {entry['capability']} "
            f"({entry['active_providers']} of {entry['providers']} providers active)"
            for entry in catalogue_entries
        )
        prompt = (
            f"REGISTERED CAPABILITIES\n{listing}\n\n"
            f"TASK\n{task}\n\n"
            f"Which single capability does this task require?"
        )

        try:
            result = await self.llm.generate(
                prompt, system=CAPABILITY_SYSTEM_PROMPT, json_mode=True, max_tokens=200
            )
        except LLMUnavailableError as exc:
            # No keyword fallback: a hidden rule table would be exactly the
            # hardcoded routing this phase exists to remove.
            raise CoordinationError(
                f"Cannot determine the required capability: the LLM is unavailable "
                f"({exc}). The coordinator will not guess."
            ) from exc

        try:
            parsed = json.loads(result.text)
            chosen = parsed.get("capability")
            rationale = str(parsed.get("rationale", ""))[:400]
        except (json.JSONDecodeError, AttributeError) as exc:
            raise CoordinationError(
                f"The model did not return usable JSON: {exc}. Raw: {result.text[:200]!r}"
            ) from exc

        # Constrain the model to reality: it may only pick something that is
        # genuinely registered.
        if chosen not in catalogue:
            raise CoordinationError(
                f"No registered capability fits this task. The model chose "
                f"{chosen!r}, which is not in the live catalogue {catalogue}."
            )

        log.info("capability_resolved", task=task[:80], capability=chosen)
        return CapabilityResolution(
            capability=chosen,
            rationale=rationale,
            catalogue=catalogue,
            llm={"model": result.model, "provider": result.provider,
                 "latency_ms": round(result.latency_ms, 1)},
        )

    # --- step 4: do not trust the directory blindly -----------------------
    async def verify_selection(self, selected: dict[str, Any]) -> list[VerificationCheck]:
        """Cross-check the discovery result against the identity authority.

        ANS is a directory. The DID Document is the trust anchor, and ANS does
        not control it, so an endpoint substitution in the registry is
        detectable here.
        """
        checks: list[VerificationCheck] = []
        did = selected["did"]
        endpoint = selected["endpoint"]

        # 1. The identity exists and is ACTIVE according to the registry.
        try:
            response = await self.iam.get(f"/api/v1/agents/did/{did}", timeout=10.0)
            response.raise_for_status()
            identity = response.json()
        except httpx.HTTPError as exc:
            checks.append(VerificationCheck(
                "identity_resolves", False,
                f"could not resolve {did} at the identity authority: {exc}"))
            return checks
        active = identity.get("status") == "ACTIVE"
        checks.append(VerificationCheck(
            "identity_active", active,
            f"identity status {identity.get('status')}"))

        # 2. The endpoint ANS gave matches the one published in the DID
        #    Document. A compromised directory cannot forge this.
        try:
            response = await self.iam.get(
                f"/api/v1/agents/did/{did}/did-document", timeout=10.0
            )
            response.raise_for_status()
            document = response.json()
        except httpx.HTTPError as exc:
            checks.append(VerificationCheck(
                "did_document", False, f"could not fetch the DID Document: {exc}"))
            return checks

        published = [
            service.get("serviceEndpoint")
            for service in document.get("service", [])
            if service.get("serviceEndpoint")
        ]
        matches = endpoint.rstrip("/") in [p.rstrip("/") for p in published]
        checks.append(VerificationCheck(
            "endpoint_binding", matches,
            f"ANS endpoint {endpoint} is published in the DID Document"
            if matches else
            f"ANS says {endpoint}, DID Document publishes {published or 'nothing'}"))

        # 3. The public key ANS reported (via resolve) is the published one.
        checks.append(VerificationCheck(
            "did_document_key", bool(document.get("verificationMethod")),
            document["verificationMethod"][0]["id"]
            if document.get("verificationMethod") else "no verification method"))

        return checks

    # --- full flow --------------------------------------------------------
    async def coordinate(
        self,
        task: str,
        *,
        capability: str | None = None,
        required_credentials: list[str] | None = None,
        organization: str | None = None,
        require_healthy_endpoint: bool = False,
    ) -> CoordinationOutcome:
        outcome = CoordinationOutcome(task=task, capability=None, discovery=None,
                                      selected=None)

        # 1/2. capability
        if capability:
            catalogue = [e["capability"] for e in await self.ans.capabilities_catalogue()]
            if capability not in catalogue:
                outcome.reason = "CAPABILITY_NOT_REGISTERED"
                raise CoordinationError(
                    f"Capability {capability!r} is not registered in the ANS. "
                    f"Registered: {catalogue}"
                )
            resolution = CapabilityResolution(
                capability=capability,
                rationale="supplied explicitly by the caller",
                catalogue=catalogue,
            )
        else:
            resolution = await self.resolve_capability(task)
        outcome.capability = resolution

        # 3. discovery
        discovery = await self.ans.discover({
            "capability": resolution.capability,
            "required_credentials": required_credentials or [],
            "organization": organization,
            "require_healthy_endpoint": require_healthy_endpoint,
        })
        outcome.discovery = discovery

        selected = discovery.get("selected")
        if not selected:
            # Honest failure. No fallback endpoint exists to fall back to.
            outcome.reason = discovery.get("reason", "NO_MATCHING_AGENT")
            log.warning("coordination_no_match", capability=resolution.capability,
                        candidates=discovery.get("candidate_count"))
            return outcome
        outcome.selected = selected

        # 4. verify before trusting
        outcome.verification = await self.verify_selection(selected)
        outcome.verified = all(c.passed for c in outcome.verification)
        outcome.reason = "AGENT_SELECTED" if outcome.verified else "VERIFICATION_FAILED"
        if not outcome.verified:
            failed = [c.name for c in outcome.verification if not c.passed]
            log.error("coordination_verification_failed", did=selected["did"],
                      failed=failed)
        return outcome
