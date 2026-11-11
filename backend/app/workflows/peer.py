"""Agent-to-agent work instructions, and an agent's own call to the AEM.

THE TWO HOPS OF EVERY WORKFLOW STEP, and who proves what on each:

    coordinator --(signed instruction)--> specialist --(signed enforce)--> IAM/AEM
                    coordinator's key                    specialist's key

Hop 1 tells the specialist WHO is asking. The coordinator signs the
instruction with its own Ed25519 key; the specialist verifies the signature
against the coordinator's PUBLIC DID Document, checks freshness, refuses a
replayed nonce, and refuses an instruction addressed to anyone else (the
signed body carries `audience` = the specialist's DID, so a captured
instruction cannot be replayed to a second specialist).

Hop 2 is where AUTHORITY comes from, and it is the specialist's own: it calls
the AEM signed with its own key, and the PDP decides on the specialist's own
verified credentials. The coordinator's instruction never lends the
coordinator's authority (confused-deputy mitigation), and a specialist only
attempts tools in its own declared toolset (paper R-77).

The wire format is the control-plane proof the rest of the system already
uses (app/controlplane/proof.py): one signing scheme, not two.
"""
from __future__ import annotations

import json
from collections import OrderedDict
from typing import Any

import httpx

from app.controlplane.client import canonical_body, control_plane_headers
from app.controlplane.proof import (
    HEADER_KEY_ID,
    HEADER_NONCE,
    HEADER_PRINCIPAL,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    ControlPlanePayload,
    body_digest,
    timestamp_is_fresh,
)
from app.identity.did_document import public_key_from_document
from app.identity.signer import Signer, verify_signature

INSTRUCTION_PATH = "/work"
ENFORCE_PATH = "/api/v1/enforce"


class InstructionRejected(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


def sign_instruction(signer: Signer, *, did: str, kid: str, audience: str,
                     body: dict[str, Any]) -> tuple[bytes, dict[str, str]]:
    payload = canonical_body({**body, "audience": audience})
    headers = control_plane_headers(signer, principal_did=did, kid=kid, method="POST",
                                    path=INSTRUCTION_PATH, body=payload)
    headers["Content-Type"] = "application/json"
    return payload, headers


class InstructionVerifier:
    """Verifies inbound instructions. One per agent process."""

    def __init__(self, iam: httpx.AsyncClient, own_did: str, *,
                 window_seconds: int = 120, nonce_capacity: int = 4096) -> None:
        self.iam = iam
        self.own_did = own_did
        self.window_seconds = window_seconds
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._capacity = nonce_capacity

    async def verify(self, headers: Any, raw: bytes) -> tuple[str, dict[str, Any]]:
        get = lambda name: headers.get(name) or headers.get(name.lower())  # noqa: E731
        principal, kid = get(HEADER_PRINCIPAL), get(HEADER_KEY_ID)
        nonce, timestamp, signature = get(HEADER_NONCE), get(HEADER_TIMESTAMP), get(HEADER_SIGNATURE)
        if not all((principal, kid, nonce, timestamp, signature)):
            raise InstructionRejected("INSTRUCTION_UNSIGNED", "missing proof headers")
        fresh, detail = timestamp_is_fresh(timestamp, window_seconds=self.window_seconds)
        if not fresh:
            raise InstructionRejected("INSTRUCTION_STALE", detail)
        replay_key = f"{principal}|{nonce}"
        if replay_key in self._seen:
            raise InstructionRejected("INSTRUCTION_REPLAYED", "nonce already used")
        try:
            body = json.loads(raw or b"{}")
        except ValueError as exc:
            raise InstructionRejected("INSTRUCTION_MALFORMED", str(exc)) from exc
        if body.get("audience") != self.own_did:
            raise InstructionRejected("INSTRUCTION_WRONG_AUDIENCE",
                                      f"addressed to {body.get('audience')!r}")

        response = await self.iam.get(f"/api/v1/agents/did/{principal}/did-document")
        if response.status_code != 200:
            raise InstructionRejected("INSTRUCTION_SENDER_UNRESOLVABLE",
                                      f"DID Document lookup returned {response.status_code}")
        document = response.json()
        status = (document.get("agentMetadata") or {}).get("status")
        if status != "ACTIVE":
            raise InstructionRejected("INSTRUCTION_SENDER_INACTIVE", f"sender is {status}")
        try:
            public_key = public_key_from_document(document, kid)
        except ValueError as exc:
            raise InstructionRejected("INSTRUCTION_KEY_UNKNOWN", str(exc)) from exc
        payload = ControlPlanePayload(principal=principal, method="POST", path=INSTRUCTION_PATH,
                                      body_sha256=body_digest(raw), nonce=nonce,
                                      timestamp=timestamp)
        result = verify_signature(public_key, payload.signing_bytes(), signature)
        if not result.valid:
            raise InstructionRejected("INSTRUCTION_SIGNATURE_INVALID", result.reason)

        self._seen[replay_key] = None
        while len(self._seen) > self._capacity:
            self._seen.popitem(last=False)
        return principal, body


async def enforce_as_self(iam: httpx.AsyncClient, signer: Signer, *, did: str, kid: str,
                          tool: str, arguments: dict[str, Any], purpose: str,
                          request_id: str | None = None,
                          approval_id: str | None = None) -> dict[str, Any]:
    """Ask the AEM to run one protected tool, as THIS agent, signed with its key."""
    body: dict[str, Any] = {"subject": {"did": did}, "tool": tool, "arguments": arguments,
                            "purpose": purpose}
    if request_id:
        body["request_id"] = request_id
    if approval_id:
        body["approval_id"] = approval_id
    payload = canonical_body(body)
    # A 429 is "not now", never "no": honour Retry-After and try again with a
    # FRESH proof (a new nonce), up to three times. Without this a busy
    # minute turned a perfectly authorizable step into a FAILED workflow.
    for attempt in range(3):
        headers = control_plane_headers(signer, principal_did=did, kid=kid, method="POST",
                                        path=ENFORCE_PATH, body=payload)
        headers["Content-Type"] = "application/json"
        response = await iam.post(ENFORCE_PATH, content=payload, headers=headers, timeout=30.0)
        if response.status_code != 429 or attempt == 2:
            break
        import asyncio
        await asyncio.sleep(min(max(int(response.headers.get("Retry-After") or 5), 1), 60))
    if response.status_code != 200:
        return {"executed": False, "http_status": response.status_code,
                "decision": {"decision": "ERROR", "reason": response.text[:300]}}
    return response.json()


# DATA MINIMISATION (CSA paper R-243). A specialist hands the coordinator the
# FINDINGS its screening needs, never the underlying record: the coordinator
# routes work and has no business holding a customer's credit file. Anything
# not listed here stays with the specialist that was authorized to read it.
FINDINGS_FIELDS: dict[str, tuple[str, ...]] = {
    "get_kyc_record": ("identity_verified", "address_verified", "sanctions_hit", "pep"),
    "get_credit_profile": ("credit_score", "score_band", "delinquencies_24m"),
    "verify_loan_documents": ("complete", "missing"),
    "get_fraud_signals": ("signal_level",),
    "assess_loan_risk": ("affordability_band", "instalment_to_income"),
    "approve_loan_application": ("application_id", "status"),
}


def minimise(tool: str, result: Any) -> Any:
    if not isinstance(result, dict):
        return result
    keep = FINDINGS_FIELDS.get(tool)
    if keep is None:
        return {"withheld": True, "note": "no findings schema for this tool"}
    out = {k: result.get(k) for k in keep}
    if result.get("simulated"):
        out["simulated"] = True
        out["adapter"] = result.get("adapter")
    return out
