"""Agent-side ANS client: register, heartbeat, deregister, discover.

The agent proves control of its DID by signing the registration payload with
the same Ed25519 key it has held since Phase 1. Nothing new is minted, and the
private key never leaves the agent process -- the ANS only ever sees a
signature and the public key it independently resolves from the DID Document.

PHASE 4.5: heartbeat and deregistration are signed too, with the SAME key, as
control-plane request proofs. A heartbeat is no longer an assertion anyone can
make on an agent's behalf. The two proof types cannot be confused for one
another -- the proof purpose is inside the signed payload -- so a captured
registration cannot be presented as a heartbeat, or the reverse.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from app.ans.proof import RegistrationPayload
from app.controlplane.client import canonical_body, control_plane_headers
from app.core.logging import get_logger
from app.identity.signer import Signer

log = get_logger("agent.ans")


class ANSRegistrationError(RuntimeError):
    """The ANS refused this agent's registration."""


@dataclass
class ANSClientState:
    registered: bool = False
    last_error: str | None = None
    last_heartbeat_at: datetime | None = None
    heartbeats_sent: int = 0
    heartbeats_failed: int = 0
    endpoint: str | None = None


class ANSClient:
    def __init__(
        self,
        *,
        base_url: str,
        did: str,
        kid: str,
        signer: Signer,
        endpoint: str,
        capabilities: list[str],
        organization: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.did = did
        self.kid = kid
        self.signer = signer
        self.endpoint = endpoint
        self.capabilities = sorted(capabilities)
        self.organization = organization
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout)
        self.state = ANSClientState(endpoint=endpoint)

    async def aclose(self) -> None:
        await self.client.aclose()

    # --- registration ----------------------------------------------------
    def build_signed_registration(self, nonce: str | None = None) -> dict[str, Any]:
        payload = RegistrationPayload.build(
            did=self.did,
            endpoint=self.endpoint,
            capabilities=self.capabilities,
            organization=self.organization,
            nonce=nonce,
        )
        signature = self.signer.sign(self.kid, payload.signing_bytes())
        return {**payload.to_dict(), "signature": signature.signature_b64}

    async def register(self) -> dict[str, Any]:
        body = self.build_signed_registration()
        try:
            response = await self.client.post("/api/v1/ans/register", json=body)
        except httpx.HTTPError as exc:
            self.state.registered = False
            self.state.last_error = f"ANS_UNREACHABLE: {type(exc).__name__}: {exc}"
            log.error("ans_register_failed", did=self.did, error=self.state.last_error)
            return {"accepted": False, "reason": "ANS_UNREACHABLE",
                    "detail": self.state.last_error}

        result = response.json()
        if response.status_code == 201 and result.get("accepted"):
            self.state.registered = True
            self.state.last_error = None
            log.info("ans_registered", did=self.did, endpoint=self.endpoint,
                     capabilities=self.capabilities)
            return result

        self.state.registered = False
        self.state.last_error = f"{result.get('reason')}: {result.get('detail')}"
        log.error("ans_register_rejected", did=self.did, reason=result.get("reason"),
                  detail=result.get("detail"))
        return result

    # --- control-plane proofs ---------------------------------------------
    def _signed(self, method: str, path: str, body: Any) -> tuple[bytes, dict[str, str]]:
        """Serialise the body ONCE and sign exactly those bytes.

        The proof binds sha256(body), so the bytes hashed and the bytes sent
        must be identical -- hence `content=` rather than `json=` on the request
        below. Passing `json=` would let httpx re-serialise with different
        spacing and every heartbeat would fail as a signature mismatch.
        """
        payload = canonical_body(body)
        headers = control_plane_headers(
            self.signer, principal_did=self.did, kid=self.kid,
            method=method, path=path, body=payload,
        )
        headers["Content-Type"] = "application/json"
        return payload, headers

    # --- liveness --------------------------------------------------------
    async def heartbeat(self, *, status: str = "ACTIVE", active_tasks: int = 0) -> bool:
        path = "/api/v1/ans/heartbeat"
        body, headers = self._signed("POST", path, {
            "did": self.did, "status": status, "active_tasks": active_tasks,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        try:
            response = await self.client.post(path, content=body, headers=headers)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            self.state.heartbeats_failed += 1
            self.state.last_error = f"{type(exc).__name__}: {exc}"
            log.warning("ans_heartbeat_failed", did=self.did, error=self.state.last_error)
            return False
        self.state.heartbeats_sent += 1
        self.state.last_heartbeat_at = datetime.now(timezone.utc)
        return True

    async def heartbeat_loop(
        self, stop: asyncio.Event, interval: int, load: "callable[[], int] | None" = None
    ) -> None:
        """Report liveness until asked to stop.

        If the ANS forgets this agent (restart with an empty registry, say), the
        heartbeat 404s and the agent re-registers with a fresh signed proof
        rather than silently disappearing from discovery.
        """
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
                return
            except asyncio.TimeoutError:
                pass
            active = load() if load else 0
            ok = await self.heartbeat(active_tasks=active)
            if not ok and self.state.registered:
                log.info("ans_reregistering", did=self.did)
                await self.register()

    # --- shutdown --------------------------------------------------------
    async def unregister(self, reason: str = "GRACEFUL_SHUTDOWN") -> bool:
        path = f"/api/v1/ans/unregister/{self.did}"
        body, headers = self._signed("POST", path, {"reason": reason})
        try:
            response = await self.client.post(path, content=body, headers=headers)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("ans_unregister_failed", did=self.did, error=str(exc))
            return False
        self.state.registered = False
        log.info("ans_unregistered", did=self.did, reason=reason)
        return True

    # --- discovery (used by the coordinator) ------------------------------
    async def discover(self, query: dict[str, Any]) -> dict[str, Any]:
        response = await self.client.post(
            "/api/v1/ans/discover", json={**query, "requester_did": self.did},
            timeout=20.0,
        )
        response.raise_for_status()
        return response.json()

    async def capabilities_catalogue(self) -> list[dict[str, Any]]:
        response = await self.client.get("/api/v1/ans/capabilities", timeout=10.0)
        response.raise_for_status()
        return response.json()

    async def resolve(self, did: str) -> dict[str, Any]:
        response = await self.client.get(f"/api/v1/ans/resolve/{did}", timeout=10.0)
        response.raise_for_status()
        return response.json()

    def status(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "registered": self.state.registered,
            "endpoint": self.endpoint,
            "capabilities": self.capabilities,
            "heartbeats_sent": self.state.heartbeats_sent,
            "heartbeats_failed": self.state.heartbeats_failed,
            "last_heartbeat_at": (
                self.state.last_heartbeat_at.isoformat()
                if self.state.last_heartbeat_at else None
            ),
            "last_error": self.state.last_error,
        }
