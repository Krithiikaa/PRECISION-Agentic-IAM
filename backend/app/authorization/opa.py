"""Client for the real Open Policy Agent runtime.

THIS IS AN HTTP CLIENT, NOT A POLICY ENGINE. It contains no rules, no
allow/deny table and no evaluation logic. Every decision in this system is
computed by OPA evaluating Rego. If OPA is not running, this module cannot
substitute for it -- it raises, and the PDP turns that into a DENY.

That is deliberate. A Python fallback that "approximated" the policy would be a
second, divergent implementation of the security decision, and the first time it
disagreed with Rego it would do so silently.

OPA dialect note: the runtime is OPA 1.x, so the policy modules are Rego v1.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

log = get_logger("authz.opa")


class OPAUnavailableError(RuntimeError):
    """OPA could not be reached, or did not return a usable decision.

    Always results in DENY. Never in ALLOW.
    """


class OPAPolicyError(RuntimeError):
    """OPA rejected a policy module (compile error, bad path)."""


@dataclass(frozen=True)
class OPAResult:
    document: dict[str, Any]
    latency_ms: float


class OPAClient:
    def __init__(
        self,
        settings: Settings | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.base_url = self.settings.opa_url.rstrip("/")
        self._client = client
        self._owns_client = client is None

    @asynccontextmanager
    async def _http(self):
        """Yield an HTTP client for one call.

        When no client was injected, a fresh one is opened and closed per
        request rather than cached on the instance. Authorization calls are
        low-volume and single-digit-milliseconds, so the connection saving is
        negligible -- while a cached client is bound to the event loop that
        created it, which makes the object unusable from any other loop. Not
        caching removes that whole class of failure.
        """
        if self._client is not None:
            yield self._client
            return
        async with httpx.AsyncClient(timeout=self.settings.opa_timeout_seconds) as client:
            yield client

    async def aclose(self) -> None:
        """Close an INJECTED client. A per-call client closes itself."""
        if self._client is not None and not self._owns_client:
            return
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # --- health ----------------------------------------------------------
    async def health(self) -> dict[str, Any]:
        """Is the policy engine actually up? Reported, never assumed."""
        try:
            async with self._http() as client:
                response = await client.get(f"{self.base_url}/health")
            return {
                "available": response.status_code == 200,
                "url": self.base_url,
                "detail": f"HTTP {response.status_code}",
            }
        except httpx.HTTPError as exc:
            return {
                "available": False,
                "url": self.base_url,
                "detail": f"{type(exc).__name__}: {exc}",
            }

    # --- evaluation -------------------------------------------------------
    async def evaluate(
        self, input_document: dict[str, Any], *, decision_url: str | None = None
    ) -> OPAResult:
        """Ask OPA for a decision.

        `decision_url` selects the Rego entrypoint. It defaults to the
        data-plane one; Phase 4.5 passes the control-plane entrypoint so both
        planes are evaluated by the SAME engine and the same client, with the
        same failure handling, against different policy packages.

        Raises `OPAUnavailableError` on any failure -- transport, timeout,
        non-200, unparseable body, or a missing `result` key. The caller must
        convert that into a denial; there is no code path here that returns a
        permissive default.
        """
        import time

        url = decision_url or self.settings.opa_decision_url
        started = time.perf_counter()
        try:
            async with self._http() as client:
                response = await client.post(url, json={"input": input_document})
        except httpx.HTTPError as exc:
            raise OPAUnavailableError(
                f"OPA at {self.base_url} is unreachable: {type(exc).__name__}: {exc}"
            ) from exc
        latency_ms = (time.perf_counter() - started) * 1000

        if response.status_code != 200:
            raise OPAUnavailableError(
                f"OPA returned HTTP {response.status_code} for {url}: "
                f"{response.text[:200]}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise OPAUnavailableError(f"OPA returned a non-JSON body: {exc}") from exc

        if "result" not in body:
            # An undefined result means the decision rule is not loaded. That is
            # an outage of the policy layer, not a permissive answer.
            raise OPAUnavailableError(
                f"OPA has no decision at {url!r}: the policy module is not "
                f"loaded. Body: {str(body)[:200]}"
            )
        result = body["result"]
        if not isinstance(result, dict) or "decision" not in result:
            raise OPAUnavailableError(
                f"OPA returned a malformed decision document: {str(result)[:200]}"
            )
        return OPAResult(document=result, latency_ms=latency_ms)

    # --- policy management (used by the PAP) ------------------------------
    async def put_policy(self, module_id: str, rego_source: str) -> None:
        """Load or replace a policy module. OPA compiles it and may reject it."""
        try:
            async with self._http() as client:
                response = await client.put(
                    f"{self.base_url}/v1/policies/{module_id}",
                    content=rego_source.encode("utf-8"),
                    headers={"Content-Type": "text/plain"},
                )
        except httpx.HTTPError as exc:
            raise OPAUnavailableError(
                f"Cannot reach OPA to load policy {module_id!r}: {exc}"
            ) from exc
        if response.status_code != 200:
            raise OPAPolicyError(
                f"OPA rejected policy {module_id!r}: HTTP {response.status_code} "
                f"{response.text[:400]}"
            )

    async def delete_policy(self, module_id: str) -> None:
        """Remove a module. This is what makes deactivation real: the rules
        genuinely leave the engine rather than being flagged inactive."""
        try:
            async with self._http() as client:
                response = await client.delete(f"{self.base_url}/v1/policies/{module_id}")
        except httpx.HTTPError as exc:
            raise OPAUnavailableError(
                f"Cannot reach OPA to remove policy {module_id!r}: {exc}"
            ) from exc
        if response.status_code not in (200, 404):
            raise OPAPolicyError(
                f"OPA refused to remove {module_id!r}: HTTP {response.status_code} "
                f"{response.text[:200]}"
            )

    # --- policy DATA (Phase 5.5) ------------------------------------------
    # Rules and their configuration are separated on purpose. `policies/*.rego`
    # says what "high value" MEANS; `policies/data/*.json` says what the
    # numbers are. A threshold is something a risk committee changes; a rule is
    # something a security reviewer changes. Keeping them in one file would
    # make every threshold change a policy code change.
    #
    # This is OPA's own data API, so the values live in `data.` and are read by
    # Rego like any other document. Nothing about the decision moves into
    # Python -- Python only PUTs the numbers.

    async def put_data(self, path: str, document: Any) -> None:
        """Load or replace a data document at `data.<path>`."""
        try:
            async with self._http() as client:
                response = await client.put(
                    f"{self.base_url}/v1/data/{path.strip('/')}", json=document
                )
        except httpx.HTTPError as exc:
            raise OPAUnavailableError(
                f"Cannot reach OPA to load data {path!r}: {exc}"
            ) from exc
        if response.status_code not in (200, 204):
            raise OPAPolicyError(
                f"OPA rejected data document {path!r}: HTTP "
                f"{response.status_code} {response.text[:400]}"
            )

    async def get_data(self, path: str) -> Any:
        """Read a data document back. `None` means OPA does not hold one.

        Used by the PAP's reconcile and status report, so "the thresholds are
        loaded" is something the system can observe rather than assume. Policy
        fails CLOSED when they are absent, and an operator needs to be able to
        see that before it bites.
        """
        try:
            async with self._http() as client:
                response = await client.get(f"{self.base_url}/v1/data/{path.strip('/')}")
        except httpx.HTTPError as exc:
            raise OPAUnavailableError(
                f"Cannot reach OPA to read data {path!r}: {exc}"
            ) from exc
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise OPAUnavailableError(
                f"OPA returned HTTP {response.status_code} reading data {path!r}"
            )
        try:
            return response.json().get("result")
        except ValueError as exc:
            raise OPAUnavailableError(f"OPA returned a non-JSON body: {exc}") from exc

    async def delete_data(self, path: str) -> None:
        """Remove a data document. Policy then fails closed, by design."""
        try:
            async with self._http() as client:
                response = await client.delete(f"{self.base_url}/v1/data/{path.strip('/')}")
        except httpx.HTTPError as exc:
            raise OPAUnavailableError(
                f"Cannot reach OPA to remove data {path!r}: {exc}"
            ) from exc
        if response.status_code not in (200, 204, 404):
            raise OPAPolicyError(
                f"OPA refused to remove data {path!r}: HTTP {response.status_code}"
            )

    async def list_policies(self) -> list[str]:
        try:
            async with self._http() as client:
                response = await client.get(f"{self.base_url}/v1/policies")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise OPAUnavailableError(f"Cannot list OPA policies: {exc}") from exc
        return [entry["id"] for entry in response.json().get("result", [])]
