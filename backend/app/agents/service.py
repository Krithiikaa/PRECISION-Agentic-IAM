"""The agent process.

Each agent runs as its own service. On boot it:

  1. opens its OWN keystore directory and generates its OWN Ed25519 key pair
     (the private key never leaves the agent host, not even to the registry)
  2. self-registers its DID + PUBLIC key with the IAM registry
  3. on a DID collision, verifies the published key matches its own and
     REFUSES TO START if it does not -- someone else has claimed its DID
  4. checks the LLM is genuinely reachable and the configured model is pulled
  5. serves /health, /ready, /identity, /did-document, /task, /sign, /verify,
     /a2a/send, /a2a/inbound, /events/stream

There is no code path in which this process reports a task result that the
LLM did not actually produce.
"""
from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from app.agents.ans_client import ANSClient
from app.agents.base import AgentIdentity, TaskRequest
from app.agents.coordinator import CoordinationError, Coordinator
from app.agents.definitions import AgentDefinition, get_definition
from app.agents.runtime import AgentRuntime
from app.agents.wallet import CredentialWallet
from app.core.config import get_settings
from app.core.errors import KeyStoreError
from app.core.logging import get_logger
from app.identity.did import build_agent_did, key_id
from app.identity.keys import EncryptedFileKeyStore
from app.controlplane.client import canonical_body, control_plane_headers
from app.identity.signer import Signer, verify_signature
from app.llm.ollama import build_llm_provider
from app.monitoring.events import EventType

log = get_logger("agent.service")


class AgentServiceConfig(BaseModel):
    slug: str
    iam_api_url: str = "http://localhost:8000"
    ans_url: str = "http://localhost:8100"
    host: str = "0.0.0.0"
    port: int = 9000
    public_url: str | None = None
    keystore_dir: str = "./.keystore-agents"
    register_timeout: float = 10.0

    @classmethod
    def from_env(cls) -> "AgentServiceConfig":
        slug = os.environ.get("AGENT_SLUG")
        if not slug:
            raise RuntimeError("AGENT_SLUG must be set (e.g. AGENT_SLUG=risk-001)")
        definition = get_definition(slug)
        port = int(os.environ.get("AGENT_PORT", definition.port))
        return cls(
            slug=slug,
            iam_api_url=os.environ.get("IAM_API_URL", "http://localhost:8000"),
            ans_url=os.environ.get("ANS_URL", "http://localhost:8100"),
            host=os.environ.get("AGENT_HOST", "0.0.0.0"),
            port=port,
            public_url=os.environ.get("AGENT_PUBLIC_URL", f"http://localhost:{port}"),
            keystore_dir=os.environ.get("AGENT_KEYSTORE_DIR", "./.keystore-agents"),
        )


class TaskIn(BaseModel):
    instruction: str = Field(min_length=1)
    task_id: str | None = None
    correlation_id: str | None = None
    sender_did: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    injected: bool = False


class SignIn(BaseModel):
    message: str


class CoordinateIn(BaseModel):
    """Ask the coordinator to find the right agent for a task."""

    task: str = Field(min_length=1)
    capability: str | None = Field(
        default=None,
        description="Skip LLM capability resolution and use this capability.",
    )
    required_credentials: list[str] = Field(default_factory=list)
    organization: str | None = None
    require_healthy_endpoint: bool = False


class PresentIn(BaseModel):
    """Ask the agent to present credentials it holds."""

    capability: str | None = None
    credential_type: str | None = None
    credential_ids: list[str] | None = None
    challenge: str | None = None
    domain: str | None = None


class VerifyIn(BaseModel):
    message: str
    signature: str


class A2ASendIn(BaseModel):
    """Ask THIS agent to instruct another one (Phase 7).

    The agent signs with its own Phase 1 key -- the private key never leaves
    this process -- and POSTs the envelope to the receiver it discovered.
    """

    receiver_did: str
    receiver_endpoint: str | None = Field(
        default=None,
        description="Where to send it. Omitted means resolve through the ANS, "
                    "then cross-check against the DID Document.",
    )
    action: str = "execute_payment"
    resource_type: str = "payment_instructions"
    resource_id: str
    purpose: str = "payment_settlement"
    amount_inr: int | None = None
    currency: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    transaction_id: str | None = Field(
        default=None,
        description="Reuse it to retry -- after a lost response, or once the "
                    "humans an escalation asked for have decided.",
    )
    ttl_seconds: int = 300
    correlation_id: str | None = None
    credentials: list[str] = Field(default_factory=list)


class A2AInboundIn(BaseModel):
    """A signed envelope arriving from another agent (Phase 7)."""

    envelope: dict[str, Any]


class AgentBootstrapError(RuntimeError):
    """Raised when the agent cannot establish a trustworthy identity."""


class LocalEventStream:
    """Per-process event fan-out for this agent's own telemetry."""

    def __init__(self) -> None:
        self._queues: set[asyncio.Queue] = set()
        self.recent: list[dict[str, Any]] = []

    def publish(self, event: dict[str, Any]) -> None:
        self.recent = (self.recent + [event])[-200:]
        for q in list(self._queues):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._queues.add(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._queues.discard(q)


async def _confirm_identity_with_iam(
    client: httpx.AsyncClient,
    definition: AgentDefinition,
    did: str,
    public_key_multibase: str,
    endpoint: str | None,
) -> dict[str, Any]:
    """Confirm that this process's key really controls its registered DID.

    PHASE 5 -- S-7. This function used to CREATE the identity if it did not
    exist, by POSTing to /api/v1/agents unauthenticated. That was the hole: an
    agent minting its own identity means anyone who can reach the port can mint
    one too, choosing any slug and publishing their own key under it. Creating
    an identity is an administrative act, and it is now authorized and audited
    like one -- see scripts/provision_agents.py.

    So the agent no longer creates anything. It CONFIRMS, and refuses to start
    if it cannot:

        identity missing            -> not provisioned; stop and say so
        published key != our key    -> another key controls this DID; stop

    The second case was already fatal and stays fatal. Serving under a DID this
    process cannot prove it controls would produce signatures nobody can
    verify, or -- worse -- imply this process is the legitimate holder when it
    is not.
    """
    existing = await client.get(f"/api/v1/agents/did/{did}")
    if existing.status_code == 404:
        raise AgentBootstrapError(
            f"NOT PROVISIONED: {did} has no registered identity. Agents no "
            f"longer create their own identities (Phase 5, S-7): creating one "
            f"is an authorized administrative operation. Provision it with "
            f"`python3 scripts/provision_agents.py` and start this process again."
        )
    if existing.status_code != 200:
        raise AgentBootstrapError(
            f"Cannot resolve {did}: {existing.status_code} {existing.text[:200]}"
        )

    record = existing.json()
    published = (record.get("active_key") or {}).get("public_key_multibase")
    if published != public_key_multibase:
        raise AgentBootstrapError(
            f"IDENTITY CONFLICT for {did}: the registry publishes public key "
            f"{published!r} but this process holds {public_key_multibase!r}. "
            f"Refusing to start."
        )
    log.info("agent_identity_confirmed", did=did)
    return record


def create_agent_service(config: AgentServiceConfig) -> FastAPI:
    definition = get_definition(config.slug)
    settings = get_settings()
    did = build_agent_did(config.slug, settings.did_method)
    kid = key_id(did)
    state: dict[str, Any] = {
        "registered": False,
        "registration_error": None,
        "llm_health": None,
        "runtime": None,
        "ans": None,
        "ans_registered": False,
        "coordinator": None,
    }
    stream = LocalEventStream()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # --- 1. agent-held key material ---------------------------------
        keystore = EncryptedFileKeyStore(
            os.path.join(config.keystore_dir, config.slug), settings.keystore_master_key
        )
        if keystore.exists(kid):
            handle = keystore.get_public_key(kid)
            log.info("agent_key_loaded", kid=kid)
        else:
            handle = keystore.generate_key(kid)
            log.info("agent_key_generated", kid=kid)

        identity = AgentIdentity(
            did=did,
            slug=config.slug,
            name=definition.name,
            kid=handle.kid,
            public_key_multibase=handle.public_key_multibase,
            controller_did=settings.organization_did,
            endpoint=config.public_url,
            capabilities=definition.capabilities,
        )

        iam = httpx.AsyncClient(base_url=config.iam_api_url, timeout=config.register_timeout)
        app.state.iam = iam

        # --- 2. confirm the provisioned identity ------------------------
        try:
            await _confirm_identity_with_iam(
                iam, definition, did, handle.public_key_multibase, config.public_url
            )
            state["registered"] = True
        except AgentBootstrapError as exc:
            # Both of these are fatal. An identity conflict means another key
            # controls this DID; being unprovisioned means there is no identity
            # to act under at all. Neither is a state to serve traffic in.
            if "IDENTITY CONFLICT" in str(exc) or "NOT PROVISIONED" in str(exc):
                await iam.aclose()
                raise
            state["registration_error"] = str(exc)
            log.error("agent_registration_failed", error=str(exc))
        except httpx.HTTPError as exc:
            state["registration_error"] = f"IAM_UNREACHABLE: {exc}"
            log.error("agent_registration_failed", error=str(exc))

        # --- 3. LLM reachability ----------------------------------------
        llm = build_llm_provider(settings)
        health = await llm.health()
        state["llm_health"] = health
        if not health.available:
            log.error("llm_unavailable", detail=health.detail, model=health.model)

        # --- 4. runtime --------------------------------------------------
        async def sink(event_type: str, metadata: dict[str, Any]) -> None:
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "agent_did": did,
                **metadata,
            }
            stream.publish(event)
            # Forward to the central audit trail, SIGNED. Ingest used to be
            # unauthenticated, which made an event's agent_did a claim rather
            # than a fact -- and the audit trail forgeable by anyone who could
            # reach the port. The agent now proves control of the DID it writes
            # under, with the same key and the same control-plane proof it uses
            # for a heartbeat, so an event is attributable to the process that
            # actually produced it.
            path = "/api/v1/audit/events"
            try:
                payload = canonical_body(event)
                headers = control_plane_headers(
                    Signer(keystore), principal_did=did, kid=handle.kid,
                    method="POST", path=path, body=payload,
                )
                headers["Content-Type"] = "application/json"
                await iam.post(path, content=payload, headers=headers, timeout=3.0)
            except httpx.HTTPError:
                log.warning("audit_forward_failed", event_type=event_type)

        # The wallet holds credentials issued ABOUT this agent, and signs
        # presentations with this agent's own key.
        wallet = CredentialWallet(
            iam=iam, holder_did=did, holder_kid=handle.kid, signer=Signer(keystore)
        )
        state["runtime"] = AgentRuntime(
            identity=identity,
            llm=llm,
            system_prompt=definition.system_prompt,
            signer=Signer(keystore),
            event_sink=sink,
            wallet=wallet,
        )
        state["keystore"] = keystore
        state["wallet"] = wallet
        if state["registered"]:
            held = await wallet.refresh()
            log.info("wallet_loaded", did=did, credentials=len(held),
                     attested=wallet.attested_capabilities())

        # --- 5. announce ourselves to the Agent Naming Service -------------
        # The agent proves control of its DID by signing the registration with
        # the same key it already holds. Nothing new is minted.
        ans = ANSClient(
            base_url=config.ans_url,
            did=did,
            kid=handle.kid,
            signer=Signer(keystore),
            endpoint=config.public_url,
            capabilities=list(definition.capabilities),
            organization=settings.organization_did,
        )
        state["ans"] = ans
        registration = await ans.register()
        state["ans_registered"] = bool(registration.get("accepted"))
        if not state["ans_registered"]:
            log.error("ans_registration_failed", did=did,
                      reason=registration.get("reason"))

        stop = asyncio.Event()
        state["ans_stop"] = stop
        runtime_ref = state["runtime"]
        heartbeat_task = asyncio.create_task(
            ans.heartbeat_loop(
                stop,
                settings.ans_heartbeat_interval_seconds,
                load=lambda: getattr(runtime_ref, "tasks_in_flight", 0),
            )
        )
        state["ans_task"] = heartbeat_task

        # Coordinator agents get a planner that discovers through the ANS.
        if definition.agent_type.value == "COORDINATOR":
            state["coordinator"] = Coordinator(
                ans=ans, llm=llm, iam_client=iam, did=did
            )
        log.info(
            "agent_started", did=did, port=config.port, registered=state["registered"],
            llm_available=health.available,
        )
        try:
            yield
        finally:
            # Graceful shutdown: tell the ANS we are going away so no further
            # work is routed here, rather than waiting for the heartbeat to lapse.
            stop.set()
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            if state.get("ans_registered"):
                await ans.unregister("GRACEFUL_SHUTDOWN")
            await ans.aclose()
            await llm.aclose()
            await iam.aclose()

    app = FastAPI(
        title=f"{definition.name} ({did})",
        description=definition.purpose,
        version="0.2.0",
        lifespan=lifespan,
    )
    # A browser console must reach the agent directly: only the agent can
    # produce a holder proof, because only it has its own private key. The IAM
    # API cannot proxy that on its behalf.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def runtime() -> AgentRuntime:
        rt = state.get("runtime")
        if rt is None:
            raise HTTPException(503, "Agent runtime is not initialised")
        return rt

    @app.get("/health")
    async def health() -> dict[str, Any]:
        llm_health = state["llm_health"]
        rt = state.get("runtime")
        return {
            "agent": definition.name,
            "did": did,
            "status": "UP",
            "registered_with_iam": state["registered"],
            "registration_error": state["registration_error"],
            "llm": {
                "available": bool(llm_health and llm_health.available),
                "provider": llm_health.provider if llm_health else None,
                "model": llm_health.model if llm_health else None,
                "detail": llm_health.detail if llm_health else "not checked",
            },
            "runtime": rt.status() if rt else None,
            "credentials": (
                state["wallet"].status() if state.get("wallet") else None
            ),
            "ans": state["ans"].status() if state.get("ans") else None,
        }

    @app.get("/ready")
    async def ready() -> JSONResponse:
        llm_health = state["llm_health"]
        checks = {
            "runtime_initialised": state.get("runtime") is not None,
            "registered_with_iam": state["registered"],
            "registered_with_ans": bool(state.get("ans_registered")),
            "llm_available": bool(llm_health and llm_health.available),
        }
        ok = all(checks.values())
        return JSONResponse(
            status_code=200 if ok else 503,
            content={"ready": ok, "checks": checks,
                     "detail": None if ok else "Agent cannot accept tasks"},
        )

    @app.get("/identity")
    async def identity() -> dict[str, Any]:
        return runtime().identity.to_public_dict()

    @app.get("/did-document")
    async def did_document(request: Request) -> Any:
        """Resolved through the registry -- the same path a peer would take."""
        response = await request.app.state.iam.get(f"/api/v1/agents/did/{did}/did-document")
        if response.status_code != 200:
            raise HTTPException(response.status_code, response.text[:300])
        return response.json()

    @app.post("/task")
    async def task(body: TaskIn) -> dict[str, Any]:
        rt = runtime()
        llm_health = state["llm_health"]
        if not (llm_health and llm_health.available):
            raise HTTPException(
                503,
                f"LLM unavailable, refusing to fabricate a result: "
                f"{llm_health.detail if llm_health else 'not checked'}",
            )
        request = TaskRequest(
            instruction=body.instruction,
            task_id=body.task_id or TaskRequest(instruction="x").task_id,
            correlation_id=body.correlation_id,
            sender_did=body.sender_did,
            context=body.context,
            injected=body.injected,
        )
        result = await rt.execute_task(request)
        if result.status == "FAILED":
            raise HTTPException(502, result.error or "Task failed")
        return result.to_dict()

    @app.post("/sign")
    async def sign(body: SignIn) -> dict[str, Any]:
        rt = runtime()
        try:
            signature = Signer(state["keystore"]).sign(rt.identity.kid, body.message)
        except KeyStoreError as exc:
            raise HTTPException(500, str(exc)) from exc
        await rt.emit(EventType.SIGNATURE_CREATED, kid=rt.identity.kid)
        return {
            "did": did,
            "verification_method": rt.identity.kid,
            "algorithm": signature.algorithm,
            "message": body.message,
            "signature": signature.signature_b64,
        }

    @app.post("/verify")
    async def verify(body: VerifyIn) -> dict[str, Any]:
        rt = runtime()
        result = verify_signature(
            rt.identity.public_key_multibase, body.message, body.signature, rt.identity.kid
        )
        return {"valid": result.valid, "reason": result.reason,
                "verification_method": result.verification_method}

    @app.get("/credentials")
    async def credentials(refresh: bool = True) -> dict[str, Any]:
        """What this agent holds. Documents are public artefacts, meant to be shown."""
        wallet: CredentialWallet = state["wallet"]
        if refresh:
            await wallet.refresh()
        return {
            **wallet.status(),
            "credentials": [c.summary() for c in wallet.credentials],
        }

    @app.post("/present")
    async def present(body: PresentIn) -> dict[str, Any]:
        """Build a Verifiable Presentation signed with THIS agent's private key.

        The IAM API cannot do this on the agent's behalf: it does not hold this
        agent's private key. That is what makes the holder proof meaningful.
        """
        rt = runtime()
        wallet: CredentialWallet = state["wallet"]
        await wallet.refresh()
        selected = wallet.select(
            capability=body.capability,
            credential_type=body.credential_type,
            credential_ids=body.credential_ids,
        )
        if not selected:
            raise HTTPException(
                404,
                f"{did} holds no usable credential matching "
                f"capability={body.capability!r} type={body.credential_type!r}",
            )
        document = wallet.present(
            selected, challenge=body.challenge, domain=body.domain
        )
        await rt.emit(
            EventType.CREDENTIAL_PRESENTED,
            presentation_id=document["id"],
            credential_ids=[c.credential_id for c in selected],
            challenge=body.challenge,
        )
        return {"presentation_id": document["id"], "presentation": document}

    @app.post("/coordinate")
    async def coordinate(body: CoordinateIn) -> dict[str, Any]:
        """Find the right agent for a task, dynamically.

        There is no endpoint table in this process. The coordinator asks the
        ANS what capabilities exist, has the LLM pick one, asks the ANS who
        provides it, and verifies the answer against the identity authority
        before returning it.
        """
        planner: Coordinator | None = state.get("coordinator")
        if planner is None:
            raise HTTPException(
                400,
                f"{definition.name} is not a coordinator; only the coordinator "
                f"agent performs discovery.",
            )
        rt = runtime()
        await rt.emit(EventType.ANS_DISCOVERY_STARTED, task=body.task[:120],
                      capability=body.capability)
        try:
            outcome = await planner.coordinate(
                body.task,
                capability=body.capability,
                required_credentials=body.required_credentials,
                organization=body.organization,
                require_healthy_endpoint=body.require_healthy_endpoint,
            )
        except CoordinationError as exc:
            await rt.emit(EventType.COORDINATOR_DISCOVERY_FAILED, error=str(exc))
            raise HTTPException(422, str(exc)) from exc

        if outcome.capability:
            await rt.emit(EventType.COORDINATOR_CAPABILITY_RESOLVED,
                          capability=outcome.capability.capability,
                          rationale=outcome.capability.rationale)
        if outcome.selected and outcome.verified:
            await rt.emit(EventType.COORDINATOR_DISCOVERY_COMPLETE,
                          selected=outcome.selected["did"],
                          endpoint=outcome.selected["endpoint"])
        else:
            await rt.emit(EventType.COORDINATOR_DISCOVERY_FAILED,
                          reason=outcome.reason)
        return outcome.to_dict()

    @app.post("/a2a/send")
    async def a2a_send(body: A2ASendIn, request: Request) -> dict[str, Any]:
        """Sign a transaction and send it to another agent.

        THE PRIVATE KEY NEVER LEAVES THIS PROCESS. The IAM API cannot do this
        on the agent's behalf -- it does not hold this agent's key, which is
        exactly what makes the sender's signature meaningful.

        The endpoint is resolved through the ANS and then CROSS-CHECKED
        against the DID Document published by the identity authority, which
        the ANS does not control. A poisoned directory therefore sends the
        instruction nowhere useful rather than to an attacker: the envelope
        names its receiver, and only that receiver holds the key needed to
        submit it.
        """
        import httpx as _httpx

        from app.protocols.a2a.client import build_signed_transaction

        rt = runtime()
        endpoint = body.receiver_endpoint
        if endpoint is None:
            client: ANSClient | None = state.get("ans")
            if client is None:
                raise HTTPException(503, "ANS client is not initialised")
            try:
                resolved = await client.resolve(body.receiver_did)
            except _httpx.HTTPError as exc:
                raise HTTPException(
                    502, f"cannot resolve {body.receiver_did}: {exc}") from exc
            endpoint = resolved.get("endpoint")
            published = [
                service.get("serviceEndpoint")
                for service in (resolved.get("did_document") or {}).get("service", [])
            ]
            if not endpoint or endpoint.rstrip("/") not in [
                (p or "").rstrip("/") for p in published
            ]:
                # ANS is a DIRECTORY, not a trust anchor. Refused rather than
                # trusted: this is the endpoint-substitution attack.
                raise HTTPException(
                    502,
                    f"the ANS endpoint for {body.receiver_did} is not published "
                    f"in its DID Document; refusing to send an instruction to "
                    f"an endpoint the identity authority does not vouch for",
                )

        envelope = build_signed_transaction(
            Signer(state["keystore"]),
            sender_did=did, sender_kid=rt.identity.kid,
            receiver_did=body.receiver_did,
            action=body.action, resource_type=body.resource_type,
            resource_id=body.resource_id, purpose=body.purpose,
            domain=get_settings().a2a_domain,
            payload=body.payload, amount_inr=body.amount_inr,
            currency=body.currency, transaction_id=body.transaction_id,
            ttl_seconds=body.ttl_seconds, correlation_id=body.correlation_id,
            credential_ids=body.credentials,
        )
        await rt.emit(EventType.A2A_REQUEST,
                      transaction_id=envelope["transactionId"],
                      receiver=body.receiver_did, action=body.action,
                      resource_id=body.resource_id)

        async with _httpx.AsyncClient(timeout=60.0) as http:
            try:
                response = await http.post(f"{endpoint.rstrip('/')}/a2a/inbound",
                                           json={"envelope": envelope})
            except _httpx.HTTPError as exc:
                # A timeout is UNKNOWN, never a denial and never a success.
                # The caller must retry the SAME transaction id, which the
                # idempotency model makes safe.
                raise HTTPException(
                    504,
                    f"no answer from {body.receiver_did}: {exc}. The outcome is "
                    f"UNKNOWN -- retry transaction {envelope['transactionId']} "
                    f"rather than issuing a new one.",
                ) from exc

        answer = response.json() if response.content else {}
        await rt.emit(EventType.A2A_RESPONSE,
                      transaction_id=envelope["transactionId"],
                      status=answer.get("outcome", {}).get("status")
                      if isinstance(answer.get("outcome"), dict) else None)
        return {
            "transaction_id": envelope["transactionId"],
            "sent_to": body.receiver_did,
            "endpoint": endpoint,
            "envelope": envelope,
            "response": answer,
            "note": (
                "A signature is not authorization. The receiver relayed this "
                "to the IAM plane, which verified it and asked the PDP."
            ),
        }

    @app.post("/a2a/inbound")
    async def a2a_inbound(body: A2AInboundIn, request: Request) -> dict[str, Any]:
        """Receive a signed instruction, and relay it to the IAM plane.

        THIS AGENT DECIDES NOTHING. It has no PIP, no PDP and no database,
        and that is the correct shape: an agent must not be able to
        authorize what it was asked to do. Its one job is to prove it is the
        addressee -- which it does with a control-plane proof signed by its
        own key -- and to carry the envelope UNCHANGED.

        Relaying it unchanged is not a convention. Every field is inside the
        sender's signature, so a receiver that edited one would invalidate
        the instruction rather than widen it.
        """
        import httpx as _httpx

        from app.controlplane.client import canonical_body, control_plane_headers
        from app.protocols.a2a.client import build_signed_response

        rt = runtime()
        envelope = body.envelope
        await rt.emit(EventType.A2A_REQUEST,
                      transaction_id=envelope.get("transactionId"),
                      sender=envelope.get("senderDid"), inbound=True)

        path = "/api/v1/a2a/transactions"
        payload = canonical_body({"envelope": envelope})
        headers = control_plane_headers(
            Signer(state["keystore"]), principal_did=did, kid=rt.identity.kid,
            method="POST", path=path, body=payload,
        )
        headers["Content-Type"] = "application/json"

        iam: httpx.AsyncClient = request.app.state.iam
        try:
            response = await iam.post(path, content=payload, headers=headers,
                                      timeout=60.0)
        except _httpx.HTTPError as exc:
            raise HTTPException(502, f"the IAM plane is unreachable: {exc}") from exc

        outcome = response.json() if response.content else {}
        status = outcome.get("status") or "REJECTED"
        decision = (outcome.get("authorization") or {}).get("decision")
        reason = outcome.get("reason")

        await rt.emit(EventType.A2A_RESPONSE,
                      transaction_id=envelope.get("transactionId"),
                      status=status, reason=reason)

        # The answer is SIGNED. Without that a third party can fabricate
        # "your payment succeeded", and the sender has no way to tell.
        signed = build_signed_response(
            Signer(state["keystore"]), responder_did=did,
            responder_kid=rt.identity.kid,
            original_sender_did=envelope.get("senderDid") or "",
            transaction_id=envelope.get("transactionId") or "",
            status=status, decision=decision, reason=reason,
            policy=(outcome.get("authorization") or {}).get("policy"),
            authorization_request_id=(outcome.get("transaction") or {}).get(
                "authorization_request_id"),
            result_sha256=(outcome.get("transaction") or {}).get("result_sha256"),
            approval_id=(outcome.get("approval") or {}).get("approval_id")
            if isinstance(outcome.get("approval"), dict) else None,
            domain=get_settings().a2a_domain,
        )
        return {"outcome": outcome, "response": signed}

    @app.get("/ans")
    async def ans_status() -> dict[str, Any]:
        client: ANSClient | None = state.get("ans")
        if client is None:
            raise HTTPException(503, "ANS client is not initialised")
        return client.status()

    @app.get("/events/stream")
    async def events_stream() -> StreamingResponse:
        import json as _json

        async def generator() -> AsyncIterator[str]:
            for event in stream.recent[-20:]:
                yield f"data: {_json.dumps(event)}\n\n"
            async for event in stream.subscribe():
                yield f"data: {_json.dumps(event)}\n\n"

        return StreamingResponse(generator(), media_type="text/event-stream")

    return app


def main() -> None:  # pragma: no cover - process entrypoint
    import uvicorn

    config = AgentServiceConfig.from_env()
    uvicorn.run(
        create_agent_service(config), host=config.host, port=config.port, log_level="info"
    )


if __name__ == "__main__":  # pragma: no cover
    main()
