"""The Agent Naming Service process.

Runs as its own service on its own port, with its own lifecycle. It shares the
database and the identity/credential libraries with the IAM API -- it does not
reimplement DID resolution or credential verification, it calls them.

PHASE 4.5 -- S-4. Heartbeat, deregistration and the on-demand sweep now sit
behind the control-plane guard. Before this, liveness was whatever the first
caller said it was: anyone who could reach this port could POST a heartbeat
naming any DID and keep a dead agent in discovery, or send `status: OFFLINE`
and remove a healthy one. An agent must now prove control of the identity it
names, using the same Ed25519 key it already proved registration with.

Discovery and the registry reads stay OPEN, deliberately. Closing them would
break the coordinator without protecting anything mutable -- a discovery result
is a routing hint that the caller must still authenticate and authorize.

Background work it genuinely does:
  * sweeps for agents whose heartbeats stopped, demoting them STALE -> OFFLINE
  * mirrors upstream identity revocation into the registry
  * probes registered endpoints, so "registry says ACTIVE" and "the endpoint
    actually answers" are distinguishable
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    status as http_status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.ans.discovery import DiscoveryEngine, DiscoveryQuery
from app.ans.proof import RegistrationPayload
from app.ans.registry import ANSRegistry, describe_agent
from app.api.deps import KeyStoreDep, SessionDep, SettingsDep, get_keystore
from app.api.errors import install_error_handlers
from app.audit.service import AuditService
from app.controlplane.guard import ControlPlaneGuard, body_key, fixed, path_param
from app.core.config import get_settings
from app.core.errors import ConflictError, IdentityError, KeyStoreError, NotFoundError
from app.core.logging import configure_logging, get_logger
from app.db.database import session_scope
from app.db.models.ans import ANSStatus
from app.monitoring.events import Event, EventType

log = get_logger("ans.service")
router = APIRouter(prefix="/api/v1/ans", tags=["ans"])


# --- schemas ---------------------------------------------------------------
class RegisterRequest(BaseModel):
    """A registration is a signed statement, not a bare assertion."""

    did: str
    endpoint: str
    capabilities: list[str]
    organization: str | None = None
    nonce: str
    timestamp: str
    signature: str = Field(description="Ed25519 signature over the canonical payload")

    def to_payload(self) -> RegistrationPayload:
        return RegistrationPayload(
            did=self.did, endpoint=self.endpoint,
            capabilities=sorted(self.capabilities), organization=self.organization,
            nonce=self.nonce, timestamp=self.timestamp,
        )


class HeartbeatRequest(BaseModel):
    did: str
    status: ANSStatus = ANSStatus.ACTIVE
    endpoint: str | None = None
    active_tasks: int | None = Field(default=None, ge=0)
    timestamp: str | None = None


class DiscoverRequest(BaseModel):
    capability: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    required_credentials: list[str] = Field(default_factory=list)
    organization: str | None = None
    status: list[ANSStatus] | None = None
    purpose: str | None = None
    min_trust_score: int | None = None
    require_healthy_endpoint: bool = False
    requester_did: str | None = None
    limit: int = Field(default=20, ge=1, le=100)

    def to_query(self) -> DiscoveryQuery:
        return DiscoveryQuery(
            capability=self.capability, capabilities=self.capabilities,
            required_credentials=self.required_credentials,
            organization=self.organization, status=self.status, purpose=self.purpose,
            min_trust_score=self.min_trust_score,
            require_healthy_endpoint=self.require_healthy_endpoint,
            requester_did=self.requester_did, limit=self.limit,
        )


class UnregisterRequest(BaseModel):
    reason: str = "GRACEFUL_SHUTDOWN"


# --- routes ----------------------------------------------------------------
@router.post("/register", status_code=http_status.HTTP_201_CREATED)
async def register(body: RegisterRequest, request: Request, session: SessionDep) -> JSONResponse:
    """Register an agent. Requires proof of control of the DID being claimed."""
    result = await ANSRegistry(session).register(
        body.to_payload(), body.signature,
        source_ip=request.client.host if request.client else None,
    )
    # A rejected registration is a 403 with the failing check named -- an
    # answer, not a server error.
    return JSONResponse(status_code=201 if result.accepted else 403,
                        content=result.to_dict())


@router.post("/heartbeat", dependencies=[Depends(
    ControlPlaneGuard("ans_heartbeat", target=body_key("did")))])
async def heartbeat(body: HeartbeatRequest, session: SessionDep) -> dict[str, Any]:
    """Report liveness. The caller must have proved control of `did`.

    The guard binds the proof to the exact request body, so the `did` here is
    the `did` that was signed -- an attacker cannot sign for an identity it
    controls and then swap in another. Endpoint mutation remains impossible
    (the registry refuses it below): moving where traffic goes requires a fresh
    signed REGISTRATION, which is a different proof with a different purpose.
    """
    agent = await ANSRegistry(session).heartbeat(
        body.did, status=body.status, endpoint=body.endpoint,
        active_tasks=body.active_tasks,
    )
    await AuditService(session).record(
        Event(EventType.ANS_HEARTBEAT_ACCEPTED, agent_did=agent.did,
              resource="ans_registry", action="ans_heartbeat", decision="ACCEPTED",
              reason="AUTHENTICATED_SELF_HEARTBEAT",
              metadata={"status": agent.status.value,
                        "active_tasks": body.active_tasks})
    )
    return {"did": agent.did, "status": agent.status.value,
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None}


@router.post("/discover")
async def discover(
    body: DiscoverRequest, session: SessionDep, keystore: KeyStoreDep
) -> dict[str, Any]:
    """Find agents matching a query. Returns an empty result rather than guessing."""
    outcome = await DiscoveryEngine(session, keystore).discover(body.to_query())
    return outcome.to_dict()


@router.get("/resolve/{did}")
async def resolve(did: str, session: SessionDep) -> dict[str, Any]:
    return await ANSRegistry(session).resolve(did)


@router.get("/agents")
async def list_agents(
    session: SessionDep,
    agent_status: ANSStatus | None = None,
    capability: str | None = None,
) -> list[dict[str, Any]]:
    agents = await ANSRegistry(session).list_agents(
        status=agent_status, capability=capability
    )
    return [describe_agent(a) for a in agents]


@router.get("/capabilities")
async def capabilities(session: SessionDep) -> list[dict[str, Any]]:
    """The capability catalogue: what this network can actually do."""
    return await ANSRegistry(session).capability_catalogue()


@router.get("/agents/{did}/health")
async def agent_health(did: str, session: SessionDep) -> dict[str, Any]:
    """Probe the agent's endpoint now. Registry claim vs observed reality."""
    return await ANSRegistry(session).probe(did)


@router.post("/unregister/{did}", dependencies=[Depends(
    ControlPlaneGuard("ans_deregister", target=path_param("did")))])
async def unregister(did: str, body: UnregisterRequest, session: SessionDep) -> dict[str, Any]:
    """Remove an agent from discovery.

    Permitted for the agent itself (a graceful shutdown) or for a principal
    holding `registry_admin` (an operator standing an agent down). Nobody else:
    unauthenticated deregistration is a one-request denial of service against
    any agent in the network.
    """
    agent = await ANSRegistry(session).unregister(did, body.reason)
    await AuditService(session).record(
        Event(EventType.ANS_DEREGISTRATION_ACCEPTED, agent_did=agent.did,
              resource="ans_registry", action="ans_deregister", decision="ACCEPTED",
              reason=body.reason, metadata={"status": agent.status.value})
    )
    return {"did": agent.did, "status": agent.status.value, "reason": body.reason}


@router.get("/discovery/{request_id}")
async def discovery_request(
    request_id: str, session: SessionDep, keystore: KeyStoreDep
) -> dict[str, Any]:
    record = await DiscoveryEngine(session, keystore).get_request(request_id)
    if record is None:
        raise NotFoundError(f"Unknown discovery request {request_id}")
    return record


@router.post("/sweep", dependencies=[Depends(
    ControlPlaneGuard("ans_sweep", target=fixed("ans_registry")))])
async def sweep(session: SessionDep) -> dict[str, Any]:
    """Run the liveness sweep on demand. The service also does this on a timer."""
    registry = ANSRegistry(session)
    moved = await registry.sweep()
    revoked = await registry.reconcile_identities()
    return {**moved, "revoked": revoked}


# --- background loop -------------------------------------------------------
async def _sweeper(stop: asyncio.Event) -> None:
    """Demote agents that stopped reporting; mirror identity revocations."""
    settings = get_settings()
    while not stop.is_set():
        try:
            async with session_scope() as session:
                registry = ANSRegistry(session, settings)
                moved = await registry.sweep()
                revoked = await registry.reconcile_identities()
            if moved["stale"] or moved["offline"] or revoked:
                log.info("ans_sweep", stale=moved["stale"], offline=moved["offline"],
                         revoked=revoked)
        except Exception as exc:  # noqa: BLE001 - a sweep failure must not kill the loop
            log.error("ans_sweep_failed", error=f"{type(exc).__name__}: {exc}")
        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.ans_sweep_interval_seconds)
        except asyncio.TimeoutError:
            continue


async def _prober(stop: asyncio.Event) -> None:
    """Probe registered endpoints so DEGRADED reflects reality, not a claim."""
    settings = get_settings()
    interval = max(settings.ans_heartbeat_interval_seconds * 2, 20)
    async with httpx.AsyncClient(
        timeout=settings.ans_health_probe_timeout_seconds
    ) as client:
        while not stop.is_set():
            try:
                async with session_scope() as session:
                    registry = ANSRegistry(session, settings)
                    for agent in await registry.list_agents():
                        if agent.status in (ANSStatus.OFFLINE, ANSStatus.REVOKED,
                                            ANSStatus.TERMINATED):
                            continue
                        await registry.probe(agent.did, client)
            except Exception as exc:  # noqa: BLE001
                log.error("ans_probe_failed", error=f"{type(exc).__name__}: {exc}")
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue


def create_ans_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    stop = asyncio.Event()
    tasks: list[asyncio.Task] = []

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        get_keystore()   # fail fast if key material is unusable
        tasks.append(asyncio.create_task(_sweeper(stop)))
        tasks.append(asyncio.create_task(_prober(stop)))
        log.info("ans_started", port=settings.ans_port,
                 heartbeat_interval=settings.ans_heartbeat_interval_seconds,
                 stale_after=settings.ans_agent_timeout_seconds,
                 offline_after=settings.ans_agent_offline_seconds)
        try:
            yield
        finally:
            stop.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    app = FastAPI(
        title="Agent Naming Service",
        description=(
            "Capability-aware agent discovery. ANS answers 'which agent should "
            "I contact?'. It does NOT answer 'is this request authorized?' -- "
            "that is the PDP in Phase 4."
        ),
        version="0.3.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:3000"],
        allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
    )

    install_error_handlers(app)

    @app.get("/health")
    async def health(session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
        try:
            await session.execute(text("SELECT 1"))
            database = {"available": True, "detail": "OK"}
        except Exception as exc:  # noqa: BLE001
            database = {"available": False, "detail": f"{type(exc).__name__}: {exc}"}
        registered = await ANSRegistry(session, settings).list_agents()
        by_status: dict[str, int] = {}
        for agent in registered:
            by_status[agent.status.value] = by_status.get(agent.status.value, 0) + 1
        return {
            "service": "agent-naming-service",
            "status": "UP",
            "phase": 3,
            "database": database,
            "registered_agents": len(registered),
            "agents_by_status": by_status,
            "config": {
                "heartbeat_interval_seconds": settings.ans_heartbeat_interval_seconds,
                "stale_after_seconds": settings.ans_agent_timeout_seconds,
                "offline_after_seconds": settings.ans_agent_offline_seconds,
            },
        }

    @app.get("/ready")
    async def ready(session: SessionDep) -> JSONResponse:
        try:
            await session.execute(text("SELECT 1"))
            return JSONResponse(status_code=200, content={"ready": True})
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(status_code=503,
                                content={"ready": False, "detail": str(exc)})

    app.include_router(router)
    return app


app = create_ans_app()


def main() -> None:  # pragma: no cover - process entrypoint
    import uvicorn

    settings = get_settings()
    uvicorn.run(create_ans_app(), host=settings.ans_host, port=settings.ans_port,
                log_level="info")


if __name__ == "__main__":  # pragma: no cover
    main()
