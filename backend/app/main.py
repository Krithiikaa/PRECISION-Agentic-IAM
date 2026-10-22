"""Agentic IAM API - Phase 1 (identity plane).

Implemented here today: agent registry, DID assignment, Ed25519 key custody,
DID Document publication, signing/verification, audit trail, live event stream.

Phase 2 adds the credential plane: issuer identities, signed Verifiable
Credentials, independent verification, status/revocation and presentations
with holder proof.

Phase 4 adds the authorization plane: PIP context collection, a PDP backed by a
real OPA runtime evaluating Rego, PAP policy lifecycle, and the AEM enforcement
boundary in front of protected tools. Phase 4.5 authenticates the control plane.

Phase 5 adds human-in-the-loop authorization: real OIDC human identity via
Keycloak, an approval request a person can actually judge, a signed and bound
single-use approval artifact, and PDP RE-EVALUATION -- a human decision is
evidence policy weighs, never an ALLOW on its own.

Phase 6 adds just-in-time temporary access: signed, time- and use-bounded
mandates that are an INPUT to authorization and never a substitute for one.

Phase 7 adds secure agent-to-agent transactions: a canonical signed envelope,
receiver binding enforced cryptographically AND by authentication, exactly-once
execution arbitrated by the database, and four-way amount reconciliation. A
valid signature is never authorization -- every transaction reaches the PDP.

Not implemented yet, and not pretended to be: MCP (8), sessions (9),
anomaly/trust (10), kill switch (11). See docs/PHASE_STATUS.md.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.deps import get_keystore, get_llm_provider
from app.api.errors import install_error_handlers
from app.api.routes import (
    a2a,
    agents,
    audit,
    authorization,
    credentials,
    events,
    health,
    hitl,
    identity,
    jit,
    loans,
)
from app.core.config import DEV_MASTER_KEY, get_settings
from app.core.errors import ConflictError, IdentityError, KeyStoreError, NotFoundError
from app.core.logging import configure_logging, get_logger
from app.authorization.pap import PolicyAdministrationPoint
from app.controlplane.principals import ControlPlanePrincipalRegistry
from app.hitl.authority import ApprovalAuthority
from app.jit.authority import JITAuthority
from app.humans.oidc import OIDCValidator
from app.credentials.issuer_registry import IssuerRegistry
from app.db.database import session_scope

log = get_logger("api")


async def _policy_reconciler(stop: asyncio.Event, interval: int = 15) -> None:
    """Keep OPA's policy set in step with the manifest.

    OPA holds policy in memory, so an OPA restart leaves it with nothing loaded
    and -- correctly, but unhelpfully -- denying everything. This restores the
    set instead of requiring an operator to notice. It never relaxes anything:
    it only ever loads policy that the manifest already declares ACTIVE.
    """
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            return
        except asyncio.TimeoutError:
            pass
        try:
            async with session_scope() as session:
                outcome = await PolicyAdministrationPoint(session).reconcile()
            if outcome.get("reconciled"):
                log.warning("policy_set_restored", **outcome)
        except Exception as exc:  # noqa: BLE001 - must not kill the loop
            log.error("policy_reconcile_failed", error=f"{type(exc).__name__}: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)

    keystore = get_keystore()
    log.info("keystore_ready", backend=keystore.backend_name, directory=settings.keystore_dir)
    if settings.keystore_master_key == DEV_MASTER_KEY:
        if settings.is_production:
            raise RuntimeError(
                "Refusing to start in production with the development master key"
            )
        # LOUD IN DEVELOPMENT TOO. The development key is published in this
        # repository, so every keystore encrypted under it is readable by
        # anyone who has the repository. That is fine for synthetic demo
        # material and catastrophic for anything else -- and the difference
        # is easy to forget once the system has been running for a while.
        log.warning(
            "development_master_key_in_use",
            detail="key material is encrypted under the PUBLISHED development "
                   "key and is readable by anyone with this repository",
            remedy="set KEYSTORE_MASTER_KEY to a generated value before "
                   "storing anything that is not synthetic",
        )

    # Credential issuers must exist before any credential can be verified: the
    # verifier resolves the issuer's public key from this registry. Idempotent.
    try:
        async with session_scope() as session:
            issuers = await IssuerRegistry(session, keystore, settings).ensure_configured_issuers()
        log.info("issuers_ready", issuers=[i.did for i in issuers])
    except Exception as exc:  # noqa: BLE001
        # Non-fatal: the identity plane still works and /health reports the fault.
        log.error("issuer_bootstrap_failed", error=f"{type(exc).__name__}: {exc}")

    # Phase 4.5: control-plane administrators must exist before anything can
    # authenticate against them. Idempotent, and roles are reconciled from
    # configuration on every start so revoking a privilege does not require a
    # database edit. A failure here is FATAL, unlike the issuer bootstrap: the
    # issuer registry failing degrades credential issuance, but a missing
    # administrator registry means every administrative operation would be
    # refused with "principal unknown" -- safe, but silently unoperable, and an
    # operator would spend a long time hunting the wrong problem.
    async with session_scope() as session:
        principals = await ControlPlanePrincipalRegistry(
            session, keystore, settings
        ).ensure_configured_principals()
    log.info("control_plane_principals_ready",
             principals={p.did: list(p.roles) for p in principals})

    # Phase 5: the approval authority must exist before any approval can be
    # signed OR VERIFIED. Fatal for the same reason the principal registry is:
    # without it every escalated action stays blocked forever, safely but
    # silently, and an operator would hunt the wrong problem.
    async with session_scope() as session:
        authority = await ApprovalAuthority(session, keystore, settings).ensure()
    log.info("approval_authority_ready", did=authority.did, kid=authority.kid)

    # Phase 6: the JIT authority must exist before any mandate can be signed OR
    # VERIFIED. Fatal for the same reason the approval authority is -- without
    # it every presented mandate would fail as JIT_AUTHORITY_UNKNOWN, safely
    # but silently, and an operator would hunt the wrong problem.
    #
    # A SEPARATE key from the approval authority, deliberately: attesting that
    # a human decided something and minting temporary machine authority are
    # different powers, and sharing a key would mean compromising it yields
    # both.
    async with session_scope() as session:
        jit_authority = await JITAuthority(session, keystore, settings).ensure()
    log.info("jit_authority_ready", did=jit_authority.did, kid=jit_authority.kid)

    # The identity provider is checked but NOT required to start. A Keycloak
    # outage means no human can approve anything, so escalated actions stay
    # blocked -- which is the correct behaviour, not a reason to refuse to
    # serve the rest of the system.
    identity_provider = await OIDCValidator(settings).provider_health()
    if identity_provider["available"] and identity_provider["issuer_matches_configuration"]:
        log.info("identity_provider_ready", issuer=identity_provider["issuer"])
    elif identity_provider["available"]:
        log.error(
            "identity_provider_issuer_mismatch",
            configured=settings.keycloak_issuer,
            advertised=identity_provider["issuer"],
            consequence="every human token will be refused as ISSUER_INVALID",
        )
    else:
        log.error(
            "identity_provider_unavailable",
            url=identity_provider["url"], detail=identity_provider["detail"],
            consequence="no human can authenticate; escalated actions stay BLOCKED",
        )

    # Phase 4: load the policy set into OPA. A failure here is LOUD but
    # non-fatal, because failing to load policy is not the same as failing
    # safe -- the PDP already denies when OPA has no decision, so an unloaded
    # policy set means everything is refused rather than everything permitted.
    # /api/v1/authorize/health reports the real state.
    try:
        async with session_scope() as session:
            loaded = await PolicyAdministrationPoint(session, settings).load_all()
        log.info("policies_ready", **loaded)
    except Exception as exc:  # noqa: BLE001
        log.error(
            "policy_load_failed",
            error=f"{type(exc).__name__}: {exc}",
            consequence="authorization will DENY until policy loads",
        )

    # Startup validation of the LLM. A failure is loud but non-fatal: the
    # identity plane still works, and /health reports exactly what is wrong.
    llm = get_llm_provider()
    llm_health = await llm.health()
    if llm_health.available:
        log.info("llm_ready", provider=llm_health.provider, model=llm_health.model)
    else:
        log.error(
            "llm_unavailable", provider=llm_health.provider, model=llm_health.model,
            base_url=llm_health.base_url, detail=llm_health.detail,
        )
    stop = asyncio.Event()
    reconciler = asyncio.create_task(_policy_reconciler(stop))
    try:
        yield
    finally:
        stop.set()
        reconciler.cancel()
        await asyncio.gather(reconciler, return_exceptions=True)
        await llm.aclose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Agentic AI IAM - POC",
        description=__doc__,
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    install_error_handlers(app)

    app.include_router(health.router)
    app.include_router(agents.router)
    app.include_router(identity.router)
    app.include_router(credentials.router)
    app.include_router(audit.router)
    app.include_router(events.router)
    app.include_router(authorization.router)
    app.include_router(hitl.router)
    app.include_router(loans.router)
    app.include_router(jit.router)
    app.include_router(a2a.router)
    return app


app = create_app()
