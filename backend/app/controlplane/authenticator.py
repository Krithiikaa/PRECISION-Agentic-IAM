"""Control-plane AUTHENTICATION: who is calling?

This module answers exactly one question and refuses to answer any other. It
does not decide whether the caller may do the thing -- that is the PDP, and
keeping the two apart is the whole point of the layering:

    AUTHENTICATION   proves an identity        (here)
    AUTHORIZATION    grants an operation       (PDP -> OPA -> Rego)

TWO KINDS OF CALLER, one question. Phase 4.5 authenticated machines with an
Ed25519 proof of DID control. Phase 5 adds PEOPLE, who hold no key and prove
themselves with an OIDC token from Keycloak instead. Both paths end at the same
place -- a principal with a type and (for administrators and humans) roles --
so a single set of Rego rules covers both, and `principal.type` distinguishes
them where it matters.

    Authorization: Bearer <OIDC access token>   -> type "human"
    X-CP-* signed proof headers                 -> type "agent" | "administrator"

A caller presenting BOTH is refused rather than silently resolved one way: an
ambiguous principal is not a principal.

There is no rule in this file of the form "principal X may do Y". If one ever
appears here, policy has leaked out of OPA and into middleware, where nobody
will review it.

CHECK ORDER, which is itself a security property:

    1. headers present            -> 401, the caller did not even try
    2. payload well formed        -> 401
    3. principal resolves         -> 403
    4. principal eligible         -> 403
    5. body digest matches        -> 403   (before the signature: cheap, and
                                            proves the signed bytes are these)
    6. timestamp fresh            -> 403
    7. nonce unused               -> 403
    8. SIGNATURE VERIFIES         -> 403
    9. nonce consumed (atomically)

The signature is verified BEFORE the nonce is consumed, so an attacker cannot
burn a legitimate agent's nonces by replaying captured values with garbage
signatures. The consumption itself is a DATABASE unique index, not a
read-then-write in Python, so two concurrent presentations of the same nonce
cannot both succeed.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.controlplane.proof import (
    HEADER_KEY_ID,
    HEADER_NONCE,
    HEADER_PRINCIPAL,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    REQUIRED_HEADERS,
    AuthReason,
    ControlPlanePayload,
    body_digest,
    timestamp_is_fresh,
)
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.models.agent import AgentStatus
from app.db.models.controlplane import ControlPlaneProof, PrincipalStatus
from app.db.models.hitl import HumanStatus
from app.db.repositories.agents import AgentRepository
from app.humans.oidc import HumanIdentity, OIDCReason, OIDCValidator, TokenInvalid, bearer_token
from app.humans.principals import HumanPrincipalRegistry
from app.identity.did import is_administrator_did, is_agent_did
from app.identity.did_document import public_key_from_document
from app.identity.signer import verify_signature
from app.monitoring.events import Event, EventType

log = get_logger("controlplane.auth")

# Identity states that make an agent unable to speak to the control plane at
# all. A terminated agent must not be able to keep itself alive in discovery.
INELIGIBLE_AGENT_STATES = (AgentStatus.TERMINATED, AgentStatus.SUSPENDED)


@dataclass(frozen=True)
class ControlPlanePrincipalView:
    """An AUTHENTICATED principal. Never constructed on a failed proof.

    `roles` is what the REGISTRY granted (administrators) or what the validated
    TOKEN carried (humans) -- never what the caller claimed. There is no field
    here a request body can populate.
    """

    did: str
    type: str                       # "agent" | "administrator" | "human"
    roles: tuple[str, ...] = ()
    name: str | None = None
    status: str | None = None
    verification_method: str | None = None
    # Populated for humans only: who Keycloak said this is.
    subject: str | None = None
    issuer: str | None = None
    username: str | None = None

    @property
    def is_human(self) -> bool:
        return self.type == "human"

    @property
    def principal_urn(self) -> str:
        return self.did

    def to_dict(self) -> dict[str, Any]:
        document = {
            "did": self.did,
            "type": self.type,
            "roles": sorted(self.roles),
            "status": self.status,
            "authenticated": True,
        }
        if self.is_human:
            document.update({
                "subject": self.subject,
                "issuer": self.issuer,
                "username": self.username,
            })
        return document


@dataclass
class AuthenticationResult:
    authenticated: bool
    reason: str
    detail: str
    # 401 means "you did not authenticate"; 403 means "you did, badly, or you
    # are not eligible". Kept distinct because they tell an operator different
    # things: 401 is usually a misconfigured client, 403 is usually an attack
    # or a revoked identity.
    http_status: int = 403
    principal: ControlPlanePrincipalView | None = None
    checks: list[dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "authenticated": self.authenticated,
            "reason": self.reason,
            "detail": self.detail,
            "principal": self.principal.to_dict() if self.principal else None,
            "checks": self.checks,
            "latency_ms": round(self.latency_ms, 2),
        }


class ControlPlaneAuthenticator:
    def __init__(
        self,
        session: AsyncSession,
        settings: Settings | None = None,
        oidc: OIDCValidator | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.agents = AgentRepository(session)
        self.audit = AuditService(session)
        self.oidc = oidc or OIDCValidator(self.settings)
        self.humans = HumanPrincipalRegistry(session)

    async def authenticate(
        self,
        *,
        headers: dict[str, str],
        method: str,
        path: str,
        body: bytes,
        operation: str,
        target: str | None = None,
        source_ip: str | None = None,
        now: datetime | None = None,
    ) -> AuthenticationResult:
        now = now or datetime.now(timezone.utc)
        started = time.perf_counter()
        checks: list[dict[str, Any]] = []
        # Case-insensitive: HTTP header names are, and a client that sends
        # `x-cp-nonce` is not an attacker.
        lookup = {k.lower(): v for k, v in headers.items()}

        def check(name: str, passed: bool, detail: str) -> bool:
            checks.append({"name": name, "passed": passed, "detail": detail})
            return passed

        async def reject(
            reason: str, detail: str, *, http_status: int = 403,
            principal_did: str = "unknown", principal_type: str = "unknown",
            nonce: str = "", timestamp: str = "", signature: str = "",
            verification_method: str | None = None, stage: str = "authentication",
        ) -> AuthenticationResult:
            latency = (time.perf_counter() - started) * 1000
            await self._record(
                principal_did=principal_did, principal_type=principal_type,
                method=method, path=path, operation=operation, target=target,
                nonce=nonce, body_sha256=body_digest(body), timestamp=timestamp,
                signature=signature, verification_method=verification_method,
                accepted=False, stage=stage, reason=reason, detail=detail,
                source_ip=source_ip, latency_ms=latency, now=now,
            )
            await self.audit.record(
                Event(
                    EventType.CONTROL_PLANE_REJECTED,
                    agent_did=principal_did if principal_did != "unknown" else None,
                    resource="control_plane",
                    action=operation,
                    decision="REJECTED",
                    reason=reason,
                    metadata={
                        "detail": detail, "operation": operation, "target": target,
                        "method": method, "path": path, "http_status": http_status,
                        "principal_type": principal_type, "checks": checks,
                        "source_ip": source_ip, "stage": stage,
                    },
                )
            )
            log.warning("control_plane_rejected", operation=operation,
                        principal=principal_did, reason=reason, detail=detail)
            return AuthenticationResult(False, reason, detail, http_status,
                                        checks=checks, latency_ms=latency)

        # --- 0. which kind of caller is this? -----------------------------
        # A human proves identity with an OIDC token; a machine with a signed
        # DID proof. Presenting both is refused: an ambiguous principal is not
        # a principal, and silently preferring one would let a caller with a
        # weak credential of one kind hide behind a strong one of the other.
        token = bearer_token(headers)
        has_proof_headers = any(h.lower() in lookup for h in REQUIRED_HEADERS)
        if token and has_proof_headers:
            check("credential_kind", False,
                  "both an OIDC token and a signed control-plane proof were presented")
            return await reject(
                AuthReason.PROOF_MALFORMED,
                "present either an OIDC bearer token or a signed control-plane "
                "proof, not both",
                http_status=401, stage="credential_kind",
            )
        if token:
            return await self._authenticate_human(
                token=token, method=method, path=path, body=body,
                operation=operation, target=target, source_ip=source_ip,
                now=now, started=started, checks=checks, check=check, reject=reject,
            )

        # --- 1. is there a proof at all? ---------------------------------
        missing = [h for h in REQUIRED_HEADERS if h.lower() not in lookup]
        if missing:
            check("proof_present", False, f"missing header(s): {missing}")
            return await reject(
                AuthReason.PROOF_MISSING,
                f"This operation requires a signed control-plane proof. "
                f"Missing header(s): {', '.join(missing)}.",
                http_status=401, stage="proof_present",
            )
        check("proof_present", True, "all proof headers present")

        principal_did = lookup[HEADER_PRINCIPAL.lower()].strip()
        nonce = lookup[HEADER_NONCE.lower()].strip()
        timestamp = lookup[HEADER_TIMESTAMP.lower()].strip()
        signature = lookup[HEADER_SIGNATURE.lower()].strip()
        offered_kid = (lookup.get(HEADER_KEY_ID.lower()) or "").strip() or None

        # --- 2. shape ------------------------------------------------------
        if not principal_did or not nonce or not timestamp or not signature:
            check("proof_shape", False, "an empty proof header was supplied")
            return await reject(AuthReason.PROOF_MALFORMED,
                                "one or more proof headers is empty",
                                http_status=401, stage="proof_shape")
        if len(nonce) > 128 or len(signature) > 256 or len(timestamp) > 64:
            check("proof_shape", False, "a proof header exceeds its maximum length")
            return await reject(AuthReason.PROOF_MALFORMED,
                                "a proof header exceeds its maximum length",
                                http_status=401, stage="proof_shape",
                                principal_did=principal_did)
        check("proof_shape", True, "proof headers are well formed")

        # --- 3. resolve the principal and its PUBLIC key -------------------
        # The same trust path a third party would take: the public key comes
        # from the published DID Document, never from the request.
        resolution = await self._resolve(principal_did)
        if resolution.error is not None:
            check("principal_resolved", False, resolution.error[1])
            return await reject(resolution.error[0], resolution.error[1],
                                principal_did=principal_did,
                                principal_type=resolution.type,
                                nonce=nonce, timestamp=timestamp, signature=signature,
                                stage="principal_resolved")
        check("principal_resolved",
              True, f"{resolution.type} {principal_did} ({resolution.status})")

        verification_method = resolution.kid
        if offered_kid and offered_kid != verification_method:
            # A caller may TELL us which key it used; it does not get to choose
            # one. Resolution decides, and a mismatch is refused rather than
            # silently ignored.
            check("verification_method", False,
                  "the offered key id is not this principal's verification method")
            return await reject(
                AuthReason.SIGNATURE_INVALID,
                f"offered key id does not match the principal's verification method",
                principal_did=principal_did, principal_type=resolution.type,
                nonce=nonce, timestamp=timestamp, signature=signature,
                verification_method=verification_method, stage="verification_method",
            )
        check("verification_method", True, verification_method)

        # --- 4. the body must be the body that was signed -------------------
        digest = body_digest(body)
        payload = ControlPlanePayload(
            principal=principal_did, method=method, path=path,
            body_sha256=digest, nonce=nonce, timestamp=timestamp,
        )

        # --- 5. freshness ---------------------------------------------------
        ok, detail = timestamp_is_fresh(
            timestamp, now=now,
            window_seconds=self.settings.control_plane_freshness_seconds,
        )
        if not check("timestamp", ok, detail):
            return await reject(AuthReason.TIMESTAMP_STALE, detail,
                                principal_did=principal_did,
                                principal_type=resolution.type,
                                nonce=nonce, timestamp=timestamp, signature=signature,
                                verification_method=verification_method,
                                stage="timestamp")

        # --- 6. nonce not already spent -------------------------------------
        used = await self.session.execute(
            select(ControlPlaneProof.id).where(
                ControlPlaneProof.principal_did == principal_did,
                ControlPlaneProof.nonce == nonce,
                ControlPlaneProof.accepted.is_(True),
            )
        )
        if used.scalar_one_or_none() is not None:
            check("nonce", False, "this nonce has already been used")
            return await reject(AuthReason.NONCE_REPLAYED,
                                "this control-plane proof has already been presented",
                                principal_did=principal_did,
                                principal_type=resolution.type,
                                nonce=nonce, timestamp=timestamp, signature=signature,
                                verification_method=verification_method,
                                stage="nonce")
        check("nonce", True, "unused")

        # --- 7. the proof itself --------------------------------------------
        # Real Ed25519 over the canonical payload. A mismatch anywhere -- a
        # different body, a different path, a swapped DID, a forged signature --
        # lands here.
        result = verify_signature(resolution.public_key, payload.signing_bytes(),
                                  signature, verification_method)
        if not check("signature", result.valid,
                     "signature verifies against the DID Document"
                     if result.valid else result.reason):
            return await reject(AuthReason.SIGNATURE_INVALID, result.reason,
                                principal_did=principal_did,
                                principal_type=resolution.type,
                                nonce=nonce, timestamp=timestamp, signature=signature,
                                verification_method=verification_method,
                                stage="signature")

        # --- 8. consume the nonce -------------------------------------------
        latency = (time.perf_counter() - started) * 1000
        try:
            await self._record(
                principal_did=principal_did, principal_type=resolution.type,
                method=method, path=path, operation=operation, target=target,
                nonce=nonce, body_sha256=digest, timestamp=timestamp,
                signature=signature, verification_method=verification_method,
                accepted=True, stage="accepted", reason=AuthReason.VALID,
                detail="control-plane proof accepted", source_ip=source_ip,
                latency_ms=latency, now=now,
            )
        except IntegrityError:
            # Lost the race for this nonce. Fail closed: the other presentation
            # won, and this one is by definition a replay.
            await self.session.rollback()
            return await reject(AuthReason.NONCE_REPLAYED,
                                "this control-plane proof has already been presented",
                                principal_did=principal_did,
                                principal_type=resolution.type,
                                nonce=nonce, timestamp=timestamp, signature=signature,
                                verification_method=verification_method,
                                stage="nonce")

        principal = ControlPlanePrincipalView(
            did=principal_did, type=resolution.type, roles=resolution.roles,
            name=resolution.name, status=resolution.status,
            verification_method=verification_method,
        )
        await self.audit.record(
            Event(
                EventType.CONTROL_PLANE_AUTHENTICATED,
                agent_did=principal_did,
                resource="control_plane",
                action=operation,
                decision="AUTHENTICATED",
                reason=AuthReason.VALID,
                metadata={
                    "operation": operation, "target": target, "method": method,
                    "path": path, "principal_type": resolution.type,
                    "roles": sorted(resolution.roles), "source_ip": source_ip,
                    "latency_ms": round(latency, 2),
                },
            )
        )
        return AuthenticationResult(True, AuthReason.VALID,
                                    "control-plane proof accepted",
                                    200, principal, checks, latency)

    # --- human authentication (Phase 5) -----------------------------------
    async def _authenticate_human(
        self, *, token, method, path, body, operation, target, source_ip, now,
        started, checks, check, reject,
    ) -> AuthenticationResult:
        """Authenticate a person with an OIDC access token from Keycloak.

        There is no nonce and no replay ledger here, and that is deliberate
        rather than an omission. A machine proof is a single-use statement
        about ONE request; an OIDC token is a bounded-lifetime statement about
        an IDENTITY, and it is meant to be presented repeatedly. Replay
        protection lives where it belongs for humans: on the APPROVAL, which is
        single-use, bound to one action and consumed atomically. Requiring a
        fresh token per request would protect nothing and break every browser.
        """
        try:
            identity: HumanIdentity = self.oidc.validate(token)
        except TokenInvalid as exc:
            check("oidc_token", False, exc.detail)
            await self.audit.record(
                Event(
                    EventType.HUMAN_AUTHENTICATION_FAILED,
                    resource="control_plane", action=operation,
                    decision="REJECTED", reason=exc.reason,
                    # The reason CLASS only. Never the token, never which key
                    # was tried, never what the server expected instead.
                    metadata={"operation": operation, "source_ip": source_ip,
                              "provider": "keycloak-oidc"},
                )
            )
            # 401 for "we cannot tell who you are"; the provider being down is
            # also a 401, because we still cannot tell -- and it must never be
            # a reason to proceed.
            return await reject(exc.reason, exc.detail, http_status=401,
                                principal_type="human", stage="oidc_token")
        check("oidc_token", True,
              f"OIDC token valid for {identity.username or identity.subject} "
              f"from {identity.issuer}")

        principal_record = await self.humans.upsert(identity)
        if principal_record.status is not HumanStatus.ACTIVE:
            # The token is genuinely valid -- this person really is who they
            # say. They have been stood down locally, which is a different
            # thing from being unknown, and is reported as such.
            check("principal_eligible", False,
                  f"human principal is {principal_record.status.value}")
            return await reject(
                AuthReason.PRINCIPAL_NOT_ELIGIBLE,
                f"this human principal is {principal_record.status.value}",
                principal_did=identity.principal_urn, principal_type="human",
                stage="principal_eligible",
            )
        check("principal_eligible", True, principal_record.status.value)

        latency = (time.perf_counter() - started) * 1000
        # The proof ledger records human authentications too, so one query
        # answers "who addressed the control plane, machine or human?".
        #
        # `nonce` gets a FRESH per-request marker, not the token's `jti`. That
        # column carries a partial unique index enforcing single use, which is
        # exactly right for a machine proof about ONE request -- and exactly
        # wrong for a token, which is a bounded-lifetime statement about an
        # IDENTITY and is meant to be presented repeatedly. Writing the `jti`
        # here made the SECOND request with any token die on a constraint
        # violation. Human replay protection lives where it belongs: on the
        # APPROVAL, which is single-use and consumed atomically.
        #
        # The `jti` is still recorded, in `detail`, so a specific token can be
        # traced through the audit trail. It is an identifier, not a secret.
        await self._record(
            principal_did=identity.principal_urn, principal_type="human",
            method=method, path=path, operation=operation, target=target,
            nonce=f"oidc:{uuid.uuid4().hex}", body_sha256=body_digest(body),
            timestamp=str(identity.issued_at),
            # NEVER the token itself. A bearer token in the audit trail is a
            # credential in the audit trail.
            signature="[oidc-bearer-token-not-stored]",
            verification_method=f"{identity.issuer}#oidc",
            accepted=True, stage="accepted", reason=AuthReason.VALID,
            detail=f"OIDC token accepted (jti={identity.token_id})",
            source_ip=source_ip, latency_ms=latency, now=now,
        )

        principal = ControlPlanePrincipalView(
            did=identity.principal_urn,
            type="human",
            # Roles from THIS token, read fresh. Never from the stored row.
            roles=identity.roles,
            name=identity.display_name,
            status=principal_record.status.value,
            verification_method=f"{identity.issuer}#oidc",
            subject=identity.subject,
            issuer=identity.issuer,
            username=identity.username,
        )
        await self.audit.record(
            Event(
                EventType.HUMAN_AUTHENTICATED,
                request_id=None,
                resource="control_plane",
                action=operation,
                decision="AUTHENTICATED",
                reason=AuthReason.VALID,
                metadata={
                    "principal": identity.principal_urn,
                    "username": identity.username,
                    "issuer": identity.issuer,
                    "provider": identity.provider,
                    "roles": sorted(identity.roles),
                    "operation": operation,
                    "target": target,
                    "source_ip": source_ip,
                    "latency_ms": round(latency, 2),
                },
            )
        )
        return AuthenticationResult(True, AuthReason.VALID,
                                    "OIDC token accepted", 200,
                                    principal, checks, latency)

    # --- principal resolution ---------------------------------------------
    @dataclass
    class _Resolution:
        type: str = "unknown"
        public_key: str = ""
        kid: str = ""
        roles: tuple[str, ...] = ()
        name: str | None = None
        status: str | None = None
        error: tuple[str, str] | None = None

    async def _resolve(self, did: str) -> "_Resolution":
        """Resolve a DID to a public key, a kind and any granted roles.

        Agents resolve through the PHASE 1 registry; administrators through the
        control-plane principal registry. Neither path invents a key, and
        neither falls back to the other: a DID that is not an agent and not an
        administrator is simply unknown.
        """
        if is_agent_did(did):
            return await self._resolve_agent(did)
        if is_administrator_did(did):
            return await self._resolve_administrator(did)
        return self._Resolution(
            error=(AuthReason.PRINCIPAL_UNKNOWN,
                   f"{did!r} is not an agent or administrator DID"),
        )

    async def _resolve_agent(self, did: str) -> "_Resolution":
        identity = await self.agents.get_by_did(did)
        if identity is None:
            return self._Resolution(
                type="agent",
                error=(AuthReason.PRINCIPAL_UNKNOWN,
                       "the claimed identity is not registered"),
            )
        if identity.status in INELIGIBLE_AGENT_STATES:
            return self._Resolution(
                type="agent", status=identity.status.value,
                error=(AuthReason.PRINCIPAL_NOT_ELIGIBLE,
                       f"identity is {identity.status.value}"),
            )
        document = await self.agents.get_did_document(did)
        if document is None:
            return self._Resolution(
                type="agent", status=identity.status.value,
                error=(AuthReason.PRINCIPAL_NOT_RESOLVABLE,
                       "no DID Document is published for this identity"),
            )
        try:
            public_key = public_key_from_document(document.document)
            kid = document.document["verificationMethod"][0]["id"]
        except (ValueError, KeyError, IndexError) as exc:
            return self._Resolution(
                type="agent", status=identity.status.value,
                error=(AuthReason.PRINCIPAL_NOT_RESOLVABLE,
                       f"unusable DID Document: {exc}"),
            )
        # An agent NEVER carries control-plane roles. It can act for itself and
        # nothing more; there is no configuration that grants an agent
        # administrative privilege.
        return self._Resolution(
            type="agent", public_key=public_key, kid=kid, roles=(),
            name=identity.name, status=identity.status.value,
        )

    async def _resolve_administrator(self, did: str) -> "_Resolution":
        from app.db.models.controlplane import ControlPlanePrincipal

        result = await self.session.execute(
            select(ControlPlanePrincipal).where(ControlPlanePrincipal.did == did)
        )
        principal = result.scalar_one_or_none()
        if principal is None:
            return self._Resolution(
                type="administrator",
                error=(AuthReason.PRINCIPAL_UNKNOWN,
                       "the claimed administrator is not registered"),
            )
        if principal.status is not PrincipalStatus.ACTIVE:
            return self._Resolution(
                type="administrator", status=principal.status.value,
                error=(AuthReason.PRINCIPAL_NOT_ELIGIBLE,
                       f"administrator is {principal.status.value}"),
            )
        try:
            public_key = public_key_from_document(principal.did_document)
        except (ValueError, KeyError, IndexError) as exc:
            return self._Resolution(
                type="administrator", status=principal.status.value,
                error=(AuthReason.PRINCIPAL_NOT_RESOLVABLE,
                       f"unusable DID Document: {exc}"),
            )
        return self._Resolution(
            type="administrator", public_key=public_key, kid=principal.kid,
            roles=tuple(principal.roles or ()), name=principal.name,
            status=principal.status.value,
        )

    # --- persistence -------------------------------------------------------
    async def _record(self, **kw: Any) -> None:
        """Persist the proof attempt. Secrets are never written here.

        The signature is truncated to 256 characters: enough to correlate two
        presentations of the same proof, never enough to replay one. The
        request body is not stored at all -- only its digest.
        """
        now = kw.pop("now")
        self.session.add(
            ControlPlaneProof(
                principal_did=kw["principal_did"][:255],
                principal_type=kw["principal_type"],
                method=kw["method"][:8],
                path=kw["path"][:512],
                operation=kw["operation"][:64],
                target=(kw["target"] or None) and kw["target"][:255],
                nonce=kw["nonce"][:128],
                body_sha256=kw["body_sha256"],
                timestamp=kw["timestamp"][:64],
                signature=kw["signature"][:256],
                verification_method=kw["verification_method"],
                accepted=kw["accepted"],
                stage=kw["stage"][:32],
                reason=kw["reason"][:64],
                detail=kw["detail"],
                source_ip=kw["source_ip"],
                latency_ms=kw["latency_ms"],
                created_at=now,
            )
        )
        await self.session.flush()
