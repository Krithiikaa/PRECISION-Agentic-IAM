"""Operations-console aggregates: overview, verified service health, MCP activity.

    GET /api/v1/console/overview   counts across every subsystem, from the database
    GET /api/v1/console/health     each dependency PROBED now, with latency
    GET /api/v1/console/mcp        MCP sessions, invocations and the tool catalogue

All three are `audit_read` (AUDITOR, IAM_ADMIN, the identity administrator
machine principal) -- they summarise exactly what those roles may already read
piecemeal, and reveal the system's topology, so they are not public.

NOTHING HERE IS ASSUMED. A service is reported `up` only if a probe made during
this request succeeded; a count is a query result. Where a figure cannot be
produced (Redis unreachable, OPA down) the response says so with the error,
instead of a zero that would read as "all quiet".
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text

from app.api.deps import LLMDep, SessionDep, SettingsDep
from app.audit.service import AuditService
from app.controlplane.guard import ControlPlaneGuard, fixed
from app.db.models.a2a import A2ATransaction
from app.db.models.agent import Agent
from app.db.models.ans import ANSAgent
from app.db.models.authorization import AuthorizationDecisionRecord
from app.db.models.credential import Credential, CredentialStatus
from app.db.models.hitl import ApprovalRequest
from app.db.models.jit import JITGrant, JITGrantStatus
from app.db.models.mcp import MCPInvocation, MCPSession, MCPSessionStatus
from app.db.models.security import (
    AgentSessionState,
    AgentTrust,
    AlertStatus,
    DetectorCursor,
    IncidentStatus,
    SecurityAlert,
    SecurityIncident,
    SessionState,
)

router = APIRouter(prefix="/api/v1/console", tags=["console"])

POLICY_DATA = Path(__file__).resolve().parents[4] / "policies" / "data" / "mcp_policy.json"


def _counts(rows) -> dict[str, int]:
    return {str(getattr(k, "value", k)): int(n) for k, n in rows}


@router.get("/overview", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=fixed("console_overview")))])
async def overview(session: SessionDep) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    day = now - timedelta(hours=24)
    q = session.execute

    agents = _counts((await q(select(Agent.status, func.count()).group_by(Agent.status))).all())
    delegated = (await q(select(func.count()).where(Agent.parent_agent_id.is_not(None)))).scalar_one()
    contained = (await q(select(func.count()).where(
        AgentSessionState.state == SessionState.TERMINATED_IMMEDIATE_SECURITY_LOCKOUT))).scalar_one()
    reduced = _counts((await q(select(AgentTrust.level, func.count())
                               .group_by(AgentTrust.level))).all())

    stored = _counts((await q(select(CredentialStatus.status, func.count())
                              .group_by(CredentialStatus.status))).all())
    lapsed = (await q(select(func.count()).select_from(Credential)
                      .join(CredentialStatus, CredentialStatus.credential_id == Credential.credential_id)
                      .where(CredentialStatus.status == "ACTIVE", Credential.expires_at <= now))).scalar_one()

    decisions = _counts((await q(select(AuthorizationDecisionRecord.decision, func.count())
                                 .where(AuthorizationDecisionRecord.decided_at >= day)
                                 .group_by(AuthorizationDecisionRecord.decision))).all())
    latency = (await q(select(func.avg(AuthorizationDecisionRecord.latency_ms))
                       .where(AuthorizationDecisionRecord.decided_at >= day))).scalar_one()

    jit_active = (await q(select(func.count()).where(
        JITGrant.status == JITGrantStatus.ACTIVE, JITGrant.expires_at > now))).scalar_one()
    approvals = _counts((await q(select(ApprovalRequest.status, func.count())
                                 .group_by(ApprovalRequest.status))).all())
    a2a = _counts((await q(select(A2ATransaction.status, func.count())
                           .group_by(A2ATransaction.status))).all())
    mcp_sessions = (await q(select(func.count()).where(
        MCPSession.status == MCPSessionStatus.ACTIVE))).scalar_one()
    mcp_calls = _counts((await q(select(MCPInvocation.status, func.count())
                                 .where(MCPInvocation.created_at >= day)
                                 .group_by(MCPInvocation.status))).all())
    alerts = _counts((await q(select(SecurityAlert.severity, func.count())
                              .where(SecurityAlert.status == AlertStatus.OPEN)
                              .group_by(SecurityAlert.severity))).all())
    incidents_open = (await q(select(func.count()).where(
        SecurityIncident.status == IncidentStatus.CONTAINED))).scalar_one()

    from app.db.models.loan import LoanWorkflowRecord
    workflows = _counts((await q(select(LoanWorkflowRecord.status, func.count())
                                 .group_by(LoanWorkflowRecord.status))).all())

    return {
        "generated_at": now.isoformat(),
        "agents": {"by_status": agents, "delegated": delegated, "contained": contained,
                   "trust_levels_recorded": reduced},
        "credentials": {"by_stored_status": stored, "active_but_lapsed": lapsed},
        "authorization_24h": {"by_decision": decisions,
                              "mean_latency_ms": round(latency, 1) if latency else None},
        "jit": {"active": jit_active},
        "approvals": {"by_status": approvals},
        "a2a": {"by_status": a2a},
        "mcp": {"active_sessions": mcp_sessions, "invocations_24h": mcp_calls},
        "security": {"open_alerts_by_severity": alerts, "open_incidents": incidents_open},
        "loan_workflows": {"by_status": workflows,
                           "note": "SIMULATED loan management system; state durable in PostgreSQL"},
        "recent_audit": await AuditService(session).query(limit=12),
    }


async def _probe(name: str, fn) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        detail = await fn()
        ok = bool(detail.pop("_ok", True)) if isinstance(detail, dict) else True
    except Exception as exc:  # noqa: BLE001 - reported, never hidden
        ok, detail = False, {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    return {"service": name, "up": ok,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            **(detail if isinstance(detail, dict) else {})}


@router.get("/health", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=fixed("console_health")))])
async def health(session: SessionDep, settings: SettingsDep, llm: LLMDep) -> dict[str, Any]:
    from app.authorization.opa import OPAClient
    from app.humans.oidc import OIDCValidator

    async def postgres():
        await session.execute(text("SELECT 1"))
        return {"detail": "SELECT 1 succeeded"}

    async def opa():
        client = OPAClient(settings)
        try:
            h = await client.health()
        finally:
            await client.aclose()
        return {"_ok": h.get("available", False), "detail": h.get("detail"), "url": h.get("url")}

    async def keycloak():
        h = await OIDCValidator(settings).provider_health()
        return {"_ok": bool(h.get("available") and h.get("issuer_matches_configuration")),
                "detail": h.get("detail"), "issuer": h.get("issuer")}

    async def redis():
        import redis.asyncio as aioredis
        client = aioredis.from_url(settings.redis_url, socket_timeout=2, socket_connect_timeout=2)
        try:
            pong = await client.ping()
        finally:
            await client.aclose()
        return {"_ok": bool(pong), "detail": "PING ok; used by rate limiting and the SSS push"}

    async def ans():
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(f"{settings.ans_base_url}/health")
        return {"_ok": r.status_code == 200, "detail": f"HTTP {r.status_code}",
                "url": settings.ans_base_url}

    async def agents():
        rows = (await session.execute(select(ANSAgent.did, ANSAgent.status, ANSAgent.last_seen))).all()
        total: dict[str, int] = {}
        for k in [r.status.value for r in rows]:
            total[k] = total.get(k, 0) + 1
        return {"_ok": total.get("ACTIVE", 0) > 0, "detail": "ANS registry statuses",
                "by_status": total}

    async def mcp():
        live = (await session.execute(select(func.count()).where(
            MCPSession.status == MCPSessionStatus.ACTIVE))).scalar_one()
        return {"detail": "gateway served in-process by this API; session ledger readable",
                "resource_uri": settings.mcp_resource_uri, "active_sessions": live}

    async def a2a():
        client = OPAClient(settings)
        try:
            loaded = await client.get_data("agentic_iam/config/a2a") is not None
        finally:
            await client.aclose()
        return {"_ok": loaded, "detail": "A2A policy configuration loaded in OPA"
                if loaded else "A2A policy configuration ABSENT: every payment denies"}

    async def detector():
        if not settings.anomaly_detector_enabled:
            return {"_ok": False, "detail": "DISABLED by configuration (gate profile)"}
        row = (await session.execute(select(DetectorCursor))).scalars().first()
        if row is None or row.updated_at is None:
            return {"_ok": False, "detail": "no cursor yet"}
        age = (datetime.now(timezone.utc) - row.updated_at).total_seconds()
        return {"_ok": age < max(30, settings.anomaly_poll_seconds * 10),
                "detail": f"cursor advanced {int(age)}s ago (seq {row.last_seq})"}

    async def llm_probe():
        h = await llm.health()
        return {"_ok": h.available, "detail": h.detail, "model": h.model}

    checks = [await _probe(n, f) for n, f in (
        ("PostgreSQL", postgres), ("OPA / Rego", opa), ("Keycloak / OIDC", keycloak),
        ("Redis", redis), ("Agent Naming Service", ans), ("Agent runtimes", agents),
        ("MCP gateway", mcp), ("A2A", a2a), ("Anomaly detector", detector),
        ("LLM (Ollama)", llm_probe))]
    return {"checked_at": datetime.now(timezone.utc).isoformat(), "services": checks,
            "not_present": ["metrics/log aggregation (Prometheus, SIEM): not deployed"]}


@router.get("/mcp", dependencies=[Depends(
    ControlPlaneGuard("audit_read", target=fixed("mcp_activity")))])
async def mcp_activity(session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
    from app.enforcement.tools import build_default_registry

    eligible = set(json.loads(POLICY_DATA.read_text()).get("eligible_actions", []))
    sessions = (await session.execute(
        select(MCPSession).order_by(MCPSession.created_at.desc()).limit(50))).scalars().all()
    calls = (await session.execute(
        select(MCPInvocation).order_by(MCPInvocation.created_at.desc()).limit(100))).scalars().all()
    return {
        "resource_uri": settings.mcp_resource_uri,
        "note": "tools/list is discovery, never permission: every tools/call is "
                "decided by the PDP on the caller's own credentials",
        "tools": [{**t, "mcp_eligible": t["action"] in eligible}
                  for t in build_default_registry().describe()],
        "sessions": [{"session_id": s.session_id, "agent_did": s.agent_did,
                      "status": s.status.value, "client": s.client_name,
                      "protocol_version": s.protocol_version,
                      "created_at": s.created_at.isoformat(),
                      "last_activity_at": s.last_activity_at.isoformat()
                      if s.last_activity_at else None,
                      "termination_reason": s.termination_reason} for s in sessions],
        "invocations": [{"request_id": c.request_id, "agent_did": c.agent_did,
                         "tool": c.tool_name, "purpose": c.claimed_purpose,
                         "status": c.status.value, "decision": c.decision,
                         "reason": c.decision_reason or c.reason,
                         "policy": f"{c.policy_id}:{c.policy_version}" if c.policy_id else None,
                         "created_at": c.created_at.isoformat()} for c in calls],
    }
