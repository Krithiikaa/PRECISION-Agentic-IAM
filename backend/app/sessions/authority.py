"""Cross-Protocol Session Authority (SA): the kill switch and its reversal.

CSA paper R-156 (SA: global session oversight, orchestration of global logout,
propagation of state changes), R-161 (global logout flow), R-214
(instantaneous global session invalidation), R-212 (surgical VC revocation),
R-213/R-215 (discovery stops returning the compromised DID), R-216
(forensics with blast radius) and R-235 (override justification and
mandatory post-incident review).

WHAT `contain()` DOES, in order, inside ONE database transaction:

    1. snapshot the impact (what the agent can reach right now)
    2. SSS ledger -> TERMINATED_IMMEDIATE_SECURITY_LOCKOUT     <- the control
    3. identity    -> SUSPENDED (keys kept: they are forensic evidence)
    4. JIT         -> every live mandate revoked
    5. MCP         -> every live session revoked
    5b. HITL       -> every PENDING or APPROVED-but-unspent approval CANCELLED
                      (Phase 12: a sign-off given before the compromise must
                      not be spendable after reinstatement)
    6. ANS         -> entry REVOKED, so discovery stops returning it now
    7. VCs         -> revoked ONLY if the operator asks (irreversible)
    8. children    -> every ACTIVE delegated sub-agent contained too
    9. alerts      -> OPEN alerts for the agent marked CONTAINED

Step 2 alone is sufficient for enforcement: the PIP reads the ledger inside
every decision and `security/session.rego` denies a locked-out subject.
Steps 3-8 are defence in depth AND fast failure: each protocol refuses at
its own boundary with a clear reason instead of carrying the request all the
way to a policy denial. None of them is a second authorization path -- each
reuses the revocation method its own module already exposes.

WHAT IT DELIBERATELY DOES NOT DO: touch any other agent. Containment is keyed
on one DID (plus its delegated children), and the report counts the active
agents left untouched, so "we stopped the compromised one without stopping
the bank" is a number in the response rather than a claim.

REINSTATEMENT is a separate, human-only act: a different principal from the
one who contained (separation of duties), a written review, and the agent
must re-register with the ANS using a fresh signed proof. Revoked VCs and
mandates stay revoked.

Phase 12 adds TRUST REVALIDATION before any state is changed. Reinstatement
is refused when the identity is terminated or expired, has no ACTIVE key, or
any delegation ancestor is still locked out or not ACTIVE -- otherwise a
cascade-contained child could be brought back while the parent whose
compromise caused the cascade is still contained.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.db.models.a2a import A2ATransaction
from app.db.models.agent import Agent, AgentStatus
from app.db.models.ans import ANSAgent, ANSStatus
from app.db.models.audit import AuditEvent
from app.db.models.credential import Credential, CredentialStatus, CredentialStatusValue
from app.db.models.hitl import ApprovalRequest, ApprovalStatus
from app.db.models.jit import JITGrant, JITGrantStatus
from app.db.models.mcp import MCPSession, MCPSessionStatus
from app.db.models.security import (
    AlertStatus,
    IncidentStatus,
    IncidentTrigger,
    SecurityAlert,
    SecurityIncident,
    SessionState,
    TrustSignal,
)
from app.identity.keys import KeyStore
from app.monitoring.events import Event, EventType
from app.sessions.sss import SessionChange, SessionStateSynchronizer
from app.trust.engine import TrustEngine

log = get_logger("sessions.authority")

# A delegation tree deeper than this is refused at spawn time (see
# app/agents/delegation.py), so a cascade can never need more.
MAX_CASCADE_DEPTH = 8
MIN_REVIEW_LENGTH = 20


class ReinstatementRefused(ConflictError):
    """A refused reinstatement, carrying the server's revalidation results.

    Still a ConflictError (HTTP 409, `CONFLICT`); the route adds the structured
    `revalidation` list so an operator sees which check failed instead of a
    sentence to parse. `revalidation` is None for refusals made before the
    checks run (wrong state, missing review, separation of duties).
    """

    def __init__(self, message: str, revalidation: list[dict[str, Any]] | None = None) -> None:
        super().__init__(message)
        self.revalidation = revalidation


@dataclass
class ContainmentReport:
    incident_id: str
    agent_did: str
    trigger: str
    contained_at: datetime
    containment_ms: float
    actions: dict[str, Any]
    impact: dict[str, Any]
    cascaded: list[str] = field(default_factory=list)
    unaffected_active_agents: int = 0
    changes: list[SessionChange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "agent_did": self.agent_did,
            "trigger": self.trigger,
            "contained_at": self.contained_at.isoformat(),
            "containment_ms": round(self.containment_ms, 2),
            "actions": self.actions,
            "impact": self.impact,
            "cascaded_to": self.cascaded,
            "unaffected_active_agents": self.unaffected_active_agents,
        }


class SessionAuthority:
    def __init__(
        self,
        session: AsyncSession,
        keystore: KeyStore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.keystore = keystore
        self.settings = settings or get_settings()
        self.sss = SessionStateSynchronizer(session, self.settings)
        self.trust = TrustEngine(session, self.settings)
        self.audit = AuditService(session)

    # ------------------------------------------------------------------ #
    # Impact analysis (paper R-216: forensics with context, blast radius)
    # ------------------------------------------------------------------ #
    async def impact(self, agent_did: str, *, window_hours: int = 24) -> dict[str, Any]:
        agent = await self._agent(agent_did)
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=window_hours)

        credentials = (await self.session.execute(
            select(Credential.credential_id, Credential.credential_type, Credential.claims)
            .join(CredentialStatus, CredentialStatus.credential_id == Credential.credential_id)
            .where(Credential.subject_did == agent_did,
                   CredentialStatus.status == CredentialStatusValue.ACTIVE,
                   Credential.expires_at > now)
        )).all()
        grants = (await self.session.execute(
            select(JITGrant.grant_id, JITGrant.action, JITGrant.resource_type, JITGrant.expires_at)
            .where(JITGrant.agent_did == agent_did, JITGrant.status == JITGrantStatus.ACTIVE)
        )).all()
        mcp_sessions = (await self.session.execute(
            select(func.count(MCPSession.id)).where(
                MCPSession.agent_did == agent_did,
                MCPSession.status == MCPSessionStatus.ACTIVE)
        )).scalar_one()
        approvals = (await self.session.execute(
            select(ApprovalRequest.approval_id, ApprovalRequest.action)
            .where(ApprovalRequest.agent_did == agent_did,
                   ApprovalRequest.status.in_([ApprovalStatus.PENDING, ApprovalStatus.APPROVED]))
        )).all()
        children = (await self.session.execute(
            select(Agent.did, Agent.status).where(Agent.parent_agent_id == agent.id)
        )).all()
        sent_to = (await self.session.execute(
            select(A2ATransaction.receiver_did, func.count())
            .where(A2ATransaction.sender_did == agent_did, A2ATransaction.created_at >= since)
            .group_by(A2ATransaction.receiver_did)
        )).all()
        received_from = (await self.session.execute(
            select(A2ATransaction.sender_did, func.count())
            .where(A2ATransaction.receiver_did == agent_did, A2ATransaction.created_at >= since)
            .group_by(A2ATransaction.sender_did)
        )).all()
        activity = (await self.session.execute(
            select(AuditEvent.event_type, func.count())
            .where(AuditEvent.agent_did == agent_did, AuditEvent.occurred_at >= since)
            .group_by(AuditEvent.event_type).order_by(func.count().desc()).limit(15)
        )).all()
        resources = (await self.session.execute(
            select(AuditEvent.resource, func.count())
            .where(AuditEvent.agent_did == agent_did, AuditEvent.occurred_at >= since,
                   AuditEvent.event_type == EventType.TOOL_EXECUTED)
            .group_by(AuditEvent.resource)
        )).all()
        ans = (await self.session.execute(
            select(ANSAgent.status, ANSAgent.endpoint).where(ANSAgent.did == agent_did)
        )).one_or_none()
        open_alerts = (await self.session.execute(
            select(SecurityAlert.alert_id, SecurityAlert.rule, SecurityAlert.severity)
            .where(SecurityAlert.agent_did == agent_did, SecurityAlert.status == AlertStatus.OPEN)
        )).all()
        trust = await self.trust.assess(agent_did)

        return {
            "agent": {
                "did": agent.did, "name": agent.name, "type": agent.agent_type.value,
                "status": agent.status.value, "owner": agent.owner,
                "controller": agent.controller_did,
                "parent": agent.parent.did if agent.parent else None,
                "capabilities": list(agent.capabilities or []),
            },
            "session": await self.sss.fact(agent_did),
            "trust": trust.to_fact(),
            "ans": {"status": ans.status.value, "endpoint": ans.endpoint} if ans else None,
            "reachable": {
                "active_credentials": [
                    {"credential_id": c.credential_id, "type": c.credential_type,
                     "capability": (c.claims or {}).get("capability"),
                     "resources": (c.claims or {}).get("allowed_resources")
                                  or (c.claims or {}).get("allowedResources")}
                    for c in credentials],
                "live_jit_grants": [
                    {"grant_id": g.grant_id, "action": g.action,
                     "resource_type": g.resource_type, "expires_at": g.expires_at.isoformat()}
                    for g in grants],
                "live_mcp_sessions": int(mcp_sessions),
                "open_approvals": [{"approval_id": a.approval_id, "action": a.action}
                                   for a in approvals],
                "delegated_children": [{"did": c.did, "status": c.status.value}
                                       for c in children],
            },
            "collaborators": {
                "window_hours": window_hours,
                "instructed": {d: n for d, n in sent_to},
                "instructed_by": {d: n for d, n in received_from},
            },
            "recent_activity": {t: n for t, n in activity},
            "resources_touched": {r: n for r, n in resources if r},
            "open_alerts": [{"alert_id": a.alert_id, "rule": a.rule,
                             "severity": a.severity.value} for a in open_alerts],
        }

    # ------------------------------------------------------------------ #
    # Containment (the kill switch)
    # ------------------------------------------------------------------ #
    async def contain(
        self,
        agent_did: str,
        *,
        justification: str,
        opened_by: str,
        trigger: IncidentTrigger = IncidentTrigger.MANUAL,
        alert_id: str | None = None,
        revoke_credentials: bool = False,
        _depth: int = 0,
    ) -> ContainmentReport:
        if not justification or len(justification.strip()) < 10:
            raise ValidationError("Containment needs a justification of at least 10 characters")
        started = time.perf_counter()
        now = datetime.now(timezone.utc)
        agent = await self._agent(agent_did)

        current = await self.sss.get(agent_did)
        if current and current.state == SessionState.TERMINATED_IMMEDIATE_SECURITY_LOCKOUT:
            raise ConflictError(
                f"{agent_did} is already contained under incident {current.incident_id}"
            )

        impact = await self.impact(agent_did)
        incident_id = f"inc-{now:%Y%m%d}-{secrets.token_hex(4)}"
        reason = f"SECURITY_LOCKOUT: {justification.strip()[:200]}"
        actions: dict[str, Any] = {}

        # 2. THE CONTROL. Everything after this is defence in depth.
        change = await self.sss.set_state(
            agent_did, SessionState.TERMINATED_IMMEDIATE_SECURITY_LOCKOUT,
            reason=reason, changed_by=opened_by, incident_id=incident_id, now=now)
        actions["session_state"] = {"state": change.state.value, "version": change.version}

        # 3. identity
        if agent.status == AgentStatus.ACTIVE:
            from app.agents.registry import AgentRegistry  # local: avoids an import cycle
            await AgentRegistry(self.session, self.keystore, self.settings).set_status(
                agent_did, AgentStatus.SUSPENDED, reason=f"incident {incident_id}")
            actions["identity"] = "SUSPENDED"
        else:
            actions["identity"] = f"unchanged ({agent.status.value})"

        # 4. JIT mandates
        from app.jit.service import JITService
        revoked_grants = await JITService(self.session, self.keystore, self.settings) \
            .revoke_for_agent(agent_did, reason=f"incident {incident_id}",
                              revoked_by=opened_by, now=now)
        actions["jit_grants_revoked"] = revoked_grants

        # 5. MCP sessions
        from app.protocols.mcp.session import MCPSessionService
        closed = await MCPSessionService(self.session, self.settings) \
            .revoke_for_agent(agent_did, now=now)
        actions["mcp_sessions_revoked"] = closed

        # 5b. Human approvals: withdrawn, not merely left for the PDP to deny.
        from app.hitl.service import ApprovalService
        cancelled = await ApprovalService(self.session, None, self.settings).cancel_for_agent(
            agent_did, reason=f"incident {incident_id}: agent contained", now=now)
        actions["approvals_cancelled"] = cancelled
        if closed or revoked_grants:
            await self.audit.record(Event(
                EventType.SESSION_REVOKED, agent_did=agent_did, reason=f"incident {incident_id}",
                metadata={"mcp_sessions": closed, "jit_grants": revoked_grants,
                          "incident_id": incident_id}))

        # 6. ANS: stop being discoverable NOW, not at the next reconcile sweep.
        ans_row = (await self.session.execute(
            select(ANSAgent).where(ANSAgent.did == agent_did))).scalar_one_or_none()
        if ans_row is not None and ans_row.status not in (ANSStatus.REVOKED, ANSStatus.TERMINATED):
            ans_row.status = ANSStatus.REVOKED
            await self.audit.record(Event(
                EventType.ANS_AGENT_REVOKED, agent_did=agent_did, reason="SECURITY_LOCKOUT",
                metadata={"incident_id": incident_id, "ans_status": "REVOKED"}))
            actions["ans"] = "REVOKED"
        else:
            actions["ans"] = f"unchanged ({ans_row.status.value if ans_row else 'not registered'})"

        # 7. credentials: only on request. Revocation cannot be undone.
        if revoke_credentials:
            from app.credentials.status import CredentialStatusService
            status_service = CredentialStatusService(self.session)
            revoked_vcs = []
            for vc in impact["reachable"]["active_credentials"]:
                await status_service.revoke(vc["credential_id"], f"incident {incident_id}")
                revoked_vcs.append(vc["credential_id"])
            actions["credentials_revoked"] = revoked_vcs
        else:
            actions["credentials_revoked"] = []

        # 8. delegated children: a sub-agent never outlives its parent's compromise.
        cascaded: list[str] = []
        changes = [change]
        if _depth < MAX_CASCADE_DEPTH:
            children = (await self.session.execute(
                select(Agent).where(Agent.parent_agent_id == agent.id,
                                    Agent.status == AgentStatus.ACTIVE)
            )).scalars().all()
            for child in children:
                child_report = await self.contain(
                    child.did, justification=f"parent {agent_did} contained ({incident_id})",
                    opened_by=opened_by, trigger=trigger, alert_id=alert_id,
                    revoke_credentials=revoke_credentials, _depth=_depth + 1)
                cascaded.append(child.did)
                cascaded.extend(child_report.cascaded)
                changes.extend(child_report.changes)

        # 9. alerts
        await self.session.execute(
            update(SecurityAlert)
            .where(SecurityAlert.agent_did == agent_did, SecurityAlert.status == AlertStatus.OPEN)
            .values(status=AlertStatus.CONTAINED))

        elapsed = (time.perf_counter() - started) * 1000
        unaffected = (await self.session.execute(
            select(func.count(Agent.id)).where(Agent.status == AgentStatus.ACTIVE)
        )).scalar_one()

        self.session.add(SecurityIncident(
            incident_id=incident_id, agent_did=agent_did, status=IncidentStatus.CONTAINED,
            trigger=trigger, alert_id=alert_id, opened_by=opened_by,
            justification=justification.strip(),
            containment={"actions": actions, "impact": impact, "cascaded_to": cascaded},
            contained_at=now, containment_ms=elapsed))
        await self.audit.record(Event(
            EventType.INCIDENT_CONTAINED, agent_did=agent_did, decision="CONTAINED",
            reason=justification.strip()[:500],
            metadata={"incident_id": incident_id, "trigger": trigger.value,
                      "alert_id": alert_id, "opened_by": opened_by,
                      "containment_ms": round(elapsed, 2), "actions": actions,
                      "cascaded_to": cascaded, "unaffected_active_agents": unaffected}))
        await self.session.flush()
        log.warning("agent_contained", agent=agent_did, incident=incident_id,
                    trigger=trigger.value, ms=round(elapsed, 2), cascaded=len(cascaded))

        return ContainmentReport(
            incident_id=incident_id, agent_did=agent_did, trigger=trigger.value,
            contained_at=now, containment_ms=elapsed, actions=actions, impact=impact,
            cascaded=cascaded, unaffected_active_agents=unaffected, changes=changes)

    # ------------------------------------------------------------------ #
    # Reinstatement (human, reviewed, separation of duties)
    # ------------------------------------------------------------------ #
    async def reinstate(
        self, incident_id: str, *, reinstated_by: str, review: str
    ) -> tuple[dict[str, Any], SessionChange]:
        incident = (await self.session.execute(
            select(SecurityIncident).where(SecurityIncident.incident_id == incident_id)
            .with_for_update()
        )).scalar_one_or_none()
        if incident is None:
            raise NotFoundError(f"Unknown incident {incident_id}")

        refusal = None
        if incident.status != IncidentStatus.CONTAINED:
            refusal = f"incident is {incident.status.value}, not CONTAINED"
        elif not review or len(review.strip()) < MIN_REVIEW_LENGTH:
            refusal = f"a post-incident review of at least {MIN_REVIEW_LENGTH} characters is required"
        elif reinstated_by == incident.opened_by:
            refusal = ("the principal who contained an agent may not reinstate it "
                       "(separation of duties)")
        if refusal:
            await self.audit.record(Event(
                EventType.INCIDENT_REINSTATEMENT_REFUSED, agent_did=incident.agent_did,
                decision="REFUSED", reason=refusal,
                metadata={"incident_id": incident_id, "requested_by": reinstated_by}))
            await self.session.flush()
            raise ReinstatementRefused(f"Reinstatement refused: {refusal}")

        agent = await self._agent(incident.agent_did)
        if agent.status == AgentStatus.TERMINATED:
            raise ConflictError(f"{agent.did} has been TERMINATED; termination is permanent")

        now = datetime.now(timezone.utc)
        revalidation = await self.revalidate(agent, now=now)
        failed = [c for c in revalidation if not c["passed"]]
        if failed:
            refusal = "trust revalidation failed: " + "; ".join(
                f"{c['check']}: {c['detail']}" for c in failed)
            await self.audit.record(Event(
                EventType.INCIDENT_REINSTATEMENT_REFUSED, agent_did=agent.did,
                decision="REFUSED", reason=refusal[:500],
                metadata={"incident_id": incident_id, "requested_by": reinstated_by,
                          "revalidation": revalidation}))
            await self.session.flush()
            raise ReinstatementRefused(f"Reinstatement refused: {refusal}", revalidation)

        change = await self.sss.set_state(
            agent.did, SessionState.ACTIVE, reason=f"reinstated after {incident_id}",
            changed_by=reinstated_by, incident_id=incident_id, now=now)
        if agent.status == AgentStatus.SUSPENDED:
            from app.agents.registry import AgentRegistry
            await AgentRegistry(self.session, self.keystore, self.settings).set_status(
                agent.did, AgentStatus.ACTIVE, reason=f"reinstated after {incident_id}")

        # The reviewer has examined the agent; the signals that led here are
        # retired with the review as their justification, so the agent does
        # not come back already UNTRUSTED. Retired, not deleted: they stay in
        # the table for the record.
        retired = (await self.session.execute(
            update(TrustSignal)
            .where(TrustSignal.agent_did == agent.did, TrustSignal.expires_at > now)
            .values(expires_at=now)
        )).rowcount or 0
        await self.trust.recompute(agent.did, now=now, cause=f"reinstated after {incident_id}")

        incident.status = IncidentStatus.REINSTATED
        incident.reinstated_by = reinstated_by
        incident.reinstated_at = now
        incident.review = review.strip()
        await self.session.execute(
            update(SecurityAlert)
            .where(SecurityAlert.agent_did == agent.did, SecurityAlert.status == AlertStatus.CONTAINED)
            .values(status=AlertStatus.RESOLVED))
        await self.audit.record(Event(
            EventType.INCIDENT_REINSTATED, agent_did=agent.did, decision="REINSTATED",
            reason=review.strip()[:500],
            metadata={"incident_id": incident_id, "reinstated_by": reinstated_by,
                      "contained_by": incident.opened_by, "signals_retired": int(retired),
                      "revalidation": revalidation}))
        await self.session.flush()
        return {
            "incident_id": incident_id, "agent_did": agent.did, "status": "REINSTATED",
            "signals_retired": int(retired),
            "revalidation": revalidation,
            "still_required": [
                "the agent must re-register with the ANS using a fresh signed proof",
                "revoked credentials and JIT mandates stay revoked; re-issue if needed",
            ],
        }, change

    async def revalidate(self, agent: Agent, *, now: datetime) -> list[dict[str, Any]]:
        """Re-check the identity facts a reinstatement must not assume.

        Every check reads CURRENT state. None of them consults the incident
        or the reviewer's opinion: a review explains why the agent is safe,
        these establish that it still CAN be trusted to exist.
        """
        from app.db.models.agent import AgentKey, KeyStatus

        checks: list[dict[str, Any]] = []

        def check(name: str, passed: bool, detail: str) -> None:
            checks.append({"check": name, "passed": bool(passed), "detail": detail})

        check("identity_not_terminated", agent.status != AgentStatus.TERMINATED,
              agent.status.value)
        expired = agent.expires_at is not None and agent.expires_at <= now
        check("identity_not_expired", not expired,
              agent.expires_at.isoformat() if agent.expires_at else "no expiry")
        active_keys = (await self.session.execute(
            select(func.count(AgentKey.id)).where(
                AgentKey.agent_id == agent.id, AgentKey.status == KeyStatus.ACTIVE)
        )).scalar_one()
        check("active_signing_key", active_keys > 0, f"{active_keys} ACTIVE key(s)")

        # Every delegation ancestor must itself be ACTIVE and not locked out.
        # Walked with explicit queries: a lazy self-referential load is not
        # available on an async session.
        parent_id, depth, blocked = agent.parent_agent_id, 0, []
        while parent_id is not None and depth < MAX_CASCADE_DEPTH:
            parent = (await self.session.execute(
                select(Agent).where(Agent.id == parent_id))).scalar_one_or_none()
            if parent is None:
                blocked.append("delegation parent record is missing")
                break
            state = await self.sss.get(parent.did)
            if parent.status != AgentStatus.ACTIVE:
                blocked.append(f"{parent.did} is {parent.status.value}")
            if state is not None and state.state == SessionState.TERMINATED_IMMEDIATE_SECURITY_LOCKOUT:
                blocked.append(f"{parent.did} is locked out (incident {state.incident_id})")
            parent_id, depth = parent.parent_agent_id, depth + 1
        check("ancestors_not_contained", not blocked,
              "; ".join(blocked) if blocked else
              ("no delegation parent" if agent.parent_agent_id is None
               else "every ancestor ACTIVE"))
        return checks

    async def incidents(self, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = (await self.session.execute(
            select(SecurityIncident).order_by(SecurityIncident.contained_at.desc()).limit(limit)
        )).scalars()
        return [incident_dict(r) for r in rows]

    async def get_incident(self, incident_id: str) -> dict[str, Any]:
        row = (await self.session.execute(
            select(SecurityIncident).where(SecurityIncident.incident_id == incident_id)
        )).scalar_one_or_none()
        if row is None:
            raise NotFoundError(f"Unknown incident {incident_id}")
        return incident_dict(row, full=True)

    async def _agent(self, agent_did: str) -> Agent:
        agent = (await self.session.execute(
            select(Agent).where(Agent.did == agent_did))).scalar_one_or_none()
        if agent is None:
            raise NotFoundError(f"{agent_did} is not a registered agent")
        return agent


def incident_dict(row: SecurityIncident, *, full: bool = False) -> dict[str, Any]:
    out = {
        "incident_id": row.incident_id, "agent_did": row.agent_did,
        "status": row.status.value, "trigger": row.trigger.value,
        "alert_id": row.alert_id, "opened_by": row.opened_by,
        "justification": row.justification,
        "contained_at": row.contained_at.isoformat(),
        "containment_ms": row.containment_ms,
        "reinstated_by": row.reinstated_by,
        "reinstated_at": row.reinstated_at.isoformat() if row.reinstated_at else None,
        "review": row.review,
        "cascaded_to": (row.containment or {}).get("cascaded_to", []),
    }
    if full:
        out["containment"] = row.containment
    return out
