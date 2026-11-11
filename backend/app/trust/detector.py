"""Rule-based anomaly detection over the audit trail.

CSA paper R-123 (behaviour tracking), R-201 (behavioural baselines per DID),
R-203 (tools outside the toolset), R-206 (scope creep beyond VC-attested
capability), R-207 (anomalous JIT requests), R-253 (ephemeral-agent spawn
abuse), R-254 (delegation escalation) and R-129 (automated response).

WHAT THIS IS, stated plainly: deterministic rules over events this system
already records, not machine learning. The paper names ML anomaly detection
(R-124); that is NOT built here and the traceability matrix says so. Rules
are what a POC can make explainable and testable: every alert cites the audit
sequence numbers that produced it.

THE ATTRIBUTION RULE -- the most important line in this file.
Only events whose `agent_did` was AUTHENTICATED may lower that agent's trust.
An AEM denial, an MCP invocation denial, an A2A denial and a JIT refusal are
all produced after the caller proved who it is. A failed signature, a
rejected control-plane proof or an MCP authentication failure names a DID the
caller merely CLAIMED -- and if those moved trust, an attacker could get any
victim agent auto-contained by sending garbage in its name. Those still
produce a visible alert (a SOC wants to know), with `attributed=False` and no
trust signal.

HOW IT RUNS: one cursor over `audit_events.seq`, claimed with
`FOR UPDATE SKIP LOCKED` so several API workers never double-process, and
alerts deduplicated by a UNIQUE key per (rule, agent, time bucket) so a
restart or a race cannot double-count either.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.models.audit import AuditEvent
from app.db.models.security import (
    AlertSeverity,
    DetectorCursor,
    IncidentTrigger,
    SecurityAlert,
    SessionState,
    TrustLevel,
)
from app.identity.keys import KeyStore
from app.monitoring.events import Event, EventType
from app.sessions.authority import ContainmentReport, SessionAuthority
from app.sessions.sss import SessionChange, SessionStateSynchronizer
from app.trust.engine import TrustEngine

log = get_logger("trust.detector")

CURSOR_NAME = "anomaly-detector"
SUSPENDED = -1   # cursor value meaning "detection was switched off"
SYSTEM_PRINCIPAL = "system:anomaly-detector"

# Denials whose reason means "you asked for something your credentials do not
# cover" -- scope creep in the paper's terms -- as opposed to an expired
# credential or a pending approval, which are ordinary operational states.
SCOPE_REASONS = frozenset({
    "RESOURCE_NOT_ALLOWED", "MISSING_CAPABILITY", "PURPOSE_NOT_ALLOWED",
    "ACTION_NOT_ALLOWED", "JIT_SCOPE_EXCEEDS_DECISION", "JIT_ACTION_NOT_ELIGIBLE",
    "MCP_TOOL_NOT_PERMITTED",
})
# Denials produced AFTER authentication. Counted for bursts and scope rules.
AUTHENTICATED_DENIALS = frozenset({
    EventType.AEM_BLOCKED, EventType.MCP_INVOCATION_DENIED,
})
# Replays caught after authentication: the authenticated caller re-presented
# something already spent. Attributed.
AUTHENTICATED_REPLAYS = frozenset({
    EventType.APPROVAL_REPLAY_REJECTED, EventType.JIT_REPLAY_BLOCKED,
    EventType.MCP_REPLAY_BLOCKED, EventType.MCP_SESSION_BINDING_VIOLATION,
})
# Events naming a DID the caller only CLAIMED. Alert, never a trust signal.
UNAUTHENTICATED_CLAIMS = frozenset({
    EventType.SIGNATURE_INVALID, EventType.CONTROL_PLANE_REPLAY_DETECTED,
    EventType.MCP_AUTHENTICATION_FAILED,
})
# The detector's own output and the Session Authority's. Never re-analysed.
IGNORED = frozenset({
    EventType.ANOMALY_DETECTED, EventType.TRUST_UPDATED, EventType.SSS_UPDATED,
    EventType.INCIDENT_CONTAINED, EventType.INCIDENT_REINSTATED,
    EventType.INCIDENT_REINSTATEMENT_REFUSED, EventType.SESSION_REVOKED,
})

# Trust weight per rule. Chosen so that ONE kind of misbehaviour degrades an
# agent to REDUCED (human approval for sensitive actions) and it takes several
# DISTINCT kinds inside the signal TTL to reach UNTRUSTED -- a single noisy
# rule should not be able to trigger the kill switch on its own.
WEIGHTS = {
    "SCOPE_VIOLATION": 15,
    "DENIAL_BURST": 25,
    "CREDENTIAL_REPLAY": 35,
    "JIT_ESCALATION": 20,
    "RATE_SPIKE": 20,
    "SPAWN_BURST": 25,
    "DELEGATION_ESCALATION": 30,
}
SCOPE_BUCKET_SECONDS = 600
REPLAY_BUCKET_SECONDS = 60


@dataclass
class Finding:
    rule: str
    severity: AlertSeverity
    agent_did: str | None
    summary: str
    bucket: int
    evidence: dict[str, Any]
    attributed: bool = True
    observed_at: datetime | None = None


@dataclass
class DetectionRun:
    processed: int = 0
    last_seq: int = 0
    alerts: list[dict[str, Any]] = field(default_factory=list)
    contained: list[ContainmentReport] = field(default_factory=list)
    changes: list[SessionChange] = field(default_factory=list)
    skipped_locked: bool = False
    stale_skipped: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"processed": self.processed, "last_seq": self.last_seq,
                "stale_skipped": self.stale_skipped,
                "alerts": self.alerts,
                "contained": [r.to_dict() for r in self.contained],
                "skipped_locked": self.skipped_locked}


class AnomalyDetector:
    def __init__(
        self,
        session: AsyncSession,
        keystore: KeyStore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.keystore = keystore
        self.settings = settings or get_settings()
        self.trust = TrustEngine(session, self.settings)
        self.audit = AuditService(session)

    async def suspend(self) -> None:
        """Record that detection is OFF, so turning it back on does not replay
        the unmonitored window.

        REGRESSION. The gate harness runs the API with the detector off,
        because the gates attack as risk-001 on purpose. Restoring the normal
        profile then resumed the OLD cursor, read the whole gate sweep as live
        behaviour, and contained risk-001 again. Switching detection off is a
        deliberate operator act, recorded in the audit trail; a CRASH is not,
        and keeps its cursor so nothing that happened during an outage is
        missed.
        """
        await self.session.execute(
            pg_insert(DetectorCursor).values(name=CURSOR_NAME, last_seq=SUSPENDED,
                                             updated_at=datetime.now(timezone.utc))
            .on_conflict_do_update(index_elements=["name"],
                                   set_={"last_seq": SUSPENDED,
                                         "updated_at": datetime.now(timezone.utc)}))
        await self.audit.record(Event(
            EventType.ANOMALY_DETECTOR_DISABLED, decision="DISABLED",
            reason="ANOMALY_DETECTOR_ENABLED=false at startup",
            metadata={"note": "events while disabled are not analysed"}))
        await self.session.flush()

    async def start_from_head(self) -> int | None:
        """Create the cursor AT THE CURRENT HEAD of the audit trail, if absent.

        Called once by the IAM API before its detection loop starts. A
        detector switched on against an existing system watches from that
        moment: it does not replay the history it was not running for.

        FOUND THE HARD WAY. Without this, the first live start read the whole
        historical trail -- months of DELIBERATE denials and replays produced
        by the security gates -- turned them into fresh trust signals, and
        automatically contained a healthy agent. Returns the starting seq, or
        None if a cursor already existed.
        """
        head = (await self.session.execute(select(func.max(AuditEvent.seq)))).scalar_one() or 0
        # A cursor SUSPENDED by a detector-off start (see `suspend`) is
        # resumed at the head too: the window it was switched off for is
        # deliberately not replayed.
        resumed = (await self.session.execute(
            update(DetectorCursor)
            .where(DetectorCursor.name == CURSOR_NAME, DetectorCursor.last_seq == SUSPENDED)
            .values(last_seq=head, updated_at=datetime.now(timezone.utc))
            .returning(DetectorCursor.last_seq)
        )).scalar_one_or_none()
        if resumed is not None:
            await self.session.flush()
            return resumed
        created = (await self.session.execute(
            pg_insert(DetectorCursor).values(name=CURSOR_NAME, last_seq=head,
                                             updated_at=datetime.now(timezone.utc))
            .on_conflict_do_nothing(index_elements=["name"])
            .returning(DetectorCursor.last_seq)
        )).scalar_one_or_none()
        await self.session.flush()
        return created

    async def run_once(self, *, limit: int = 500) -> DetectionRun:
        run = DetectionRun()
        await self.session.execute(
            pg_insert(DetectorCursor).values(name=CURSOR_NAME, last_seq=0)
            .on_conflict_do_nothing(index_elements=["name"]))
        cursor = (await self.session.execute(
            select(DetectorCursor).where(DetectorCursor.name == CURSOR_NAME)
            .with_for_update(skip_locked=True)
        )).scalar_one_or_none()
        if cursor is None:   # another worker holds it this tick
            run.skipped_locked = True
            return run
        if cursor.last_seq == SUSPENDED:
            await self.start_from_head()
            return run

        events = (await self.session.execute(
            select(AuditEvent).where(AuditEvent.seq > cursor.last_seq)
            .order_by(AuditEvent.seq.asc()).limit(limit)
        )).scalars().all()
        for event in events:
            run.processed += 1
            run.last_seq = event.seq
            if event.event_type in IGNORED:
                continue
            # SECOND LAYER against replaying history: an event older than the
            # signal lifetime could not contribute to a current score anyway,
            # so it raises nothing -- however far behind the cursor is.
            if event.occurred_at < datetime.now(timezone.utc) - timedelta(
                    seconds=self.settings.trust_signal_ttl_seconds):
                run.stale_skipped += 1
                continue
            for finding in await self._evaluate(event):
                finding.observed_at = event.occurred_at
                await self._raise(finding, run)

        if events:
            cursor.last_seq = events[-1].seq
            cursor.updated_at = datetime.now(timezone.utc)
        await self.session.flush()
        return run

    # ---------------------------------------------------------------- rules
    async def _evaluate(self, e: AuditEvent) -> list[Finding]:
        did = e.agent_did
        ts = e.occurred_at.timestamp()
        out: list[Finding] = []
        s = self.settings

        if e.event_type in AUTHENTICATED_DENIALS and did:
            if (e.reason or "") in SCOPE_REASONS:
                out.append(Finding(
                    "SCOPE_VIOLATION", AlertSeverity.MEDIUM, did,
                    f"requested {e.resource}/{e.action} outside its attested scope ({e.reason})",
                    int(ts // SCOPE_BUCKET_SECONDS),
                    {"seq": e.seq, "reason": e.reason, "resource": e.resource,
                     "action": e.action}))
            window = s.anomaly_denial_burst_window_seconds
            denials = await self._count(did, AUTHENTICATED_DENIALS, e.occurred_at, window)
            if denials >= s.anomaly_denial_burst_count:
                out.append(Finding(
                    "DENIAL_BURST", AlertSeverity.HIGH, did,
                    f"{denials} authorization denials within {window}s",
                    int(ts // window), {"seq": e.seq, "denials": denials, "window_s": window}))

        if e.event_type in AUTHENTICATED_REPLAYS and did:
            out.append(Finding(
                "CREDENTIAL_REPLAY", AlertSeverity.HIGH, did,
                f"re-presented an already-spent artifact ({e.event_type})",
                int(ts // REPLAY_BUCKET_SECONDS), {"seq": e.seq, "event": e.event_type}))

        if e.event_type in UNAUTHENTICATED_CLAIMS:
            out.append(Finding(
                "UNVERIFIED_IDENTITY_CLAIM", AlertSeverity.MEDIUM, did,
                f"{e.event_type} naming {did or 'no DID'}; claim unverified, trust unchanged",
                int(ts // REPLAY_BUCKET_SECONDS), {"seq": e.seq, "event": e.event_type,
                                                   "reason": e.reason},
                attributed=False))

        if e.event_type == EventType.JIT_DENIED and did:
            window = s.anomaly_jit_denied_window_seconds
            n = await self._count(did, {EventType.JIT_DENIED}, e.occurred_at, window)
            if n >= s.anomaly_jit_denied_count:
                out.append(Finding(
                    "JIT_ESCALATION", AlertSeverity.MEDIUM, did,
                    f"{n} refused JIT mandate requests within {window}s",
                    int(ts // window), {"seq": e.seq, "refusals": n}))

        if e.event_type in (EventType.AEM_INTERCEPT, EventType.MCP_REQUEST) and did:
            window = s.anomaly_rate_spike_window_seconds
            n = await self._count(did, {EventType.AEM_INTERCEPT, EventType.MCP_REQUEST},
                                  e.occurred_at, window)
            if n >= s.anomaly_rate_spike_count:
                out.append(Finding(
                    "RATE_SPIKE", AlertSeverity.MEDIUM, did,
                    f"{n} protected-resource requests within {window}s",
                    int(ts // window), {"seq": e.seq, "requests": n, "window_s": window}))

        if e.event_type == EventType.AGENT_SPAWNED:
            parent = (e.event_metadata or {}).get("parent_did")
            if parent:
                window = s.anomaly_spawn_window_seconds
                n = await self._count_spawns(parent, e.occurred_at, window)
                if n >= s.anomaly_spawn_count:
                    out.append(Finding(
                        "SPAWN_BURST", AlertSeverity.HIGH, parent,
                        f"spawned {n} delegated agents within {window}s",
                        int(ts // window), {"seq": e.seq, "spawned": n}))

        if e.event_type == EventType.AGENT_SPAWN_REFUSED and did and \
                (e.reason or "").startswith("DELEGATION_"):
            out.append(Finding(
                "DELEGATION_ESCALATION", AlertSeverity.HIGH, did,
                f"attempted to delegate beyond its own authority ({e.reason})",
                int(ts // REPLAY_BUCKET_SECONDS), {"seq": e.seq, "reason": e.reason}))
        return out

    async def _count(self, did: str, types, until: datetime, window_s: int) -> int:
        return int((await self.session.execute(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.agent_did == did,
                AuditEvent.event_type.in_(list(types)),
                AuditEvent.occurred_at > until - timedelta(seconds=window_s),
                AuditEvent.occurred_at <= until)
        )).scalar_one())

    async def _count_spawns(self, parent_did: str, until: datetime, window_s: int) -> int:
        return int((await self.session.execute(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.event_type == EventType.AGENT_SPAWNED,
                AuditEvent.event_metadata["parent_did"].as_string() == parent_did,
                AuditEvent.occurred_at > until - timedelta(seconds=window_s),
                AuditEvent.occurred_at <= until)
        )).scalar_one())

    # ------------------------------------------------------------- response
    async def _raise(self, f: Finding, run: DetectionRun) -> None:
        dedup = f"{f.rule}:{f.agent_did or '-'}:{f.bucket}"
        alert_id = f"alr-{secrets.token_hex(6)}"
        inserted = (await self.session.execute(
            pg_insert(SecurityAlert).values(
                alert_id=alert_id, agent_did=f.agent_did, rule=f.rule,
                severity=f.severity, summary=f.summary[:512], dedup_key=dedup,
                attributed=f.attributed, evidence=f.evidence)
            .on_conflict_do_nothing(index_elements=["dedup_key"])
            .returning(SecurityAlert.alert_id)
        )).scalar_one_or_none()
        if inserted is None:
            return   # already raised for this window

        await self.audit.record(Event(
            EventType.ANOMALY_DETECTED, agent_did=f.agent_did, decision=f.severity.value,
            reason=f.rule,
            metadata={"alert_id": alert_id, "summary": f.summary, "attributed": f.attributed,
                      "evidence": f.evidence}))
        run.alerts.append({"alert_id": alert_id, "rule": f.rule, "severity": f.severity.value,
                           "agent_did": f.agent_did, "attributed": f.attributed,
                           "summary": f.summary})
        if not f.attributed or not f.agent_did:
            return

        # Observed at the EVENT's time, so the signal expires relative to when
        # the behaviour happened, not to when the detector got round to it.
        assessment = await self.trust.record_signal(
            f.agent_did, f.rule, WEIGHTS[f.rule], alert_id=alert_id, detail=f.summary,
            observed_at=f.observed_at)
        if assessment.level == TrustLevel.UNTRUSTED and assessment.changed_level:
            await self._trust_collapsed(f.agent_did, alert_id, assessment.score, run)
        elif assessment.level == TrustLevel.REDUCED and assessment.changed_level:
            sss = SessionStateSynchronizer(self.session, self.settings)
            current = await sss.get(f.agent_did)
            if current is None or current.state == SessionState.ACTIVE:
                run.changes.append(await sss.set_state(
                    f.agent_did, SessionState.REDUCED_TRUST,
                    reason=f"trust {assessment.score} after {f.rule}",
                    changed_by=SYSTEM_PRINCIPAL))

    async def _trust_collapsed(self, did: str, cause_alert: str, score: int,
                               run: DetectionRun) -> None:
        alert_id = f"alr-{secrets.token_hex(6)}"
        summary = f"trust collapsed to {score}; below the UNTRUSTED threshold"
        await self.session.execute(
            pg_insert(SecurityAlert).values(
                alert_id=alert_id, agent_did=did, rule="TRUST_COLLAPSE",
                severity=AlertSeverity.CRITICAL, summary=summary,
                dedup_key=f"TRUST_COLLAPSE:{did}:{cause_alert}", attributed=True,
                evidence={"score": score, "caused_by": cause_alert})
            .on_conflict_do_nothing(index_elements=["dedup_key"]))
        await self.audit.record(Event(
            EventType.ANOMALY_DETECTED, agent_did=did, decision="CRITICAL",
            reason="TRUST_COLLAPSE",
            metadata={"alert_id": alert_id, "summary": summary, "caused_by": cause_alert}))
        run.alerts.append({"alert_id": alert_id, "rule": "TRUST_COLLAPSE",
                           "severity": "CRITICAL", "agent_did": did, "attributed": True,
                           "summary": summary})
        if not self.settings.auto_containment_enabled:
            return
        sss = SessionStateSynchronizer(self.session, self.settings)
        current = await sss.get(did)
        if current and current.state == SessionState.TERMINATED_IMMEDIATE_SECURITY_LOCKOUT:
            return
        report = await SessionAuthority(self.session, self.keystore, self.settings).contain(
            did, justification=f"automated: {summary}", opened_by=SYSTEM_PRINCIPAL,
            trigger=IncidentTrigger.AUTOMATED, alert_id=alert_id)
        run.contained.append(report)
        run.changes.extend(report.changes)
