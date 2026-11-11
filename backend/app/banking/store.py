"""Durable state of the SIMULATED loan management system (Phase 12).

PostgreSQL is the only authority for workflow-created applications, their
documents, the workflow queue and its transitions. See app/db/models/loan.py
for the concurrency model.

TWO READ PATHS, and why:

  * MUTABLE state (status, decision, steps, lease) is read only from the
    database, inside the caller's transaction, by the async functions below.

  * IMMUTABLE facts (amount, officer of record, customer, applicant) are
    needed by SYNCHRONOUS code on the authorization path -- the PIP's
    material attributes, the approval binding, maker-checker. They are
    cached write-through at submission, and on a miss (after a restart, or
    when another worker took the submission) loaded with a short synchronous
    read. They never change after submission, so a cache of them cannot be
    stale. A fact that cannot be loaded is reported unavailable, and every
    consumer of it fails closed.

The adapters stay labelled SIMULATED: there is no real LMS behind this.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.models.loan import (
    LoanApplicationRecord,
    LoanDocumentRecord,
    LoanWorkflowRecord,
    LoanWorkflowTransition,
)

log = get_logger("banking.store")

SIMULATED = {"simulated": True,
             "disclaimer": "SIMULATED ADAPTER - synthetic data, not a real check"}
APPLICATION_DISCLAIMER = "SYNTHETIC DEMO APPLICATION - not a real credit decision"
DURABLE_PREFIX = "loan-w"

TERMINAL = frozenset({"APPROVED", "DECLINED", "FAILED"})
RECORDABLE = frozenset({"AWAITING_APPROVAL", *TERMINAL})

# Tunables, read at call time so tests can shorten them.
RESUME_AFTER_SECONDS = 15
LEASE_SECONDS = 120

_FACTS: dict[str, dict[str, Any]] = {}
IMMUTABLE_KEYS = ("application_id", "customer_id", "applicant_name", "amount_inr",
                  "term_months", "product", "declared_monthly_income_inr",
                  "submitted_by", "submitted_at")


class WorkflowConflict(ValueError):
    """A state change the current durable state does not permit."""


def is_durable(application_id: str | None) -> bool:
    return bool(application_id) and application_id.startswith(DURABLE_PREFIX)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _format_inr(amount: int) -> str:
    from app.enforcement.resources import format_inr
    return format_inr(amount)


def application_dict(row: LoanApplicationRecord) -> dict[str, Any]:
    return {
        "application_id": row.application_id, "customer_id": row.customer_id,
        "applicant_name": row.applicant_name, "amount_inr": int(row.amount_inr),
        "amount_display": _format_inr(int(row.amount_inr)), "product": row.product,
        "term_months": row.term_months,
        "declared_monthly_income_inr": int(row.declared_monthly_income_inr),
        "status": row.status, "risk_band": row.risk_band, "submitted_by": row.submitted_by,
        "submitted_at": _iso(row.submitted_at), "decision_note": row.decision_note,
        "decided_at": _iso(row.decided_at), "disclaimer": APPLICATION_DISCLAIMER,
        "durable": True,
    }


def workflow_dict(row: LoanWorkflowRecord) -> dict[str, Any]:
    return {
        "workflow_id": row.workflow_id, "application_id": row.application_id,
        "status": row.status, "submitted_by": row.submitted_by,
        "submitted_at": _iso(row.submitted_at), "updated_at": _iso(row.updated_at),
        "completed_at": _iso(row.completed_at), "coordinator": row.coordinator,
        "steps": list(row.steps or []), "decision": row.decision, "approval": row.approval,
        "customer_message": row.customer_message, "resuming": bool(row.resuming),
        "attempts": row.attempts, "version": row.version,
        **SIMULATED, "adapter": "loan-management-system", "durable": True,
    }


# ---------------------------------------------------------------------------
# Immutable facts for synchronous readers
# ---------------------------------------------------------------------------
def _remember(app: dict[str, Any]) -> None:
    _FACTS[app["application_id"]] = {k: app[k] for k in IMMUTABLE_KEYS}


def _sync_load(application_id: str) -> dict[str, Any] | None:
    """One short synchronous read, for a fact not yet cached in this process."""
    import psycopg
    from psycopg.rows import dict_row

    url = get_settings().database_url
    for prefix in ("postgresql+psycopg://", "postgresql+asyncpg://"):
        url = url.replace(prefix, "postgresql://")
    try:
        with psycopg.connect(url, row_factory=dict_row, connect_timeout=5) as conn:
            row = conn.execute(
                "SELECT application_id, customer_id, applicant_name, amount_inr, term_months, "
                "product, declared_monthly_income_inr, submitted_by, submitted_at, status, risk_band "
                "FROM loan_applications WHERE application_id = %s", (application_id,)
            ).fetchone()
    except psycopg.Error as exc:
        log.error("loan_fact_load_failed", application_id=application_id,
                  error=f"{type(exc).__name__}: {exc}")
        return None
    if row is None:
        return None
    row["amount_inr"] = int(row["amount_inr"])
    row["declared_monthly_income_inr"] = int(row["declared_monthly_income_inr"])
    row["submitted_at"] = _iso(row["submitted_at"])
    return row


def facts(application_id: str, *, fresh: bool = False) -> dict[str, Any] | None:
    """Immutable facts of a durable application, or None if it cannot be read.

    `fresh=True` re-reads (and returns the CURRENT status) for display paths;
    the cache still answers if the row is not yet visible to a new
    connection (the submitting transaction has not committed).
    """
    if not is_durable(application_id):
        return None
    if fresh or application_id not in _FACTS:
        row = _sync_load(application_id)
        if row is not None:
            mutable = {"status": row.pop("status"), "risk_band": row.pop("risk_band")}
            _remember(row)
            if fresh:
                return {**row, **mutable}
    cached = _FACTS.get(application_id)
    return dict(cached) if cached else None


def forget_cached_facts() -> None:
    """Simulates a process restart in tests: the cache is not the authority."""
    _FACTS.clear()


# ---------------------------------------------------------------------------
# Submission
# ---------------------------------------------------------------------------
def submission_digest(body: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


async def _transition(session: AsyncSession, workflow_id: str, from_status: str | None,
                      to_status: str, *, actor: str | None, reason: str | None,
                      request_id: str | None, detail: dict[str, Any] | None = None) -> None:
    from app.audit.service import AuditService
    from app.monitoring.events import Event, EventType

    session.add(LoanWorkflowTransition(
        workflow_id=workflow_id, from_status=from_status, to_status=to_status, actor=actor,
        reason=(reason or "")[:512] or None, request_id=request_id, detail=detail or {}))
    await AuditService(session).record(Event(
        EventType.LOAN_WORKFLOW_TRANSITION, agent_did=actor if actor and actor.startswith("did:")
        else None, request_id=request_id, resource="loan_workflows", action="TRANSITION",
        decision=to_status, reason=(reason or "")[:500] or None,
        metadata={"workflow_id": workflow_id, "from": from_status, "to": to_status,
                  "actor": actor, **(detail or {})}))


async def submit(session: AsyncSession, *, customer_id: str, applicant_name: str,
                 amount_inr: int, term_months: int, product: str,
                 declared_monthly_income_inr: int, submitted_by: str,
                 documents: list[dict[str, str]], idempotency_key: str | None = None,
                 request_digest: str | None = None) -> tuple[dict, dict, bool]:
    """Create application, documents and workflow in the caller's transaction.

    Returns (application, workflow, created). With an idempotency key, a
    repeat of the same submission by the same officer returns the original
    instead of creating a second application; the same key with a DIFFERENT
    body is a conflict, never a silent overwrite.
    """
    if idempotency_key:
        existing = (await session.execute(select(LoanWorkflowRecord).where(
            LoanWorkflowRecord.submitted_by == submitted_by,
            LoanWorkflowRecord.idempotency_key == idempotency_key))).scalar_one_or_none()
        if existing is not None:
            if existing.request_digest != request_digest:
                raise WorkflowConflict("Idempotency-Key reused with a different submission")
            app = (await session.execute(select(LoanApplicationRecord).where(
                LoanApplicationRecord.application_id == existing.application_id))).scalar_one()
            return application_dict(app), workflow_dict(existing), False

    now = _now()
    application_id = f"{DURABLE_PREFIX}{secrets.token_hex(4)}"
    workflow_id = f"wf-{secrets.token_hex(5)}"
    app = LoanApplicationRecord(
        application_id=application_id, customer_id=customer_id, applicant_name=applicant_name,
        amount_inr=amount_inr, term_months=term_months, product=product,
        declared_monthly_income_inr=declared_monthly_income_inr, status="AWAITING_DECISION",
        risk_band="UNASSESSED", submitted_by=submitted_by, submitted_at=now)
    session.add(app)
    await session.flush()
    seen = set()
    for d in documents:
        digest = hashlib.sha256(d["content"].encode("utf-8")).hexdigest()
        if (d["type"], digest) in seen:
            continue
        seen.add((d["type"], digest))
        session.add(LoanDocumentRecord(application_id=application_id, doc_type=d["type"],
                                       sha256=digest, stored_at=now))
    wf = LoanWorkflowRecord(
        workflow_id=workflow_id, application_id=application_id, status="SUBMITTED",
        submitted_by=submitted_by, submitted_at=now, updated_at=now, steps=[],
        customer_message="Your application has been received.",
        idempotency_key=idempotency_key, request_digest=request_digest)
    session.add(wf)
    await session.flush()
    await _transition(session, workflow_id, None, "SUBMITTED", actor=submitted_by,
                      reason="submitted by the officer of record", request_id=workflow_id)
    application = application_dict(app)
    _remember(application)
    return application, workflow_dict(wf), True


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------
async def get_application(session: AsyncSession, application_id: str) -> dict | None:
    row = (await session.execute(select(LoanApplicationRecord).where(
        LoanApplicationRecord.application_id == application_id))).scalar_one_or_none()
    return application_dict(row) if row else None


async def get_workflow(session: AsyncSession, workflow_id: str) -> dict | None:
    row = (await session.execute(select(LoanWorkflowRecord).where(
        LoanWorkflowRecord.workflow_id == workflow_id))).scalar_one_or_none()
    return workflow_dict(row) if row else None


async def list_workflows(session: AsyncSession, *, limit: int = 200) -> list[dict]:
    rows = (await session.execute(select(LoanWorkflowRecord).order_by(
        LoanWorkflowRecord.submitted_at.desc()).limit(limit))).scalars()
    return [workflow_dict(r) for r in rows]


async def transitions(session: AsyncSession, workflow_id: str) -> list[dict]:
    rows = (await session.execute(select(LoanWorkflowTransition).where(
        LoanWorkflowTransition.workflow_id == workflow_id).order_by(
        LoanWorkflowTransition.id))).scalars()
    return [{"from": r.from_status, "to": r.to_status, "actor": r.actor, "reason": r.reason,
             "request_id": r.request_id, "at": _iso(r.occurred_at), "detail": r.detail}
            for r in rows]


# ---------------------------------------------------------------------------
# Coordinator tools (reached ONLY through the AEM, on the coordinator's own
# credential; `session` and `request_id` are injected by the AEM)
# ---------------------------------------------------------------------------
async def claim_next(session: AsyncSession, *, queue: str, request_id: str | None,
                     coordinator: str | None) -> dict[str, Any]:
    now = _now()
    # 1. Expired leases: the run was abandoned (crash, restart, lost outcome).
    #    Returned to the queue with the approval binding preserved, and the
    #    transition is recorded rather than done silently.
    expired = (await session.execute(
        select(LoanWorkflowRecord).where(LoanWorkflowRecord.status == "IN_PROGRESS",
                                         LoanWorkflowRecord.lease_expires_at <= now)
        .with_for_update(skip_locked=True))).scalars().all()
    for wf in expired:
        back = "AWAITING_APPROVAL" if wf.approval else "SUBMITTED"
        await _transition(session, wf.workflow_id, "IN_PROGRESS", back, actor=coordinator,
                          reason="lease expired: the previous run was abandoned",
                          request_id=request_id, detail={"expired_lease": wf.lease_token})
        wf.status, wf.lease_token, wf.lease_expires_at = back, None, None
        wf.updated_at, wf.version = now, wf.version + 1
    if expired:
        await session.flush()

    def pick(status: str, *extra):
        return (select(LoanWorkflowRecord)
                .where(LoanWorkflowRecord.status == status, *extra)
                .order_by(LoanWorkflowRecord.updated_at).limit(1)
                .with_for_update(skip_locked=True))

    wf = (await session.execute(pick("SUBMITTED"))).scalar_one_or_none()
    if wf is None:
        wf = (await session.execute(pick(
            "AWAITING_APPROVAL",
            LoanWorkflowRecord.updated_at <= now - timedelta(seconds=RESUME_AFTER_SECONDS)
        ))).scalar_one_or_none()
    if wf is None:
        return {"queue": queue, "workflow": None}

    previous = wf.status
    token = secrets.token_hex(16)
    wf.resuming = previous == "AWAITING_APPROVAL"
    wf.status, wf.lease_token = "IN_PROGRESS", token
    wf.lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
    wf.attempts, wf.version, wf.updated_at = wf.attempts + 1, wf.version + 1, now
    wf.coordinator = coordinator or wf.coordinator
    await _transition(session, wf.workflow_id, previous, "IN_PROGRESS", actor=coordinator,
                      reason="resumed to re-check a human approval" if wf.resuming
                      else "claimed", request_id=request_id,
                      detail={"attempt": wf.attempts})
    app = (await session.execute(select(LoanApplicationRecord).where(
        LoanApplicationRecord.application_id == wf.application_id))).scalar_one()
    await session.flush()
    return {"queue": queue, "workflow": {**workflow_dict(wf), "claim_token": token},
            # What the coordinator needs to route work and to recover, and
            # nothing more: no financial data beyond the amount it must show.
            "application": {"application_id": app.application_id,
                            "customer_id": app.customer_id, "amount_inr": int(app.amount_inr),
                            "term_months": app.term_months, "status": app.status}}


async def record_outcome(session: AsyncSession, *, workflow_id: str, status: str,
                         claim_token: str | None, request_id: str | None,
                         steps: list | None = None, decision: dict | None = None,
                         approval: dict | None = None, customer_message: str | None = None,
                         coordinator: str | None = None) -> dict[str, Any]:
    if status not in RECORDABLE:
        raise WorkflowConflict(f"status must be one of {sorted(RECORDABLE)}")
    wf = (await session.execute(select(LoanWorkflowRecord).where(
        LoanWorkflowRecord.workflow_id == workflow_id).with_for_update())).scalar_one_or_none()
    if wf is None:
        from app.enforcement.resources import ResourceNotFoundError
        raise ResourceNotFoundError(f"No loan workflow {workflow_id!r}")

    # A retry of the record that already succeeded (the response was lost):
    # recognised by its fencing token and answered, not applied twice.
    if (claim_token and wf.last_lease_token == claim_token and wf.status == status
            and wf.lease_token is None):
        return {**workflow_dict(wf), "idempotent_replay": True}
    if wf.status in TERMINAL:
        raise WorkflowConflict(f"workflow {workflow_id} is already {wf.status}")
    if wf.status != "IN_PROGRESS":
        raise WorkflowConflict(f"workflow {workflow_id} is {wf.status}, not IN_PROGRESS: "
                               "it must be claimed before an outcome is recorded")
    if not claim_token or claim_token != wf.lease_token:
        raise WorkflowConflict(
            f"stale or missing claim token for {workflow_id}: the lease expired and the "
            "workflow was re-claimed, so this run may not record an outcome")

    now = _now()
    previous = wf.status
    wf.steps = list(steps if steps is not None else wf.steps)
    wf.decision = decision if decision is not None else wf.decision
    wf.approval = approval if approval is not None else wf.approval
    wf.customer_message = customer_message or wf.customer_message
    wf.coordinator = coordinator or wf.coordinator
    wf.status, wf.updated_at, wf.version = status, now, wf.version + 1
    wf.last_lease_token, wf.lease_token, wf.lease_expires_at = claim_token, None, None
    if status in TERMINAL:
        wf.completed_at = now
    if status == "DECLINED":
        await decline(session, wf.application_id, (decision or {}).get("summary", "declined"))
    await _transition(session, workflow_id, previous, status, actor=coordinator,
                      reason=(decision or {}).get("summary"), request_id=request_id,
                      detail={"steps": len(wf.steps),
                              "approval_id": (wf.approval or {}).get("approval_id")})
    await session.flush()
    return workflow_dict(wf)


# ---------------------------------------------------------------------------
# Specialist tools over durable applications
# ---------------------------------------------------------------------------
async def _application_row(session: AsyncSession, application_id: str) -> LoanApplicationRecord:
    row = (await session.execute(select(LoanApplicationRecord).where(
        LoanApplicationRecord.application_id == application_id))).scalar_one_or_none()
    if row is None:
        from app.enforcement.resources import ResourceNotFoundError
        raise ResourceNotFoundError(f"No loan application {application_id!r}")
    return row


async def documents(session: AsyncSession, application_id: str) -> list[dict[str, str]]:
    await _application_row(session, application_id)
    rows = (await session.execute(select(LoanDocumentRecord).where(
        LoanDocumentRecord.application_id == application_id).order_by(
        LoanDocumentRecord.stored_at, LoanDocumentRecord.doc_type))).scalars()
    return [{"type": r.doc_type, "sha256": r.sha256} for r in rows]


async def application_for_risk(session: AsyncSession, application_id: str) -> dict[str, Any]:
    row = await _application_row(session, application_id)
    return {"amount_inr": int(row.amount_inr), "term_months": row.term_months,
            "declared_monthly_income_inr": int(row.declared_monthly_income_inr)}


async def approve(session: AsyncSession, application_id: str, *, decision_note: str,
                  request_id: str | None) -> dict[str, Any]:
    """Decide an application AT MOST ONCE. A second decision is refused."""
    row = (await session.execute(
        update(LoanApplicationRecord)
        .where(LoanApplicationRecord.application_id == application_id,
               LoanApplicationRecord.status == "AWAITING_DECISION")
        .values(status="APPROVED", decision_note=decision_note, decided_at=_now(),
                decided_by_request=request_id)
        .returning(LoanApplicationRecord))).scalar_one_or_none()
    if row is None:
        current = await _application_row(session, application_id)
        raise WorkflowConflict(f"loan application {application_id} is already "
                               f"{current.status}; refusing a second decision")
    return application_dict(row)


async def decline(session: AsyncSession, application_id: str, reason: str) -> None:
    await session.execute(
        update(LoanApplicationRecord)
        .where(LoanApplicationRecord.application_id == application_id,
               LoanApplicationRecord.status == "AWAITING_DECISION")
        .values(status="DECLINED", decision_note=reason[:2000], decided_at=_now()))
