"""End-to-end loan workflow: submission and status (blueprint steps 1-2, 17).

    POST /api/v1/loan-workflows          a loan officer submits an application
    GET  /api/v1/loan-workflows          every workflow, newest first
    GET  /api/v1/loan-workflows/{id}     one workflow: steps, decision, message
    GET  /api/v1/loan-workflows/{id}/transitions   every state change, in order

Phase 12: state is DURABLE (PostgreSQL, app/banking/store.py) and survives a
restart. A submission may carry an `Idempotency-Key` header: a repeat by the
same officer returns the original workflow instead of a second application.

WHAT HAPPENS AFTER SUBMISSION is not in this file, deliberately. The
coordinator AGENT claims the workflow with its own signed request, discovers
specialists through the ANS, and each specialist calls the AEM with its own
key (app/workflows/). This route only records what a human asked for, as the
authenticated officer, in the SIMULATED loan management system.

Documents are uploaded as content; only their SHA-256 digests are kept, in
the simulated document store.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import SessionDep
from app.audit.service import AuditService
from app.banking import store
from app.controlplane.guard import ControlPlaneGuard, fixed, path_param
from app.core.errors import ConflictError, NotFoundError
from app.monitoring.events import Event, EventType

router = APIRouter(prefix="/api/v1/loan-workflows", tags=["loan-workflows"])


class DocumentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(pattern=r"^[A-Z_]{3,32}$")
    content: str = Field(min_length=1, max_length=20_000)


class SubmitIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    customer_id: str = Field(pattern=r"^customer-[0-9a-z]{3,16}$")
    applicant_name: str = Field(min_length=2, max_length=128)
    amount_inr: int = Field(gt=0, le=1_000_000_000)
    term_months: int = Field(ge=6, le=360)
    product: str = Field(default="SECURED_PERSONAL_LOAN", max_length=48)
    declared_monthly_income_inr: int = Field(ge=0, le=100_000_000)
    documents: list[DocumentIn] = Field(default_factory=list, max_length=10)


async def _public(session, workflow: dict[str, Any]) -> dict[str, Any]:
    return {**workflow,
            "application": await store.get_application(session, workflow["application_id"])}


@router.post("", status_code=201, dependencies=[Depends(
    ControlPlaneGuard("loan_workflow_submit", target=fixed("loan_intake")))])
async def submit(body: SubmitIn, request: Request, session: SessionDep,
                 idempotency_key: str | None = Header(default=None, alias="Idempotency-Key",
                                                      max_length=128)) -> dict[str, Any]:
    principal = request.state.control_plane_principal
    officer = getattr(principal, "username", None) or principal.did
    payload = body.model_dump()
    try:
        application, workflow, created = await store.submit(
            session, customer_id=body.customer_id, applicant_name=body.applicant_name,
            amount_inr=body.amount_inr, term_months=body.term_months, product=body.product,
            declared_monthly_income_inr=body.declared_monthly_income_inr,
            submitted_by=officer, documents=[d.model_dump() for d in body.documents],
            idempotency_key=idempotency_key,
            request_digest=store.submission_digest(payload) if idempotency_key else None)
    except store.WorkflowConflict as exc:
        raise ConflictError(str(exc)) from exc
    if created:
        await AuditService(session).record(Event(
            EventType.LOAN_WORKFLOW_SUBMITTED, agent_did=principal.did,
            resource="loan_applications", action="SUBMIT", decision="SUBMITTED",
            request_id=workflow["workflow_id"],
            metadata={"workflow_id": workflow["workflow_id"],
                      "application_id": application["application_id"],
                      "amount_inr": body.amount_inr, "submitted_by": officer,
                      "documents": sorted({d.type for d in body.documents}),
                      "idempotency_key": bool(idempotency_key)}))
    return {**workflow, "application": application, "idempotent_replay": not created}


@router.get("", dependencies=[Depends(
    ControlPlaneGuard("loan_read", target=fixed("loan_workflows")))])
async def list_all(session: SessionDep) -> list[dict[str, Any]]:
    return [await _public(session, w) for w in await store.list_workflows(session)]


@router.get("/{workflow_id}", dependencies=[Depends(
    ControlPlaneGuard("loan_read", target=path_param("workflow_id")))])
async def read(workflow_id: str, session: SessionDep) -> dict[str, Any]:
    workflow = await store.get_workflow(session, workflow_id)
    if workflow is None:
        raise NotFoundError(f"No loan workflow {workflow_id!r}")
    return await _public(session, workflow)


@router.get("/{workflow_id}/transitions", dependencies=[Depends(
    ControlPlaneGuard("loan_read", target=path_param("workflow_id")))])
async def read_transitions(workflow_id: str, session: SessionDep) -> list[dict[str, Any]]:
    if await store.get_workflow(session, workflow_id) is None:
        raise NotFoundError(f"No loan workflow {workflow_id!r}")
    return await store.transitions(session, workflow_id)
