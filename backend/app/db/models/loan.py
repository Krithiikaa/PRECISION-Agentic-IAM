"""Durable loan workflow state (Phase 12).

Replaces the in-process dicts of the SIMULATED loan management system for
everything the WORKFLOW creates: applications submitted by an officer, their
document digests, the workflow queue and every lifecycle transition. The
adapters remain simulated (no bank, bureau or KYC provider is behind them);
what is no longer simulated is that their state survives a restart.

The Phase 4-7 demonstration fixtures (loan-2201, pay-3310, ...) are NOT moved:
the security gates reset and tamper with them deliberately, and they are not
workflow state.

CONCURRENCY MODEL
  * claim      SELECT ... FOR UPDATE SKIP LOCKED, then a LEASE (token +
               expiry). Two coordinators can never hold one workflow.
  * record     conditional on status=IN_PROGRESS AND the lease token
               (a fencing token): a run whose lease expired and was
               re-claimed cannot overwrite the newer run's result.
  * decide     UPDATE ... WHERE status='AWAITING_DECISION': an application
               is decided at most once, whatever retries or recoveries do.
  * submit     optional Idempotency-Key, UNIQUE per officer.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.agent import JSONType


class LoanApplicationRecord(Base):
    __tablename__ = "loan_applications"

    application_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    customer_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    applicant_name: Mapped[str] = mapped_column(String(128), nullable=False)
    amount_inr: Mapped[int] = mapped_column(BigInteger, nullable=False)
    term_months: Mapped[int] = mapped_column(Integer, nullable=False)
    product: Mapped[str] = mapped_column(String(48), nullable=False)
    declared_monthly_income_inr: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_band: Mapped[str] = mapped_column(String(32), nullable=False, default="UNASSESSED")
    submitted_by: Mapped[str] = mapped_column(String(255), nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decision_note: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_by_request: Mapped[str | None] = mapped_column(String(128))


class LoanDocumentRecord(Base):
    __tablename__ = "loan_documents"
    __table_args__ = (UniqueConstraint("application_id", "doc_type", "sha256"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    application_id: Mapped[str] = mapped_column(
        ForeignKey("loan_applications.application_id", ondelete="CASCADE"),
        nullable=False, index=True)
    doc_type: Mapped[str] = mapped_column(String(32), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    stored_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LoanWorkflowRecord(Base):
    __tablename__ = "loan_workflows"
    __table_args__ = (
        UniqueConstraint("submitted_by", "idempotency_key",
                         name="uq_loan_workflows_officer_idempotency"),
        Index("ix_loan_workflows_status_updated", "status", "updated_at"),
    )

    workflow_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    application_id: Mapped[str] = mapped_column(
        ForeignKey("loan_applications.application_id"), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    submitted_by: Mapped[str] = mapped_column(String(255), nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    coordinator: Mapped[str | None] = mapped_column(String(255))
    # The lease. `lease_token` is the fencing token of the CURRENT claim;
    # `last_lease_token` the one that recorded the latest outcome, so an
    # identical retry of that record is recognised instead of refused.
    lease_token: Mapped[str | None] = mapped_column(String(64))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_lease_token: Mapped[str | None] = mapped_column(String(64))
    resuming: Mapped[bool] = mapped_column(nullable=False, default=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    steps: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    decision: Mapped[dict | None] = mapped_column(JSONType)
    approval: Mapped[dict | None] = mapped_column(JSONType)
    customer_message: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    request_digest: Mapped[str | None] = mapped_column(String(64))


class LoanWorkflowTransition(Base):
    """One row per state change, in order. Audit-correlated by request_id."""

    __tablename__ = "loan_workflow_transitions"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=False), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(
        ForeignKey("loan_workflows.workflow_id", ondelete="CASCADE"), nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(String(32))
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(String(512))
    request_id: Mapped[str | None] = mapped_column(String(128), index=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)
    detail: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
