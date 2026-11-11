"""Phase 12: durable loan workflow state.

Four new tables; no existing table is altered. Workflows that existed only in
the previous process's memory are gone already (that was the defect); there
is nothing to migrate.

Revision ID: e12c5f9a3d20
Revises: d12a0c4e7b51
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e12c5f9a3d20"
down_revision = "d12a0c4e7b51"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "loan_applications",
        sa.Column("application_id", sa.String(32), primary_key=True),
        sa.Column("customer_id", sa.String(64), nullable=False),
        sa.Column("applicant_name", sa.String(128), nullable=False),
        sa.Column("amount_inr", sa.BigInteger(), nullable=False),
        sa.Column("term_months", sa.Integer(), nullable=False),
        sa.Column("product", sa.String(48), nullable=False),
        sa.Column("declared_monthly_income_inr", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("risk_band", sa.String(32), nullable=False),
        sa.Column("submitted_by", sa.String(255), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by_request", sa.String(128), nullable=True),
    )
    op.create_index("ix_loan_applications_customer_id", "loan_applications", ["customer_id"])
    op.create_table(
        "loan_documents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("application_id", sa.String(32),
                  sa.ForeignKey("loan_applications.application_id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("doc_type", sa.String(32), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("stored_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("application_id", "doc_type", "sha256"),
    )
    op.create_index("ix_loan_documents_application_id", "loan_documents", ["application_id"])
    op.create_table(
        "loan_workflows",
        sa.Column("workflow_id", sa.String(32), primary_key=True),
        sa.Column("application_id", sa.String(32),
                  sa.ForeignKey("loan_applications.application_id"), nullable=False,
                  unique=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("submitted_by", sa.String(255), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("coordinator", sa.String(255), nullable=True),
        sa.Column("lease_token", sa.String(64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_lease_token", sa.String(64), nullable=True),
        sa.Column("resuming", sa.Boolean(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("steps", JSONB, nullable=False),
        sa.Column("decision", JSONB, nullable=True),
        sa.Column("approval", JSONB, nullable=True),
        sa.Column("customer_message", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("request_digest", sa.String(64), nullable=True),
        sa.UniqueConstraint("submitted_by", "idempotency_key",
                            name="uq_loan_workflows_officer_idempotency"),
    )
    op.create_index("ix_loan_workflows_status_updated", "loan_workflows", ["status", "updated_at"])
    op.create_table(
        "loan_workflow_transitions",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column("workflow_id", sa.String(32),
                  sa.ForeignKey("loan_workflows.workflow_id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("from_status", sa.String(32), nullable=True),
        sa.Column("to_status", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("reason", sa.String(512), nullable=True),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
                  nullable=False),
        sa.Column("detail", JSONB, nullable=False),
    )
    op.create_index("ix_loan_workflow_transitions_workflow_id", "loan_workflow_transitions",
                    ["workflow_id"])
    op.create_index("ix_loan_workflow_transitions_request_id", "loan_workflow_transitions",
                    ["request_id"])


def downgrade() -> None:
    op.drop_table("loan_workflow_transitions")
    op.drop_table("loan_workflows")
    op.drop_table("loan_documents")
    op.drop_table("loan_applications")
