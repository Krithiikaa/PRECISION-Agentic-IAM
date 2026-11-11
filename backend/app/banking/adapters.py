"""SIMULATED enterprise adapters for the loan workflow.

THESE ARE NOT INTEGRATIONS. There is no KYC provider, credit bureau, fraud
service, document store or core-banking system behind them. Each adapter is a
deterministic in-process stand-in returning synthetic data, and every record it
returns carries `"simulated": True` and the adapter name, so nothing downstream
can mistake it for a real verification.

What IS real is the path to them: every adapter function is a PROTECTED TOOL
(app/enforcement/tools.py). It cannot be called except through the AEM after
the PDP returned ALLOW for the calling agent's own verified credentials, with
the resource and action taken from the tool's spec rather than from the caller.
Replacing an adapter with a real integration changes the handler, not the
authorization path.

    adapter                   protected tool               resource type
    ------------------------  ---------------------------  ---------------
    KYC registry              get_kyc_record               kyc_records
    credit bureau             get_credit_profile           credit_records   (existing)
    document store            verify_loan_documents        loan_documents
    fraud screening           get_fraud_signals            fraud_signals
    risk model                assess_loan_risk             risk_models
    loan management system    approve_loan_application     loan_applications (existing)
                              claim/record workflow        loan_workflows
                              (+ submission: a human route, not an agent tool)

Phase 12: application, document and workflow state for everything the
workflow creates is DURABLE (app/banking/store.py). The adapters are still
simulated; their state now survives a restart.

Thresholds that decide a LOAN are not here. The risk model computes figures;
the decision agent's recommendation and the human approval bands live in
policy and in the workflow's documented rules.
"""
from __future__ import annotations

from typing import Any

from app.banking import store
from app.enforcement import resources

KYC_RECORDS = "kyc_records"
LOAN_DOCUMENTS = "loan_documents"
FRAUD_SIGNALS = "fraud_signals"
RISK_MODELS = "risk_models"

SIMULATED = {"simulated": True,
             "disclaimer": "SIMULATED ADAPTER - synthetic data, not a real check"}


def _tag(adapter: str, record: dict[str, Any]) -> dict[str, Any]:
    return {**record, **SIMULATED, "adapter": adapter}


# --- KYC registry -----------------------------------------------------------
_KYC: dict[str, dict[str, Any]] = {
    "customer-007": {"identity_verified": True, "id_document": "PASSPORT",
                     "address_verified": True, "sanctions_hit": False, "pep": False},
    "customer-042": {"identity_verified": True, "id_document": "DRIVING_LICENCE",
                     "address_verified": False, "sanctions_hit": False, "pep": False},
    "customer-666": {"identity_verified": False, "id_document": None,
                     "address_verified": False, "sanctions_hit": True, "pep": False},
}


def get_kyc_record(customer_id: str) -> dict[str, Any]:
    record = _KYC.get(customer_id)
    if record is None:
        raise resources.ResourceNotFoundError(f"No KYC record for {customer_id!r}")
    return _tag("kyc-registry", {"customer_id": customer_id, **record})


# --- Fraud screening --------------------------------------------------------
_FRAUD: dict[str, dict[str, Any]] = {
    "customer-007": {"prior_fraud_flags": 0, "application_velocity_30d": 1,
                     "device_mismatch": False, "synthetic_identity_score": 0.04},
    "customer-042": {"prior_fraud_flags": 0, "application_velocity_30d": 4,
                     "device_mismatch": True, "synthetic_identity_score": 0.31},
    "customer-666": {"prior_fraud_flags": 2, "application_velocity_30d": 9,
                     "device_mismatch": True, "synthetic_identity_score": 0.92},
}


def get_fraud_signals(customer_id: str) -> dict[str, Any]:
    record = _FRAUD.get(customer_id)
    if record is None:
        raise resources.ResourceNotFoundError(f"No fraud screening data for {customer_id!r}")
    level = ("HIGH" if record["prior_fraud_flags"] or record["synthetic_identity_score"] > 0.8
             else "ELEVATED" if record["device_mismatch"] or record["application_velocity_30d"] > 3
             else "LOW")
    return _tag("fraud-screening", {"customer_id": customer_id, **record, "signal_level": level})


# --- Document store -------------------------------------------------------
# Phase 12: DURABLE. Digests are stored in `loan_documents` at submission
# (computed server-side from the uploaded content) and survive a restart. A
# submitted document "verifies" when the store holds a digest for its type.
REQUIRED_DOCUMENT_TYPES = ("IDENTITY_PROOF", "INCOME_PROOF", "ADDRESS_PROOF")


async def verify_loan_documents(application_id: str, *, session, **_: Any) -> dict[str, Any]:
    stored = await store.documents(session, application_id)
    present = {d["type"] for d in stored}
    missing = [t for t in REQUIRED_DOCUMENT_TYPES if t not in present]
    return _tag("document-store", {
        "application_id": application_id, "documents": stored,
        "missing": missing, "complete": not missing,
    })


# --- Risk model ------------------------------------------------------------
async def assess_loan_risk(application_id: str, *, session, **_: Any) -> dict[str, Any]:
    """Deterministic affordability figures from the application itself.

    Uses the applicant's DECLARED monthly income on the application. It does
    NOT read payroll: no agent holds a credential for payroll_records, and the
    risk model is no exception.
    """
    if store.is_durable(application_id):
        app = await store.application_for_risk(session, application_id)
    else:
        app = resources._LOAN_APPLICATIONS.get(application_id)
        if app is None:
            raise resources.ResourceNotFoundError(f"No loan application {application_id!r}")
    income = int(app.get("declared_monthly_income_inr") or 0)
    term = int(app.get("term_months") or 1)
    # Flat 11% annual rate, standard amortisation.
    r = 0.11 / 12
    emi = app["amount_inr"] * r / (1 - (1 + r) ** -term)
    ratio = round(emi / income, 3) if income else None
    band = ("UNASSESSABLE" if ratio is None else "LOW" if ratio <= 0.3
            else "MEDIUM" if ratio <= 0.5 else "HIGH")
    return _tag("risk-model", {"application_id": application_id,
                               "monthly_instalment_inr": round(emi),
                               "declared_monthly_income_inr": income,
                               "instalment_to_income": ratio, "affordability_band": band})


# --- Loan management system ---------------------------------------------
# Phase 12: DURABLE (app/banking/store.py, PostgreSQL). Submission is a human
# act through a Keycloak-authenticated, Rego-authorized route; the workflow
# queue is reached by the coordinator ONLY through two protected tools, so
# even picking up work is a PDP decision on the coordinator's own credential.
# `session`, `request_id` and `subject_did` are injected by the AEM -- never
# taken from the caller -- so the recorded coordinator is the authenticated
# subject, not a name in the arguments.
LOAN_WORKFLOWS = "loan_workflows"
WORKFLOW_QUEUE_ID = "loan-intake"


async def claim_next_loan_workflow(queue: str = WORKFLOW_QUEUE_ID, *, session,
                                   request_id: str | None = None,
                                   subject_did: str | None = None) -> dict[str, Any]:
    return await store.claim_next(session, queue=queue, request_id=request_id,
                                  coordinator=subject_did)


async def record_loan_workflow_outcome(workflow_id: str, status: str, *, session,
                                       request_id: str | None = None,
                                       subject_did: str | None = None,
                                       claim_token: str | None = None,
                                       steps: list[dict[str, Any]] | None = None,
                                       decision: dict[str, Any] | None = None,
                                       approval: dict[str, Any] | None = None,
                                       customer_message: str | None = None,
                                       coordinator: str | None = None) -> dict[str, Any]:
    if coordinator and subject_did and coordinator != subject_did:
        raise store.WorkflowConflict("the recorded coordinator must be the authenticated caller")
    return await store.record_outcome(
        session, workflow_id=workflow_id, status=status, claim_token=claim_token,
        request_id=request_id, steps=steps, decision=decision, approval=approval,
        customer_message=customer_message, coordinator=subject_did)


async def approve_loan_application(application_id: str, decision_note: str = "", *, session,
                                   request_id: str | None = None,
                                   **_: Any) -> dict[str, Any]:
    """The protected decision, for durable AND demonstration applications.

    A durable (workflow) application is decided at most once, in PostgreSQL;
    a second decision is refused, whatever retry or recovery asks for it.
    The Phase 5 demonstration fixtures keep their in-memory behaviour, which
    the security gates rely on.
    """
    if store.is_durable(application_id):
        return await store.approve(session, application_id, decision_note=decision_note,
                                   request_id=request_id)
    return resources.approve_loan_application(application_id, decision_note)


def reset_workflows() -> None:
    """Tests only: forget cached immutable facts (the database is truncated)."""
    store.forget_cached_facts()
