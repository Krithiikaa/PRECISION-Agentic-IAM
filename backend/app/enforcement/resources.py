"""Protected resources for the Phase 4 enforcement demonstration.

SCOPE NOTE.

This is NOT the full synthetic banking dataset -- that is still a later phase.
It is the smallest set of real resources behind the enforcement boundary, one
per property being demonstrated:

    credit_records     the risk agent's credential names this in allowedResources
    payroll_records    nothing names this
    loan_applications  named by the credential AND gated on a human approval

Same agent, same identity, same valid credential:

    credit_records     -> ALLOW                       (Phase 4)
    payroll_records    -> DENY                        (Phase 4)
    loan_applications  -> HUMAN_APPROVAL_REQUIRED     (Phase 5)

That progression is the point. Each contrast is produced by policy, not by the
resource being absent.

The data is synthetic and obviously so. No real person is represented.
"""
from __future__ import annotations

from typing import Any

# Resource type identifiers, shared with the Rego policies and the tool specs.
CREDIT_RECORDS = "credit_records"
PAYROLL_RECORDS = "payroll_records"
LOAN_APPLICATIONS = "loan_applications"
# Phase 7. The resource an A2A transaction acts on: a payment instruction
# one agent asks another to execute. It carries an amount, so the whole
# amount-integrity chain has something real to run against.
PAYMENT_INSTRUCTIONS = "payment_instructions"


class ResourceNotFoundError(KeyError):
    """The record does not exist. Distinct from 'not permitted'."""


class AmountReconciliationError(ValueError):
    """The amount authorized is not the amount that would be moved.

    Raised INSIDE the enforcement boundary, at the last possible moment,
    so a record that changed between the PDP decision and the execution
    cannot be settled at the new figure. Distinct from a policy denial:
    policy said yes, to a different number.
    """


# Synthetic credit profiles. Values are invented and internally consistent only.
_CREDIT_RECORDS: dict[str, dict[str, Any]] = {
    "customer-007": {
        "customer_id": "customer-007",
        "credit_score": 742,
        "score_band": "GOOD",
        "open_accounts": 4,
        "total_balance_gbp": 18450,
        "utilisation_pct": 31,
        "delinquencies_24m": 0,
        "oldest_account_years": 11,
        "synthetic": True,
    },
    "customer-042": {
        "customer_id": "customer-042",
        "credit_score": 588,
        "score_band": "SUBPRIME",
        "open_accounts": 9,
        "total_balance_gbp": 41200,
        "utilisation_pct": 88,
        "delinquencies_24m": 3,
        "oldest_account_years": 4,
        "synthetic": True,
    },
}

# Synthetic payroll records. Present ONLY so an unauthorised resource exists to
# be denied; no agent in this system holds a credential naming payroll_records.
_PAYROLL_RECORDS: dict[str, dict[str, Any]] = {
    "customer-007": {
        "customer_id": "customer-007",
        "employer": "Synthetic Manufacturing Ltd",
        "annual_salary_gbp": 54000,
        "pay_frequency": "MONTHLY",
        "national_insurance_number": "QQ000000A",  # deliberately the reserved test value
        "synthetic": True,
    },
}


def get_credit_record(customer_id: str) -> dict[str, Any]:
    try:
        return dict(_CREDIT_RECORDS[customer_id])
    except KeyError as exc:
        raise ResourceNotFoundError(f"No credit record for {customer_id!r}") from exc


def get_payroll_record(customer_id: str) -> dict[str, Any]:
    try:
        return dict(_PAYROLL_RECORDS[customer_id])
    except KeyError as exc:
        raise ResourceNotFoundError(f"No payroll record for {customer_id!r}") from exc


def known_customers() -> list[str]:
    return sorted(_CREDIT_RECORDS)


# --- Loan applications (Phase 5; amounts became material in Phase 5.5) -----
# The high-value decision that a human must sign off. Amounts are in Indian
# rupees, matching the demonstration in the phase specification. Entirely
# synthetic: no real applicant, no real institution, no real money.
#
# The AMOUNT here is DATA. What an amount MEANS -- autonomous, one approver, two
# approvers -- is a POLICY question answered by Rego against thresholds held in
# `policies/data/loan_amount_policy.json`. There is deliberately no threshold in
# this file and no `if amount > x` anywhere in Python.
#
# `submitted_by` is the officer of record. It exists so maker-checker is
# enforceable: the person who put an application forward must not be the person
# who signs it off. It is server-side state, never anything a caller supplies.
_LOAN_APPLICATIONS: dict[str, dict[str, Any]] = {
    "loan-2201": {
        "application_id": "loan-2201",
        "customer_id": "customer-220",
        "applicant_name": "C. Demo Applicant",
        "amount_inr": 500_000,
        "amount_display": "\u20b95,00,000",
        "product": "SECURED_PERSONAL_LOAN",
        "term_months": 36,
        "status": "AWAITING_DECISION",
        "risk_band": "LOW",
        "submitted_by": "iam.admin",
        "submitted_at": "2026-08-30T08:50:00Z",
        "disclaimer": "SYNTHETIC DEMO APPLICATION - not a real credit decision",
    },
    "loan-7842": {
        "application_id": "loan-7842",
        "customer_id": "customer-007",
        "applicant_name": "A. Demo Applicant",
        "amount_inr": 2_500_000,
        "amount_display": "\u20b925,00,000",
        "product": "SECURED_PERSONAL_LOAN",
        "term_months": 60,
        "status": "AWAITING_DECISION",
        "risk_band": "MEDIUM",
        "submitted_by": "iam.admin",
        "submitted_at": "2026-08-30T09:00:00Z",
        "disclaimer": "SYNTHETIC DEMO APPLICATION - not a real credit decision",
    },
    "loan-1001": {
        "application_id": "loan-1001",
        "customer_id": "customer-101",
        "applicant_name": "B. Demo Applicant",
        "amount_inr": 1_500_000,
        "amount_display": "\u20b915,00,000",
        "product": "UNSECURED_PERSONAL_LOAN",
        "term_months": 24,
        "status": "AWAITING_DECISION",
        "risk_band": "MEDIUM",
        "submitted_by": "iam.admin",
        "submitted_at": "2026-08-30T09:05:00Z",
        "disclaimer": "SYNTHETIC DEMO APPLICATION - not a real credit decision",
    },
    # Above the single-approver limit: two distinct humans, or nothing happens.
    "loan-9001": {
        "application_id": "loan-9001",
        "customer_id": "customer-900",
        "applicant_name": "D. Demo Applicant",
        "amount_inr": 20_000_000,
        "amount_display": "\u20b92,00,00,000",
        "product": "COMMERCIAL_TERM_LOAN",
        "term_months": 120,
        "status": "AWAITING_DECISION",
        "risk_band": "HIGH",
        "submitted_by": "iam.admin",
        "submitted_at": "2026-08-30T09:10:00Z",
        "disclaimer": "SYNTHETIC DEMO APPLICATION - not a real credit decision",
    },
    # Submitted BY a loan officer, so that officer signing it off is
    # self-approval and is refused. Maker and checker are different people.
    "loan-5150": {
        "application_id": "loan-5150",
        "customer_id": "customer-515",
        "applicant_name": "E. Demo Applicant",
        "amount_inr": 3_000_000,
        "amount_display": "\u20b930,00,000",
        "product": "SECURED_PERSONAL_LOAN",
        "term_months": 48,
        "status": "AWAITING_DECISION",
        "risk_band": "MEDIUM",
        "submitted_by": "loan.officer",
        "submitted_at": "2026-08-30T09:15:00Z",
        "disclaimer": "SYNTHETIC DEMO APPLICATION - not a real credit decision",
    },
}


def known_loan_applications() -> list[str]:
    return sorted(_LOAN_APPLICATIONS)


def get_loan_application(application_id: str) -> dict[str, Any]:
    record = _LOAN_APPLICATIONS.get(application_id)
    if record is None:
        raise ResourceNotFoundError(f"No loan application {application_id!r}")
    return dict(record)


# --- Material attributes (Phase 5.5) ---------------------------------------
# The facts about a resource that CHANGE THE MEANING OR RISK of an operation on
# it. For a loan that is the amount and the officer of record.
#
# Two properties make this worth having, and both depend on it being read HERE
# rather than accepted from a caller:
#
#   * POLICY evaluates the amount. `input.pip.resource.attributes.amount_inr`
#     is established by the PIP from this function. A caller can put anything
#     in `input.context`; no rule reads it.
#   * The APPROVAL BINDS the amount. The digest an approval is bound to covers
#     these attributes, recomputed from server-side state at re-evaluation --
#     so an amount changed after a human agreed to it invalidates the approval
#     instead of riding along with it.
#
# Anything not resolvable is reported as `{"available": False}` with a reason.
# It is never defaulted to a number, because a defaulted amount would be a
# threshold decision made by an absent record.
MATERIAL_ATTRIBUTE_KEYS: tuple[str, ...] = ("amount_inr", "currency", "submitted_by")


def material_attributes(
    resource_type: str, resource_id: str | None
) -> dict[str, Any]:
    """Server-side facts about one resource instance that policy may weigh.

    PHASE 7 added a second resource type. The LOAN branch below is unchanged,
    byte for byte, and a test asserts it: every approval already granted is
    bound to a digest that covers these exact values, so altering what this
    returns for a loan would invalidate stored approvals that are still
    perfectly valid records of what somebody agreed to.
    """
    if resource_type == LOAN_APPLICATIONS and resource_id:
        record = _LOAN_APPLICATIONS.get(resource_id)
        if record is None:
            return {
                "available": False,
                "detail": f"loan application {resource_id!r} could not be read",
            }
        return {
            "available": True,
            "amount_inr": record["amount_inr"],
            "currency": "INR",
            "submitted_by": record["submitted_by"],
        }
    if resource_type == PAYMENT_INSTRUCTIONS and resource_id:
        record = _PAYMENT_INSTRUCTIONS.get(resource_id)
        if record is None:
            return {
                "available": False,
                "detail": f"payment instruction {resource_id!r} could not be read",
            }
        return {
            "available": True,
            "amount_inr": record["amount_inr"],
            "currency": record["currency"],
            "submitted_by": record["submitted_by"],
        }
    return {
        "available": False,
        "detail": f"no material attributes are defined for {resource_type!r}",
    }


def set_loan_amount(application_id: str, amount_inr: int) -> None:
    """Change an application's amount. The TAMPERING lever for the negative tests.

    Deliberately real: §3 requires that an amount changed between the human
    seeing it and the action executing invalidates the approval. Faking that by
    editing a request in flight would prove nothing -- the record itself has to
    move, and the binding has to notice.
    """
    record = _LOAN_APPLICATIONS.get(application_id)
    if record is None:
        raise ResourceNotFoundError(f"No loan application {application_id!r}")
    record["amount_inr"] = int(amount_inr)
    record["amount_display"] = format_inr(amount_inr)


def format_inr(amount: int) -> str:
    """Indian digit grouping: 20000000 -> Rs 2,00,00,000."""
    digits = str(int(amount))
    if len(digits) <= 3:
        grouped = digits
    else:
        head, tail = digits[:-3], digits[-3:]
        parts = []
        while len(head) > 2:
            parts.insert(0, head[-2:])
            head = head[:-2]
        if head:
            parts.insert(0, head)
        grouped = ",".join(parts) + "," + tail
    return "\u20b9" + grouped


def approve_loan_application(application_id: str, decision_note: str = "") -> dict[str, Any]:
    """Record the loan decision. THIS is the protected side effect.

    Reaching this function at all means: a valid credential, a policy match,
    every human approval the amount requires bound to this exact application,
    and an enforcement grant the AEM minted after the PDP said ALLOW. Every one
    of those had to hold.

    The mutation is deliberately real -- the application's status changes -- so
    "the resource was not accessed" is an OBSERVABLE claim in the negative
    tests rather than an assertion about control flow.
    """
    record = _LOAN_APPLICATIONS.get(application_id)
    if record is None:
        raise ResourceNotFoundError(f"No loan application {application_id!r}")
    record["status"] = "APPROVED"
    record["decision_note"] = decision_note
    return dict(record)


def loan_application_status(application_id: str) -> str | None:
    """Read the status WITHOUT the enforcement boundary, for tests only.

    Lets a negative test assert the resource genuinely did not change, rather
    than inferring it from a response body.
    """
    record = _LOAN_APPLICATIONS.get(application_id)
    return record["status"] if record else None


# The pristine demo set, kept so `reset_loan_applications` restores AMOUNTS as
# well as statuses. A tampering test that permanently altered an amount would
# leak into every test that ran after it.
_PRISTINE_LOAN_APPLICATIONS = {
    key: dict(value) for key, value in _LOAN_APPLICATIONS.items()
}


def reset_loan_applications() -> None:
    """Restore the demo applications. Used between tests."""
    for key, pristine in _PRISTINE_LOAN_APPLICATIONS.items():
        _LOAN_APPLICATIONS[key] = dict(pristine)


# --- Payment instructions (Phase 7) ----------------------------------------
# THE A2A DEMONSTRATION RESOURCE. A payment instruction is what one agent asks
# another to execute, and it is the reason Phase 7 needs a resource at all:
# `credit_records` has no amount, and `loan_applications` is an APPROVAL
# resource whose dual-control boundary Phase 7 must not disturb.
#
# The AMOUNT here is DATA. What an amount MEANS -- autonomous, one approver,
# two approvers -- is a POLICY question answered by Rego against thresholds in
# `policies/data/a2a_policy.json`. There is deliberately no threshold in this
# file and no `if amount > x` anywhere in Python.
#
# `submitted_by` is the officer of record, so maker-checker is enforceable on
# a payment exactly as it is on a loan: the person who raised an instruction
# must not be the person who signs it off.
#
# Entirely synthetic: no real beneficiary, no real institution, no real money.
_PAYMENT_INSTRUCTIONS: dict[str, dict[str, Any]] = {
    # Below the autonomous limit: the sending agent's own credential decides.
    "pay-3310": {
        "instruction_id": "pay-3310",
        "customer_id": "customer-220",
        "beneficiary_ref": "cust-220-savings",
        "beneficiary_name": "C. Demo Beneficiary",
        "amount_inr": 50_000,
        "amount_display": "\u20b950,000",
        "currency": "INR",
        "rail": "NEFT",
        "narrative": "Loan disbursement settlement",
        "status": "AWAITING_EXECUTION",
        "submitted_by": "iam.admin",
        "raised_at": "2026-09-22T08:50:00Z",
        "disclaimer": "SYNTHETIC DEMO INSTRUCTION - no real funds move",
    },
    # Above the autonomous limit, at or below the single-approver limit:
    # ONE authorized PAYMENT_OFFICER.
    "pay-3311": {
        "instruction_id": "pay-3311",
        "customer_id": "customer-007",
        "beneficiary_ref": "cust-007-current",
        "beneficiary_name": "A. Demo Beneficiary",
        "amount_inr": 500_000,
        "amount_display": "\u20b95,00,000",
        "currency": "INR",
        "rail": "RTGS",
        "narrative": "Supplier settlement",
        "status": "AWAITING_EXECUTION",
        "submitted_by": "iam.admin",
        "raised_at": "2026-09-22T08:55:00Z",
        "disclaimer": "SYNTHETIC DEMO INSTRUCTION - no real funds move",
    },
    # Above the single-approver limit: TWO distinct humans, or nothing happens.
    "pay-3312": {
        "instruction_id": "pay-3312",
        "customer_id": "customer-900",
        "beneficiary_ref": "cust-900-escrow",
        "beneficiary_name": "D. Demo Beneficiary",
        "amount_inr": 5_000_000,
        "amount_display": "\u20b950,00,000",
        "currency": "INR",
        "rail": "RTGS",
        "narrative": "Commercial escrow release",
        "status": "AWAITING_EXECUTION",
        "submitted_by": "iam.admin",
        "raised_at": "2026-09-22T09:00:00Z",
        "disclaimer": "SYNTHETIC DEMO INSTRUCTION - no real funds move",
    },
    # Raised BY a payment officer, so that officer signing it off is
    # self-approval and is refused. Maker and checker are different people.
    "pay-3313": {
        "instruction_id": "pay-3313",
        "customer_id": "customer-515",
        "beneficiary_ref": "cust-515-savings",
        "beneficiary_name": "E. Demo Beneficiary",
        "amount_inr": 750_000,
        "amount_display": "\u20b97,50,000",
        "currency": "INR",
        "rail": "NEFT",
        "narrative": "Refund settlement",
        "status": "AWAITING_EXECUTION",
        "submitted_by": "payment.officer",
        "raised_at": "2026-09-22T09:05:00Z",
        "disclaimer": "SYNTHETIC DEMO INSTRUCTION - no real funds move",
    },
}


def known_payment_instructions() -> list[str]:
    return sorted(_PAYMENT_INSTRUCTIONS)


def get_payment_instruction(instruction_id: str) -> dict[str, Any]:
    record = _PAYMENT_INSTRUCTIONS.get(instruction_id)
    if record is None:
        raise ResourceNotFoundError(f"No payment instruction {instruction_id!r}")
    return dict(record)


def set_payment_amount(instruction_id: str, amount_inr: int) -> None:
    """Change an instruction's amount. The TAMPERING lever for Phase 7.

    Deliberately real, for the same reason `set_loan_amount` is: an amount
    changed between the sender signing it and the transaction executing must
    invalidate the authorization, and faking that by editing a request in
    flight would prove nothing. The record itself has to move, and the
    reconciliation has to notice.
    """
    record = _PAYMENT_INSTRUCTIONS.get(instruction_id)
    if record is None:
        raise ResourceNotFoundError(f"No payment instruction {instruction_id!r}")
    record["amount_inr"] = int(amount_inr)
    record["amount_display"] = format_inr(amount_inr)


def payment_instruction_status(instruction_id: str) -> str | None:
    """Read the status WITHOUT the enforcement boundary, for tests only.

    Lets a negative test assert no money moved, rather than inferring it from
    a response body.
    """
    record = _PAYMENT_INSTRUCTIONS.get(instruction_id)
    return record["status"] if record else None


def payment_execution_count(instruction_id: str) -> int:
    """How many times this instruction has been executed.

    The exactly-once assertion reads THIS, not a response. A concurrency test
    that only checked responses could not tell one execution from two that
    both reported success.
    """
    record = _PAYMENT_INSTRUCTIONS.get(instruction_id)
    return int(record.get("executions", 0)) if record else 0


def execute_payment_instruction(
    instruction_id: str, expected_amount_inr: int | None = None,
    narrative: str = "",
) -> dict[str, Any]:
    """Execute the payment. THIS is the protected side effect.

    Reaching this function at all means: a verified A2A envelope from an
    ACTIVE sender, a receiver that authenticated as the addressee, a
    non-replayed transaction, a valid scoped credential, a policy match, every
    human approval the amount requires, and an enforcement grant the AEM
    minted after the PDP said ALLOW. Every one of those had to hold.

    THE LAST RECONCILIATION HAPPENS HERE. `expected_amount_inr` is the amount
    the PDP authorized, carried down by the AEM. If the record has moved since
    -- by any path, including one nobody has thought of -- this refuses rather
    than moving a different sum from the one that was permitted. It is the
    final link in the chain, and it is inside the boundary rather than in
    front of it precisely so no caller can skip it.

    The mutation is deliberately real -- status changes and an execution is
    counted -- so "no money moved" is an OBSERVABLE claim in the negative
    tests rather than an assertion about control flow.
    """
    record = _PAYMENT_INSTRUCTIONS.get(instruction_id)
    if record is None:
        raise ResourceNotFoundError(f"No payment instruction {instruction_id!r}")
    if expected_amount_inr is not None and record["amount_inr"] != expected_amount_inr:
        raise AmountReconciliationError(
            f"Refusing to execute {instruction_id}: the authorization permitted "
            f"{expected_amount_inr} but the instruction now reads "
            f"{record['amount_inr']}. An amount that moved after it was "
            f"authorized is not the amount that was authorized."
        )
    record["status"] = "EXECUTED"
    record["executions"] = int(record.get("executions", 0)) + 1
    if narrative:
        record["execution_narrative"] = narrative
    return {
        "instruction_id": instruction_id,
        "status": "EXECUTED",
        "amount_inr": record["amount_inr"],
        "currency": record["currency"],
        "beneficiary_ref": record["beneficiary_ref"],
        "rail": record["rail"],
        "executions": record["executions"],
        "disclaimer": record["disclaimer"],
    }


# The pristine demo set, kept so `reset_payment_instructions` restores AMOUNTS
# and execution counts as well as statuses. A tampering test that permanently
# altered an amount would leak into every test that ran after it.
_PRISTINE_PAYMENT_INSTRUCTIONS = {
    key: dict(value) for key, value in _PAYMENT_INSTRUCTIONS.items()
}


def reset_payment_instructions() -> None:
    """Restore the demo instructions. Used between tests."""
    for key, pristine in _PRISTINE_PAYMENT_INSTRUCTIONS.items():
        _PAYMENT_INSTRUCTIONS[key] = dict(pristine)
