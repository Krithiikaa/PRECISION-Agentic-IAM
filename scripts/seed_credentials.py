#!/usr/bin/env python3
"""Issue the demo credential set to the running agents.

Idempotent-ish: it issues a fresh credential each run. Use --replace to revoke
any existing ACTIVE credentials of the same type first.

All compliance data here is SYNTHETIC. Nothing in this repository constitutes a
real SOX attestation or any other real compliance certification.
"""
from __future__ import annotations

import argparse
import json
import sys
import pathlib
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cp_sign                                                  # noqa: E402

API = "http://localhost:8000"
BANK = "did:poc:organization:bank-demo"
COMPLIANCE = "did:poc:organization:compliance-authority"

# (subject slug, issuer, type, claims, ttl)
CREDENTIAL_SET = [
    ("risk-001", BANK, "AgentCapabilityCredential", {
        "capability": "credit_analysis",
        "allowed_actions": ["READ_CREDIT_PROFILE"],
        "allowed_resources": ["credit_records"],
        "purpose": "loan_assessment",
    }, 3600),
    ("risk-001", BANK, "AgentRoleCredential", {
        "role": "risk_analyst", "department": "credit_risk",
    }, 86400),
    ("risk-001", COMPLIANCE, "ComplianceCredential", {
        "framework": "SOX", "status": "COMPLIANT",
        "scope": "financial_data_processing",
        "disclaimer": "DEMO / SYNTHETIC COMPLIANCE CREDENTIAL - not a real attestation",
    }, 86400 * 30),
    # risk-002 and risk-003 exist so discovery has to choose between real
    # providers. Their credential situations differ deliberately, which is what
    # makes the compliance filter observable:
    #   risk-001  SOX valid
    #   risk-002  SOX short-lived, so it expires during a demo
    #   risk-003  no SOX credential at all
    # --- Phase 7 -----------------------------------------------------
    # The SENDER's authority to instruct a payment. An A2A transaction
    # authorizes the SENDER, so this credential is what the PDP weighs --
    # and payments-001, the agent that actually carries the instruction
    # out, deliberately holds nothing over payment_instructions. Giving it
    # one would change no decision, which is the confused-deputy property
    # expressed as a fact about the seeded data.
    ("risk-001", BANK, "AgentCapabilityCredential", {
        "capability": "payment_execution",
        "allowed_actions": ["EXECUTE_PAYMENT"],
        "allowed_resources": ["payment_instructions"],
        "purpose": "payment_settlement",
    }, 3600),
    ("risk-002", BANK, "AgentCapabilityCredential", {
        "capability": "credit_analysis",
        "allowed_actions": ["READ_CREDIT_PROFILE"],
        "allowed_resources": ["credit_records"],
        "purpose": "loan_assessment",
    }, 3600),
    ("risk-002", COMPLIANCE, "ComplianceCredential", {
        "framework": "SOX", "status": "COMPLIANT",
        "scope": "financial_data_processing",
        "disclaimer": "DEMO / SYNTHETIC COMPLIANCE CREDENTIAL - not a real attestation",
    }, 30),
    ("risk-003", BANK, "AgentCapabilityCredential", {
        "capability": "credit_analysis",
        "allowed_actions": ["READ_CREDIT_PROFILE"],
        "allowed_resources": ["credit_records"],
        "purpose": "loan_assessment",
    }, 3600),
    ("kyc-001", BANK, "AgentCapabilityCredential", {
        "capability": "kyc_verification",
        "allowed_actions": ["READ_KYC_RECORD"],
        "allowed_resources": ["kyc_records"],
        "purpose": "identity_verification",
    }, 3600),
    ("fraud-001", BANK, "AgentCapabilityCredential", {
        "capability": "fraud_detection",
        "allowed_actions": ["READ_FRAUD_HISTORY", "READ_TRANSACTION_PATTERNS"],
        "allowed_resources": ["fraud_records", "transaction_records"],
        "purpose": "fraud_assessment",
    }, 3600),
    ("coordinator-001", BANK, "AgentCapabilityCredential", {
        "capability": "loan_workflow_coordination",
        "allowed_actions": ["DISCOVER_AGENT", "DELEGATE_TASK"],
        "allowed_resources": ["agent_registry"],
        "purpose": "loan_assessment",
    }, 3600),
    ("decision-001", BANK, "AgentCapabilityCredential", {
        "capability": "loan_decision",
        "allowed_actions": ["EVALUATE_FINDINGS"],
        "allowed_resources": ["specialist_findings"],
        "purpose": "loan_assessment",
    }, 3600),
]


def call(method: str, path: str, body=None):
    # PHASE 5 / S-7. Minting a credential is an authorized administrative act:
    # unauthenticated, a caller could mint itself a capability credential and
    # the PDP would faithfully ALLOW on it. This script signs as the machine
    # identity administrator.
    if method == "POST" and (path.endswith("/credentials/issue")
                             or path.endswith("/revoke")):
        data, headers = cp_sign.signed(cp_sign.IDENTITY_ADMIN, method, path, body)
    else:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"content-type": "application/json"}
    req = urllib.request.Request(f"{API}{path}", data=data, method=method,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:200]
        raise SystemExit(f"{method} {path} failed: {exc.code} {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Cannot reach the IAM API at {API}: {exc}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replace", action="store_true",
                        help="Revoke existing ACTIVE credentials of the same type first")
    args = parser.parse_args()

    print(f"Issuing {len(CREDENTIAL_SET)} credentials\n")
    for slug, issuer, credential_type, claims, ttl in CREDENTIAL_SET:
        subject = f"did:poc:agent:{slug}"
        if args.replace:
            for existing in call("GET", f"/api/v1/credentials?subject={subject}"):
                if existing["credential_type"] == credential_type and \
                        existing["status"] == "ACTIVE":
                    call("POST", f"/api/v1/credentials/{existing['credential_id']}/revoke",
                         {"reason": "SUPERSEDED"})
                    print(f"  revoked  {existing['credential_id']}")

        result = call("POST", "/api/v1/credentials/issue", {
            "issuer": issuer, "subject": subject,
            "credential_type": credential_type, "claims": claims,
            "expires_in_seconds": ttl,
        })
        summary = result["summary"]
        print(f"  issued   {credential_type:<28} -> {slug:<16} "
              f"ttl={ttl:>7}s  {result['credential_id']}")

    print("\nInventory:")
    for slug in sorted({s for s, *_ in CREDENTIAL_SET}):
        held = call("GET", f"/api/v1/credentials?subject=did:poc:agent:{slug}")
        active = [c for c in held if c["status"] == "ACTIVE"]
        types = ", ".join(sorted(c["credential_type"] for c in active))
        print(f"  {slug:<18} {len(active)} active: {types}")


if __name__ == "__main__":
    main()
