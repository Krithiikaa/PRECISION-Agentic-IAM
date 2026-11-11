# Loan workflow specialist access (blueprint steps 5-9).
#
# One row per specialist resource: which action reaches it and which
# capability a VERIFIED credential must attest. The same shape as
# loan/credit.rego, written as a table so a reviewer sees every specialist's
# boundary at once. Each agent reaches only its own row, because each holds a
# credential for only its own capability -- the KYC agent cannot read fraud
# signals, the fraud agent cannot verify documents.
#
# `capabilities`, `allowed_resources` and `allowed_purposes` are derived in
# decision.rego from credentials the Phase 2 verifier ACCEPTED; nothing a
# caller supplies reaches them. resource-scope (loan/resource_scope.rego)
# still denies any resource a valid credential does not name.
package agentic_iam.authz

import rego.v1

loan_workflow := {"policy_id": "loan-workflow-access", "policy_version": "v1"}

workflow_rules := {
	{"resource": "kyc_records", "action": "read", "capability": "kyc_verification"},
	{"resource": "fraud_signals", "action": "read", "capability": "fraud_detection"},
	{"resource": "loan_documents", "action": "verify", "capability": "document_verification"},
	{"resource": "risk_models", "action": "assess", "capability": "affordability_assessment"},
	# The coordinator's access to the workflow queue in the loan management
	# system: picking up work and recording outcomes. It reads no customer data.
	{"resource": "loan_workflows", "action": "claim", "capability": "loan_workflow_coordination"},
	{"resource": "loan_workflows", "action": "record", "capability": "loan_workflow_coordination"},
}

workflow_resource_types := {r.resource | some r in workflow_rules}

allow contains object.union(loan_workflow, {"reason": "VALID_CREDENTIAL_AND_POLICY_MATCH"}) if {
	some rule in workflow_rules
	rule.resource == input.resource.type
	rule.action == input.action
	input.purpose == "loan_assessment"
	rule.capability in capabilities
	input.resource.type in allowed_resources
	"loan_assessment" in allowed_purposes
}

deny contains object.union(loan_workflow, {"reason": "PURPOSE_NOT_ALLOWED"}) if {
	input.resource.type in workflow_resource_types
	count(valid_credentials) > 0
	not input.purpose in allowed_purposes
}
