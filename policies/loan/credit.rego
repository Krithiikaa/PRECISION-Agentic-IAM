# Credit-record read policy (spec POLICY 1).
#
# Note what this rule matches on: capability, credential scope, resource, action
# and purpose. It does NOT match on an agent DID. Any agent holding a valid
# credit_analysis credential scoped to credit_records for loan_assessment
# satisfies it; no agent is named, and naming one would be exactly the
# hardcoded authorization the spec forbids.
package agentic_iam.authz

import rego.v1

loan_credit_read := {"policy_id": "loan-credit-read", "policy_version": "v1"}

# POLICY 1: valid credit capability + READ + credit_records + loan_assessment.
allow contains object.union(loan_credit_read, {"reason": "VALID_CREDENTIAL_AND_POLICY_MATCH"}) if {
	input.action == "read"
	input.resource.type == "credit_records"
	input.purpose == "loan_assessment"
	"credit_analysis" in capabilities
	"credit_records" in allowed_resources
	"loan_assessment" in allowed_purposes
}

# PURPOSE is enforced separately from ACTION. A credential issued for
# loan_assessment does not authorise the same read for a different purpose --
# this is what stops "the action name was right" from being sufficient.
deny contains object.union(loan_credit_read, {"reason": "PURPOSE_NOT_ALLOWED"}) if {
	input.resource.type == "credit_records"
	count(valid_credentials) > 0
	not input.purpose in allowed_purposes
}
