# Reading a loan application (Phase 6).
#
# WHY THIS EXISTS, and it is not to make a demo prettier.
#
# Phase 6 gives a mandate a FINANCIAL CEILING (`max_amount_inr`), compared on
# every use against the amount the PIP reads server-side. Until this rule
# existed, that ceiling could not be exercised end to end: the only JIT-eligible
# action was `read` on `credit_records`, which carries no amount, and every
# amount-bearing action -- `approve_loan`, `disburse_funds`,
# `override_decision` -- is deliberately excluded from JIT by T-2. So a real
# security control shipped with no live path through it.
#
# Reading an application is the honest way to close that. It is a genuine
# operation (a risk agent reads the application it is assessing), it carries an
# amount, and it is NOT an approval action -- so nothing here touches the
# dual-control boundary. T-2 is untouched: this rule permits READING a loan,
# never deciding one.
#
# WHAT IT DOES NOT DO. It grants no authority over `approve_loan`. An agent
# holding a mandate to read applications up to a ceiling still cannot approve
# any of them, at any amount, with or without a mandate.
#
# COMPILATION NOTE. This module introduces NO new cross-module rule name. It
# consumes `capabilities`, `allowed_resources` and `allowed_purposes`, all of
# which are defined in decision.rego, which OPA loads first. Nothing needs
# seeding, and removing this module leaves every other module compiling.
package agentic_iam.authz

import rego.v1

loan_application_read := {"policy_id": "loan-application-read", "policy_version": "v1"}

# Valid credit capability + READ + loan_applications + loan_assessment.
#
# Matched on capability and credential scope, never on an agent DID -- the same
# discipline loan/credit.rego follows, for the same reason.
allow contains object.union(loan_application_read, {"reason": "VALID_CREDENTIAL_AND_POLICY_MATCH"}) if {
	input.action == "read"
	input.resource.type == "loan_applications"
	input.purpose == "loan_assessment"
	"credit_analysis" in capabilities
	"loan_applications" in allowed_resources
	"loan_assessment" in allowed_purposes
}

# Purpose is enforced separately from action, exactly as it is for credit
# records: a credential issued to assess a loan does not authorise reading one
# for something else.
deny contains object.union(loan_application_read, {"reason": "PURPOSE_NOT_ALLOWED"}) if {
	input.action == "read"
	input.resource.type == "loan_applications"
	count(valid_credentials) > 0
	not input.purpose in allowed_purposes
}
