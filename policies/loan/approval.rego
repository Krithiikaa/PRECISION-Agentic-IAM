# High-value loan decisions (Phase 5).
#
# The rule that closes the loop:
#
#     valid capability credential
#   + resource the credential actually names
#   + purpose the credential was issued for
#   + a VALID, BOUND, UNCONSUMED human approval
#   = ALLOW
#
# Every one of those is required. The human approval is an ADDITIONAL
# condition, never a substitute: an agent with no credential and a signed
# approval is still denied, because approving an action does not grant the
# agent the standing to perform it. A human says "yes, do this"; the credential
# says "you are the kind of thing that may".
#
# PHASE 5.5. `approval_satisfied` now also requires ENOUGH DISTINCT HUMANS --
# the count loan/amount.rego computes live from the amount on the record. This
# rule did not have to change to gain dual control, which is the point: the
# requirement is expressed once, in the fact, rather than repeated in every
# rule that depends on it.
#
# Read alongside loan/amount.rego, which decides how many people an amount
# needs and permits the small ones outright; security/sensitive.rego, which
# escalates this action while it is unapproved; and security/human_approval.rego,
# which establishes what `approval_satisfied` means.
package agentic_iam.authz

import rego.v1

loan_approval := {"policy_id": "loan-approval", "policy_version": "v1"}

allow contains object.union(loan_approval, {"reason": "HUMAN_APPROVED_AND_POLICY_MATCH"}) if {
	input.action == "approve_loan"
	input.resource.type == "loan_applications"

	# The agent must be authorised to act here in its own right...
	some c in valid_credentials
	"loan_applications" in c.claims.allowedResources
	c.claims.purpose == input.purpose

	# ...AND a human must have approved this exact action.
	approval_satisfied
}

# A loan decision attempted for a purpose the credential was not issued for.
#
# Stated explicitly so the reason is diagnostic rather than the default
# NO_MATCHING_POLICY -- and, because deny-overrides beats escalation, so that a
# request which is ALREADY invalid is refused outright instead of being sent to
# a human. Nobody should be asked to approve something that would be denied
# whatever they decided.
deny contains object.union(loan_approval, {"reason": "PURPOSE_NOT_ALLOWED"}) if {
	input.action == "approve_loan"
	input.resource.type == "loan_applications"
	count(valid_credentials) > 0
	not input.purpose in allowed_purposes
}
