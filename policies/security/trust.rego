# Risk-adaptive enforcement (CSA paper R-103, R-128, R-210).
#
# Consumes the Trust & Risk Engine's verdict as the PIP computed it
# (`input.pip.trust`). The level is derived from recorded, unexpired anomaly
# signals; callers cannot supply it (`trust_score` is a rejected context key).
#
#   TRUSTED     no effect: the request is decided exactly as before
#   REDUCED     sensitive actions need a human, even inside the agent's own
#               amount band -- the paper's "stricter policy" step
#   UNTRUSTED   every request is denied
#
# These rules can only NARROW. Nothing here allows anything.
package agentic_iam.authz

import rego.v1

trust_policy := {"policy_id": "trust-adaptive", "policy_version": "v1"}

# Defined here rather than reusing sensitive.rego's set: OPA compiles the whole
# policy set on every PUT, and a reference to a name in a module that is not
# loaded yet takes the entire set down. A superset is harmless -- it only
# decides which actions a REDUCED-trust agent needs a human for.
trust_sensitive_actions := {
	"approve_loan", "disburse_funds", "override_decision", "execute_payment",
}

deny contains object.union(trust_policy, {
	"reason": "TRUST_TOO_LOW",
	"detail": "the agent's trust score is below the UNTRUSTED threshold",
}) if {
	input.pip.subject_resolved == true
	input.pip.trust.level == "UNTRUSTED"
}

human_required contains object.union(trust_policy, {
	"reason": "REDUCED_TRUST_REQUIRES_HUMAN",
	"required_approvals": 1,
}) if {
	input.pip.subject_resolved == true
	input.pip.trust.level == "REDUCED"
	input.action in trust_sensitive_actions
	not approval_satisfied
	# loan/amount.rego owns the two-person band; guarded so the reported
	# escalation is the one asking for the larger number of humans.
	not requires_dual_control
}
