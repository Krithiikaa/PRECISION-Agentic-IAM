# Sensitive-action policy (spec POLICY 6; extended in Phase 5 and Phase 5.5).
#
# Phase 4 made HUMAN_APPROVAL_REQUIRED a decision value with nothing behind it.
# PHASE 5 GIVES IT A CONDITION: the escalation fires only while the action is
# UNAPPROVED. Once every approval the action needs exists, is valid, is bound to
# this exact request and is unconsumed, this rule stops firing and the request
# is decided on its merits -- by loan/approval.rego, which still requires a
# valid capability credential.
#
# That conditionality is the whole mechanism. Without it, an approved action
# would escalate forever and the approval could never be used; with it, and
# only it, the second PDP evaluation can reach ALLOW.
#
# PHASE 5.5 MAKES THE ESCALATION AMOUNT-AWARE, by standing aside in the two
# cases loan/amount.rego owns:
#
#     within_agent_authority   a small enough loan decides on the agent's own
#                              credential. Referring every trivial loan to a
#                              person manufactures rubber-stamping, which is a
#                              worse control than not asking.
#     requires_dual_control    a large enough loan needs TWO people, and
#                              loan/amount.rego raises that escalation with its
#                              own reason and its own count.
#
# Everything else -- a loan in the middle band, and `disburse_funds` /
# `override_decision` at any amount -- escalates here, to one human, exactly as
# it did in Phase 5. A sensitive action whose amount cannot be established also
# lands here: it still requires a human, which is the safe side of that
# uncertainty.
#
# Ordering matters: the combining algorithm is deny-overrides, so a sensitive
# action attempted with an expired or revoked credential is DENIED outright
# rather than escalated. A human is never asked to approve a request that is
# already invalid -- and, just as importantly, an EXPIRED or CONSUMED approval
# is a DENY from human_approval.rego rather than a fresh escalation, so a
# refused action does not quietly loop back to another approval screen.
package agentic_iam.authz

import rego.v1

sensitive_action := {"policy_id": "sensitive-action", "policy_version": "v3"}

sensitive_actions := {"approve_loan", "disburse_funds", "override_decision"}

human_required contains object.union(sensitive_action, {
	"reason": "SENSITIVE_ACTION_REQUIRES_HUMAN",
	"required_approvals": 1,
}) if {
	input.action in sensitive_actions
	not approval_satisfied

	# loan/amount.rego owns both of these bands. Guarded rather than left to
	# the combining algorithm's tie-break: two human_required entries would
	# both be correct, and the one REPORTED would be whichever sorted first --
	# which could tell an operator "one human" for a request that needs two.
	not within_agent_authority
	not requires_dual_control
}
