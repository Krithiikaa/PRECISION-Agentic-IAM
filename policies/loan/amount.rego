# Amount-based loan authorization (Phase 5.5).
#
# THE GAP THIS FILE CLOSES. Until now a LOAN_OFFICER could approve ANY amount,
# because no amount reached any decision. `approve_loan` escalated on the name
# of the action and nothing else, so a five-lakh loan and a two-crore loan were
# the same authorization question. They are not.
#
#     <= agent_autonomous_limit      the agent's own credential is enough
#     <= single_approver_limit       ONE authorized LOAN_OFFICER
#     above that                     TWO distinct authorized humans
#
# WHERE THE NUMBER COMES FROM. `input.pip.resource.attributes.amount_inr`, which
# the PIP read from the loan application record SERVER-SIDE. It is not
# `input.context.amount`: a caller may put anything there and no rule reads it.
# A browser that displays an amount is displaying it, not asserting it.
#
# WHERE THE THRESHOLDS COME FROM. `data.agentic_iam.config.loan`, pushed into
# the engine by the PAP from `policies/data/loan_amount_policy.json`. Rules and
# their configuration are separate because they change for different reasons and
# are reviewed by different people. There is deliberately no threshold literal
# anywhere in this file, and none in Python.
#
# FAIL CLOSED. If the configuration is not loaded, this file DENIES. An absent
# threshold must never read as "no limit" -- that is the single most dangerous
# way for a configuration document to go missing.
package agentic_iam.authz

import rego.v1

loan_amount := {"policy_id": "loan-amount", "policy_version": "v1"}

# --- the configuration -----------------------------------------------------
amount_config := data.agentic_iam.config.loan

config_present if {
	is_number(amount_config.thresholds.agent_autonomous_limit_inr)
	is_number(amount_config.thresholds.single_approver_limit_inr)
}

autonomous_limit := amount_config.thresholds.agent_autonomous_limit_inr

single_approver_limit := amount_config.thresholds.single_approver_limit_inr

# --- the facts -------------------------------------------------------------
# Scoped to the loan DECISION on a loan application. `disburse_funds` and
# `override_decision` keep their Phase 5 behaviour -- always a human -- because
# widening an amount-based exemption to actions that were never analysed for it
# would be exactly the wrong direction to be casual in.
amount_sensitive_action if {
	input.action == "approve_loan"
	input.resource.type == "loan_applications"
}

amount_known if {
	input.pip.resource.attributes.available == true
	is_number(input.pip.resource.attributes.amount_inr)
}

loan_amount_inr := input.pip.resource.attributes.amount_inr

# The band this request falls in. Each is guarded on the configuration being
# present, so a missing data document produces NO band rather than the most
# permissive one.
within_agent_authority if {
	amount_sensitive_action
	config_present
	amount_known
	loan_amount_inr <= autonomous_limit
}

requires_single_approver if {
	amount_sensitive_action
	config_present
	amount_known
	loan_amount_inr > autonomous_limit
	loan_amount_inr <= single_approver_limit
}

requires_dual_control if {
	amount_sensitive_action
	config_present
	amount_known
	loan_amount_inr > single_approver_limit
}

# HOW MANY DISTINCT HUMANS this request needs, computed LIVE on every
# evaluation. Read by human_approval.rego, which will not treat an approval as
# satisfied until that many distinct people have signed it.
#
# Deliberately not read from the approval record: an attacker who could lower
# the stored number would otherwise lower the requirement. The stored number is
# for the queue to display; THIS is what gates the action.
required_approvals := 2 if {
	requires_dual_control
} else := 1

# --- ALLOW: the agent's own authority ---------------------------------------
# Below the autonomous limit the agent still needs everything Phase 4 required:
# a valid credential, naming this resource, issued for this purpose. The amount
# removes the HUMAN, not the authorization.
allow contains object.union(loan_amount, {"reason": "WITHIN_AGENT_APPROVAL_AUTHORITY"}) if {
	input.action == "approve_loan"
	input.resource.type == "loan_applications"
	within_agent_authority

	some c in valid_credentials
	"loan_applications" in c.claims.allowedResources
	c.claims.purpose == input.purpose
}

# --- HUMAN_APPROVAL_REQUIRED: two people ------------------------------------
# Above the single-approver limit. Carries `required_approvals` so the AEM can
# open a request for the right number of people without deciding the number
# itself -- policy decides, the enforcement layer carries.
human_required contains object.union(loan_amount, {
	"reason": "DUAL_APPROVAL_REQUIRED",
	"required_approvals": 2,
}) if {
	requires_dual_control
	not approval_satisfied
}

# --- DENY: the configuration is not loaded ----------------------------------
# The engine restarted and nobody pushed the data document, or somebody removed
# it. Either way the thresholds are unknown, and an unknown threshold is not a
# permissive one.
deny contains object.union(loan_amount, {"reason": "LOAN_POLICY_UNCONFIGURED"}) if {
	amount_sensitive_action
	not config_present
}

# --- DENY: the amount cannot be established ---------------------------------
# A loan decision on an application this system cannot read. Nobody should be
# asked to approve an amount nobody can state, and no agent should proceed on
# one either.
deny contains object.union(loan_amount, {"reason": "RESOURCE_ATTRIBUTES_UNAVAILABLE"}) if {
	amount_sensitive_action
	config_present
	not amount_known
}
