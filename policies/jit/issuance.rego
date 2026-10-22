# JIT mandate ISSUANCE (Phase 6).
#
# THE QUESTION THIS PACKAGE ANSWERS:
#
#     May a mandate be issued for this already-permitted action, and with what
#     bounds?
#
# It is deliberately a SEPARATE package from `agentic_iam.authz`, evaluated
# through the same OPA runtime exactly as the control plane is. "May a mandate
# be issued?" is a different question from "is this action permitted?", and
# answering it inside the data-plane combining algorithm would let an issuance
# rule contribute a deny to an ordinary action that never asked for a mandate.
#
# WHAT THE CALLER HAS ALREADY DONE before this is evaluated, and why it matters:
# the AEM ran the FULL data-plane PDP evaluation for the action being mandated.
# `input.decision` carries that verdict. So this package never has to decide
# whether the agent may act -- it already knows -- and the property that falls
# out is the one the whole phase rests on:
#
#     A MANDATE CAN ONLY EVER BE ISSUED FOR SOMETHING THE AGENT COULD DO AT
#     THAT INSTANT. It can never confer authority the PDP would have refused.
#
# In particular a HUMAN_APPROVAL_REQUIRED verdict refuses the mandate outright,
# which is what makes "you cannot use JIT to bypass HITL" structural rather
# than a rule somebody remembered to write.
#
# WHERE THE NUMBERS COME FROM. `data.agentic_iam.config.jit`, pushed into the
# engine by the PAP from `policies/data/jit_policy.json`. There is deliberately
# no TTL literal anywhere in this file, and none in Python.
#
# FAIL CLOSED. If the configuration is not loaded, this file DENIES. An absent
# maximum TTL must never read as "unlimited".
package agentic_iam.jit

import rego.v1

jit_issuance := {"policy_id": "jit-issuance", "policy_version": "v1"}

# --- the configuration -----------------------------------------------------
config := data.agentic_iam.config.jit

config_present if {
	is_number(config.max_ttl_seconds)
	is_number(config.max_uses)
}

max_ttl := config.max_ttl_seconds

max_uses := config.max_uses

# --- the facts -------------------------------------------------------------
# The PDP verdict for the action being mandated, established BEFORE this
# package is evaluated. Anything other than a clean ALLOW means no mandate.
decision_allowed if input.decision.decision == "ALLOW"

decision_escalated if input.decision.decision == "HUMAN_APPROVAL_REQUIRED"

requested_ttl := input.requested.ttl_seconds

requested_uses := input.requested.max_uses

# Is the action/resource pair on the allow-list? An allow-list, never a
# deny-list: an action nobody has analysed for reuse is not eligible, which is
# the safe direction for a list that grows over time.
action_eligible if {
	permitted := config.jit_eligible_actions[input.requested.action]
	input.requested.resource_type in permitted
}

# The Phase 5.5 human-approval actions, excluded from JIT by name as well as by
# omission from the allow-list. Two independent reasons to refuse, because this
# is the interaction that would quietly undo maker-checker -- see the reasoning
# recorded in policies/data/jit_policy.json.
action_excluded if {
	input.requested.action in config.excluded_actions.actions
}

resource_ids_required if config.require_explicit_resource_ids.enabled == true

has_explicit_resource_ids if count(input.requested.resource_ids) > 0

approval_required_for_issuance if config.require_approval_for_issuance.enabled == true

has_valid_approval if input.pip.approval.valid == true

# --- ALLOW -----------------------------------------------------------------
# Every condition must hold. There is no partial issuance and no "issue it with
# a smaller TTL than asked for" -- a caller that asked for too much is told so,
# rather than silently given something different from what it will plan around.
allow contains object.union(jit_issuance, {"reason": "JIT_ISSUANCE_PERMITTED"}) if {
	config_present
	decision_allowed
	action_eligible
	not action_excluded
	requested_ttl > 0
	requested_ttl <= max_ttl
	requested_uses > 0
	requested_uses <= max_uses
	resource_ids_satisfied
	approval_satisfied_for_issuance
}

resource_ids_satisfied if not resource_ids_required

resource_ids_satisfied if {
	resource_ids_required
	has_explicit_resource_ids
}

approval_satisfied_for_issuance if not approval_required_for_issuance

approval_satisfied_for_issuance if {
	approval_required_for_issuance
	has_valid_approval
}

# --- DENY, each naming ONE thing -------------------------------------------
# The configuration is not loaded. An unknown ceiling is not an absent one.
deny contains object.union(jit_issuance, {"reason": "JIT_POLICY_UNCONFIGURED"}) if {
	not config_present
}

# The action itself was not permitted. The mandate is refused for the SAME
# reason the action was, so a caller is not told "JIT denied" when what
# actually happened is that it may not perform the action at all.
deny contains object.union(jit_issuance, {
	"reason": "JIT_SCOPE_EXCEEDS_DECISION",
	"detail": input.decision.reason,
}) if {
	config_present
	not decision_allowed
	not decision_escalated
}

# THE HITL BOUNDARY. Policy wants a human for this action, and a mandate is not
# a human. Refused with the escalation's own reason attached so the caller
# learns it needs an approval, not a bigger TTL.
deny contains object.union(jit_issuance, {
	"reason": "JIT_SCOPE_EXCEEDS_DECISION",
	"detail": "the action requires human approval; a mandate cannot substitute for one",
	"escalation_reason": input.decision.reason,
}) if {
	config_present
	decision_escalated
}

deny contains object.union(jit_issuance, {"reason": "JIT_ACTION_NOT_ELIGIBLE"}) if {
	config_present
	decision_allowed
	not action_eligible
}

deny contains object.union(jit_issuance, {
	"reason": "JIT_ACTION_NOT_ELIGIBLE",
	"detail": "this action is excluded from JIT because a mandate would carry a human decision further than the human gave it",
}) if {
	config_present
	action_excluded
}

deny contains object.union(jit_issuance, {
	"reason": "JIT_TTL_EXCEEDS_POLICY_MAXIMUM",
	"max_ttl_seconds": max_ttl,
}) if {
	config_present
	decision_allowed
	requested_ttl > max_ttl
}

deny contains object.union(jit_issuance, {"reason": "JIT_MALFORMED_REQUEST"}) if {
	config_present
	decision_allowed
	requested_ttl <= 0
}

deny contains object.union(jit_issuance, {
	"reason": "JIT_USES_EXCEED_POLICY_MAXIMUM",
	"max_uses": max_uses,
}) if {
	config_present
	decision_allowed
	requested_uses > max_uses
}

deny contains object.union(jit_issuance, {"reason": "JIT_MALFORMED_REQUEST"}) if {
	config_present
	decision_allowed
	requested_uses <= 0
}

deny contains object.union(jit_issuance, {
	"reason": "JIT_MALFORMED_REQUEST",
	"detail": "this configuration requires a mandate to name its resources explicitly",
}) if {
	config_present
	decision_allowed
	resource_ids_required
	not has_explicit_resource_ids
}

deny contains object.union(jit_issuance, {
	"reason": "JIT_SCOPE_EXCEEDS_DECISION",
	"detail": "this configuration requires a valid human approval before a mandate may be issued",
}) if {
	config_present
	decision_allowed
	approval_required_for_issuance
	not has_valid_approval
}

# --- the combining algorithm ----------------------------------------------
# DENY-OVERRIDES, DEFAULT-DENY, identical in shape to the data plane. An
# absent, empty or non-matching rule set therefore denies. There is no path
# through this file that yields ALLOW without a rule explicitly saying so.
default decision := {
	"decision": "DENY",
	"reason": "JIT_POLICY_UNCONFIGURED",
	"policy_id": null,
	"policy_version": null,
}

decision := result if {
	ordered := sort([d | some d in deny])
	count(ordered) > 0
	result := object.union(ordered[0], {"decision": "DENY"})
}

decision := result if {
	count(deny) == 0
	ordered := sort([a | some a in allow])
	count(ordered) > 0
	result := object.union(ordered[0], {
		"decision": "ALLOW",
		# The bounds the mandate is issued under, echoed so the AEM carries
		# what POLICY approved rather than what the caller asked for. They are
		# the same value here only because a request over the ceiling is
		# denied outright rather than silently reduced.
		"granted_ttl_seconds": requested_ttl,
		"granted_max_uses": requested_uses,
		"max_amount_inr": config.max_amount_inr.value,
	})
}
