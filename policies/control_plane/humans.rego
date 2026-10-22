# Human authority over the control plane (Phase 5).
#
# This is where the S-7 closure and the approval authorization live, and where
# the two most important separations in this phase are enforced.
#
# 1. HUMAN ROLE != AGENT CAPABILITY. `LOAN_OFFICER` and `credit_analysis` sit
#    in different trust domains and never meet. Nothing here reads a
#    credential; nothing in the data-plane policies reads a human role.
#
# 1b. (Phase 7) PAYMENT_OFFICER != LOAN_OFFICER. Approving a lending decision
#    and approving the movement of money are different authorities, and
#    neither is a superset of the other. A loan officer is refused a payment
#    approval by name, and a payment officer is refused a loan approval by
#    name. Both are tested.
#
# 2. APPROVING != ADMINISTERING. A loan officer approves loan decisions and has
#    NO authority over agents, credentials or policy. An IAM administrator
#    manages agents, credentials and policy and CANNOT approve a loan. Neither
#    is a superset of the other, and there is deliberately no role that is
#    both.
#
# An auditor can approve nothing and change nothing. That is the whole point of
# the role, and it is stated as a rule rather than left to the absence of one.
#
# PHASE 5.5 adds the two SEPARATION-OF-DUTIES rules that were missing:
#
#   SELF-APPROVAL      the officer who submitted an application may not sign it
#                      off. Maker and checker are different people.
#   TWO-PERSON         under dual control, a human who has already signed one
#                      approval may not satisfy the second one as well.
#
# Both are decided HERE, on server-resolved facts about the approval, and both
# are additionally refused by the database and the artifact verifier. Three
# independent refusals, because separation of duties failing quietly is exactly
# the failure nobody notices until an audit.
package agentic_iam.control_plane

import rego.v1

humans := {"policy_id": "cp-humans", "policy_version": "v1"}

principal_is_human if input.principal.type == "human"

# Realm roles from the VALIDATED token, placed in the input document by the
# server. A request body cannot reach this field.
human_roles contains role if {
	principal_is_human
	some role in input.principal.roles
}

has_human_role(role) if role in human_roles

# --- IAM administration (S-7) ---------------------------------------------
# The identity control plane: creating and terminating agents, minting and
# revoking credentials. Unauthenticated, these let any caller mint itself a
# capability credential and receive ALLOW from the PDP.
iam_admin_operations := {
	"agent_create",
	"agent_status_change",
	"credential_issue",
	"credential_revoke",
	"credential_present",
	"identity_sign",
	"audit_ingest",
}

allow contains object.union(humans, {"reason": "HUMAN_IAM_ADMIN"}) if {
	principal_is_human
	input.operation in iam_admin_operations
	has_human_role("IAM_ADMIN")
}

# --- Approval (§29) --------------------------------------------------------
# Not every authenticated human may approve every action. The role required
# depends on WHAT is being approved, which is why the guard passes the action
# through on the target rather than just an approval id.
loan_decision_actions := {"approve_loan", "disburse_funds", "override_decision"}

# Phase 7. Payments are approved by a DEDICATED role, deliberately not
# LOAN_OFFICER. A loan officer's authority is over lending decisions; letting
# it extend to moving money would be privilege creep arriving as a side
# effect, and neither role is a superset of the other.
payment_actions := {"execute_payment"}

allow contains object.union(humans, {"reason": "HUMAN_LOAN_OFFICER"}) if {
	principal_is_human
	input.operation in {"approval_decide", "approval_cancel"}
	input.target.action in loan_decision_actions
	has_human_role("LOAN_OFFICER")
	not self_approval
	not already_signed_this_approval
}

# The payment approver. Subject to exactly the same two separations of duty a
# loan approver is: the person who raised the instruction may not sign it off,
# and a person who has already signed may not satisfy the second sign-off
# under dual control.
allow contains object.union(humans, {"reason": "HUMAN_PAYMENT_OFFICER"}) if {
	principal_is_human
	input.operation in {"approval_decide", "approval_cancel"}
	input.target.action in payment_actions
	has_human_role("PAYMENT_OFFICER")
	not self_approval
	not already_signed_this_approval
}

# --- separation of duties (Phase 5.5) --------------------------------------
# The identity of a person is (issuer, subject). A username is a label, and a
# subject id is only unique within its issuer -- comparing either alone would
# let two people count as one, which under dual control means one person
# satisfying both approvals.

# The officer of record on the resource, resolved SERVER-SIDE by the guard from
# the approval record and the resource it names. A request body cannot reach it.
submitted_by := input.target.submitted_by

self_approval if {
	prohibit_self_approval
	is_string(submitted_by)
	submitted_by == input.principal.username
}

# Configuration, alongside the amount thresholds: whether maker-checker is in
# force. Absent configuration means IT IS -- an unloaded switch must not read as
# "separation of duties is off".
prohibit_self_approval if {
	data.agentic_iam.config.loan.separation_of_duties.prohibit_self_approval == true
}

prohibit_self_approval if {
	not is_boolean(data.agentic_iam.config.loan.separation_of_duties.prohibit_self_approval)
}

# Everyone who has already signed this approval, resolved server-side from
# `approval_signoffs`.
already_signed_this_approval if {
	some existing in input.target.existing_approvers
	existing.issuer == input.principal.issuer
	existing.subject == input.principal.subject
}

# Reading a pending approval is a lower bar than deciding it: an auditor must
# be able to see what was asked without being able to answer it.
#
# PAYMENT_OFFICER joined this set in Phase 7, and it is not optional. An
# approver who cannot OPEN the request cannot make an informed decision, and
# `APPROVAL_VIEWED` is the audit evidence that they did -- an approval decided
# by someone who never opened it is visible as exactly that. Granting the
# decide authority without the read authority would have produced approvals
# that are technically valid and worthless.
allow contains object.union(humans, {"reason": "HUMAN_MAY_VIEW"}) if {
	principal_is_human
	input.operation == "approval_view"
	some role in {"LOAN_OFFICER", "PAYMENT_OFFICER", "IAM_ADMIN", "AUDITOR"}
	has_human_role(role)
}

# --- explicit denials, so the audit trail is diagnostic --------------------
# Each of these is already covered by default-deny. They are stated so an
# operator reading CONTROL_PLANE_DENIED learns WHY, and so the separations
# above are assertions in the policy rather than gaps in it.

deny contains object.union(humans, {"reason": "HUMAN_MAY_NOT_ADMINISTER_IAM"}) if {
	principal_is_human
	input.operation in iam_admin_operations
	not has_human_role("IAM_ADMIN")
}

deny contains object.union(humans, {"reason": "HUMAN_MAY_NOT_APPROVE_THIS"}) if {
	principal_is_human
	input.operation in {"approval_decide", "approval_cancel"}
	input.target.action in loan_decision_actions
	not has_human_role("LOAN_OFFICER")
}

# A LOAN_OFFICER reaching for a payment lands here, and so does everybody
# else without PAYMENT_OFFICER. Stated explicitly so the audit trail shows
# that the role separation held rather than that no rule matched.
deny contains object.union(humans, {"reason": "HUMAN_MAY_NOT_APPROVE_THIS"}) if {
	principal_is_human
	input.operation in {"approval_decide", "approval_cancel"}
	input.target.action in payment_actions
	not has_human_role("PAYMENT_OFFICER")
}

# MAKER-CHECKER. The right role, the right action, and the wrong person: whoever
# put this application forward. Denied by name, because "you are not authorised"
# would send an operator looking at role assignments for a problem that is not
# there.
deny contains object.union(humans, {"reason": "SELF_APPROVAL_PROHIBITED"}) if {
	principal_is_human
	input.operation in {"approval_decide", "approval_cancel"}
	self_approval
}

# TWO-PERSON CONTROL. A human who has already signed this approval, coming back
# for the second sign-off. The database refuses the INSERT as well; this refuses
# the REQUEST, so the attempt never reaches the record layer and is denied with
# a policy id an auditor can trace.
deny contains object.union(humans, {"reason": "APPROVER_ALREADY_SIGNED"}) if {
	principal_is_human
	input.operation == "approval_decide"
	already_signed_this_approval
}

# An approval for an action no role is defined for. Fails closed and says so,
# rather than landing on the default and looking like a missing principal.
deny contains object.union(humans, {"reason": "NO_ROLE_APPROVES_THIS_ACTION"}) if {
	principal_is_human
	input.operation in {"approval_decide", "approval_cancel"}
	not input.target.action in loan_decision_actions
	not input.target.action in payment_actions
}

# A human reaching for a machine operation. Humans do not heartbeat, do not
# deregister agents and do not administer policy: policy administration is
# deliberately left to a machine principal with a key, so that changing what
# the system enforces requires more than a browser session.
human_only_denied := {
	"ans_heartbeat",
	"ans_deregister",
	"ans_sweep",
	"policy_reload",
	"policy_activate",
	"policy_deactivate",
	"pdp_query",
	"aem_enforce",
	# Phase 5.5. Rotating the approval-signing key is machine/control-plane
	# administration, not something a browser session does. A LOAN_OFFICER
	# certainly cannot, and neither can an IAM_ADMIN: changing which key signs
	# approvals must require a principal that holds a key of its own.
	"approval_key_rotate",
	# And no human may restate a loan amount from a browser. An officer who
	# could amend an amount and then approve it would have defeated the amount
	# policy and maker-checker in one move.
	"loan_amend",
	# Phase 6. A mandate is MACHINE authority: it says what an agent may do
	# briefly, and it is obtained by an agent proving control of its own key.
	# A human asking for one would be asking for authority to be minted for a
	# principal that is not them, from a browser session -- which is precisely
	# the shape of escalation this boundary exists to refuse.
	"jit_request",
	# Rotating the mandate-signing key is key custody, exactly as
	# approval_key_rotate is. Neither a LOAN_OFFICER nor an IAM_ADMIN reaches
	# it: changing which key attests what an agent may temporarily do must
	# require a principal that holds a key of its own.
	"jit_key_rotate",
	# Phase 7. Submitting an A2A envelope is MACHINE-to-machine traffic: it
	# requires proving control of the receiving agent's key, which a browser
	# session does not have and must not be given. A human who could submit
	# one would be relaying an instruction on an agent's behalf, which is the
	# shape of escalation receiver binding exists to refuse.
	"a2a_submit",
	# And administering the transaction ledger is machine/control-plane
	# operations, like ans_sweep.
	"a2a_administer",
}

deny contains object.union(humans, {"reason": "HUMAN_MAY_NOT_PERFORM_MACHINE_OPERATION"}) if {
	principal_is_human
	input.operation in human_only_denied
}

# --- machine principals reaching for HITL ----------------------------------
# The agent self-approval attack, refused by name. An agent must never be able
# to create or answer its own approval; if it could, the entire phase would be
# a formality it performs on itself.
deny contains object.union(humans, {"reason": "AGENT_MAY_NOT_APPROVE"}) if {
	principal_is_agent
	input.operation in {"approval_decide", "approval_view", "approval_cancel"}
}
