# Agent-to-agent transaction authorization (Phase 7).
#
# THE RULE THIS FILE EXISTS TO ENFORCE:
#
#     A VALID A2A SIGNATURE DOES NOT MAKE A TRANSACTION ALLOWED.
#     It makes it EVALUABLE.
#
# There is no path from "the envelope verified" to ALLOW that skips this file,
# and -- more importantly -- there is no path through this file that skips any
# OTHER file. Credential state, the subject's identity status and resource
# scope all still run against the SENDER, and any one of them denying still
# denies. An agent whose credential was revoked a second ago cannot instruct
# anybody to do anything, however perfect its signature.
#
# WHAT THIS FILE READS. `input.pip.a2a` is a VERDICT the A2A service reached:
# it resolved the sender's public key from the PHASE 1 DID Document (not from
# the ANS, which is a directory), verified the Ed25519 signature over the
# canonical envelope, checked the signing key was allowed to sign when it
# claims to have, checked the audience and the freshness against the SERVER
# clock, confirmed the receiver is the authenticated submitter, and compared
# the signed amount against what the PIP read from the record. Rego never sees
# a signature, exactly as it never sees a credential's.
#
# WHAT IT NEVER READS. Nothing from `input.context`. An agent supplying
# `{"a2a": {"valid": true}}` is supplying a string; the PIP overwrites the
# field with what the service established, and `strip_decision_claims` removes
# the obvious self-assertions before policy is reached. In particular NO RULE
# HERE READS AN AMOUNT FROM THE ENVELOPE -- `input.pip.a2a.signed_amount_inr`
# is reported so policy can see that the sender committed to a figure, and the
# figure the bands are compared against is
# `input.pip.resource.attributes.amount_inr`, read server-side.
#
# --------------------------------------------------------------------------
# WHY THIS IS ONE MODULE AND NOT TWO
# --------------------------------------------------------------------------
#
# OPA compiles the WHOLE policy set on every `PUT /v1/policies/{id}`, so a
# module referencing a rule defined in a module that is not loaded yet fails
# with `rego_unsafe_var_error` and takes the ENTIRE set down -- every gate at
# once, not just the new one. That is the Phase 6 finding, and it is why
# `decision.rego` seeds cross-module names.
#
# Splitting the payment bands into their own module would have introduced
# exactly that dependency and required two new seeds in `decision.rego`. Phase
# 7 therefore introduces ZERO new cross-module rule names: every name this
# module READS (`valid_credentials`, `capabilities`, `allowed_resources`,
# `allowed_purposes`, `approval_satisfied`) is already defined or already
# seeded in `decision.rego`, which OPA loads first, and every name it DEFINES
# (`deny`, `allow`, `human_required`) is already seeded there too.
#
# Removing this module therefore leaves every other module compiling, and
# removing it DENIES rather than grants -- there is no other `allow` rule in
# the set for `execute_payment` on `payment_instructions`.
#
# --------------------------------------------------------------------------
# WHY `execute_payment` IS NOT IN security/sensitive.rego
# --------------------------------------------------------------------------
#
# `sensitive.rego` escalates its action set to ONE human, and guards itself out
# of the two bands `loan/amount.rego` owns. Both of those guard names are
# loan-scoped, so adding `execute_payment` to that set would escalate EVERY
# payment -- including a trivial one -- to a person. Referring every small
# payment to a human manufactures rubber-stamping, which is a worse control
# than not asking.
#
# `loan/amount.rego` only needed those guards because `approve_loan` was
# already in the set from Phase 5. Phase 7 has no such legacy, so this module
# owns the payment escalation outright and `sensitive.rego` is not touched.
#
# --------------------------------------------------------------------------
# WHY DUAL CONTROL IS ASSERTED HERE AND NOT VIA `approval_satisfied`
# --------------------------------------------------------------------------
#
# THIS IS THE MOST IMPORTANT DECISION IN THIS FILE.
#
# `approval_satisfied` (security/human_approval.rego) requires
# `distinct_approvers >= required_approvals`, and `required_approvals` is
# defined ONLY by `loan/amount.rego` as `2 if requires_dual_control else 1`.
# `requires_dual_control` is guarded on `input.action == "approve_loan"`.
#
# So for a PAYMENT, `required_approvals` evaluates to 1 -- and a payment that
# must have two humans would be satisfied by one, silently, while passing
# every existing test. That is a security regression, not an inconvenience.
#
# Promoting `required_approvals` to a shared rule would mean editing
# `decision.rego`'s seed, `loan/amount.rego` and `human_approval.rego` -- three
# load-bearing modules that eight green gates depend on, to make Phase 7
# easier. Instead this module asserts the COUNT DIRECTLY, on
# `input.pip.approval.distinct_approvers`, which the approval verifier computes
# from the (issuer, subject) pairs inside the SIGNED artifact.
#
# Nothing about Phase 5.5 changes, and payments above the single-approver
# limit get GENUINE dual control: two distinct humans, refused if one person
# signs twice, with the count carried on the escalation so the AEM opens the
# request for the right number of people.
package agentic_iam.authz

import rego.v1

a2a := {"policy_id": "a2a-transaction", "policy_version": "v1"}

# --- the configuration -----------------------------------------------------
# `data.agentic_iam.config.a2a`, pushed into the engine by the PAP from
# `policies/data/a2a_policy.json`. There is deliberately no threshold literal
# anywhere in this file, and none in Python.
a2a_config := data.agentic_iam.config.a2a

a2a_config_present if {
	is_number(a2a_config.thresholds.agent_autonomous_limit_inr)
	is_number(a2a_config.thresholds.single_approver_limit_inr)
}

a2a_autonomous_limit := a2a_config.thresholds.agent_autonomous_limit_inr

a2a_single_approver_limit := a2a_config.thresholds.single_approver_limit_inr

# --- the facts, named ------------------------------------------------------
# Each is a separate rule so a denial can name the ONE thing that was wrong.
# "transaction invalid" tells an operator nothing; "the envelope is addressed
# to another agent" tells them everything.

a2a_present if input.pip.a2a.present == true

a2a_valid if input.pip.a2a.valid == true

a2a_receiver_bound if input.pip.a2a.receiver_bound == true

a2a_payload_verified if input.pip.a2a.payload_verified == true

# THE AMOUNT THE SENDER SIGNED AGREES WITH THE AMOUNT THE SERVER HOLDS.
# Established by the service, which compared them; asserted here so the
# requirement is reviewable in Rego rather than emergent from Python control
# flow. A signed amount is evidence of intent, never evidence of the figure.
a2a_amount_reconciled if input.pip.a2a.amount_reconciled == true

# Is the action/resource pair on the allow-list? An allow-list, never a
# deny-list: an action nobody has analysed for agent-to-agent instruction is
# not eligible, which is the safe direction for a list that grows over time.
a2a_action_eligible if {
	permitted := a2a_config.a2a_eligible_actions[input.action]
	input.resource.type in permitted
}

# The amount, read SERVER-SIDE by the PIP from the resource record. NOT
# `input.pip.a2a.signed_amount_inr`, and NOT `input.context.amount`.
a2a_amount_known if {
	input.pip.resource.attributes.available == true
	is_number(input.pip.resource.attributes.amount_inr)
}

a2a_amount_inr := input.pip.resource.attributes.amount_inr

# --- the bands -------------------------------------------------------------
# Each is guarded on the configuration being present, so a missing data
# document produces NO band rather than the most permissive one.
a2a_within_agent_authority if {
	a2a_present
	a2a_config_present
	a2a_amount_known
	a2a_amount_inr <= a2a_autonomous_limit
}

a2a_requires_single_approver if {
	a2a_present
	a2a_config_present
	a2a_amount_known
	a2a_amount_inr > a2a_autonomous_limit
	a2a_amount_inr <= a2a_single_approver_limit
}

a2a_requires_dual_control if {
	a2a_present
	a2a_config_present
	a2a_amount_known
	a2a_amount_inr > a2a_single_approver_limit
}

# --- the approval, counted here rather than delegated ----------------------
# `distinct_approvers` counts (issuer, subject) pairs inside the VERIFIED
# artifact -- what the approval authority actually attested to, not rows in a
# table. One human signing twice cannot reach 2, because the artifact verifier
# refuses a document naming the same person twice and the database refuses the
# second INSERT.
a2a_approval_usable if {
	input.pip.approval.present == true
	input.pip.approval.valid == true
	input.pip.approval.decision == "APPROVED"
	input.pip.approval.bound_to_request == true
}

a2a_one_approver if {
	a2a_approval_usable
	input.pip.approval.distinct_approvers >= 1
}

a2a_two_approvers if {
	a2a_approval_usable
	input.pip.approval.distinct_approvers >= 2
}

# --- ALLOW: the sender's own authority, below the autonomous limit ---------
# The amount removes the HUMAN, not the authorization. Everything Phase 4
# required still holds: a valid credential, naming this resource, issued for
# this purpose -- and matched on the credential, never on an agent DID.
allow contains object.union(a2a, {"reason": "A2A_TRANSACTION_AUTHORIZED"}) if {
	a2a_present
	a2a_valid
	a2a_receiver_bound
	a2a_payload_verified
	a2a_amount_reconciled
	a2a_config_present
	a2a_action_eligible
	a2a_within_agent_authority

	some c in valid_credentials
	input.resource.type in c.claims.allowedResources
	c.claims.purpose == input.purpose
}

# --- ALLOW: one authorized human, in the middle band ----------------------
allow contains object.union(a2a, {"reason": "A2A_HUMAN_APPROVED_AND_POLICY_MATCH"}) if {
	a2a_present
	a2a_valid
	a2a_receiver_bound
	a2a_payload_verified
	a2a_amount_reconciled
	a2a_config_present
	a2a_action_eligible
	a2a_requires_single_approver

	some c in valid_credentials
	input.resource.type in c.claims.allowedResources
	c.claims.purpose == input.purpose

	a2a_one_approver
}

# --- ALLOW: TWO DISTINCT humans, above the single-approver limit ----------
# The count is asserted directly rather than through `approval_satisfied`,
# which would evaluate `required_approvals` as 1 for a payment. See the module
# header: this is what makes dual control on a payment real.
allow contains object.union(a2a, {"reason": "A2A_DUAL_CONTROL_SATISFIED"}) if {
	a2a_present
	a2a_valid
	a2a_receiver_bound
	a2a_payload_verified
	a2a_amount_reconciled
	a2a_config_present
	a2a_action_eligible
	a2a_requires_dual_control

	some c in valid_credentials
	input.resource.type in c.claims.allowedResources
	c.claims.purpose == input.purpose

	a2a_two_approvers
}

# --- HUMAN_APPROVAL_REQUIRED: one human -----------------------------------
# Carries `required_approvals` so the AEM opens the request for the right
# number of people without deciding the number itself: policy decides, the
# enforcement layer carries.
human_required contains object.union(a2a, {
	"reason": "A2A_PAYMENT_REQUIRES_HUMAN",
	"required_approvals": 1,
}) if {
	a2a_present
	a2a_valid
	a2a_amount_reconciled
	a2a_action_eligible
	a2a_requires_single_approver
	not a2a_one_approver
}

# --- HUMAN_APPROVAL_REQUIRED: two distinct humans -------------------------
# Guarded on the COUNT, not on `approval_satisfied`. With one signature in
# hand this still escalates -- correctly -- rather than falling silently to
# the default deny, so the queue keeps showing "1 of 2" and the second officer
# knows they are needed.
#
# `DUAL_APPROVAL_REQUIRED` is reused verbatim from Phase 5.5 rather than given
# an A2A-specific twin: it means exactly the same thing, and a second spelling
# would be a second thing the console and the queue must learn.
human_required contains object.union(a2a, {
	"reason": "DUAL_APPROVAL_REQUIRED",
	"required_approvals": 2,
}) if {
	a2a_present
	a2a_valid
	a2a_amount_reconciled
	a2a_action_eligible
	a2a_requires_dual_control
	not a2a_two_approvers
}

# --- DENY: the configuration is not loaded --------------------------------
# The engine restarted and nobody pushed the data document, or somebody
# removed it. Either way the thresholds are unknown, and an unknown threshold
# is not a permissive one.
deny contains object.union(a2a, {"reason": "A2A_POLICY_UNCONFIGURED"}) if {
	a2a_present
	not a2a_config_present
}

# --- DENY: the action is not eligible for agent-to-agent instruction ------
deny contains object.union(a2a, {"reason": "A2A_ACTION_NOT_ELIGIBLE"}) if {
	a2a_present
	a2a_config_present
	not a2a_action_eligible
}

# --- DENY: the amount cannot be established -------------------------------
# A payment against a record this system cannot read. Nobody should be asked
# to approve a sum nobody can state, and no agent should move one.
deny contains object.union(a2a, {"reason": "RESOURCE_ATTRIBUTES_UNAVAILABLE"}) if {
	a2a_present
	a2a_config_present
	a2a_action_eligible
	not a2a_amount_known
}

# --- DENY: the signed amount and the server's amount disagree -------------
# THE CENTRAL FINANCIAL RULE, stated as policy rather than left to the service
# that detected it. Never trust a client-provided amount merely because it is
# cryptographically signed.
deny contains object.union(a2a, {"reason": "A2A_AMOUNT_MISMATCH"}) if {
	a2a_present
	not a2a_amount_reconciled
}

# --- DENY: the envelope did not verify ------------------------------------
# DEFENCE IN DEPTH. The A2A service refuses every one of these before the PDP
# is asked at all, so in a correct system these rules never fire. They are
# stated anyway: if the service is ever refactored and the hard refusal is
# dropped, POLICY STILL DENIES -- and the intent is reviewable here rather
# than depending on one Python branch staying correct.
a2a_envelope_failures := {
	"A2A_ENVELOPE_MISSING",
	"A2A_ENVELOPE_MALFORMED",
	"A2A_PROTOCOL_UNSUPPORTED",
	"A2A_PROOF_PURPOSE_INVALID",
	"A2A_SIGNATURE_INVALID",
	"A2A_DOMAIN_MISMATCH",
	"A2A_RECEIVER_MISMATCH",
	"A2A_SENDER_UNKNOWN",
	"A2A_SENDER_NOT_ELIGIBLE",
	"A2A_SENDER_NOT_RESOLVABLE",
	"A2A_KEY_UNKNOWN",
	"A2A_KEY_RETIRED",
	"A2A_KEY_REVOKED",
	"A2A_TRANSACTION_STALE",
	"A2A_TRANSACTION_EXPIRED",
	"A2A_TRANSACTION_NOT_YET_VALID",
	"A2A_TTL_EXCEEDS_MAXIMUM",
	"A2A_REPLAY_BLOCKED",
	"A2A_TRANSACTION_ID_REUSE",
}

deny contains object.union(a2a, {"reason": input.pip.a2a.reason}) if {
	a2a_present
	not a2a_valid
	input.pip.a2a.reason in a2a_envelope_failures
}

# --- DENY: the receiver is not the submitter ------------------------------
# Stated separately from the catch-all above so the REPLAY-TOWARD-ANOTHER-
# RECEIVER attack is denied by name. The control plane refuses it first
# (`agent_self.rego` denies PRINCIPAL_IS_NOT_THE_SUBJECT), the service refuses
# it second, and this is the third. Receiver binding failing quietly is
# exactly the failure nobody notices until an audit.
deny contains object.union(a2a, {
	"reason": "A2A_RECEIVER_MISMATCH",
	"detail": "the envelope is addressed to an agent other than the submitter",
}) if {
	a2a_present
	not a2a_receiver_bound
}

# --- DENY: the payload is not the payload that was signed -----------------
deny contains object.union(a2a, {"reason": "A2A_ENVELOPE_MALFORMED"}) if {
	a2a_present
	a2a_valid
	not a2a_payload_verified
}
