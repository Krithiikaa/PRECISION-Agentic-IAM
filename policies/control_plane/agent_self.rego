# An agent's control-plane authority over ITSELF (Phase 4.5).
#
# This is the policy that closes S-4. Before it, ANY caller could POST a
# heartbeat naming any DID and keep a dead agent looking alive -- or move it
# out of discovery. Now the caller must have proved control of the DID it
# names, and this rule requires that the DID it proved is the DID it is acting
# on.
#
#     attacker proves nothing            -> authentication refuses  (401)
#     attacker proves it is attacker-x   -> this rule does not fire (403)
#     risk-001 proves it is risk-001     -> ALLOW
#
# An agent has NO other control-plane authority. There is deliberately no rule
# here granting an agent policy administration, however many credentials it
# holds: capability credentials describe what an agent may do with DATA, and
# must never accumulate into authority over the DECISION MACHINERY.
package agentic_iam.control_plane

import rego.v1

agent_self := {"policy_id": "cp-agent-self", "policy_version": "v1"}

# Operations an agent may perform ON ITSELF.
#
# `audit_ingest` joined this set in Phase 5: the running agents report their own
# activity into the audit trail, and that is legitimate -- bound to self,
# exactly like a heartbeat. An agent writing history for ANOTHER agent is not,
# and falls through to the PRINCIPAL_IS_NOT_THE_SUBJECT rule below.
#
# `jit_request` joined in Phase 6, and belongs here for the same reason
# `pdp_query` does: an agent asking for a mandate FOR ITSELF is asking about
# its own authority, and the real gate is elsewhere -- issuance runs the full
# data-plane PDP evaluation, so an agent can only obtain a mandate for
# something it could already do. An agent asking for a mandate naming ANOTHER
# agent is a different thing entirely, and falls through to
# PRINCIPAL_IS_NOT_THE_SUBJECT below.
#
# `jit_revoke` is deliberately NOT here. Ending a live temporary authority is
# an operator action: an agent must not be the only thing able to contain its
# own mandate, and the asymmetry between "may ask" and "may revoke" is the
# point rather than an oversight.
#
# `a2a_submit` joined in Phase 7, and it is the most load-bearing member of
# this set. An A2A envelope names a RECEIVER inside its signature, and the
# target resolver for this operation reads that field -- so `acts_on_self`
# below means "the agent submitting this envelope is the agent it is
# addressed to". THAT IS THE RECEIVER BINDING, and it is enforced by a rule
# that already existed rather than by a new one:
#
#     A -> B, submitted by B    receiverDid == principal   -> ALLOW
#     A -> B, submitted by C    receiverDid != principal   -> PRINCIPAL_IS_NOT_THE_SUBJECT
#     A -> B, submitted by A    receiverDid != principal   -> PRINCIPAL_IS_NOT_THE_SUBJECT
#
# The last case matters as much as the second: if a SENDER could submit an
# envelope addressed to somebody else, it would control both ends of the flow
# and the receiver's consent to receive would not exist.
#
# `a2a_administer` is deliberately NOT here, for the reason `jit_revoke` is
# not: sweeping expired transactions is an operator action.
self_operations := {
	"ans_heartbeat",
	"ans_deregister",
	"pdp_query",
	"aem_enforce",
	"audit_ingest",
	"jit_request",
	"a2a_submit",
}

allow contains object.union(agent_self, {"reason": "AGENT_ACTING_ON_SELF"}) if {
	principal_is_agent
	input.operation in self_operations
	acts_on_self
}

# An agent naming a DIFFERENT subject. Stated as an explicit deny with its own
# reason rather than left to the default: "you may not act for another agent"
# is the single most important thing an operator can be told here, and
# NO_MATCHING_CONTROL_PLANE_POLICY would not say it.
deny contains object.union(agent_self, {"reason": "PRINCIPAL_IS_NOT_THE_SUBJECT"}) if {
	principal_is_agent
	input.operation in self_operations
	not acts_on_self
}

# An agent reaching for an administrative operation. Also explicit: this is the
# privilege-escalation attempt, and it should be legible in the audit trail as
# exactly that.
#
# Guarded against the HITL operations so the more diagnostic
# AGENT_MAY_NOT_APPROVE in humans.rego is the reason REPORTED. Both denials are
# correct and both fire; the combining algorithm's deterministic sort would
# otherwise report the vaguer one, and "an agent tried to approve its own
# action" is the single most important thing to see in an audit trail.
approval_operations := {"approval_decide", "approval_view", "approval_cancel"}

deny contains object.union(agent_self, {"reason": "AGENT_MAY_NOT_ADMINISTER"}) if {
	principal_is_agent
	not input.operation in self_operations
	not input.operation in approval_operations
}
