# Administrative authority over the control plane (Phase 4.5).
#
# This is the policy that closes S-5 and S-6. Policy administration, forced
# registry sweeps and signing as a custodied identity are the operations that
# can change what every later decision will be -- so they require a principal
# that is not an agent, holding the specific role for that operation.
#
# LEAST PRIVILEGE IS REAL HERE, not decorative. The roles are granted
# separately in configuration, so the identity administrator genuinely cannot
# activate a policy and the policy administrator genuinely cannot sign as an
# agent. That is a security property with a test, not a comment.
#
# NOTE ON ROLE NAMES: the authenticator records which roles a principal was
# granted; THIS FILE decides what they permit. A reviewer asking "what can a
# policy_admin do?" reads Rego, not Python.
package agentic_iam.control_plane

import rego.v1

administration := {"policy_id": "cp-administration", "policy_version": "v1"}

# operation -> the role required to perform it.
# ONE map, deliberately. The UNKNOWN_CONTROL_PLANE_OPERATION rule below is
# derived from it, so an operation added anywhere else would be denied as
# unrecognised even while another file allowed it -- and under deny-overrides
# the denial would win, silently.
required_role := {
	"policy_reload": "policy_admin",
	"policy_activate": "policy_admin",
	"policy_deactivate": "policy_admin",
	"ans_sweep": "registry_admin",
	"ans_deregister": "registry_admin",
	"identity_sign": "identity_admin",
	"pdp_query": "enforcement",
	"aem_enforce": "enforcement",

	# Phase 5 / S-7. Reachable by a MACHINE administrator holding
	# `identity_admin`, and separately by a HUMAN holding IAM_ADMIN (see
	# humans.rego). Both paths exist because automation and the seeding
	# scripts have no browser and must not be given one -- but neither is a
	# fallback for the other, and a caller with neither is refused.
	"agent_create": "identity_admin",
	"agent_status_change": "identity_admin",
	"credential_issue": "identity_admin",
	"credential_revoke": "identity_admin",
	"credential_present": "identity_admin",
	"audit_ingest": "identity_admin",

	# Phase 5.5. Rotating the key that signs human approvals. `identity_admin`
	# because it is key custody, and NOT `policy_admin`: the administrator who
	# decides what the rules are should not also be the one who decides which
	# key attests that a human agreed to something.
	"approval_key_rotate": "identity_admin",

	# Amending a loan amount. Its OWN role, held by nobody else. The amount
	# decides how many humans a request needs, so the ability to change it is
	# as consequential as the ability to approve -- and must not arrive as a
	# side effect of administering identity or policy.
	"loan_amend": "loan_admin",

	# Phase 6. Revoking a live mandate is containment, so it sits with the
	# administrator who already governs identity state -- the same authority
	# that can suspend an agent should be able to end its temporary access,
	# and needing two different administrators to contain one agent would be
	# an obstacle at exactly the wrong moment.
	"jit_revoke": "identity_admin",

	# Rotating the key that signs mandates. `identity_admin` for the same
	# reason `approval_key_rotate` is: it is key custody, and the
	# administrator who decides what the rules are should not also decide
	# which key attests what an agent may temporarily do.
	"jit_key_rotate": "identity_admin",

	# An administrator may also ask for a mandate -- for automation and the
	# seeding scripts, which have no browser. `enforcement` rather than an
	# administrative role, because asking for a mandate is an enforcement-path
	# operation and not an administrative one.
	"jit_request": "enforcement",

	# Phase 7. Sweeping expired A2A transactions and reading the ledger's
	# administrative surface. `identity_admin` because it is operational
	# housekeeping over agent activity, alongside `jit_revoke`.
	"a2a_administer": "identity_admin",

	# NOTE WHAT IS DELIBERATELY ABSENT: `a2a_submit`. NO administrator may
	# submit an A2A envelope, however many roles it holds.
	#
	# Receiver binding is enforced by `agent_self.rego` requiring the
	# submitting principal to BE the agent the envelope names. An
	# administrator with a role here would be a privileged bypass of exactly
	# that: `enforcement` can already drive /authorize and /enforce for any
	# subject, and extending it to A2A would let one principal submit an
	# envelope addressed to anybody. The cryptographic binding would still
	# hold, but the authentication half of the binding would not -- and it is
	# the half that stops a captured envelope being presented by whoever
	# captured it.
	#
	# The cost is that automation and the gate must sign as the receiving
	# AGENT rather than as an administrator. That is the correct cost.
}

# Operations that belong to HUMANS. An administrator key is a machine
# credential; deciding on behalf of a person is not something it can do,
# however many roles it holds. Excluded from the unknown-operation rule below
# so they are refused as "not yours" rather than "unrecognised".
human_operations := {"approval_decide", "approval_view", "approval_cancel"}

deny contains object.union(administration, {"reason": "MACHINE_MAY_NOT_APPROVE"}) if {
	principal_is_administrator
	input.operation in human_operations
}

allow contains object.union(administration, {"reason": "ADMINISTRATOR_ROLE_GRANTED"}) if {
	principal_is_administrator
	some operation, role in required_role
	input.operation == operation
	has_role(role)
}

# The principal is a genuine, authenticated administrator -- and is not
# permitted THIS operation. Distinguished from an unknown operation so the
# audit trail separates "wrong administrator" from "unrecognised action".
deny contains object.union(administration, {"reason": "MISSING_CONTROL_PLANE_ROLE"}) if {
	principal_is_administrator
	some operation, role in required_role
	input.operation == operation
	not has_role(role)
}

# An operation this policy set does not define. Denied explicitly so that
# adding a route without adding a rule fails CLOSED and says why, rather than
# silently landing on the default.
deny contains object.union(administration, {"reason": "UNKNOWN_CONTROL_PLANE_OPERATION"}) if {
	principal_is_administrator
	not input.operation in object.keys(required_role)
	not input.operation in human_operations
}
