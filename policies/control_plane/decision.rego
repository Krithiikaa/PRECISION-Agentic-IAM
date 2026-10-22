# Combining algorithm for CONTROL-PLANE decisions (Phase 4.5).
#
# A SEPARATE PACKAGE from `agentic_iam.authz` on purpose. The data plane asks
# "may this agent read this record?"; the control plane asks "may this
# principal change how the system decides?". Mixing them would mean hardening
# the control plane could alter resource-authorization semantics, and every
# data-plane rule would have to be re-read for control-plane inputs it was
# never written for.
#
# Same discipline as the data plane, independently stated:
#
#     any deny        -> DENY
#     else any allow  -> ALLOW
#     else            -> DENY / NO_MATCHING_CONTROL_PLANE_POLICY   <- fail closed
#
# There is NO human_required branch here. A control-plane operation either has
# an authorised principal or it does not; routing administration to a human
# approval flow is HITL and does not exist.
package agentic_iam.control_plane

import rego.v1

# Seeded empty so this module compiles and evaluates alone. Removing every
# control-plane policy must fail CLOSED, not fail to compile.
deny contains entry if some entry in []

allow contains entry if some entry in []

default decision := {
	"decision": "DENY",
	"reason": "NO_MATCHING_CONTROL_PLANE_POLICY",
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
	result := object.union(ordered[0], {"decision": "ALLOW"})
}

# --------------------------------------------------------------------------
# Shared helpers.
#
# CRITICAL BOUNDARY: nothing here re-checks a signature, a nonce or a
# timestamp. `input.principal` exists ONLY because the authenticator already
# proved control of that DID against the published DID Document. Policy
# consumes that verdict, exactly as the data plane consumes the Phase 2
# verifier's.
#
# Equally: `input.principal.roles` is what the REGISTRY granted. It is placed
# in the input document by the server, never copied from the request.
# --------------------------------------------------------------------------

principal_is_agent if input.principal.type == "agent"

principal_is_administrator if input.principal.type == "administrator"

granted_roles contains role if {
	some role in input.principal.roles
}

has_role(role) if role in granted_roles

# The principal is acting on ITSELF. This is the whole of an agent's
# control-plane authority: it may keep its own registration alive and stand
# itself down, and nothing else.
acts_on_self if {
	input.target.id != null
	input.target.id == input.principal.did
}
