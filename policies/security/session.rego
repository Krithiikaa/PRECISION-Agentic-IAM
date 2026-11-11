# Global session state (CSA paper section 4.2 Layer 4, R-214 kill switch).
#
# Consumes the Session State Synchronizer ledger as the PIP read it
# (`input.pip.session`). The ledger is written ONLY by the Session Authority;
# no caller can supply this fact, because the PIP builds it from the database.
#
# This one rule is what makes containment effective across EVERY protocol at
# once: the direct API, MCP tools/call and A2A transactions all reach the same
# PDP, so a locked-out agent is denied on its next request through any of them,
# whether or not any adapter was told.
package agentic_iam.authz

import rego.v1

session_policy := {"policy_id": "session-state", "policy_version": "v2"}

deny contains object.union(session_policy, {
	"reason": "SESSION_TERMINATED_SECURITY_LOCKOUT",
	"detail": "the agent's global session was terminated by the Session Authority",
}) if {
	input.pip.subject_resolved == true
	input.pip.session.state == "TERMINATED_IMMEDIATE_SECURITY_LOCKOUT"
}

# Phase 12 (v2). A delegated identity acts on authority derived from its
# parent. If ANY ancestor is no longer ACTIVE -- suspended, terminated,
# expired, or locked out by the Session Authority -- the child is denied on
# its next request. Before this rule, only containment (which cascades)
# stopped a child; an operator suspending the parent left the child working.
deny contains object.union(session_policy, {
	"reason": "DELEGATION_CHAIN_INACTIVE",
	"detail": "an ancestor in this identity's delegation chain is not active",
}) if {
	input.pip.subject_resolved == true
	input.pip.subject.delegation.chain_active == false
}
