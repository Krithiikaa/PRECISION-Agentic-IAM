# MCP invocation authorization (Phase 8).
#
# THE RULE THIS FILE EXISTS TO ENFORCE:
#
#     A VALID ACCESS TOKEN DOES NOT MAKE AN INVOCATION ALLOWED.
#     It makes it EVALUABLE.
#
# And its twin, which is the one the MCP ecosystem gets wrong most often:
#
#     DISCOVERY IS NOT PERMISSION.
#     `tools/list` returns the catalogue. Nothing in this file is consulted
#     for it, and nothing about appearing in it grants anything.
#
# There is no path from "the token verified and the session was bound" to
# ALLOW that skips this file, and no path THROUGH this file that skips any
# other. Credential state, subject status, resource scope, purpose scope,
# sensitive-action escalation, the loan amount bands, approvals and mandates
# all still run, and any one of them denying still denies. An agent whose
# credential was revoked a second ago cannot invoke anything over MCP,
# however fresh its OAuth token.
#
# WHAT THIS FILE READS. `input.pip.mcp` is a VERDICT the MCP transport
# reached before the PDP was asked: it validated the access token's
# signature, issuer, audience and expiry against Keycloak's JWKS, mapped the
# token's `azp` claim to an agent DID, proved the presented session belongs
# to THAT DID, found the named tool in the protected registry, and validated
# the arguments against the tool's declared schema. Rego never sees a token,
# exactly as it never sees a signature or a credential.
#
# WHAT IT NEVER READS. Nothing from `input.context`. An agent supplying
# `{"mcp": {"valid": true}}` is supplying a string: the PIP overwrites the
# field with what the transport established, and `strip_decision_claims`
# removes the obvious self-assertions before policy is reached.
#
# --------------------------------------------------------------------------
# WHY THIS IS ONE MODULE, AND WHY IT ADDS NO CROSS-MODULE NAMES
# --------------------------------------------------------------------------
#
# OPA compiles the WHOLE policy set on every `PUT /v1/policies/{id}`, so a
# module referencing a rule defined in a module that is not loaded yet fails
# with `rego_unsafe_var_error` and takes the ENTIRE set down -- every gate at
# once. That is the Phase 6 finding; Phase 7 responded by introducing zero
# new cross-module names, and Phase 8 does the same.
#
# Every name this module READS (`valid_credentials`, `allowed_purposes`) is
# already defined in `decision.rego`, which OPA loads first. Every name it
# DEFINES (`deny`, `allow`) is already seeded there. `decision.rego` and
# `security/sensitive.rego` are untouched by this phase.
#
# Removing this module leaves every other module compiling, and removing it
# DENIES rather than grants: without `mcp_channel_permitted` contributing,
# the deny below simply stops firing and the ordinary rules decide -- which
# is the pre-Phase-8 behaviour, not a bypass.
#
# --------------------------------------------------------------------------
# WHY THIS MODULE CONTRIBUTES A DENY AND NOT AN ALLOW
# --------------------------------------------------------------------------
#
# THIS IS THE MOST IMPORTANT DECISION IN THIS FILE.
#
# Phase 7 had to contribute `allow` rules because an A2A payment is an action
# no other module authorises -- without them, `execute_payment` would always
# have been denied. MCP is different in kind: it is a TRANSPORT for actions
# that other modules already decide. `get_credit_profile` over MCP is the
# same question as `get_credit_profile` over the direct API, and
# `loan/credit.rego` already answers it.
#
# So if this module contributed an `allow`, it would be creating a SECOND way
# to authorise an action that already had one -- and under deny-overrides a
# second allow is a widening. An agent that could not read a credit record
# directly must not be able to read it by asking over MCP instead.
#
# Therefore this module only ever SUBTRACTS. It denies invocations that the
# MCP channel must not carry, and is silent otherwise, letting the ordinary
# rules decide exactly as they would for any other caller. The channel can
# narrow what is reachable; it can never widen it.

package agentic_iam.authz

import rego.v1

mcp_invocation := {"policy_id": "mcp-invocation", "policy_version": "v1"}

# --- is this an MCP request at all? ---------------------------------------
# Every rule below guards on this. An ordinary Phase 1-7 request has
# `present == false` and is decided exactly as it was before Phase 8.
mcp_present if input.pip.mcp.present == true

mcp_config := data.agentic_iam.config.mcp

# FAIL CLOSED ON MISSING CONFIGURATION. An absent eligibility list is not
# "everything is eligible". This mirrors A2A_POLICY_UNCONFIGURED and
# JIT_POLICY_UNCONFIGURED, and for the same reason: an operator who forgot to
# push the data document must get a refusal, not an open door.
mcp_config_present if count(object.keys(mcp_config)) > 0

deny contains object.union(mcp_invocation, {"reason": "MCP_POLICY_UNCONFIGURED"}) if {
	mcp_present
	not mcp_config_present
}

# --- the transport's own verdict, restated as policy ----------------------
# The Python transport already refuses each of these. They are asserted again
# here so the properties are REVIEWABLE IN THE POLICY SET rather than
# emergent from control flow -- the same reason Phase 7 restates envelope
# validity in `a2a/transaction.rego`. A reviewer reading only the policies
# can see that an unauthenticated or unbound MCP call cannot be allowed.

deny contains object.union(mcp_invocation, {"reason": "MCP_SESSION_NOT_BOUND"}) if {
	mcp_present
	not input.pip.mcp.session_bound == true
}

deny contains object.union(mcp_invocation, {"reason": "MCP_TOKEN_MISSING"}) if {
	mcp_present
	not input.pip.mcp.authenticated == true
}

deny contains object.union(mcp_invocation, {"reason": "MCP_ARGUMENTS_MALFORMED"}) if {
	mcp_present
	not input.pip.mcp.arguments_validated == true
}

# --- which actions may be reached over MCP at all -------------------------
# NOT every protected tool should be remotely invocable merely because it
# exists. This is a risk decision, so the set is policy CONFIGURATION that a
# risk owner changes (policies/data/mcp_policy.json), never a constant in
# Python.
#
# Note this is an action allow-list, not a tool allow-list: the tool name is
# chosen by the client, while the action is what the SERVER's registry
# declares for that tool. Keying on the client's string would let a renamed
# tool slip the list.
mcp_action_eligible if {
	input.action in mcp_config.eligible_actions
}

deny contains object.union(mcp_invocation, {"reason": "MCP_ACTION_NOT_ELIGIBLE"}) if {
	mcp_present
	mcp_config_present
	not mcp_action_eligible
}

# --- purpose, restated against credential attestation ---------------------
# `allowed_purposes` is derived in decision.rego ONLY from credentials the
# Phase 2 verifier marked valid. So this denies a purpose the agent holds no
# credential for.
#
# WHY RESTATE IT when `loan/credit.rego` and `loan/application_read.rego`
# already deny PURPOSE_NOT_ALLOWED for their own resources: because those
# rules are resource-scoped, and a future protected tool over a new resource
# would have no purpose rule at all. Over a remote transport that gap would
# be reachable by anyone holding a token. This closes it for every MCP
# invocation regardless of resource, and it can only ever subtract.
deny contains object.union(mcp_invocation, {"reason": "PURPOSE_NOT_ALLOWED"}) if {
	mcp_present
	count(valid_credentials) > 0
	not input.purpose in allowed_purposes
}

# --- the channel may not carry an action for a resource nobody attested ---
# Same reasoning as the purpose rule: resource scope is enforced by
# `loan/resource_scope.rego` for the data plane, and restating it here means
# a new resource reached over MCP cannot bypass scoping by being new.
deny contains object.union(mcp_invocation, {"reason": "RESOURCE_NOT_ALLOWED"}) if {
	mcp_present
	count(valid_credentials) > 0
	not input.resource.type in allowed_resources
}
