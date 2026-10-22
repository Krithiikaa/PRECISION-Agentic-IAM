# Combining algorithm and shared helpers for the Agentic IAM PDP.
#
# Rego v1 (OPA 1.x). `if` on rule bodies and `contains` for partial sets are
# mandatory in this dialect.
#
# COMBINING ALGORITHM: DENY-OVERRIDES, DEFAULT-DENY.
#
#     any deny            -> DENY
#     else any human      -> HUMAN_APPROVAL_REQUIRED
#     else any allow      -> ALLOW
#     else                -> DENY / NO_MATCHING_POLICY     <- fail closed
#
# An absent, empty or non-matching policy set therefore denies. There is no
# path through this file that yields ALLOW without a policy explicitly saying so.
#
# When several rules deny at once, the reported one is chosen by a deterministic
# sort so the same input always yields the same reason. Every denial in the set
# is individually correct; the sort only decides which is REPORTED. Policy
# authors should therefore guard rules that would otherwise both fire on the
# same input, so the reported reason is the most diagnostic one -- see the
# subject_resolved guard in security/credential_state.rego.
package agentic_iam.authz

import rego.v1

# Seeded empty so this module compiles and evaluates on its own. If the PAP
# deactivates every policy module, `decision` must still resolve -- to DENY via
# the default below. Deactivating all policy must fail CLOSED, not fail to
# compile.
deny contains entry if some entry in []

human_required contains entry if some entry in []

allow contains entry if some entry in []

# --------------------------------------------------------------------------
# CROSS-MODULE RULE SEEDS (Phase 5.5).
#
# OPA compiles the whole policy set on every `PUT /v1/policies/{id}`, so a
# module that references a rule defined in a module which is not loaded YET
# fails with `rego_unsafe_var_error`. The dependencies here are genuinely
# mutual -- security/sensitive.rego stands aside for loan/amount.rego's bands,
# loan/amount.rego stands aside once human_approval.rego's `approval_satisfied`
# holds -- so no load order exists that satisfies all of them.
#
# Seeding the names in THIS module, which is loaded first, makes every module
# compile on its own. Each seed has a body that can never hold, so it
# contributes nothing at evaluation: the real definitions decide, and a policy
# set that is missing one of them leaves the name UNDEFINED rather than TRUE.
# That direction matters. `not within_agent_authority` on an undefined rule is
# true, so a missing loan/amount.rego escalates to a human instead of quietly
# granting an agent autonomous approval authority.
#
# Same discipline as the empty `deny`/`allow`/`human_required` seeds above:
# removing a policy module must fail CLOSED, not fail to compile.
# --------------------------------------------------------------------------

# loan/amount.rego -- the amount bands.
within_agent_authority if false

requires_dual_control if false

# security/human_approval.rego -- whether a usable approval exists.
approval_satisfied if false

# loan/amount.rego -- how many distinct humans this request needs. Seeded with
# a body that never holds, so it does NOT conflict with the real definition;
# with loan/amount.rego absent the name is undefined, and
# `approval_has_enough_distinct_humans` then never holds, which denies.
required_approvals := 1 if false

# jit/use.rego (Phase 6) -- whether a presented mandate covers this request.
# Seeded for the same reason as everything above: OPA compiles the whole policy
# set on each PUT, so a module referencing a name defined in a module that is
# not loaded yet fails with rego_unsafe_var_error and takes the ENTIRE set down
# with it -- every gate at once, not just the new one.
#
# The direction of the failure matters here too. With jit/use.rego absent,
# `jit_satisfied` is false rather than undefined, so nothing treats a missing
# JIT policy as a satisfied mandate. Removing the module denies; it does not
# grant.
jit_satisfied if false

jit_eligible if false

default decision := {
	"decision": "DENY",
	"reason": "NO_MATCHING_POLICY",
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
	ordered := sort([h | some h in human_required])
	count(ordered) > 0
	result := object.union(ordered[0], {"decision": "HUMAN_APPROVAL_REQUIRED"})
}

decision := result if {
	count(deny) == 0
	count(human_required) == 0
	ordered := sort([a | some a in allow])
	count(ordered) > 0
	result := object.union(ordered[0], {"decision": "ALLOW"})
}

# --------------------------------------------------------------------------
# Shared helpers.
#
# CRITICAL BOUNDARY: Rego NEVER re-checks a signature, an expiry date or a
# revocation list. It consumes the verdict the PHASE 2 VERIFIER already
# reached (`c.valid`). Duplicating cryptographic validation here would mean two
# implementations of the same security decision that could disagree.
# --------------------------------------------------------------------------

valid_credentials contains c if {
	some c in input.pip.credentials
	c.valid == true
}

invalid_credentials contains c if {
	some c in input.pip.credentials
	c.valid == false
}

# Capabilities attested by a credential the verifier ACCEPTED. Derived here
# rather than read from a supplied field, so no caller can assert a capability
# it does not hold a valid credential for.
capabilities contains cap if {
	some c in valid_credentials
	cap := c.claims.capability
}

# Resources a valid credential actually authorises.
allowed_resources contains r if {
	some c in valid_credentials
	some r in c.claims.allowedResources
}

# Purposes a valid credential was issued for.
allowed_purposes contains p if {
	some c in valid_credentials
	p := c.claims.purpose
}

has_any_credential if count(input.pip.credentials) > 0

no_valid_credential if count(valid_credentials) == 0
