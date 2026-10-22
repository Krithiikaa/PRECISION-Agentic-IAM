# Using a JIT mandate, as authorization policy (Phase 6).
#
# THE RULE THIS FILE EXISTS TO ENFORCE:
#
#     A mandate does NOT make an action allowed.
#     It makes a previously-answered question not need re-asking.
#
# There is no path from "this agent holds a grant" to ALLOW that skips this
# file, and -- more importantly -- there is no path through this file that
# skips any OTHER file. `jit_satisfied` is a FACT other rules may build on; it
# never contributes an allow on its own. Credential state, resource scope,
# purpose and the Phase 5.5 amount bands all still run, and any one of them
# denying still denies.
#
# That is the difference between this phase and a security regression. This
# system already has no standing permission: every protected call runs the full
# PIP -> OPA path with nothing cached. A grant that authorised access by itself
# would not be a new capability, it would be the REMOVAL of an existing
# property -- credential revocation, agent suspension and amount bands would
# all stop applying for the life of the grant. So the mandate carries forward
# exactly one thing, the EXPENSIVE precondition, and nothing else.
#
# WHAT THIS FILE READS. `input.pip.jit` is a VERDICT reached by the JIT
# service: it verified the Ed25519 signature against the JIT authority's DID
# Document, checked the signing key was allowed to sign when it claims to have,
# checked the audience and the validity window against the SERVER clock, and
# compared the mandate's scope against THIS request. Rego never sees a
# signature, exactly as it never sees a credential's.
#
# WHAT IT NEVER READS. Nothing from `input.context`. An agent supplying
# `{"jit": {"valid": true}}` is supplying a string; the PIP overwrites the
# field with what it established, and `strip_decision_claims` removes the
# obvious self-assertions before policy is reached.
package agentic_iam.authz

import rego.v1

jit_use := {"policy_id": "jit-use", "policy_version": "v1"}

# --- the facts, named ------------------------------------------------------
# Each is a separate rule so a denial can name the ONE thing that was wrong.
# "grant invalid" tells an operator nothing; "the mandate is for a different
# agent" tells them everything.

jit_present if input.pip.jit.present == true

jit_valid if input.pip.jit.valid == true

jit_bound_to_request if input.pip.jit.bound_to_request == true

jit_covers_resource if input.pip.jit.covers_resource == true

# The mandate has budget left. Reported by the PIP from the RECORD, and
# re-checked atomically by the database when the use is actually spent -- this
# is the advisory read, and the UPDATE is the authority.
jit_has_budget if input.pip.jit.uses_remaining > 0

# THE CREDENTIALS THE MANDATE RESTED ON ARE STILL VALID.
#
# Defence in depth, and the answer to "should a grant survive revocation of the
# credential it was predicated on?" -- no. The PIP already re-verifies every
# credential on every evaluation, so a revoked credential denies through
# credential_state.rego regardless of what this rule says. Asserting it here as
# well makes the INTENT reviewable rather than emergent, so nobody later reads
# the absence of a check as a decision that grants outlive revocation.
jit_credentials_still_valid if {
	every credential_id in input.pip.jit.justified_by_credentials {
		some c in valid_credentials
		c.credential_id == credential_id
	}
}

# --- the fact other policies build on --------------------------------------
# NOTE what this does NOT do: it does not allow anything. It is consumed by
# loan/credit.rego and by security/sensitive.rego, each of which additionally
# requires everything it already required.
jit_satisfied if {
	jit_present
	jit_valid
	jit_bound_to_request
	jit_covers_resource
	jit_has_budget
	jit_credentials_still_valid
}

# `jit_eligible` is seeded in decision.rego and defined here: a request is
# eligible to be SATISFIED by a mandate when one was actually presented. It
# exists so other modules can ask "was a mandate in play?" without having to
# know the shape of input.pip.jit.
jit_eligible if jit_present

# --- denials, each with its own reason --------------------------------------
# These fire only when a mandate was actually PRESENTED and found wanting. A
# request with no mandate is not denied here -- it is simply decided the way it
# would have been before Phase 6 existed, which is the whole point of a grant
# being an input rather than a gate.

deny contains object.union(jit_use, {"reason": "JIT_GRANT_UNKNOWN"}) if {
	jit_present
	input.pip.jit.reason == "JIT_GRANT_UNKNOWN"
}

deny contains object.union(jit_use, {"reason": "JIT_GRANT_EXPIRED"}) if {
	jit_present
	input.pip.jit.reason == "JIT_GRANT_EXPIRED"
}

deny contains object.union(jit_use, {"reason": "JIT_GRANT_NOT_YET_VALID"}) if {
	jit_present
	input.pip.jit.reason == "JIT_GRANT_NOT_YET_VALID"
}

deny contains object.union(jit_use, {"reason": "JIT_GRANT_REVOKED"}) if {
	jit_present
	input.pip.jit.reason == "JIT_GRANT_REVOKED"
}

deny contains object.union(jit_use, {"reason": "JIT_GRANT_EXHAUSTED"}) if {
	jit_present
	input.pip.jit.reason == "JIT_GRANT_EXHAUSTED"
}

# The substitution attacks: wrong agent, wrong action, wrong resource type,
# wrong purpose, or a resource outside the mandate. The PIP names which field
# moved; the denial carries it so an operator learns "this mandate is for
# another agent" rather than "invalid".
deny contains object.union(jit_use, {
	"reason": "JIT_GRANT_BINDING_MISMATCH",
	"differing": input.pip.jit.binding_differences,
}) if {
	jit_present
	input.pip.jit.reason == "JIT_GRANT_BINDING_MISMATCH"
}

deny contains object.union(jit_use, {"reason": "JIT_GRANT_SIGNATURE_INVALID"}) if {
	jit_present
	input.pip.jit.reason == "JIT_GRANT_SIGNATURE_INVALID"
}

deny contains object.union(jit_use, {"reason": "JIT_GRANT_PROOF_PURPOSE_INVALID"}) if {
	jit_present
	input.pip.jit.reason == "JIT_GRANT_PROOF_PURPOSE_INVALID"
}

deny contains object.union(jit_use, {"reason": "JIT_GRANT_DOMAIN_MISMATCH"}) if {
	jit_present
	input.pip.jit.reason == "JIT_GRANT_DOMAIN_MISMATCH"
}

deny contains object.union(jit_use, {"reason": "JIT_GRANT_MALFORMED"}) if {
	jit_present
	input.pip.jit.reason == "JIT_GRANT_MALFORMED"
}

deny contains object.union(jit_use, {"reason": "JIT_AUTHORITY_UNKNOWN"}) if {
	jit_present
	input.pip.jit.reason == "JIT_AUTHORITY_UNKNOWN"
}

# The signing key's own lifecycle, denied by name exactly as the approval
# authority's is.
deny contains object.union(jit_use, {"reason": "JIT_KEY_RETIRED"}) if {
	jit_present
	input.pip.jit.reason == "JIT_KEY_RETIRED"
}

deny contains object.union(jit_use, {"reason": "JIT_KEY_UNKNOWN"}) if {
	jit_present
	input.pip.jit.reason == "JIT_KEY_UNKNOWN"
}

deny contains object.union(jit_use, {"reason": "JIT_KEY_REVOKED"}) if {
	jit_present
	input.pip.jit.reason == "JIT_KEY_REVOKED"
}

# A ceiling the mandate carries was exceeded by the LIVE resource attributes --
# for a loan, the amount moved above what the mandate permits. This is the
# scope-escalation refusal, and it is evaluated against server-side facts
# rather than anything the caller said.
deny contains object.union(jit_use, {"reason": "JIT_CONSTRAINT_VIOLATED"}) if {
	jit_present
	input.pip.jit.reason == "JIT_CONSTRAINT_VIOLATED"
}

# A mandate whose underlying credentials have since been revoked. It verifies
# perfectly and is refused anyway, which is the property that keeps Phase 2's
# "revocation is invalid everywhere at once" true.
deny contains object.union(jit_use, {
	"reason": "JIT_GRANT_REVOKED",
	"detail": "the credentials this mandate rested on are no longer valid",
}) if {
	jit_present
	jit_valid
	not jit_credentials_still_valid
}
