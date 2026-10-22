# Credential-state policy (spec POLICY 3, 4, 5).
#
# These rules consume the PHASE 2 VERIFIER's verdict. They do not re-implement
# signature, expiry or revocation checking -- `c.valid` and `c.reason` are the
# verifier's output, and this file only decides what a given verdict means for
# authorization.
package agentic_iam.authz

import rego.v1

credential_state := {"policy_id": "credential-state", "policy_version": "v2"}

# POLICY 3 -- the subject offered no credential at all.
#
# Guarded on the subject being resolvable. Without the guard an unknown agent
# matches BOTH this rule and the UNKNOWN_SUBJECT rule below, and the combining
# algorithm's tie-break would report whichever reason sorts first -- telling an
# operator "no credential" when the real answer is "we do not know who this is".
# Both denials are correct; only one is diagnostic.
deny contains object.union(credential_state, {"reason": "MISSING_CAPABILITY"}) if {
	input.pip.subject_resolved == true
	not has_any_credential
}

# POLICY 4 -- every credential offered was rejected, at least one as expired.
deny contains object.union(credential_state, {"reason": "CREDENTIAL_EXPIRED"}) if {
	no_valid_credential
	some c in invalid_credentials
	c.reason == "CREDENTIAL_EXPIRED"
}

# POLICY 5 -- every credential offered was rejected, at least one as revoked.
deny contains object.union(credential_state, {"reason": "CREDENTIAL_REVOKED"}) if {
	no_valid_credential
	some c in invalid_credentials
	c.reason == "CREDENTIAL_REVOKED"
}

# Any other verifier rejection (tampered signature, unknown issuer, subject
# mismatch, unregistered). Catch-all so a NEW failure mode from the verifier
# denies rather than falling through unnoticed.
deny contains object.union(credential_state, {"reason": "CREDENTIAL_INVALID"}) if {
	no_valid_credential
	some c in invalid_credentials
	not c.reason in {"CREDENTIAL_EXPIRED", "CREDENTIAL_REVOKED"}
}

# The subject could not be resolved by the PIP at all.
deny contains object.union(credential_state, {"reason": "UNKNOWN_SUBJECT"}) if {
	input.pip.subject_resolved == false
}

# The subject is a REGISTERED identity that is not currently ACTIVE --
# SUSPENDED, TERMINATED or still PROVISIONING.
#
# FOUND DURING PHASE 6, and it is a PHASE 4 GAP rather than a Phase 6 one: the
# PIP has always reported `subject.active`, and until now nothing read it. A
# suspended agent holding a still-valid credential was authorised exactly like
# an active one, so suspending an agent did not actually stop it -- only
# revoking its credentials did.
#
# That matters most for containment. "Suspend the agent" is the obvious first
# move in an incident, and it has to mean something on its own rather than
# being a label that takes effect only once somebody also revokes every
# credential it holds.
#
# Distinct from UNKNOWN_SUBJECT on purpose: "we do not know who this is" and
# "we know exactly who this is and it is suspended" are different incidents,
# and an operator reading the trail needs to be able to tell them apart.
deny contains object.union(credential_state, {"reason": "UNKNOWN_SUBJECT", "detail": "the subject identity is not ACTIVE"}) if {
	input.pip.subject_resolved == true
	input.pip.subject.active == false
}
