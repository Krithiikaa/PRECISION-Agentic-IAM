# Human approval, as authorization policy (Phase 5).
#
# THE RULE THIS FILE EXISTS TO ENFORCE:
#
#     A human approving something does NOT make it allowed.
#     It makes it EVALUABLE.
#
# There is no path from "a human clicked approve" to ALLOW that skips this
# file. The PDP asks again, with the approval as one more fact, and policy
# decides -- exactly as it does with a credential. If an approval could
# short-circuit to ALLOW, the human would have become the authorization
# authority, and every rule about resource scope, purpose and credential state
# would be bypassable by asking a person nicely.
#
# WHAT THIS FILE READS. `input.pip.approval` is a VERDICT reached by the
# approval service: it verified the Ed25519 signature against the approval
# authority's DID Document, checked the artifact's audience and validity
# window, and compared its binding against THIS request. Rego never sees a
# signature, exactly as it never sees a credential's.
#
# WHAT IT NEVER READS. Nothing from `input.context`. An agent supplying
# `{"approval": {"valid": true}}` is supplying a string; the PIP overwrites the
# field with what it established, and `strip_decision_claims` removes the
# obvious self-assertions before policy is reached.
#
# PHASE 5.5 adds two dimensions to "is this approval usable?":
#
#   HOW MANY PEOPLE     `approval_has_enough_distinct_humans` compares the
#                       distinct approvers inside the SIGNED artifact against
#                       the requirement loan/amount.rego computes LIVE from the
#                       amount. One human never satisfies a two-human loan, and
#                       one human signing twice never satisfies it either.
#   WHICH KEY SIGNED    the approval authority rotates. A retired key keeps
#                       verifying its own history and cannot issue anything
#                       new, and the three failure modes are denied by name.
package agentic_iam.authz

import rego.v1

human_approval := {"policy_id": "human-approval", "policy_version": "v1"}

# --- the facts, named ------------------------------------------------------
# Each is a separate rule so a denial can name the ONE thing that was wrong.
# "approval invalid" tells an operator nothing; "the approval was for a
# different resource" tells them everything.

approval_present if input.pip.approval.present == true

approval_valid if input.pip.approval.valid == true

approval_decision_is_approved if input.pip.approval.decision == "APPROVED"

approval_bound_to_request if input.pip.approval.bound_to_request == true

# --- dual control (Phase 5.5) ----------------------------------------------
# `distinct_approvers` counts (issuer, subject) pairs inside the VERIFIED
# artifact -- what the approval authority actually attested to, not rows in a
# table. `required_approvals` is computed LIVE by loan/amount.rego from the
# amount on the record, NOT read from the approval. An attacker who could edit
# the stored requirement would otherwise be able to lower it.
approval_has_enough_distinct_humans if {
	input.pip.approval.distinct_approvers >= required_approvals
}

# --- the allow contribution -------------------------------------------------
# NOTE what this does NOT do: it does not allow anything on its own. It is a
# fact other policies build on -- see loan/approval.rego, which additionally
# requires a valid capability credential and a permitted resource. A human
# approval never substitutes for the agent having been authorised to act at
# all; it is an ADDITIONAL requirement on top, never a replacement.
approval_satisfied if {
	approval_present
	approval_valid
	approval_decision_is_approved
	approval_bound_to_request
	approval_has_enough_distinct_humans
}

# --- denials, each with its own reason --------------------------------------
# These fire only when an approval was actually PRESENTED and found wanting.
# An action that simply has not been approved yet is not a denial -- it is
# HUMAN_APPROVAL_REQUIRED, produced by security/sensitive.rego.
#
# The distinction matters operationally: "go and get this approved" and "the
# approval you have is not usable" are different instructions.

deny contains object.union(human_approval, {"reason": "APPROVAL_EXPIRED"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_EXPIRED"
}

deny contains object.union(human_approval, {"reason": "APPROVAL_ALREADY_CONSUMED"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_ALREADY_CONSUMED"
}

deny contains object.union(human_approval, {"reason": "APPROVAL_REJECTED"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_REJECTED"
}

# The tamper case. The artifact is genuine and correctly signed -- it is simply
# about a DIFFERENT action, resource, agent or request. Nothing was forged;
# the approval just does not apply here.
deny contains object.union(human_approval, {"reason": "APPROVAL_BINDING_MISMATCH"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_BINDING_MISMATCH"
}

deny contains object.union(human_approval, {"reason": "APPROVAL_SIGNATURE_INVALID"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_SIGNATURE_INVALID"
}

# The artifact was signed by something that is not the approval authority --
# an agent, a credential issuer, a control-plane administrator. This is the
# self-approval attack, and it is refused by name.
deny contains object.union(human_approval, {"reason": "APPROVAL_AUTHORITY_UNKNOWN"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_AUTHORITY_UNKNOWN"
}

deny contains object.union(human_approval, {"reason": "APPROVAL_DOMAIN_MISMATCH"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_DOMAIN_MISMATCH"
}

# A document that is not an approval artifact at all -- an OIDC token, a
# credential, a presentation, a control-plane proof. Token confusion, refused.
deny contains object.union(human_approval, {"reason": "APPROVAL_MALFORMED"}) if {
	approval_present
	input.pip.approval.reason in {"APPROVAL_MALFORMED", "APPROVAL_PROOF_PURPOSE_INVALID"}
}

# --- Phase 5.5 denials ------------------------------------------------------

# The artifact carries fewer sign-offs than it claims to require. The verifier
# reached this before the artifact was ever accepted.
deny contains object.union(human_approval, {"reason": "APPROVAL_INSUFFICIENT_APPROVALS"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_INSUFFICIENT_APPROVALS"
}

# THE TWO-PERSON ATTACK. An artifact naming the same human twice. The database
# refuses this at INSERT time and the verifier refuses it again on the signed
# document, so a hand-built artifact cannot claim two approvals from one person
# either. Stated here so the DENIAL SAYS SO -- "insufficient approvals" would
# describe a queue; this describes an attempt to defeat dual control.
deny contains object.union(human_approval, {"reason": "APPROVAL_APPROVERS_NOT_DISTINCT"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_APPROVERS_NOT_DISTINCT"
}

# The approval is genuine, correctly signed, bound to this request and carries
# real people -- and POLICY NOW WANTS MORE OF THEM than it does. The amount was
# raised, or a threshold was lowered, after the approval was granted. Neither is
# a forgery; the approval simply is not enough for what is being asked now.
deny contains object.union(human_approval, {"reason": "APPROVAL_INSUFFICIENT_APPROVALS"}) if {
	approval_present
	approval_valid
	approval_decision_is_approved
	approval_bound_to_request
	not approval_has_enough_distinct_humans
}

# --- signing-key lifecycle (Phase 5.5) --------------------------------------
# Rotation must not invalidate history, and must not let a retired key keep
# issuing. These three name the failures on the wrong side of that line.

# The key on the proof was rotated out before the proof claims to have been
# created. Artifacts the key REALLY signed are dated inside its window and are
# unaffected.
deny contains object.union(human_approval, {"reason": "APPROVAL_KEY_RETIRED"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_KEY_RETIRED"
}

# A verification method the approval authority never registered.
deny contains object.union(human_approval, {"reason": "APPROVAL_KEY_UNKNOWN"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_KEY_UNKNOWN"
}

# A key declared compromised. Unlike retirement, this DOES invalidate the
# artifacts it signed -- a compromised key's history is precisely what cannot
# be relied on.
deny contains object.union(human_approval, {"reason": "APPROVAL_KEY_REVOKED"}) if {
	approval_present
	input.pip.approval.reason == "APPROVAL_KEY_REVOKED"
}
