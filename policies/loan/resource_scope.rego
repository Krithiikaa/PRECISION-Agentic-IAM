# Resource-scope policy (spec POLICY 2).
#
# THE HEADLINE SECURITY DEMONSTRATION:
#
#     valid identity + valid credential  !=  unlimited access
#
# A credential scoped to credit_records says nothing about payroll_records. The
# rule is written generically over the credential's own `allowedResources`
# claim, so it is not "payroll is special" -- it is "anything the credential
# does not name is denied". Adding a new resource type needs no policy change.
package agentic_iam.authz

import rego.v1

resource_scope := {"policy_id": "resource-scope", "policy_version": "v1"}

deny contains object.union(resource_scope, {"reason": "RESOURCE_NOT_ALLOWED"}) if {
	count(valid_credentials) > 0
	not input.resource.type in allowed_resources
}
