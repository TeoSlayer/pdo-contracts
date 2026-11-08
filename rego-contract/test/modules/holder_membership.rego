package subpolicy

import rego.v1

# A check module: the holder of the applicant role is a member of an allowed
# institution, for the project the request names, by a credential its configured
# authority signed. It describes no credential; the delivery module does.

requirements := {"applicant": ["membership"]}

memberships := [c |
	some c in input.presentations.applicant
	c.type == "membership"
	c.subject == input.holders.applicant
	c.signer == input.policy_data.membershipAuthority
	c.claims.institution in input.policy_data.allowedInstitutions
	c.claims.project == input.request.project
]

default decision := false

decision if count(memberships) > 0

result := {
	"decision": decision,
	"verification_tasks": [{"index": c.index} | some c in memberships],
	"vc_supplied_verification_tasks": [],
}
