package subpolicy

import rego.v1

# A rule-based authority's policy: attest the holder's membership of an allowed
# institution, for the project the request names.

requirements := {"applicant": ["membership"]}

issues := "MembershipAttestation"

memberships := [c |
	some c in input.presentations.applicant
	c.type == "membership"
	c.trusted
	c.subject == input.holders.applicant
	c.claims.institution in input.policy_data.allowedInstitutions
	c.claims.project == input.request.project
]

default decision := false

decision if count(memberships) > 0

verification_tasks := [{"index": c.index} | some c in memberships]

credential := {
	"subject": input.holders.applicant,
	"claims": {"institution": memberships[0].claims.institution, "project": input.request.project},
}

result := {
	"decision": true,
	"verification_tasks": verification_tasks,
	"vc_supplied_verification_tasks": [],
	"credential": credential,
} if decision

result := {"decision": false, "verification_tasks": [], "vc_supplied_verification_tasks": []} if not decision
