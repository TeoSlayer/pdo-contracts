package subpolicy

import rego.v1

# Reads the fact a rule-based authority issued, about the holder, from an
# authority this policy agent trusts for it.

requirements := {"applicant": ["MembershipAttestation"]}

attestations := [c |
	some c in input.presentations.applicant
	c.type == "MembershipAttestation"
	c.trusted
	c.subject == input.holders.applicant
]

default decision := false

decision if count(attestations) > 0

result := {
	"decision": decision,
	"verification_tasks": [{"index": c.index} | some c in attestations],
	"vc_supplied_verification_tasks": [],
}
