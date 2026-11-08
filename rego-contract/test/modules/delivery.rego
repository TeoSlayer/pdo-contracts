package subpolicy

import rego.v1

# A delivery module: it requires nothing of its own, declares the type the policy
# issues, and describes the decision, naming the operation with the applicant
# role's holder as a parameter.

requirements := {}

issues := "policy_decision"

result := {
	"decision": true,
	"verification_tasks": [],
	"vc_supplied_verification_tasks": [],
	"credential": {
		"subject": input.holders.applicant,
		"claims": {"name": "do_download", "parameters": {"holder": input.holders.applicant}},
	},
}
