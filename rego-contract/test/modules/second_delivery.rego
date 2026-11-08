package subpolicy

import rego.v1

# Describes a credential without declaring its type, so the policy agent must
# refuse to issue.

requirements := {}

result := {
	"decision": true,
	"verification_tasks": [],
	"vc_supplied_verification_tasks": [],
	"credential": {
		"subject": input.holders.applicant,
		"claims": {"name": "do_download", "parameters": {"holder": "did:example:someone-else"}},
	},
}
