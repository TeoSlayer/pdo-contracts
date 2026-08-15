package subpolicy

import rego.v1

# -----------------------------------------------------------------
# Sample subpolicy A -- an attribute gate driven by policy data.
#
# A subpolicy is one composable unit of the overall policy. It MUST declare both
# rules below in `package subpolicy`; the rego_policy_agent evaluates them in
# their own engine and merges the results with the other subpolicies.
#
# This one requires the applicant to present a "membership" credential whose
# "institution" claim is on the data owner's allow list. The allow list is
# configured on the contract with set_policy and handed to Rego as
# input.policy_data, so this subpolicy cannot decide without it. It contributes
# only the decision (and flags the credential for signature verification); the
# channel key for the download is supplied by subpolicy B.
# -----------------------------------------------------------------

# data.subpolicy.requirements -- the roles/credential-types this subpolicy needs.
# Evaluated by set_rego_policy with NO input, so it must be static.
requirements := {"applicant": ["membership"]}

# data.subpolicy.result -- evaluated by issue_policy_credential with input =
# { presentations, trusted_issuers, policy_data }. The standardized credential
# view is { type, issuer, subject, claims, index }.

# the applicant's membership credentials
membership_creds := [c |
    some c in input.presentations.applicant
    c.type == "membership"
]

# those naming an institution the data owner allows (policy data driven)
matching := [c |
    some c in membership_creds
    c.claims.institution in input.policy_data.allowedInstitutions
]

# allow only when at least one membership credential names an allowed institution
default decision := false

decision if count(matching) > 0

# flag the matching credentials for signature verification (by global index);
# the rego_policy_agent verifies these in C++ against the trusted issuers
verification_tasks := [{"index": c.index} | some c in matching]

# subpolicy A only gates access; it agrees on the "do_download" operation but
# adds no parameters of its own (subpolicy B supplies the channel key)
operation := {"name": "do_download", "parameters": {}}

result := {
    "decision": decision,
    "verification_tasks": verification_tasks,
    "vc_supplied_verification_tasks": [],
    "operation": operation,
}
