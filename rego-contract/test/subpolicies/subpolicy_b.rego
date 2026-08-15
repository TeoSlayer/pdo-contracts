package subpolicy

import rego.v1

# -----------------------------------------------------------------
# Sample subpolicy B -- supplies the download operation's channel key.
#
# It requires the same role as subpolicy A ("applicant"), but a different
# credential type ("public_key"), so the requirements combinator merges them to a
# single role requiring the union of the two credential types. It emits the
# "do_download" operation carrying the requester's channel key as its parameters.
# Merged with subpolicy A (all decisions must be true; operations are unioned),
# the result is a "do_download" operation whose parameters carry the channel key
# -- exactly what the rego_token forwards to the guardian.
# -----------------------------------------------------------------

requirements := {"applicant": ["public_key"]}

# the applicant's public_key credentials (each carrying a channel key claim)
public_key_creds := [c |
    some c in input.presentations.applicant
    c.type == "public_key"
]

# allow when the applicant presents a public_key credential carrying a key claim
default decision := false

decision if {
    some c in public_key_creds
    c.claims.key
}

# flag the public_key credentials for signature verification (by global index)
verification_tasks := [{"index": c.index} | some c in public_key_creds]

# the channel key comes from the presented public_key credential; the default
# keeps the operation well-formed on deny
default channel_key := ""

channel_key := public_key_creds[0].claims.key if count(public_key_creds) > 0

# name the "do_download" guardian operation and carry the channel key as its
# parameters so the rego_token can build the capability from the issued
# policy_decision credential
operation := {"name": "do_download", "parameters": {"channel_key": channel_key}}

result := {
    "decision": decision,
    "verification_tasks": verification_tasks,
    "vc_supplied_verification_tasks": [],
    "operation": operation,
}
