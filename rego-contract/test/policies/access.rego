# Toy RBAC policy for the rego_evaluator smoke test. Nothing credential-specific
# -- just a common "allow" rule over a small input.
#
# Input shape: { "user": <string>, "role": <string> }
#   data.access.allow -> true for admins, or any user on the allow list

package access

import rego.v1

allowlist := {"alice", "bob"}

default allow := false

allow if input.role == "admin"

allow if input.user in allowlist
