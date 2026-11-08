/* Copyright 2026 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

// Hardcoded "combinator" Rego policies. These are part of the contract's
// trusted code -- NOT the swappable subpolicy modules set by set_rego_policy. One
// merges the per-subpolicy requirements; the other merges the per-subpolicy evaluation
// results. Each runs in its own engine, so both may reuse the same package and
// entrypoint (`package combine` / `data.combine.result`) without colliding.

// REGO_REQUIREMENTS_COMBINATOR
//   Merge the requirements every subpolicy declared.
//   input : { "subpolicy_requirements": [ { role: [credential_type, ...], ... }, ... ] }
//   output (data.combine.result):
//           { "requirements": { role: [credential_type, ...] },
//             "roles": [ role, ... ] }
static const char REGO_REQUIREMENTS_COMBINATOR[] = R"REGO(
package combine

import rego.v1

# every role required by any subpolicy
all_roles contains role if {
    some req in input.subpolicy_requirements
    some role in object.keys(req)
}

# union the required credential types per role across all subpolicies
merged[role] := types if {
    some role in all_roles
    types := {t |
        some req in input.subpolicy_requirements
        some t in object.get(req, role, [])
    }
}

result := {
    "requirements": merged,
    "roles": [role | some role in all_roles],
}
)REGO";

// REGO_RESULTS_COMBINATOR
//   Merge the evaluation results every subpolicy produced.
//   input : { "subpolicy_outputs": [ { "decision": bool,
//                                "verification_tasks": [ { "index": n }, ... ],
//                                "vc_supplied_verification_tasks":
//                                    [ { "index": n, "key": <pem>, "key_type": "ec"|"rsa" }, ... ],
//                                "credential": { "subject": ..., "claims": {...} } }, ... ] }
//           (credential only from the one subpolicy that describes it)
//   output (data.combine.result), on allow:
//           { "decision": true,                    # every subpolicy allowed, one described the credential
//             "verification_tasks": [ ... ],       # trusted-issuer tasks, deduplicated
//             "vc_supplied_verification_tasks": [ ... ],  # supplied-key tasks, deduplicated
//             "credential": { ... } }               # the credential to issue
//   or, on deny:
//           { "decision": false, "reason": <why the policy denied> }
static const char REGO_RESULTS_COMBINATOR[] = R"REGO(
package combine

import rego.v1

# every subpolicy allowed
all_allowed if {
    every o in input.subpolicy_outputs {
        o.decision == true
    }
}

# the credentials the subpolicies describe
credentials := [o.credential | some o in input.subpolicy_outputs; o.credential]

# the policy allows only if every subpolicy allowed and exactly one described
# the credential to issue
default decision := false
decision if {
    all_allowed
    count(credentials) == 1
}

reason := "a module denied the request" if {
    not all_allowed
} else := "no module describes the credential" if {
    count(credentials) == 0
} else := "more than one module describes the credential" if {
    count(credentials) > 1
}

# every distinct trusted-issuer task any subpolicy flagged. The whole task is
# kept; sets deduplicate identical tasks structurally.
task_set := {task |
    some o in input.subpolicy_outputs
    some task in o.verification_tasks
}

verification_tasks := [task | some task in task_set]

# every distinct supplied-key task any subpolicy flagged (each carries its own
# key and key_type).
vc_supplied_task_set := {task |
    some o in input.subpolicy_outputs
    some task in o.vc_supplied_verification_tasks
}

vc_supplied_verification_tasks := [task | some task in vc_supplied_task_set]

result := {
    "decision": true,
    "verification_tasks": verification_tasks,
    "vc_supplied_verification_tasks": vc_supplied_verification_tasks,
    "credential": credentials[0],
} if decision

result := {"decision": false, "reason": reason} if not decision
)REGO";
