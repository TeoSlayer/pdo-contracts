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

#include <string>

#include "Util.h"
#include "identity/common/Credential.h"

// rego_token is the token-object analog of download_token: it gates a guardian
// capability on a verifiable credential. Where download_token consumes a
// "DownloadCredential" issued by the basic policy_agent, rego_token consumes a
// "policy_decision" credential issued by the rego_policy_agent. The merged Rego
// operation the rego_policy_agent carries as that credential's claims --
// { "name": <operation>, "parameters": { ... } } -- names the guardian operation
// to invoke and its parameters; rego_token parses it to build the capability. It
// makes no assumption about the parameters' shape (the policy decides that).

#define REGO_TOKEN_PARAM_SCHEMA                 \
    "{"                                         \
        SCHEMA_KWS(policy_vc, VERIFIABLE_CREDENTIAL_SCHEMA)               \
    "}"

namespace ww
{
    namespace rego
    {
        namespace rego_token
        {
            // methods
            // bool initialize_contract(const Environment& env);
            bool do_operation(const Message &msg, const Environment &env, Response &rsp);
        }; // rego_token
    }; // rego
}; // ww
