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

#include <stdlib.h>
#include <stdint.h>
#include <string>

#include "Dispatch.h"

#include "Cryptography.h"
#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Types.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "contract/base.h"
#include "exchange/token_object.h"
#include "identity/policy_agent.h"
#include "rego/rego_policy_agent.h" // REGO_OPERATION_SCHEMA
#include "rego/rego_token.h"

bool ww::rego::rego_token::do_operation(
    const Message &msg,
    const Environment &env,
    Response &rsp)
{
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(REGO_TOKEN_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    ww::value::Object vc_object_in;
    ASSERT_SUCCESS(rsp, msg.get_value("policy_vc", vc_object_in), "missing required parameter; policy_vc");

    // the rego_policy_agent issues "policy_decision" credentials; verify the
    // presented credential against the issuer registered for that type
    ww::identity::VerifiableCredential vc_in;
    ASSERT_SUCCESS(rsp, ww::identity::policy_agent::verify_credential(vc_object_in, vc_in, "policy_decision"), "invalid request, ill-formed credential");

    // the credential's claims are the merged operation the policy authorized:
    // { "name": <operation>, "parameters": { ... } }. The policy -- not the token --
    // decides which operation to run and with what parameters.
    ww::value::Object &operation = vc_in.credential_.credentialSubject_.claims_;
    ASSERT_SUCCESS(rsp, operation.validate_schema(REGO_OPERATION_SCHEMA),
                   "invalid request, ill-formed operation in credential");

    const char *operation_name = operation.get_string("name");
    ASSERT_SUCCESS(rsp, operation_name != nullptr, "invalid request, operation missing name");

    ww::value::Object parameters;
    ASSERT_SUCCESS(rsp, operation.get_value("parameters", parameters),
                   "invalid request, operation missing parameters");

    // build the guardian capability for the named operation with its parameters
    ww::value::Object result;
    ASSERT_SUCCESS(rsp, ww::exchange::token_object::create_operation_package(
                            operation_name, parameters, result),
                   "unexpected error: failed to generate capability");

    // this assumes that generating the capability does not change state, depending on
    // how the nonce is created this may need to change.
    return rsp.value(result, false);
}
