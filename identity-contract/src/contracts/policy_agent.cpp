/* Copyright 2023 Intel Corporation
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

#include <string>
#include <map>

#include <stddef.h>
#include <stdint.h>

#include "Dispatch.h"

#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Types.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "contract/base.h"
#include "identity/identity.h"
#include "identity/signature_authority.h"
#include "identity/policy_agent.h"

// Configure expected VCs schemas and policy data schema
#define DUMMY_CLAIMS_SCHEMA "{}"

#define POLICY_AGENT_POLICY_DATA_SCHEMA "{}"

const std::map<std::string, const char *> ww::identity::policy_agent::get_claims_schemas()
{

    const std::map<std::string, const char *> claims_schemas = {
        {"dummy", DUMMY_CLAIMS_SCHEMA}};
    return claims_schemas;
}

const char *ww::identity::policy_agent::get_policy_data_schema()
{
    return POLICY_AGENT_POLICY_DATA_SCHEMA;
}

// end configuration

// start policy agent function logic

bool ww::identity::policy_agent::policy_agent_function(
    const std::map<std::string, ww::identity::Credential> &credentials,
    const ww::value::Object &policy_data,
    ww::identity::Credential &credential_out)
{
    // -----------------------------------------------------------------
    // -----------------------------------------------------------------
    ww::identity::Credential dummy_credential = credentials.at("dummy");
    std::string subject = dummy_credential.credentialSubject_.subject_.id_;
    credential_out.credentialSubject_.subject_.id_ = subject;
    credential_out.type_ = {"echo"};

    // -----------------------------------------------------------------
    // Write your logic here
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // Build output credential
    // -----------------------------------------------------------------

    // Set the claims
    // This contract example will just echo the same credential

    std::string dummy_claims;
    ERROR_IF_NOT(dummy_credential.credentialSubject_.claims_.serialize(dummy_claims),
                 "Error serializing credential claims");

    ERROR_IF_NOT(credential_out.credentialSubject_.claims_.deserialize(dummy_claims.c_str()),
                 "Error deserializing credential claims");

    return true;
}

// -----------------------------------------------------------------
// METHOD: initialize_contract
//   contract initialization method
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   true if successfully initialized
// -----------------------------------------------------------------
bool initialize_contract(const Environment &env, Response &rsp)
{
    // ---------- initialize the base contract ----------
    ASSERT_SUCCESS(rsp, ww::identity::policy_agent::initialize_contract(env),
                   "unexpected error: failed to initialize the contract");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// -----------------------------------------------------------------
contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD2(initialize, ww::identity::identity::initialize),

    CONTRACT_METHOD2(get_verifying_key, ww::identity::identity::get_verifying_key),
    CONTRACT_METHOD2(get_extended_verifying_key, ww::identity::identity::get_extended_verifying_key),
    CONTRACT_METHOD2(register_signing_context, ww::identity::identity::register_signing_context),
    CONTRACT_METHOD2(describe_signing_context, ww::identity::identity::describe_signing_context),
    CONTRACT_METHOD2(list_signing_contexts, ww::identity::identity::list_signing_contexts),

    // Not sure if these are appropriate for this contract
    CONTRACT_METHOD2(sign, ww::identity::identity::sign),
    CONTRACT_METHOD2(verify, ww::identity::identity::verify),

    CONTRACT_METHOD2(register_trusted_issuer, ww::identity::policy_agent::register_trusted_issuer),
    CONTRACT_METHOD2(issue_policy_credential, ww::identity::policy_agent::issue_policy_credential),
    CONTRACT_METHOD2(set_policy_data, ww::identity::policy_agent::set_policy_data),
    CONTRACT_METHOD2(get_policy_data, ww::identity::policy_agent::get_policy_data),
    CONTRACT_METHOD2(list_trusted_issuers, ww::identity::policy_agent::list_trusted_issuers),
    CONTRACT_METHOD2(get_requirements, ww::identity::policy_agent::get_requirements),

    // This is used to verify credentials that are generated by the policy agent
    CONTRACT_METHOD2(verify_credential, ww::identity::signature_authority::verify_credential),

    {NULL, NULL}};
