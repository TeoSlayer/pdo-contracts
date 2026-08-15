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

#pragma once

#include <string>
#include <vector>
#include <map>

#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Value.h"

#include "common/Credential.h"
#include "common/VerifyingContext.h"


#define POLICY_AGENT_REGISTER_ISSUER_PARAM_SCHEMA       \
    "{"                                                 \
        SCHEMA_KW(issuer_identity, "") ","              \
        SCHEMA_KW(credential_types, [ "" ]) ","         \
        SCHEMA_KW(context_path, [ "" ]) ","             \
        SCHEMA_KW(public_key, "") ","                   \
        SCHEMA_KW(chain_code, "")                       \
    "}"

#define POLICY_AGENT_ISSUE_POLICY_CREDENTIAL_PARAM_SCHEMA       \
    "{"                                                          \
        SCHEMA_KWS(presentation, VERIFIABLE_PRESENTATION_SCHEMA) \
    "}"

#define POLICY_AGENT_ISSUE_POLICY_CREDENTIAL_RESULT_SCHEMA      \
    VERIFIABLE_CREDENTIAL_SCHEMA

namespace ww
{
namespace identity
{
namespace policy_agent
{
    // Policy Agent contract methods
    bool initialize_contract(const Environment& env);
    bool issue_policy_credential(const Message& msg, const Environment& env, Response& rsp);
    bool register_trusted_issuer(const Message& msg, const Environment& env, Response& rsp);
    bool set_policy_data(const Message& msg, const Environment& env, Response& rsp);
    bool get_policy_data(const Message& msg, const Environment& env, Response& rsp);
    bool list_trusted_issuers(const Message& msg, const Environment& env, Response& rsp);
    bool get_requirements(const Message& msg, const Environment& env, Response& rsp);

    // Functions to extend the functionality of the policy agent
    bool initialize_trusted_issuers();
    bool get_trusted_issuers_map(ww::value::Object& trusted_issuers);
    bool save_trusted_issuer(const std::string& issuer_id, const ww::identity::VerifyingContext& vc, const ww::value::Array& credential_types);
    bool fetch_trusted_issuer(const std::string& issuer_id, const std::string& credential_type, const std::vector<std::string>& credential_path, ww::identity::VerifyingContext& out_vc);
    bool verify_credential(const ww::value::Object& vc_object, ww::identity::VerifiableCredential& vc, const std::string& credential_type);
    bool issue_credential(
        const std::string& originator,
        const std::string& contract_id,
        const ww::identity::Credential& credential,
        ww::identity::VerifiableCredential& vc);

    // This function must be defined by the contract, this is not a very clean way to do
    // this but WASM does not seem to support function pointers very well
    const char* get_policy_data_schema();
    const std::map<std::string, const char*>  get_claims_schemas();
    bool policy_agent_function(const std::map<std::string, ww::identity::Credential>&, const ww::value::Object&, ww::identity::Credential&);

}; // policy_agent
}; // identity
}; // ww
