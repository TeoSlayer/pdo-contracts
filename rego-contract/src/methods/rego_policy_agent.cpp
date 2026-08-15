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
#include <vector>

#include "Dispatch.h"
#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Types.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "Cryptography.h"

#include "contract/base.h"
#include "identity/policy_agent.h" // inherited trusted-issuer / policy-data / verify / issue methods
#include "rego/rego_policy_agent.h"
#include "rego/rego_combinators.h" // hardcoded requirement / result combinator policies
#include "identity/common/Credential.h"
#include "identity/crypto/Crypto.h"       // SHA384Hash, used for direct-key EC verification
#include "identity/crypto/PublicKey.h"    // EC public key, for direct-key EC verification
#include "identity/crypto/RSAPublicKey.h" // RSA public key, for direct-key RSA verification
#include "rego/rego_evaluator.h" // reused eval_rego (+ the regorus allocator hooks)

// -----------------------------------------------------------------
// State
//   rego_policy_store : this contract's own state. set_rego_policy fills it:
//     "rego_modules"  -- [ [ subpolicy_id, source ], ... ]
//     "roles"         -- [ role, ... ]                  (derived from the subpolicies)
//     "input_schema"  -- { role: <verifiable presentation schema>, ... }
//   policy_metadata_store : the SAME store the inherited policy_agent methods
//     use. We read "policy_data" / "trusted_issuers" for the Rego input, and
//     write the merged "requirements" there so get_requirements can return them.
//
// Every subpolicy and both combinators run in their OWN regorus engine (see
// eval_rego), so the fixed module name and entrypoints never collide.
// -----------------------------------------------------------------
static KeyValueStore rego_policy_store("rego_policy_store");
static KeyValueStore policy_metadata_store("policy_metadata_store");

// The contract creation hook (initialize_contract) is inherited directly from
// policy_agent; see contracts/rego_policy_agent.cpp. It primes the identity
// signing contexts, the issuer path used to sign issued credentials, the
// policy-data store, and the trusted-issuers map.

// -----------------------------------------------------------------
// subpolicy module contract
//   Every subpolicy source MUST declare both rules below in `package subpolicy` (regorus
//   errors on an unknown rule path, so neither may be omitted), and each must
//   evaluate to output matching its schema (REGO_SUBPOLICY_REQUIREMENTS_SCHEMA /
//   REGO_SUBPOLICY_RESULT_SCHEMA) -- the contract validates the output before using it.
//
//   data.subpolicy.requirements -> { role: [credential_type, ...], ... }
//       The roles/credential-types this subpolicy needs. Evaluated by set_rego_policy
//       with NO input, so it must be static (it must produce an object even if
//       it is just {}; an empty requirement set is fine).
//
//   data.subpolicy.result -> { "decision": bool,
//                        "verification_tasks": [ { "index": <number> }, ... ],
//                        "operation": { "name": ..., "parameters": {...} } }
//       Evaluated by issue_policy_credential() with input = { presentations,
//       trusted_issuers, policy_data }. `index` refers to a credential in
//       input.presentations; the contract verifies each flagged credential's
//       signature in C++.
// -----------------------------------------------------------------

// eval_rego is reused from the rego_evaluator contract (see
// identity/rego_evaluator.h); each subpolicy and combinator runs in its own
// fresh regorus engine.

// =================================================================
// set_rego_policy helpers
// =================================================================

// -----------------------------------------------------------------
// Ask every subpolicy for the credentials it requires (its "data.subpolicy.requirements"
// rule), then merge them with the requirements combinator. Returns the merged
// requirements ({ role: [credential_type, ...] }) and the list of roles. Every
// subpolicy must return a requirements object (possibly empty); otherwise it errors.
// -----------------------------------------------------------------
static bool compute_requirements(
    const ww::value::Array &modules,
    ww::value::Object &merged_requirements,
    ww::value::Array &roles,
    std::string &error_msg)
{
    // collect each subpolicy's declared requirements (the rule takes no input)
    ww::value::Array subpolicy_requirements;
    const size_t count = modules.get_count();
    for (size_t i = 0; i < count; i++)
    {
        ww::value::Array pair;
        if (!modules.get_value(i, pair))
        {
            error_msg.assign("unexpected error, ill-formed module entry");
            return false;
        }
        const char *source = pair.get_string(1);
        if (source == nullptr)
        {
            error_msg.assign("invalid request, ill-formed module pair");
            return false;
        }

        std::string output_json;
        if (!ww::rego::rego_evaluator::eval_rego(source, "data.subpolicy.requirements", "{}", output_json, error_msg))
            return false;

        // every subpolicy must return a requirements object (an empty {} is fine)
        ww::value::Object req;
        if (!req.deserialize(output_json.c_str()) || !req.validate_schema(REGO_SUBPOLICY_REQUIREMENTS_SCHEMA))
        {
            error_msg.assign("invalid request, a subpolicy returned ill-formed requirements");
            return false;
        }

        if (!subpolicy_requirements.append_value(req))
        {
            error_msg.assign("unexpected error, failed to collect subpolicy requirements");
            return false;
        }
    }

    // merge them with the requirements combinator
    ww::value::Object combinator_input_obj;
    combinator_input_obj.set_value("subpolicy_requirements", subpolicy_requirements);
    std::string combinator_input;
    if (!combinator_input_obj.serialize(combinator_input))
    {
        error_msg.assign("unexpected error, failed to serialize combinator input");
        return false;
    }

    std::string merged_output;
    if (!ww::rego::rego_evaluator::eval_rego(REGO_REQUIREMENTS_COMBINATOR, "data.combine.result", combinator_input, merged_output, error_msg))
        return false;

    ww::value::Object merged;
    if (!merged.deserialize(merged_output.c_str()))
    {
        error_msg.assign("unexpected error, failed to parse merged requirements");
        return false;
    }
    if (!merged.get_value("requirements", merged_requirements))
    {
        error_msg.assign("unexpected error, requirements combinator returned no requirements");
        return false;
    }
    if (!merged.get_value("roles", roles))
    {
        error_msg.assign("unexpected error, requirements combinator returned no roles");
        return false;
    }
    return true;
}

// -----------------------------------------------------------------
// Build the evaluate() input schema from the required roles:
//   { role: <verifiable presentation schema>, ... }
// evaluate() validates its caller's presentations against this so that every
// required role is present and each value is a verifiable presentation. (We do
// not validate the credentials themselves.)
// -----------------------------------------------------------------
static bool build_input_schema(
    const ww::value::Array &roles,
    ww::value::Object &input_schema,
    std::string &error_msg)
{
    ww::value::Object vp_schema;
    if (!vp_schema.deserialize(VERIFIABLE_PRESENTATION_SCHEMA))
    {
        error_msg.assign("unexpected error, failed to parse verifiable presentation schema");
        return false;
    }

    const size_t count = roles.get_count();
    for (size_t i = 0; i < count; i++)
    {
        const char *role = roles.get_string(i);
        if (role == nullptr)
        {
            error_msg.assign("unexpected error, ill-formed role");
            return false;
        }
        if (!input_schema.set_value(role, vp_schema))
        {
            error_msg.assign("unexpected error, failed to build the input schema");
            return false;
        }
    }
    return true;
}

// =================================================================
// Contract methods
// =================================================================

// -----------------------------------------------------------------
// METHOD: set_rego_policy
//   Set (or replace) the Rego policy: a list of [ subpolicy_id, source ] pairs. The
//   owner may call this any number of times; each call fully replaces the
//   previous policy (the modules are NOT locked).
//
//   The method also derives the per-role requirements (by invoking each subpolicy's
//   requirements rule and merging them with the requirements combinator) and
//   the matching input schema, then stores all of it.
//
// JSON PARAMETERS:
//   REGO_POLICY_AGENT_SET_POLICY_PARAM_SCHEMA
//     { "rego_modules": [ [ subpolicy_id, source ], ... ] }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::set_rego_policy(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(REGO_POLICY_AGENT_SET_POLICY_PARAM_SCHEMA),
                   "invalid request, missing 'rego_modules'");

    ww::value::Array modules;
    ASSERT_SUCCESS(rsp, msg.get_value("rego_modules", modules),
                   "invalid request, missing rego_modules");
    ASSERT_SUCCESS(rsp, modules.get_count() > 0,
                   "invalid request, rego_modules must not be empty");

    // derive the merged requirements and the roles from the subpolicies
    ww::value::Object merged_requirements;
    ww::value::Array roles;
    std::string error_msg;
    ASSERT_SUCCESS(rsp, compute_requirements(modules, merged_requirements, roles, error_msg),
                   error_msg.c_str());

    // build the evaluate() input schema from those roles
    ww::value::Object input_schema;
    ASSERT_SUCCESS(rsp, build_input_schema(roles, input_schema, error_msg),
                   error_msg.c_str());

    // persist the policy, the roles, the input schema, and the merged requirements
    std::string serialized;
    ASSERT_SUCCESS(rsp, modules.serialize(serialized),
                   "unexpected error, failed to serialize rego_modules");
    ASSERT_SUCCESS(rsp, rego_policy_store.set("rego_modules", serialized),
                   "unexpected error, failed to persist rego_modules");

    ASSERT_SUCCESS(rsp, roles.serialize(serialized),
                   "unexpected error, failed to serialize roles");
    ASSERT_SUCCESS(rsp, rego_policy_store.set("roles", serialized),
                   "unexpected error, failed to persist roles");

    ASSERT_SUCCESS(rsp, input_schema.serialize(serialized),
                   "unexpected error, failed to serialize input schema");
    ASSERT_SUCCESS(rsp, rego_policy_store.set("input_schema", serialized),
                   "unexpected error, failed to persist input schema");

    ASSERT_SUCCESS(rsp, merged_requirements.serialize(serialized),
                   "unexpected error, failed to serialize requirements");
    ASSERT_SUCCESS(rsp, policy_metadata_store.set("merged_requirements", serialized),
                   "unexpected error, failed to persist requirements");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: get_requirements
//   Return the merged per-role requirements set by set_rego_policy:
//   { role: [ credential_type, ... ], ... }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::get_requirements(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);

    std::string serialized_requirements;
    ASSERT_SUCCESS(rsp, policy_metadata_store.get("merged_requirements", serialized_requirements),
                   "invalid request, no rego policy has been set");

    ww::value::Object requirements;
    ASSERT_SUCCESS(rsp, requirements.deserialize(serialized_requirements.c_str()),
                   "unexpected error, failed to deserialize requirements");

    return rsp.value(requirements, false);
}

// -----------------------------------------------------------------
// METHOD: get_rego_policy
//   Return the whole list of [ subpolicy_id, source ] pairs.
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::get_rego_policy(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);

    std::string serialized_modules;
    ASSERT_SUCCESS(rsp, rego_policy_store.get("rego_modules", serialized_modules),
                   "invalid request, no rego policy has been set");

    ww::value::Array modules;
    ASSERT_SUCCESS(rsp, modules.deserialize(serialized_modules.c_str()),
                   "unexpected error, failed to deserialize rego modules");

    return rsp.value(modules, false);
}

// =================================================================
// evaluate() helpers
// =================================================================

// -----------------------------------------------------------------
// Standardize the caller's presentations into the shared subpolicy input:
//   input.presentations = { role: [ { type, issuer, subject, claims, index, proof_value }, ... ], ... }
//   input.trusted_issuers = { issuer_id: [ { verifying_context, credential_types }, ... ] }
//   input.policy_data   = <opaque policy data>
//
// proof_value is the credential's signature (the proof's base64 proofValue). It
// lets a subpolicy match a credential presented on its own against the same
// credential embedded (as a claim) inside another credential, since the embedded
// copy keeps its proof but hides its claims behind a base64 blob.
//
// Roles are taken from the stored `roles` list (so we never enumerate the
// presentations object). For each role we deserialize its verifiable
// presentation, then each verifiable credential, and project a Rego-friendly
// view that keeps the credential's information in a fixed shape.
//
// The per-credential `index` is global across every role. A verification task
// the merged result returns uses it to point back to the exact credential,
// whose full serialized form is kept at the same index in vc_json_by_index.
// -----------------------------------------------------------------
static bool build_rego_input(
    const ww::value::Object &presentations,
    const ww::value::Array &roles,
    std::string &input_json,
    std::vector<std::string> &vc_json_by_index)
{
    ww::value::Object rego_presentations;

    const size_t role_count = roles.get_count();
    for (size_t ri = 0; ri < role_count; ri++)
    {
        const char *role = roles.get_string(ri);
        ERROR_IF_NULL(role, "unexpected error, ill-formed role");

        ww::value::Object vp_object;
        ERROR_IF_NOT(presentations.get_value(role, vp_object),
                     "invalid request, missing presentation for a required role");

        ww::identity::VerifiablePresentation vp;
        ERROR_IF_NOT(vp.deserialize(vp_object),
                     "invalid request, ill-formed verifiable presentation");

        ww::value::Array role_creds;
        for (size_t ci = 0; ci < vp.presentation_.verifiableCredential_.size(); ci++)
        {
            ww::identity::VerifiableCredential &vc = vp.presentation_.verifiableCredential_[ci];

            ERROR_IF_NOT(!vc.credential_.type_.empty(),
                         "invalid request, credential missing type list");
            const std::string credential_type = vc.credential_.type_[0];

            // keep the full VC (with proof) so its signature can be checked later
            ww::value::Value vc_value;
            ERROR_IF_NOT(vc.serialize(vc_value),
                         "unexpected error, failed to serialize credential");
            std::string vc_str;
            ERROR_IF_NOT(vc_value.serialize(vc_str),
                         "unexpected error, failed to serialize credential string");

            const size_t index = vc_json_by_index.size();
            vc_json_by_index.push_back(vc_str);

            // standardized, Rego-friendly view that keeps all the VC's information
            ww::value::Object cred;
            cred.set_string("type", credential_type.c_str());
            cred.set_string("issuer", vc.credential_.issuer_.id_.c_str());
            cred.set_string("subject", vc.credential_.credentialSubject_.subject_.id_.c_str());
            cred.set_value("claims", vc.credential_.credentialSubject_.claims_);
            cred.set_number("index", (double)index);
            cred.set_string("proof_value", vc.proof_.proofValue_.c_str());

            ERROR_IF_NOT(role_creds.append_value(cred),
                         "unexpected error, failed to build credential view");
        }

        ERROR_IF_NOT(rego_presentations.set_value(role, role_creds),
                     "unexpected error, failed to build presentations view");
    }

    // trusted issuers map, reused as-is from the inherited policy_agent store
    ww::value::Object trusted_issuers;
    ERROR_IF_NOT(ww::identity::policy_agent::get_trusted_issuers_map(trusted_issuers),
                 "unexpected error, failed to fetch trusted issuers map");

    // opaque policy data, handed straight to the Rego
    std::string policy_data_str;
    ERROR_IF_NOT(policy_metadata_store.get("policy_data", policy_data_str),
                 "unexpected error, failed to fetch policy data");
    ww::value::Object policy_data;
    ERROR_IF_NOT(policy_data.deserialize(policy_data_str.c_str()),
                 "unexpected error, failed to deserialize policy data");

    ww::value::Object rego_input;
    rego_input.set_value("presentations", rego_presentations);
    rego_input.set_value("trusted_issuers", trusted_issuers);
    rego_input.set_value("policy_data", policy_data);

    ERROR_IF_NOT(rego_input.serialize(input_json),
                 "unexpected error, failed to serialize rego input");
    return true;
}

// -----------------------------------------------------------------
// Run every subpolicy over the shared input and collect their result objects.
// Each result is { decision, verification_tasks, operation }. On failure
// error_msg explains why.
// -----------------------------------------------------------------
static bool run_subpolicies(
    const ww::value::Array &modules,
    const std::string &input_json,
    ww::value::Array &subpolicy_outputs,
    std::string &error_msg)
{
    const size_t count = modules.get_count();
    for (size_t i = 0; i < count; i++)
    {
        ww::value::Array pair;
        if (!modules.get_value(i, pair))
        {
            error_msg.assign("unexpected error, ill-formed module entry");
            return false;
        }
        const char *source = pair.get_string(1);
        if (source == nullptr)
        {
            error_msg.assign("unexpected error, ill-formed module pair");
            return false;
        }

        std::string output_json;
        if (!ww::rego::rego_evaluator::eval_rego(source, "data.subpolicy.result", input_json, output_json, error_msg))
            return false;

        // a subpolicy must return a result of the expected shape
        ww::value::Object result;
        if (!result.deserialize(output_json.c_str()) || !result.validate_schema(REGO_SUBPOLICY_RESULT_SCHEMA))
        {
            error_msg.assign("unexpected error, a subpolicy returned an ill-formed result");
            return false;
        }
        if (!subpolicy_outputs.append_value(result))
        {
            error_msg.assign("unexpected error, failed to collect module result");
            return false;
        }
    }
    return true;
}

// -----------------------------------------------------------------
// Merge the per-subpolicy outputs with the results combinator:
//   - decision                        : true only if every subpolicy allowed
//   - verification_tasks              : every subpolicy's trusted-issuer tasks
//   - vc_supplied_verification_tasks  : every subpolicy's supplied-key tasks
//   - operation                        : every subpolicy's operation merged into one
// On failure error_msg explains why.
// -----------------------------------------------------------------
static bool combine_results(
    const ww::value::Array &subpolicy_outputs,
    bool &decision,
    ww::value::Array &verification_tasks,
    ww::value::Array &vc_supplied_verification_tasks,
    ww::value::Object &operation,
    std::string &error_msg)
{
    ww::value::Object combinator_input_obj;
    combinator_input_obj.set_value("subpolicy_outputs", subpolicy_outputs);
    std::string combinator_input;
    if (!combinator_input_obj.serialize(combinator_input))
    {
        error_msg.assign("unexpected error, failed to serialize combinator input");
        return false;
    }

    std::string merged_output;
    if (!ww::rego::rego_evaluator::eval_rego(REGO_RESULTS_COMBINATOR, "data.combine.result", combinator_input, merged_output, error_msg))
        return false;

    ww::value::Object merged;
    if (!merged.deserialize(merged_output.c_str()))
    {
        error_msg.assign("unexpected error, failed to parse merged result");
        return false;
    }

    ww::value::Boolean decision_value;
    if (!merged.get_value("decision", decision_value))
    {
        error_msg.assign("unexpected error, results combinator returned no decision");
        return false;
    }
    decision = decision_value.get();

    // both task lists and the operation always exist in the combinator's output,
    // but stay empty (the default-constructed values) if for any reason they are absent
    merged.get_value("verification_tasks", verification_tasks);
    merged.get_value("vc_supplied_verification_tasks", vc_supplied_verification_tasks);
    merged.get_value("operation", operation);
    return true;
}

// -----------------------------------------------------------------
// Verify the credential's signature directly against a public key the subpolicy
// supplied, instead of against a trusted issuer. key_type selects the algorithm:
//   "ec"  -- ECDSA over secp384r1 / SHA-384, the scheme PDO credentials use
//   "rsa" -- RSASSA-PKCS1-v1_5 / SHA-256
// The message is the base64 serialized credential the signature was computed
// over (see VerifiableCredential::build / check).
// -----------------------------------------------------------------
static bool verify_with_supplied_key(
    const ww::identity::VerifiableCredential &vc,
    const std::string &key,
    const std::string &key_type)
{
    const std::string serialized_credential(vc.get_serialized_credential());
    ww::types::ByteArray message(serialized_credential.begin(), serialized_credential.end());

    ww::types::ByteArray signature;
    if (!ww::crypto::b64_decode(vc.proof_.proofValue_, signature))
        return false;

    if (key_type == "rsa")
    {
        pdo_contracts::crypto::signing::RSAPublicKey public_key;
        if (!public_key.Deserialize(key))
            return false;
        return public_key.VerifySignature(message, signature);
    }

    if (key_type == "ec")
    {
        pdo_contracts::crypto::signing::PublicKey public_key;
        if (!public_key.Deserialize(key))
            return false;
        return public_key.VerifySignature(message, signature, pdo_contracts::crypto::SHA384Hash);
    }

    return false; // unknown key type -- cannot verify, so deny
}

// -----------------------------------------------------------------
// Look up and deserialize the credential a task points at (by its global index).
// Returns false if the index is out of range or the credential is ill-formed.
// -----------------------------------------------------------------
static bool load_task_credential(
    const ww::value::Object &task,
    const std::vector<std::string> &vc_json_by_index,
    ww::value::Object &vc_object,
    ww::identity::VerifiableCredential &vc)
{
    const int index = (int)task.get_number("index");
    if (index < 0 || (size_t)index >= vc_json_by_index.size())
        return false;

    if (!vc_object.deserialize(vc_json_by_index[index].c_str()))
        return false;

    if (!vc.deserialize(vc_object) || vc.credential_.type_.empty())
        return false;

    return true;
}

// -----------------------------------------------------------------
// Verify every trusted-issuer task: each credential is checked against the
// trusted issuer registered for its type (the type comes from the credential
// itself, which is trusted). Returns true only if every task's credential
// verifies, returning false at the first one that does not.
// -----------------------------------------------------------------
static bool perform_trusted_issuer_tasks(
    const ww::value::Array &verification_tasks,
    const std::vector<std::string> &vc_json_by_index)
{
    const size_t count = verification_tasks.get_count();
    for (size_t i = 0; i < count; i++)
    {
        ww::value::Object task;
        if (!verification_tasks.get_value(i, task))
            return false; // malformed task -- cannot verify, so deny

        ww::value::Object vc_object;
        ww::identity::VerifiableCredential vc;
        if (!load_task_credential(task, vc_json_by_index, vc_object, vc))
            return false;

        if (!ww::identity::policy_agent::verify_credential(vc_object, vc, vc.credential_.type_[0]))
            return false; // fail-safe: stop at the first failed verification
    }

    return true;
}

// -----------------------------------------------------------------
// Verify every supplied-key task: each credential is checked against the PEM
// public key carried in the task (see verify_with_supplied_key), using the task's
// key_type. Returns true only if every task's credential verifies, returning
// false at the first one that does not.
// -----------------------------------------------------------------
static bool perform_supplied_key_tasks(
    const ww::value::Array &verification_tasks,
    const std::vector<std::string> &vc_json_by_index)
{
    const size_t count = verification_tasks.get_count();
    for (size_t i = 0; i < count; i++)
    {
        ww::value::Object task;
        if (!verification_tasks.get_value(i, task))
            return false; // malformed task -- cannot verify, so deny

        ww::value::Object vc_object;
        ww::identity::VerifiableCredential vc;
        if (!load_task_credential(task, vc_json_by_index, vc_object, vc))
            return false;

        const char *key = task.get_string("key");
        const char *key_type = task.get_string("key_type");
        if (key == nullptr || key_type == nullptr)
            return false;

        if (!verify_with_supplied_key(vc, key, key_type))
            return false; // fail-safe: stop at the first failed verification
    }

    return true;
}

// -----------------------------------------------------------------
// Build and sign the policy-decision credential. The merged operation becomes the
// credential's claims. It is signed with the policy agent's issuer key, exactly
// as policy_agent issues its own credentials.
// -----------------------------------------------------------------
static bool build_output_credential(
    const Environment &env,
    const ww::value::Object &operation,
    ww::value::Object &serialized_vc_out)
{
    ww::identity::Credential credential_out;
    credential_out.type_ = {"policy_decision"};
    credential_out.issuer_.id_ = env.contract_id_;
    credential_out.credentialSubject_.subject_.id_ = env.originator_id_;

    // the merged operation is carried as the credential's claims
    std::string operation_str;
    ERROR_IF_NOT(operation.serialize(operation_str),
                 "unexpected error, failed to serialize the merged operation");
    ERROR_IF_NOT(credential_out.credentialSubject_.claims_.deserialize(operation_str.c_str()),
                 "unexpected error, failed to set the operation as claims");

    // sign the credential with the issuer context primed at initialization
    ww::identity::VerifiableCredential vc_out;
    ERROR_IF_NOT(ww::identity::policy_agent::issue_credential(
                     env.originator_id_, env.contract_id_, credential_out, vc_out),
                 "unexpected error, failed to issue the policy credential");

    ERROR_IF_NOT(vc_out.serialize(serialized_vc_out),
                 "unexpected error, failed to serialize the policy credential");
    return true;
}

// -----------------------------------------------------------------
// METHOD: issue_policy_credential
//   Standardize the caller's presentations, run every subpolicy, merge their results
//   with the results combinator, and -- if the policy allows -- verify the
//   credentials the merged result flags and issue a signed credential whose
//   claims are the merged operation.
//
// JSON PARAMETERS:
//   REGO_POLICY_AGENT_ISSUE_PARAM_SCHEMA
//     { "presentation": { role: <verifiable presentation>, ... } }
//   The keyword is "presentation" (singular) so this method can share the
//   inherited policy_agent issue op; its value is the role -> verifiable
//   presentation map. It is also validated against the per-role schema stored by
//   set_rego_policy (required roles present, each value a verifiable presentation).
//
// RETURNS:
//   VERIFIABLE_CREDENTIAL_SCHEMA -- a signed credential whose claims are the
//   merged operation, or an error if the policy denied.
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::issue_policy_credential(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SUCCESS(rsp, msg.validate_schema(REGO_POLICY_AGENT_ISSUE_PARAM_SCHEMA),
                   "invalid request, missing 'presentation'");

    ww::value::Object presentations;
    ASSERT_SUCCESS(rsp, msg.get_value("presentation", presentations),
                   "invalid request, missing presentation");

    // ---------- validate against the stored input schema ----------
    std::string serialized_schema;
    ASSERT_SUCCESS(rsp, rego_policy_store.get("input_schema", serialized_schema),
                   "invalid request, no rego policy has been set");
    ASSERT_SUCCESS(rsp, presentations.validate_schema(serialized_schema.c_str()),
                   "invalid request, presentations do not match the required roles");

    // ---------- load the configured policy ----------
    std::string serialized_roles;
    ASSERT_SUCCESS(rsp, rego_policy_store.get("roles", serialized_roles),
                   "invalid request, no rego policy has been set");
    ww::value::Array roles;
    ASSERT_SUCCESS(rsp, roles.deserialize(serialized_roles.c_str()),
                   "unexpected error, failed to deserialize roles");

    std::string serialized_modules;
    ASSERT_SUCCESS(rsp, rego_policy_store.get("rego_modules", serialized_modules),
                   "invalid request, no rego policy has been set");
    ww::value::Array modules;
    ASSERT_SUCCESS(rsp, modules.deserialize(serialized_modules.c_str()),
                   "unexpected error, failed to deserialize rego modules");

    // ---------- standardize the input ----------
    // vc_json_by_index keeps each credential's full serialized form so a
    // verification task can later refer back to it by its global index.
    std::string input_json;
    std::vector<std::string> vc_json_by_index;
    ASSERT_SUCCESS(rsp, build_rego_input(presentations, roles, input_json, vc_json_by_index),
                   "invalid request, failed to build the rego input");

    // ---------- run every subpolicy, then merge their outputs ----------
    std::string error_msg;
    ww::value::Array subpolicy_outputs;
    ASSERT_SUCCESS(rsp, run_subpolicies(modules, input_json, subpolicy_outputs, error_msg),
                   error_msg.c_str());

    bool decision = false;
    ww::value::Array verification_tasks;
    ww::value::Array vc_supplied_verification_tasks;
    ww::value::Object operation;
    ASSERT_SUCCESS(rsp, combine_results(subpolicy_outputs, decision, verification_tasks,
                                        vc_supplied_verification_tasks, operation, error_msg),
                   error_msg.c_str());

    // if any subpolicy denied, stop here -- there is no point verifying signatures
    ASSERT_SUCCESS(rsp, decision, "policy evaluation denied");

    // ---------- verify the credentials the merged result flagged ----------
    // the C++ verifier is trusted; the Rego ran over as-yet-unverified claims, so
    // a single failed signature is fail-safe and denies the request. The two task
    // lists are verified two different ways: verification_tasks against their
    // trusted issuers, vc_supplied_verification_tasks against keys the policy supplied.
    ASSERT_SUCCESS(rsp, perform_trusted_issuer_tasks(verification_tasks, vc_json_by_index),
                   "policy evaluation denied, credential verification failed");
    ASSERT_SUCCESS(rsp, perform_supplied_key_tasks(vc_supplied_verification_tasks, vc_json_by_index),
                   "policy evaluation denied, credential verification failed");

    // ---------- issue the signed credential ----------
    ww::value::Object serialized_vc_out;
    ASSERT_SUCCESS(rsp, build_output_credential(env, operation, serialized_vc_out),
                   "unexpected error, failed to build the output credential");

    return rsp.value(serialized_vc_out, false);
}
