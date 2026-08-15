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
#include "identity/identity.h"
#include "identity/policy_agent.h"
#include "identity/common/Credential.h"
#include "identity/common/VerifyingContext.h"

static KeyValueStore policy_metadata_store("policy_metadata_store");

const std::string md_issuer_path("issuer_path");
const std::string md_policy_data("policy_data");
const std::string md_trusted_issuers("trusted_issuers");
const std::string initial_issuer_path("__ISSUER__");
const std::string initial_policy_data("{}");

// -----------------------------------------------------------------
// UTILITY: load the trusted_issuers map from policy_metadata_store.
// Map shape: { <issuer_id>: [ { verifying_context, credential_types }, ... ] }
// Exposed (see policy_agent.h) so inheriting contracts -- e.g. rego_policy_agent
// -- can read the same map instead of re-fetching the store themselves.
// -----------------------------------------------------------------
bool ww::identity::policy_agent::get_trusted_issuers_map(ww::value::Object &trusted_issuers)
{
    std::string str;
    ERROR_IF_NOT(policy_metadata_store.get(md_trusted_issuers, str),
                 "unexpected error, failed to fetch trusted issuers map");
    ERROR_IF_NOT(trusted_issuers.deserialize(str.c_str()),
                 "unexpected error, failed to deserialize trusted issuers map");
    return true;
}

// -----------------------------------------------------------------
// UTILITY: persist the trusted_issuers map back to policy_metadata_store
// -----------------------------------------------------------------
static bool save_trusted_issuers_map(const ww::value::Object &trusted_issuers)
{
    std::string str;
    ERROR_IF_NOT(trusted_issuers.serialize(str),
                 "unexpected error, failed to serialize trusted issuers map");
    ERROR_IF_NOT(policy_metadata_store.set(md_trusted_issuers, str),
                 "unexpected error, failed to save trusted issuers map");
    return true;
}

// -----------------------------------------------------------------
// UTILITY: check whether a string is present in a ww::value::Array
// -----------------------------------------------------------------
static bool array_contains_string(const ww::value::Array &array, const std::string &value)
{
    const size_t count = array.get_count();
    for (size_t i = 0; i < count; i++)
    {
        const char *t = array.get_string(i);
        if (t != nullptr && std::string(t) == value)
            return true;
    }
    return false;
}

// -----------------------------------------------------------------
// FUNCTION: initialize_trusted_issuers
// -----------------------------------------------------------------
bool ww::identity::policy_agent::initialize_trusted_issuers()
{
    // empty map: { } — issuer_id keys will be added by register_trusted_issuer
    ERROR_IF_NOT(policy_metadata_store.set(md_trusted_issuers, "{}"),
                 "unexpected error, failed to initialize empty trusted issuers map");
    return true;
}

// -----------------------------------------------------------------
// FUNCTION: save_trusted_issuer
//   Append a new (verifying_context, credential_types) record to the
//   list of records stored under issuer_id. Repeated calls accumulate
//   records; multiple registrations of the same prefix path are not
//   detected here (caller decides), and first-match wins at lookup.
// -----------------------------------------------------------------
bool ww::identity::policy_agent::save_trusted_issuer(
    const std::string &issuer_id,
    const ww::identity::VerifyingContext &vc,
    const ww::value::Array &credential_types)
{
    ww::value::Object trusted_issuers;
    ERROR_IF_NOT(get_trusted_issuers_map(trusted_issuers),
                 "unexpected error, failed to load trusted issuers map");

    // serialize the verifying context so it can be stored as an Object inside the record
    ww::value::Value vctx_value;
    ERROR_IF_NOT(vc.serialize(vctx_value),
                 "unexpected error, failed to serialize verifying context");

    // build the new record { verifying_context, credential_types }
    ww::value::Object record;
    ERROR_IF_NOT(record.set_value("verifying_context", vctx_value),
                 "unexpected error, failed to set verifying_context on record");
    ERROR_IF_NOT(record.set_value("credential_types", credential_types),
                 "unexpected error, failed to set credential_types on record");

    // load the existing record array for this issuer (empty if absent), append, save back
    ww::value::Array records;
    trusted_issuers.get_value(issuer_id.c_str(), records); // failure leaves records as a valid empty array
    ERROR_IF_NOT(records.append_value(record),
                 "unexpected error, failed to append record");

    ERROR_IF_NOT(trusted_issuers.set_value(issuer_id.c_str(), records),
                 "unexpected error, failed to update trusted issuers map");

    return save_trusted_issuers_map(trusted_issuers);
}

// -----------------------------------------------------------------
// FUNCTION: fetch_trusted_issuer
//   For a given issuer_id, walk its stored records and return the first
//   record whose verifying_context.prefix_path is a prefix of
//   credential_path AND whose credential_types list contains credential_type.
//   On match, out_vc is populated with the verifying context.
// -----------------------------------------------------------------
bool ww::identity::policy_agent::fetch_trusted_issuer(
    const std::string &issuer_id,
    const std::string &credential_type,
    const std::vector<std::string> &credential_path,
    ww::identity::VerifyingContext &out_vc)
{
    ww::value::Object trusted_issuers;
    ERROR_IF_NOT(get_trusted_issuers_map(trusted_issuers),
                 "unexpected error, failed to load trusted issuers map");

    ww::value::Array records;
    ERROR_IF_NOT(trusted_issuers.get_value(issuer_id.c_str(), records),
                 "invalid request, unknown trusted issuer");

    const size_t count = records.get_count();
    for (size_t i = 0; i < count; i++)
    {
        ww::value::Object record;
        if (!records.get_value(i, record))
        {
            CONTRACT_SAFE_LOG(3, "malformed trusted issuers store: record is not an object, skipping");
            continue;
        }

        // filter by credential type first (cheap check)
        ww::value::Array types;
        if (!record.get_value("credential_types", types))
        {
            CONTRACT_SAFE_LOG(3, "malformed trusted issuers store: record missing credential_types, skipping");
            continue;
        }
        if (!array_contains_string(types, credential_type))
            continue;

        // deserialize the verifying context, then ask it whether its
        // prefix_path matches the credential's context_path
        ww::value::Object vctx_object;
        if (!record.get_value("verifying_context", vctx_object))
        {
            CONTRACT_SAFE_LOG(3, "malformed trusted issuers store: record missing verifying_context, skipping");
            continue;
        }

        ww::identity::VerifyingContext candidate;
        if (!candidate.deserialize(vctx_object))
        {
            CONTRACT_SAFE_LOG(3, "malformed trusted issuers store: failed to deserialize verifying_context, skipping");
            continue;
        }

        if (!candidate.is_prefix_of(credential_path))
            continue;

        // first match wins — re-deserialize from the same wire-format
        // object into the caller's out_vc (defensive against future
        // additions to VerifyingContext that may not be copy-safe)
        ERROR_IF_NOT(out_vc.deserialize(vctx_object),
                     "unexpected error, failed to deserialize verifying context");
        return true;
    }

    CONTRACT_SAFE_LOG(3, "no trusted context matches credential type and path for issuer");
    return false;
}

// -----------------------------------------------------------------
// FUNCTION: verify_credential
// -----------------------------------------------------------------
bool ww::identity::policy_agent::verify_credential(
    const ww::value::Object &vc_object,
    ww::identity::VerifiableCredential &vc,
    const std::string &credential_type)
{
    ERROR_IF_NOT(vc.deserialize(vc_object), "invalid request, ill-formed credential");

    // Verify the credential signature

    // The signature was computed over the base64 encoded credential so we
    // do not need to decode the credential before checking the signature
    const std::string serialized_credential(vc.get_serialized_credential());
    ww::types::ByteArray message(serialized_credential.begin(), serialized_credential.end());

    ww::types::ByteArray signature;
    ERROR_IF_NOT(ww::crypto::b64_decode(vc.proof_.proofValue_, signature),
                 "invalid request, ill-formed signature");

    ww::identity::VerifyingContext verifier;
    ERROR_IF_NOT(fetch_trusted_issuer(
                     vc.proof_.verificationMethod_.id_,
                     credential_type,
                     vc.proof_.verificationMethod_.context_path_,
                     verifier),
                 "invalid request, no trusted context matches the credential's verification method");

    ERROR_IF_NOT(verifier.extend_context_path(vc.proof_.verificationMethod_.context_path_),
                 "invalid request, ill-formed context path");

    ERROR_IF_NOT(verifier.verify_signature(message, signature),
                 "invalid request, signature verification failed");

    return true;
}

// -----------------------------------------------------------------
// FUNCTION: issue_credential
// -----------------------------------------------------------------
bool ww::identity::policy_agent::issue_credential(
    const std::string &originator,
    const std::string &contract_id,
    const ww::identity::Credential &credential,
    ww::identity::VerifiableCredential &vc)
{
    // the context path that we are using is the path configured in the policy
    // agent (initially the initial_issuer_path) plus the hash of the originator's
    // public key. the originator's public key is hashed to ensure that the context path
    // is unique to the originator.

    // hash the originator's public key
    ww::types::ByteArray originator_bytes(originator.begin(), originator.end());
    ww::types::ByteArray originator_hash;
    ERROR_IF_NOT(ww::crypto::hash::sha256_hash(originator_bytes, originator_hash),
                 "unexpected error, failed to hash the originator");

    std::string encoded_originator;
    ERROR_IF_NOT(ww::crypto::b64_encode(originator_hash, encoded_originator),
                 "unexpected error, failed to encode the originator");

    // setup the context path
    std::vector<std::string> context_path = {initial_issuer_path, encoded_originator};
    ww::identity::SigningContext context;
    std::vector<std::string> extended_path;

    ww::identity::SigningContextManager manager = ww::identity::identity::get_context_manager();
    ERROR_IF_NOT(manager.find_context(context_path, extended_path, context),
                 "unexpected error, failed to locate the policy issuer context");

    context.set_context_path(extended_path);

    // std::vector<const std::string>::iterator path_element;
    // for (path_element = extended_path.begin(); path_element < extended_path.end(); path_element++)
    //     context_path.push_back(*path_element);

    // Sign the credential using the signing context just created
    ww::identity::VerifiableCredential vc_out;
    const ww::identity::IdentityKey identity(contract_id, context_path);

    ww::value::Object credential_object;
    ERROR_IF_NOT(credential.serialize(credential_object),
                 "unexpected error, failed to serialize the credential");

    ERROR_IF_NOT(vc.build(credential_object, identity, context),
                 "unexpected error, failed to build the credential");

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
bool ww::identity::policy_agent::initialize_contract(const Environment &env)
{
    // ---------- initialize the base contract ----------
    if (!ww::identity::identity::initialize_contract(env))
        return false;

    // ----------initialize the trusted issuer ----------
    // the trusted issuer is the path to the root key used to
    // sign credentials that are generated by this policy agent
    if (!policy_metadata_store.set(md_issuer_path, initial_issuer_path))
        return false;

    std::vector<std::string> context_path = {initial_issuer_path};
    const std::string description("initial issuer path");
    const bool extensible = true;

    ww::identity::SigningContextManager manager = ww::identity::identity::get_context_manager();
    if (!manager.add_context(extensible, description, context_path))
        return false;

    // set an empty policy data
    if (!policy_metadata_store.set(md_policy_data, initial_policy_data))
        return false;

    // initialize an empty trusted-issuers map
    if (!initialize_trusted_issuers())
        return false;

    return true;
}

// -----------------------------------------------------------------
// METHOD: register_trusted_issuer
//   Register a (verifying_context, credential_types) record for a
//   trusted issuer. Only the owner of the contract may invoke this.
//
//   Repeated calls for the same issuer_id append additional records;
//   each record carries its own prefix_path and credential_types list.
//   At verification time, the first record whose prefix_path is a
//   prefix of the credential's context_path and whose credential_types
//   list contains the requested type is selected.
//
// JSON PARAMETERS:
//   POLICY_AGENT_REGISTER_ISSUER_PARAM_SCHEMA
//
// RETURNS:
//   true if the registration succeeds
// -----------------------------------------------------------------
bool ww::identity::policy_agent::register_trusted_issuer(const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(POLICY_AGENT_REGISTER_ISSUER_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string issuer_identity(msg.get_string("issuer_identity"));
    const std::string public_key_str(msg.get_string("public_key"));
    const std::string chain_code_str(msg.get_string("chain_code"));

    // credential_types is an array of credential type strings this issuer is trusted to issue;
    // the schema already enforces array-of-string shape, so we only check non-emptiness here
    ww::value::Array credential_types;
    ASSERT_SUCCESS(rsp, msg.get_value("credential_types", credential_types),
                   "invalid request, missing credential_types");
    ASSERT_SUCCESS(rsp, credential_types.get_count() > 0,
                   "invalid request, credential_types must not be empty");

    // Get and validate the path parameter. This is the path TO the
    // key relative to the contract object, any verification key from
    // this issuer must be prefixed by this key path; note that this
    // is not the same as the context_path field in Context objects
    // which describes the path to the key FROM the context.
    std::vector<std::string> prefix_path;
    ASSERT_SUCCESS(rsp, ww::identity::identity::get_context_path(msg, prefix_path, 0),
                   "invalid request, ill-formed context path");

    // ---------- create the verifying context ----------
    ww::identity::VerifyingContext verifier;
    ASSERT_SUCCESS(rsp, verifier.initialize(prefix_path, public_key_str, chain_code_str),
                   "invalid request, invalid issuer public key/chain code");
    ASSERT_SUCCESS(rsp, save_trusted_issuer(issuer_identity, verifier, credential_types),
                   "unexpected error, failed to save issuer information");

    // ---------- RETURN ----------
    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: issue_policy_credential
//   Verify credentials in the incoming verifiable presentation,
//   process the policy decision and emit a new credential.
//   Each VC's credential type is taken from the first element of its type list.
//
// JSON PARAMETERS:
//   POLICY_AGENT_ISSUE_POLICY_CREDENTIAL_PARAM_SCHEMA
// RETURNS:
//   VERIFIABLE_CREDENTIAL_SCHEMA
// -----------------------------------------------------------------
bool ww::identity::policy_agent::issue_policy_credential(const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(POLICY_AGENT_ISSUE_POLICY_CREDENTIAL_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    // deserialize the verifiable presentation
    ww::value::Object vp_object;
    ASSERT_SUCCESS(rsp, msg.get_value("presentation", vp_object),
                   "invalid request, missing presentation");

    ww::identity::VerifiablePresentation vp;
    ASSERT_SUCCESS(rsp, vp.deserialize(vp_object),
                   "invalid request, ill-formed verifiable presentation");

    const std::map<std::string, const char *> claims_schema_map = get_claims_schemas();
    std::map<std::string, ww::identity::Credential> credentials;

    for (size_t i = 0; i < vp.presentation_.verifiableCredential_.size(); i++)
    {
        // re-serialize so verify_credential can re-deserialize and check signature
        ww::value::Object vc_object;
        ASSERT_SUCCESS(rsp, vp.presentation_.verifiableCredential_[i].serialize(vc_object),
                       "unexpected error, failed to serialize credential from presentation");

        ww::identity::VerifiableCredential vc;
        ASSERT_SUCCESS(rsp, !vp.presentation_.verifiableCredential_[i].credential_.type_.empty(),
                       "invalid request, credential missing type list");

        const std::string credential_type = vp.presentation_.verifiableCredential_[i].credential_.type_[0];

        // verify against the trusted issuer for this type
        ASSERT_SUCCESS(rsp, verify_credential(vc_object, vc, credential_type),
                       ("invalid request, ill-formed credential for type: " + credential_type).c_str());

        // verify claims schema if this type is expected
        auto it = claims_schema_map.find(credential_type);
        ASSERT_SUCCESS(rsp, it != claims_schema_map.end(),
                       ("invalid request, unexpected credential type: " + credential_type).c_str());

        ASSERT_SUCCESS(rsp, vc.credential_.credentialSubject_.claims_.validate_schema(it->second),
                       ("invalid claims for " + credential_type).c_str());

        // store credential by type
        ww::value::Object tmp;
        ASSERT_SUCCESS(rsp, vc.credential_.serialize(tmp),
                       ("unexpected error when serializing credential " + credential_type).c_str());

        ASSERT_SUCCESS(rsp, credentials[credential_type].deserialize(tmp),
                       ("unexpected error when storing credential " + credential_type).c_str());
    }

    // get the policy data
    std::string policy_data_str;
    ASSERT_SUCCESS(rsp, policy_metadata_store.get(md_policy_data, policy_data_str),
                   "unexpected error, failed to fetch policy data");

    ww::value::Object policy_data_object;

    ASSERT_SUCCESS(rsp, policy_data_object.deserialize(policy_data_str.c_str()),
                   "unexpected error, failed to deserialize policy data");

    // And build the veriable credential; just wanted to note that it would be
    // completely appropriate to make a constructor for VC's that took the
    // information for build; however, there are no exceptions with our current
    // WASM interpreter so failure in the constructor would be a catastrophic
    // failure for the contract

    // ---------- RETURN ----------
    ww::identity::Credential credential_out;
    CONTRACT_SAFE_LOG(3, "prepare to evaluate the policy");
    ASSERT_SUCCESS(rsp, policy_agent_function(credentials, policy_data_object, credential_out),
                   "policy failed");
    CONTRACT_SAFE_LOG(3, "finished evaluating the policy");

    credential_out.issuer_.id_ = env.contract_id_;

    ww::identity::VerifiableCredential vc_out;
    ASSERT_SUCCESS(rsp, issue_credential(env.originator_id_, env.contract_id_, credential_out, vc_out),
                   "unexpected error, failed to create the new credential");

    ww::value::Object serialized_vc_out;
    ASSERT_SUCCESS(rsp, vc_out.serialize(serialized_vc_out),
                   "unexpected error, failed to serialized the credential");

    return rsp.value(serialized_vc_out, false);
}

// -----------------------------------------------------------------
// METHOD: issue_policy_credential
//   Verify the incoming credential, process the policy decision and emit a new credential
//
// JSON PARAMETERS:
//   POLICY_AGENT_ISSUE_POLICY_CREDENTIAL_PARAM_SCHEMA
// RETURNS:
//   true signature is verified
// -----------------------------------------------------------------
bool ww::identity::policy_agent::set_policy_data(const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);
    const char *policy_data_schema = get_policy_data_schema();

    ASSERT_SUCCESS(rsp, msg.validate_schema(policy_data_schema),
                   "invalid request, missing required parameters");

    std::string serialized_policy_data;
    ASSERT_SUCCESS(rsp, msg.serialize(serialized_policy_data), "failed to serialize policy data");

    ASSERT_SUCCESS(rsp, policy_metadata_store.set(md_policy_data, serialized_policy_data), "failed to save policy data");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: get_policy_data
//   Return the current policy data object.
//
// JSON PARAMETERS:
//   none
// RETURNS:
//   policy data object
// -----------------------------------------------------------------
bool ww::identity::policy_agent::get_policy_data(const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);

    std::string policy_data_str;
    ASSERT_SUCCESS(rsp, policy_metadata_store.get(md_policy_data, policy_data_str),
                   "unexpected error, failed to fetch policy data");

    ww::value::Object policy_data;
    ASSERT_SUCCESS(rsp, policy_data.deserialize(policy_data_str.c_str()),
                   "unexpected error, failed to deserialize policy data");

    return rsp.value(policy_data, false);
}

// -----------------------------------------------------------------
// METHOD: list_trusted_issuers
//   Return the trusted-issuers map. Each issuer ID maps to an array of
//   records, where each record is { verifying_context, credential_types }.
//   The verifying_context object itself carries its prefix_path,
//   public_key, and chain_code.
//
// JSON PARAMETERS:
//   none
// RETURNS:
//   object mapping issuer_id -> [ { verifying_context, credential_types }, ... ]
// -----------------------------------------------------------------
bool ww::identity::policy_agent::list_trusted_issuers(const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);

    ww::value::Object trusted_issuers;
    ASSERT_SUCCESS(rsp, get_trusted_issuers_map(trusted_issuers),
                   "unexpected error, failed to load trusted issuers map");

    return rsp.value(trusted_issuers, false);
}

// -----------------------------------------------------------------
// METHOD: get_requirements
//   Return the list of credential types required by this policy agent.
//
// JSON PARAMETERS:
//   none
// RETURNS:
//   array of credential type strings
// -----------------------------------------------------------------
bool ww::identity::policy_agent::get_requirements(const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);

    const std::map<std::string, const char *> claims_schema_map = get_claims_schemas();

    ww::value::Array requirements;
    for (const auto &[credential_type, schema] : claims_schema_map)
    {
        ASSERT_SUCCESS(rsp, requirements.append_string(credential_type.c_str()),
                       "unexpected error, failed to build requirements list");
    }

    return rsp.value(requirements, false);
}
