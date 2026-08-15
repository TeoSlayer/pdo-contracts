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
#include "identity/common/Credential.h"
#include "identity/common/SigningContext.h"
#include "identity/common/SigningContextManager.h"

static KeyValueStore identity_metadata_store("key_store");
static KeyValueStore signing_context_store("signing_context");

static const std::string md_description("description");
static const std::string md_vc_store("vc_store");
static const std::string initial_holder_path("__HOLDER__");

// -----------------------------------------------------------------
// VC STORE HELPERS
// -----------------------------------------------------------------
static bool load_vc_map(ww::value::Object& vc_map)
{
    std::string str;
    ERROR_IF_NOT(identity_metadata_store.get(md_vc_store, str),
                 "unexpected error, failed to fetch vc store");
    ERROR_IF_NOT(vc_map.deserialize(str.c_str()),
                 "unexpected error, failed to deserialize vc store");
    return true;
}

static bool save_vc_map(ww::value::Object& vc_map)
{
    std::string str;
    ERROR_IF_NOT(vc_map.serialize(str),
                 "unexpected error, failed to serialize vc store");
    ERROR_IF_NOT(identity_metadata_store.set(md_vc_store, str),
                 "unexpected error, failed to save vc store");
    return true;
}

static bool store_vc(const std::string& credential_type, ww::value::Object& vc_object)
{
    ww::value::Object vc_map;
    ERROR_IF_NOT(load_vc_map(vc_map),
                 "unexpected error, failed to load vc map");
    ERROR_IF_NOT(vc_map.set_value(credential_type.c_str(), vc_object),
                 "unexpected error, failed to update vc map");
    ERROR_IF_NOT(save_vc_map(vc_map),
                 "unexpected error, failed to save vc map");
    return true;
}

// -----------------------------------------------------------------
// FUNCTION: get_context_manager
// -----------------------------------------------------------------
ww::identity::SigningContextManager ww::identity::identity::get_context_manager(void)
{
    ww::identity::SigningContextManager manager(signing_context_store);
    return manager;
}

// -----------------------------------------------------------------
// FUNCTION: get_context_path
//   create a context path from a message parameter
// RETURNS:
//   true if path successfully created
// -----------------------------------------------------------------
bool ww::identity::identity::get_context_path(
    const Message& msg,
    std::vector<std::string>& context_path,
    size_t minimum_size)
{
    ww::value::Array context_path_array;
    if (! msg.get_value("context_path", context_path_array))
        return false;

    // note that minimum size defaults to 1
    if (context_path_array.get_count() < minimum_size)
        return false;

    context_path.resize(0);

    for (size_t i = 0; i < context_path_array.get_count(); i++)
    {
        const std::string s(context_path_array.get_string(i));
        context_path.push_back(s);
    }

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
bool ww::identity::identity::initialize_contract(const Environment& env)
{
    // ---------- initialize the base contract ----------
    if (! ww::contract::base::initialize_contract(env))
        return false;

    // ---------- prime signing context store ----------
    ww::identity::SigningContextManager manager(signing_context_store);
    if (! manager.initialize())
        return false;

    // ---------- prime the holder signing context ----------
    // extensible so that per-originator sub-paths can be derived at get_vp time
    std::vector<std::string> holder_path = {initial_holder_path};
    if (! manager.add_context(true, "holder signing context", holder_path))
        return false;

    // ---------- other metadata ----------
    if (! identity_metadata_store.set(md_description, "identity object"))
        return false;

    if (! identity_metadata_store.set(md_vc_store, "{}"))
        return false;

    return true;
}

// -----------------------------------------------------------------
// METHOD: initialize
//   set the basic information for the asset type
//
// JSON PARAMETERS:
//
// RETURNS:
//   true if successfully initialized
// -----------------------------------------------------------------
bool ww::identity::identity::initialize(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_UNINITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(IDENTITY_INITIALIZE_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string description(msg.get_string("description"));
    ASSERT_SUCCESS(rsp, identity_metadata_store.set(md_description, description),
                   "unexpected error, failed to save description");

    // Mark as initialized
    ASSERT_SUCCESS(rsp, ww::contract::base::mark_initialized(), "initialization failed");

    // ---------- RETURN ----------
    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD:
//   register_signing_context
//
//   Register a signing context. If the context already exists, it will be overridden
//   with the new context.
// JSON PARAMETERS:
//   IDENTITY_REGISTER_SIGNING_CONTEXT_PARAM_SCHEMA
// RETURNS:
//   boolean
// -----------------------------------------------------------------
bool ww::identity::identity::register_signing_context(
    const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(IDENTITY_REGISTER_SIGNING_CONTEXT_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    std::vector<std::string> context_path;
    ASSERT_SUCCESS(rsp, get_context_path(msg, context_path),
                   "invalid request, ill-formed context path");

    const std::string description(msg.get_string("description"));
    const bool extensible(msg.get_boolean("extensible"));

    ww::identity::SigningContextManager manager(signing_context_store);
    ASSERT_SUCCESS(rsp, manager.add_context(extensible, description, context_path),
                   "failed to register the new context");

    // ---------- RETURN ----------
    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD:
//   describe_signing_context
//
// JSON PARAMETERS:
//   IDENTITY_DESCRIBE_SIGNING_CONTEXT_PARAM_SCHEMA
// RETURNS:
//   IDENTITY_DESCRIBE_SIGNING_CONTEXT_RESULT_SCHEMA
// -----------------------------------------------------------------
bool ww::identity::identity::describe_signing_context(
    const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(IDENTITY_DESCRIBE_SIGNING_CONTEXT_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    std::vector<std::string> context_path;
    ASSERT_SUCCESS(rsp, get_context_path(msg, context_path),
                   "invalid request, ill-formed context path");

    ww::identity::SigningContextManager manager(signing_context_store);
    ww::identity::SigningContext context;
    std::vector<std::string> extended_path;

    ASSERT_SUCCESS(rsp, manager.find_context(context_path, extended_path, context),
                   "invalid request, unable to locate context");
    ASSERT_SUCCESS(rsp, extended_path.size() == 0,
                   "invalid request, extensible paths not allowed");

    // ---------- RETURN ----------
    ww::value::Value v;
    ASSERT_SUCCESS(rsp, context.serialize(v),
                   "unexpected error, failed to serialize signing context");

    return rsp.value(v, false);
}

// -----------------------------------------------------------------
// METHOD:
//   list_signing_contexts
//
//   Walk the signing-context tree starting at the given context_path
//   (empty array means root) and return a flat list of descriptors
//   { path, description, extensible }. Descent stops at extensible
//   contexts. Paths that descend past an extensible context are
//   rejected. Owner-only; keys are never returned.
//
// JSON PARAMETERS:
//   IDENTITY_LIST_SIGNING_CONTEXTS_PARAM_SCHEMA
// RETURNS:
//   IDENTITY_LIST_SIGNING_CONTEXTS_RESULT_SCHEMA
// -----------------------------------------------------------------
bool ww::identity::identity::list_signing_contexts(
    const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(IDENTITY_LIST_SIGNING_CONTEXTS_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    // accept an empty path (= root); minimum_size = 0
    std::vector<std::string> root_path;
    ASSERT_SUCCESS(rsp, get_context_path(msg, root_path, 0),
                   "invalid request, ill-formed context path");

    ww::identity::SigningContextManager manager(signing_context_store);

    ww::value::Array contexts_out;
    ASSERT_SUCCESS(rsp, manager.list_contexts(root_path, contexts_out),
                   "invalid request, failed to list signing contexts");

    ww::value::Structure result(IDENTITY_LIST_SIGNING_CONTEXTS_RESULT_SCHEMA);
    ASSERT_SUCCESS(rsp, result.set_value("contexts", contexts_out),
                   "unexpected error, failed to set contexts on result");

    return rsp.value(result, false);
}

// -----------------------------------------------------------------
// METHOD:
//   sign
//
// JSON PARAMETERS:
//   IDENTITY_SIGN_PARAM_SCHEMA
// RETURNS:
//   IDENTITY_SIGN_RESULT_SCHEMA
// -----------------------------------------------------------------
bool ww::identity::identity::sign(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    // Process the input parameters
    ASSERT_SUCCESS(rsp, msg.validate_schema(IDENTITY_SIGN_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    std::vector<std::string> context_path;
    ASSERT_SUCCESS(rsp, get_context_path(msg, context_path),
                   "invalid request, ill-formed context path");

    const std::string b64_message(msg.get_string("message"));
    ww::types::ByteArray message;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_decode(b64_message, message),
                   "invalid request, failed to decode message");

    // Find the signing context referenced by the context path
    ww::identity::SigningContextManager manager(signing_context_store);
    ww::identity::SigningContext context;
    std::vector<std::string> extended_path;

    ASSERT_SUCCESS(rsp, manager.find_context(context_path, extended_path, context),
                   "invalid request, unable to locate context");
    ASSERT_SUCCESS(rsp, context.is_extensible() || extended_path.size() == 0,
                   "invalid request, extensible paths not allowed");

    // The context that will be used to sign the message is found context
    // extended with the path from the message
    context.set_context_path(extended_path);

    ww::types::ByteArray signature;
    ASSERT_SUCCESS(rsp, context.sign_message(message, signature),
                   "unexpected error, signature failed");

    // Encode the signature
    std::string b64_signature;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_encode(signature, b64_signature),
                   "unexpected error: failed to encode signature");

    // ---------- RETURN ----------
    ww::value::String s(b64_signature.c_str());
    return rsp.value(s, false);
}

// -----------------------------------------------------------------
// METHOD:
//   sign_with_contract_key
//
//   Sign a message with the contract's OWN signing key (ContractKeys.Signing),
//   rather than a signing-context key. The public half of this key is the
//   verifying_key the ledger attests in the contract metadata, so the resulting
//   signature can be verified by anyone who trusts the wallet's ledger
//   attestation -- e.g. the external_key_authority when the wallet authorizes an
//   external key binding. Owner-only.
//
// JSON PARAMETERS:
//   IDENTITY_SIGN_WITH_CONTRACT_KEY_PARAM_SCHEMA
// RETURNS:
//   base64 encoded signature
// -----------------------------------------------------------------
bool ww::identity::identity::sign_with_contract_key(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(IDENTITY_SIGN_WITH_CONTRACT_KEY_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string b64_message(msg.get_string("message"));
    ww::types::ByteArray message;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_decode(b64_message, message),
                   "invalid request, failed to decode message");

    // the contract's own signing key; its public half is the ledger-attested
    // verifying_key
    std::string signing_key;
    ASSERT_SUCCESS(rsp, ww::contract::base::get_signing_key(signing_key),
                   "unexpected error, failed to get the contract signing key");

    ww::types::ByteArray signature;
    ASSERT_SUCCESS(rsp, ww::crypto::ecdsa::sign_message(message, signing_key, signature),
                   "unexpected error, failed to sign the message");

    std::string b64_signature;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_encode(signature, b64_signature),
                   "unexpected error, failed to encode signature");

    // ---------- RETURN ----------
    ww::value::String s(b64_signature.c_str());
    return rsp.value(s, false);
}

// -----------------------------------------------------------------
// METHOD:
//   verify
//
// JSON PARAMETERS:
//   IDENTITY_VERIFY_PARAM_SCHEMA
// RETURNS:
//
// -----------------------------------------------------------------
bool ww::identity::identity::verify(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(IDENTITY_VERIFY_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    std::vector<std::string> context_path;
    ASSERT_SUCCESS(rsp, get_context_path(msg, context_path),
                   "invalid request, ill-formed context path");

    const std::string b64_message(msg.get_string("message"));
    ww::types::ByteArray message;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_decode(b64_message, message),
                   "invalid request, failed to decode message");

    const std::string b64_signature(msg.get_string("signature"));
    ww::types::ByteArray signature;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_decode(b64_signature, signature),
                   "invalid request, failed to decode signature");

    // Find the signing context referenced by the context path
    ww::identity::SigningContextManager manager(signing_context_store);
    ww::identity::SigningContext context;
    std::vector<std::string> extended_path;

    ASSERT_SUCCESS(rsp, manager.find_context(context_path, extended_path, context),
                   "invalid request, unable to locate context");
    ASSERT_SUCCESS(rsp, context.is_extensible() || extended_path.size() == 0,
                   "invalid request, extensible paths not allowed");

    // The context that will be used to sign the message is found context
    // extended with the path from the message
    context.set_context_path(extended_path);

    ASSERT_SUCCESS(rsp, context.verify_signature(message, signature),
                   "unexpected error, signature failed");

    // ---------- RETURN ----------
    ww::value::Boolean b(true);
    return rsp.value(b, false);
}

// -----------------------------------------------------------------
// METHOD:
//   get_verifying_key
//
//   Note that this method will override the get_verifying_key method
//   from the common library. That method returned the verifying key
//   for the contract. This is a more semantically rich variant. The
//   contract verifying key should still be available from the ledger.
//
// JSON PARAMETERS:
//   IDENTITY_GET_VERIFYING_KEY_PARAM_SCHEMA
// RETURNS:
//   PEM encoded public key
// -----------------------------------------------------------------
bool ww::identity::identity::get_verifying_key(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(IDENTITY_GET_VERIFYING_KEY_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    // Get the context path parameter
    std::vector<std::string> context_path;
    ASSERT_SUCCESS(rsp, get_context_path(msg, context_path),
                   "invalid request, ill-formed context path");

    // Find the signing context referenced by the context path
    ww::identity::SigningContextManager manager(signing_context_store);
    ww::identity::SigningContext context;
    std::vector<std::string> extended_path;

    ASSERT_SUCCESS(rsp, manager.find_context(context_path, extended_path, context),
                   "invalid request, unable to locate context");
    ASSERT_SUCCESS(rsp, context.is_extensible() || extended_path.size() == 0,
                   "invalid request, extensible paths not allowed");

    // The context that will be used to sign the message is found context
    // extended with the path from the message
    context.set_context_path(extended_path);

    std::string private_key, public_key, chain_code;
    ASSERT_SUCCESS(rsp, context.generate_keys(private_key, public_key, chain_code),
                   "unexpected error, failed to generate public key");

    // ---------- RETURN ----------
    ww::value::String result(public_key.c_str());
    return rsp.value(result, false);
}

// -----------------------------------------------------------------
// METHOD:
//   get_extended_verifying_key
//
//   This method is similar to get_verifying_key, but it returns the
//   chain code associated with the verifying key. This is a separate
//   method in order to allow for different policies on who may invoke
//   the method.
//
// JSON PARAMETERS:
//   IDENTITY_GET_VERIFYING_KEY_PARAM_SCHEMA
// RETURNS:
//   PEM encoded public key
// -----------------------------------------------------------------
bool ww::identity::identity::get_extended_verifying_key(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(IDENTITY_GET_VERIFYING_KEY_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    // Get the context path parameter; an empty path is valid here and refers
    // to the root context (register_trusted_issuer accepts the same empty
    // path to mean "trust this issuer's root key for any context").
    std::vector<std::string> context_path;
    ASSERT_SUCCESS(rsp, get_context_path(msg, context_path, 0),
                   "invalid request, ill-formed context path");

    // Find the signing context referenced by the context path
    ww::identity::SigningContextManager manager(signing_context_store);
    ww::identity::SigningContext context;
    std::vector<std::string> extended_path;

    ASSERT_SUCCESS(rsp, manager.find_context(context_path, extended_path, context),
                   "invalid request, unable to locate context");
    ASSERT_SUCCESS(rsp, context.is_extensible() || extended_path.size() == 0,
                   "invalid request, extensible paths not allowed");

    // The context that will be used to sign the message is found context
    // extended with the path from the message
    context.set_context_path(extended_path);

    std::string private_key, public_key, chain_code;
    ASSERT_SUCCESS(rsp, context.generate_keys(private_key, public_key, chain_code),
                   "unexpected error, failed to generate public key");

    // ---------- RETURN ----------
    ww::value::Structure result(IDENTITY_GET_EXTENDED_VERIFYING_KEY_RESULT_SCHEMA);
    ASSERT_SUCCESS(rsp, result.set_string("public_key", public_key.c_str()),
                   "unexpected error, failed to set public key");
    ASSERT_SUCCESS(rsp, result.set_string("chain_code", chain_code.c_str()),
                   "unexpected error, failed to set chain code");

    return rsp.value(result, false);
}

// -----------------------------------------------------------------
// METHOD: add_vc
//   Store a verifiable credential in the identity's VC store,
//   indexed by the first element of its type list.
//
// JSON PARAMETERS:
//   IDENTITY_ADD_VC_PARAM_SCHEMA
// RETURNS:
//   true on success
// -----------------------------------------------------------------
bool ww::identity::identity::add_vc(const Message& msg, const Environment& env, Response& rsp)
{
    // TODO: for now, allow any person to add a VC to any wallet, for an easier UX.
    // ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(IDENTITY_ADD_VC_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    ww::value::Object vc_object;
    ASSERT_SUCCESS(rsp, msg.get_value("credential", vc_object),
                   "invalid request, missing credential");

    ww::identity::VerifiableCredential vc;
    ASSERT_SUCCESS(rsp, vc.deserialize(vc_object),
                   "invalid request, ill-formed verifiable credential");

    ASSERT_SUCCESS(rsp, !vc.credential_.type_.empty(),
                   "invalid request, credential type list is empty");

    const std::string credential_type = vc.credential_.type_[0];

    ww::value::Object serialized_vc;
    ASSERT_SUCCESS(rsp, vc.serialize(serialized_vc),
                   "unexpected error, failed to serialize credential");

    ASSERT_SUCCESS(rsp, store_vc(credential_type, serialized_vc),
                   "unexpected error, failed to store credential");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: get_vc_list
//   Return all stored verifiable credentials as a dictionary mapping
//   credential type to the VC object.
//
// JSON PARAMETERS:
//   none
// RETURNS:
//   object mapping credential_type -> VC object
// -----------------------------------------------------------------
bool ww::identity::identity::get_vc_list(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ww::value::Object vc_map;
    ASSERT_SUCCESS(rsp, load_vc_map(vc_map),
                   "unexpected error, failed to load vc store");

    return rsp.value(vc_map, false);
}

// -----------------------------------------------------------------
// METHOD: get_vp
//   Retrieve stored verifiable credentials for the given types and
//   wrap them in a signed VerifiablePresentation.
//
// JSON PARAMETERS:
//   IDENTITY_GET_VP_PARAM_SCHEMA
// RETURNS:
//   VERIFIABLE_PRESENTATION_SCHEMA
// -----------------------------------------------------------------
bool ww::identity::identity::get_vp(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(IDENTITY_GET_VP_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    ww::value::Array types_array;
    ASSERT_SUCCESS(rsp, msg.get_value("credential_types", types_array),
                   "invalid request, missing credential_types");

    // collect the stored VCs
    ww::value::Object vc_map;
    ASSERT_SUCCESS(rsp, load_vc_map(vc_map),
                   "unexpected error, failed to load vc store");

    ww::value::Array vc_list;
    const size_t count = types_array.get_count();
    for (size_t i = 0; i < count; i++)
    {
        const std::string credential_type(types_array.get_string(i));

        ww::value::Object vc_object;
        ASSERT_SUCCESS(rsp, vc_map.get_value(credential_type.c_str(), vc_object),
                       ("invalid request, no credential stored for type: " + credential_type).c_str());

        ASSERT_SUCCESS(rsp, vc_list.append_value(vc_object),
                       "unexpected error, failed to build VC list");
    }

    // build the Presentation object
    ww::identity::Identity holder;
    holder.id_ = env.contract_id_;

    ww::value::Value serialized_holder;
    ASSERT_SUCCESS(rsp, holder.serialize(serialized_holder),
                   "unexpected error, failed to serialize holder identity");

    ww::value::Object presentation_obj;
    ASSERT_SUCCESS(rsp, presentation_obj.set_value("holder", serialized_holder),
                   "unexpected error, failed to set holder in presentation");
    ASSERT_SUCCESS(rsp, presentation_obj.set_value("verifiableCredential", vc_list),
                   "unexpected error, failed to set credentials in presentation");

    // derive a per-originator signing context from the __HOLDER__ root
    ww::types::ByteArray originator_bytes(env.originator_id_.begin(), env.originator_id_.end());
    ww::types::ByteArray originator_hash;
    ASSERT_SUCCESS(rsp, ww::crypto::hash::sha256_hash(originator_bytes, originator_hash),
                   "unexpected error, failed to hash originator");

    std::string encoded_originator;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_encode(originator_hash, encoded_originator),
                   "unexpected error, failed to encode originator");

    // TODO: this doesn't make sense; the originator is always the contract owner.
    // perhaps later if we try to mimic the OID4VP, the context path will include the
    // releying party ID
    std::vector<std::string> context_path = {initial_holder_path, encoded_originator};
    ww::identity::SigningContext context;
    std::vector<std::string> extended_path;

    ww::identity::SigningContextManager manager = ww::identity::identity::get_context_manager();
    ASSERT_SUCCESS(rsp, manager.find_context(context_path, extended_path, context),
                   "unexpected error, failed to locate holder signing context");

    context.set_context_path(extended_path);

    const ww::identity::IdentityKey identity(env.contract_id_, context_path);

    // build and sign the VP
    ww::identity::VerifiablePresentation vp;
    ASSERT_SUCCESS(rsp, vp.build(presentation_obj, identity, context),
                   "unexpected error, failed to build verifiable presentation");

    ww::value::Object serialized_vp;
    ASSERT_SUCCESS(rsp, vp.serialize(serialized_vp),
                   "unexpected error, failed to serialize verifiable presentation");

    return rsp.value(serialized_vp, false);
}
