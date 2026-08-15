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

#include "Environment.h"
#include "Message.h"
#include "Response.h"

#include "identity/common/Credential.h"
#include "identity/common/SigningContextManager.h"

#define IDENTITY_INITIALIZE_PARAM_SCHEMA        \
    "{"                                         \
        SCHEMA_KW(description, "")              \
    "}"

// At some point, we would like to add a context administrator to the
// registration. The administrator of the context or of any parent
// context would be the only ones allowed to register additional
// contexts in the tree below this one or to sign objects with the
// keys in the subcontexts. The basic idea is that we can create some
// level of accountability for how subcontexts are used.

#define IDENTITY_REGISTER_SIGNING_CONTEXT_PARAM_SCHEMA  \
    "{"                                                 \
        SCHEMA_KW(context_path, [ "" ]) ","             \
        SCHEMA_KW(description, "") ","                  \
        SCHEMA_KW(extensible, true)                     \
    "}"

// At some point, we need to add an operation to unregister a signing
// context. While it may sound straightforward (and might actually be
// so), there may be issues to address with usefulness of keys that
// have been used previously

#define IDENTITY_DESCRIBE_SIGNING_CONTEXT_PARAM_SCHEMA  \
    "{"                                                 \
        SCHEMA_KW(context_path, [ "" ])                 \
    "}"

#define IDENTITY_DESCRIBE_SIGNING_CONTEXT_RESULT_SCHEMA \
    "{"                                                 \
        SCHEMA_KW(subcontexts, [ "" ]) ","              \
        SCHEMA_KW(description, "") ","                  \
        SCHEMA_KW(extensible, true)                     \
    "}"

// list_signing_contexts walks the signing-context tree starting at the
// given context_path (empty array means root) and returns a flat list
// of descriptors. Descent stops at extensible contexts. Paths that
// descend past an extensible context are rejected.

#define IDENTITY_LIST_SIGNING_CONTEXTS_PARAM_SCHEMA     \
    "{"                                                 \
        SCHEMA_KW(context_path, [ "" ])                 \
    "}"

// SIGNING_CONTEXT_DESCRIPTOR_SCHEMA is defined in SigningContextManager.h
// (the manager owns the per-node descriptor shape it produces).
#define IDENTITY_LIST_SIGNING_CONTEXTS_RESULT_SCHEMA    \
    "{"                                                 \
        SCHEMA_KWS(contexts, "[" SIGNING_CONTEXT_DESCRIPTOR_SCHEMA "]") \
    "}"

#define IDENTITY_SIGN_PARAM_SCHEMA              \
    "{"                                         \
        SCHEMA_KW(context_path, [ "" ]) ","     \
        SCHEMA_KW(message, "")                  \
    "}"

#define IDENTITY_SIGN_RESULT_SCHEMA             \
    "{"                                         \
        SCHEMA_KW(signature, "")                \
    "}"

// sign_with_contract_key signs a message with the contract's OWN signing key
// (ContractKeys.Signing), whose public half is the verifying_key the ledger
// attests in the contract metadata -- unlike sign, which uses a signing-context
// key unrelated to the ledger. This lets the wallet produce a signature anyone
// can verify against its ledger attestation (e.g. to authorize an external key
// binding).
#define IDENTITY_SIGN_WITH_CONTRACT_KEY_PARAM_SCHEMA    \
    "{"                                                 \
        SCHEMA_KW(message, "")                          \
    "}"

#define IDENTITY_VERIFY_PARAM_SCHEMA            \
    "{"                                         \
        SCHEMA_KW(context_path, [ "" ]) ","     \
        SCHEMA_KW(message, "") ","              \
        SCHEMA_KW(signature, "")                \
    "}"

#define IDENTITY_GET_VERIFYING_KEY_PARAM_SCHEMA \
    "{"                                         \
        SCHEMA_KW(context_path, [ "" ])         \
    "}"

#define IDENTITY_GET_EXTENDED_VERIFYING_KEY_RESULT_SCHEMA       \
    "{"                                                         \
        SCHEMA_KW(public_key, "") ","                           \
        SCHEMA_KW(chain_code, "")                               \
    "}"

#define IDENTITY_ADD_VC_PARAM_SCHEMA                                    \
    "{"                                                                 \
        SCHEMA_KWS(credential, VERIFIABLE_CREDENTIAL_SCHEMA)            \
    "}"

#define IDENTITY_GET_VP_PARAM_SCHEMA                    \
    "{"                                                 \
        SCHEMA_KW(credential_types, [ "" ])             \
    "}"

namespace ww
{
namespace identity
{
namespace identity
{
    bool initialize_contract(const Environment& env);
    bool initialize(const Message& msg, const Environment& env, Response& rsp);
    bool register_signing_context(const Message& msg, const Environment& env, Response& rsp);
    bool describe_signing_context(const Message& msg, const Environment& env, Response& rsp);
    bool list_signing_contexts(const Message& msg, const Environment& env, Response& rsp);
    bool sign(const Message& msg, const Environment& env, Response& rsp);
    bool sign_with_contract_key(const Message& msg, const Environment& env, Response& rsp);
    bool verify(const Message& msg, const Environment& env, Response& rsp);
    bool get_verifying_key(const Message& msg, const Environment& env, Response& rsp);
    bool get_extended_verifying_key(const Message& msg, const Environment& env, Response& rsp);
    bool add_vc(const Message& msg, const Environment& env, Response& rsp);
    bool get_vc_list(const Message& msg, const Environment& env, Response& rsp);
    bool get_vp(const Message& msg, const Environment& env, Response& rsp);

    bool get_context_path(const Message& msg, std::vector<std::string>& context_path, size_t minimum_size = 1);
    ww::identity::SigningContextManager get_context_manager(void);

}; // identity
}; // identity
}; // ww
