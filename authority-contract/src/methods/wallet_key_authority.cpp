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

#include <string>
#include <vector>
#include <stddef.h>
#include <stdint.h>

#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Types.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "contract/base.h"
#include "contract/attestation.h"
#include "identity/identity.h"
#include "identity/signature_authority.h"
#include "identity/common/Credential.h"
#include "identity/common/SigningContext.h"
#include "identity/common/SigningContextManager.h"
#include "authority/wallet_key_authority.h"

// -----------------------------------------------------------------
// METHOD: initialize_contract
//   Creation hook. Sets up (1) the identity signing contexts and VC store
//   (inherited via signature_authority -> identity), (2) the attestation module's
//   ledger key and code hash (so the owner can install the ledger's verifying key
//   and this authority can verify wallet attestations), and (3) a dedicated
//   signing context that this authority uses to sign the credentials it issues.
// -----------------------------------------------------------------
bool ww::authority::wallet_key_authority::initialize_contract(const Environment& env)
{
    // identity signing-context store + holder context + VC store (also runs the
    // base contract initialization)
    if (! ww::identity::identity::initialize_contract(env))
        return false;

    // attestation ledger key (empty until the owner sets it) + this contract's
    // own code hash
    if (! ww::contract::attestation::initialize_contract(env))
        return false;

    // the issuer signing context this authority signs issued credentials with;
    // non-extensible because we always sign from exactly this context
    std::vector<std::string> issuer_path = {WALLET_KEY_AUTHORITY_ISSUER_CONTEXT};
    ww::identity::SigningContextManager manager = ww::identity::identity::get_context_manager();
    if (! manager.add_context(false, "wallet key authority issuer context", issuer_path))
        return false;

    return true;
}

// -----------------------------------------------------------------
// Build and sign a WalletVerifyingKeyCredential for the given wallet DID and
// verifying key. Signed with this authority's issuer signing context, exactly as
// signature_authority::sign_credential signs a caller-supplied credential.
// -----------------------------------------------------------------
static bool build_wallet_verifying_key_credential(
    const Environment& env,
    const std::string& wallet_did,
    const std::string& verifying_key,
    ww::value::Object& serialized_vc_out,
    std::string& error_msg)
{
    // the wallet DID is the credential SUBJECT; the only claim is the verifying key
    ww::identity::Credential credential;
    credential.type_ = {WALLET_VERIFYING_KEY_CREDENTIAL_TYPE};
    credential.issuer_.id_ = env.contract_id_;
    credential.credentialSubject_.subject_.id_ = wallet_did;
    credential.credentialSubject_.claims_.set_string("verifying_key", verifying_key.c_str());

    ww::value::Object credential_object;
    if (! credential.serialize(credential_object))
    {
        error_msg.assign("unexpected error, failed to serialize the credential");
        return false;
    }

    // locate the authority's issuer signing context and sign with it
    const std::vector<std::string> context_path = {WALLET_KEY_AUTHORITY_ISSUER_CONTEXT};
    const ww::identity::IdentityKey identity(env.contract_id_, context_path);
    ww::identity::SigningContextManager manager = ww::identity::identity::get_context_manager();

    ww::identity::SigningContext context;
    std::vector<std::string> extended_path;
    if (! manager.find_context(context_path, extended_path, context))
    {
        error_msg.assign("unexpected error, failed to locate the issuer signing context");
        return false;
    }
    context.set_context_path(extended_path);

    ww::identity::VerifiableCredential vc;
    if (! vc.build(credential_object, identity, context))
    {
        error_msg.assign("unexpected error, failed to sign the credential");
        return false;
    }

    if (! vc.serialize(serialized_vc_out))
    {
        error_msg.assign("unexpected error, failed to serialize the signed credential");
        return false;
    }

    return true;
}

// -----------------------------------------------------------------
// METHOD: sign_credential
//   This authority's customization of signature_authority::sign_credential.
//   Rather than an owner manually signing an arbitrary credential, it verifies a
//   wallet contract's metadata against its ledger attestation, then issues a
//   signed WalletVerifyingKeyCredential asserting that the wallet (named by its
//   did:pdo DID) is associated with its ledger-registered verifying key.
//
//   Open to any caller: the wallet's creator is supplied in the request (the
//   client reads it from the ledger) and the ledger signature is checked over it,
//   so a caller cannot forge it. The credential states a public ledger fact.
//
// JSON PARAMETERS:
//   WALLET_KEY_AUTHORITY_SIGN_CREDENTIAL_PARAM_SCHEMA
//     { contract_id, creator, ledger_attestation, contract_metadata }
//
// RETURNS:
//   VERIFIABLE_CREDENTIAL_SCHEMA -- the signed WalletVerifyingKeyCredential
// -----------------------------------------------------------------
bool ww::authority::wallet_key_authority::sign_credential(
    const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(WALLET_KEY_AUTHORITY_SIGN_CREDENTIAL_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    // the ledger's verifying key is the root of trust for the attestation
    std::string ledger_key;
    ASSERT_SUCCESS(rsp, ww::contract::attestation::get_ledger_key(ledger_key) && ledger_key.length() > 0,
                   "invalid request, the ledger key has not been set");

    // verify the wallet's metadata is the metadata the ledger attested for it:
    // ww::contract::attestation checks the ledger's signature over the attestation
    // (signed for the wallet's creator) and the metadata-hash binding of the contract
    // id to its verifying key.
    //
    // Nothing here constrains what code the wallet runs, so the credential asserts
    // only that the contract registered at this id holds this verifying key; it is
    // not evidence that the subject is a wallet.
    const std::string creator(msg.get_string("creator"));
    ASSERT_SUCCESS(rsp, ww::contract::attestation::verify_ledger_attestation(msg, creator, ledger_key),
                   "invalid request, failed to verify the ledger attestation");

    // the wallet's verifying key is its ledger-registered verifying key, and its
    // DID is derived from its contract id
    const std::string contract_id(msg.get_string("contract_id"));
    const std::string verifying_key(msg.get_string("contract_metadata.verifying_key"));
    const std::string wallet_did(std::string(PDO_DID_PREFIX) + contract_id);

    std::string error_msg;
    ww::value::Object serialized_vc_out;
    ASSERT_SUCCESS(rsp, build_wallet_verifying_key_credential(env, wallet_did, verifying_key, serialized_vc_out, error_msg),
                   error_msg.c_str());

    return rsp.value(serialized_vc_out, false);
}
