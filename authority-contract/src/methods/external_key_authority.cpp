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
#include "identity/policy_agent.h"          // trusted-issuer map + verify_credential
#include "identity/signature_authority.h"
#include "identity/common/Credential.h"
#include "identity/common/SigningContext.h"
#include "identity/common/SigningContextManager.h"
#include "identity/crypto/RSAPublicKey.h"   // RSA public key, for the session key's signature
#include "authority/wallet_key_authority.h" // WALLET_VERIFYING_KEY_CREDENTIAL_TYPE
#include "authority/external_key_authority.h"

// -----------------------------------------------------------------
// METHOD: initialize_contract
//   Creation hook. Sets up the inherited identity signing contexts + VC store,
//   an empty trusted-issuers map (so a wallet_key_authority can be registered as
//   a trusted issuer of WalletVerifyingKeyCredentials), and a dedicated signing
//   context that this authority signs the credentials it issues with. It holds NO
//   ledger key: it delegates the ledger check to the wallet_key_authority that
//   issued the WalletVerifyingKeyCredential it consumes.
// -----------------------------------------------------------------
bool ww::authority::external_key_authority::initialize_contract(const Environment& env)
{
    if (! ww::identity::identity::initialize_contract(env))
        return false;

    if (! ww::identity::policy_agent::initialize_trusted_issuers())
        return false;

    std::vector<std::string> issuer_path = {EXTERNAL_KEY_AUTHORITY_ISSUER_CONTEXT};
    ww::identity::SigningContextManager manager = ww::identity::identity::get_context_manager();
    if (! manager.add_context(false, "external key authority issuer context", issuer_path))
        return false;

    return true;
}

// -----------------------------------------------------------------
// Verify a base64 signature over the payload string using a PEM public key.
//
// The wallet signs with its contract signing key (the WalletVerifyingKeyCredential's
// "verifying_key" claim is its public half), so its signature is checked with the
// wawaka ecdsa primitive -- the same SHA-256 ECDSA scheme PDO contract keys sign
// with. The session key signs with its rsa key (RSASSA-PKCS1-v1_5 / SHA-256). The
// message is the payload string bytes.
// -----------------------------------------------------------------
static bool verify_ec_signature(
    const std::string& payload, const std::string& b64_signature, const std::string& key)
{
    ww::types::ByteArray message(payload.begin(), payload.end());
    ww::types::ByteArray signature;
    if (! ww::crypto::b64_decode(b64_signature, signature))
        return false;

    return ww::crypto::ecdsa::verify_signature(message, key, signature);
}

static bool verify_rsa_signature(
    const std::string& payload, const std::string& b64_signature, const std::string& key)
{
    ww::types::ByteArray message(payload.begin(), payload.end());
    ww::types::ByteArray signature;
    if (! ww::crypto::b64_decode(b64_signature, signature))
        return false;

    pdo_contracts::crypto::signing::RSAPublicKey public_key;
    if (! public_key.Deserialize(key))
        return false;
    return public_key.VerifySignature(message, signature);
}

// -----------------------------------------------------------------
// Build and sign a publicKeyCredential asserting that the wallet (subject) controls
// the session key (the "key" claim). Signed with this authority's issuer signing
// context, exactly as signature_authority::sign_credential signs a caller-supplied
// credential.
// -----------------------------------------------------------------
static bool build_public_key_credential(
    const Environment& env,
    const std::string& wallet_did,
    const std::string& session_key,
    ww::value::Object& serialized_vc_out,
    std::string& error_msg)
{
    ww::identity::Credential credential;
    credential.type_ = {PUBLIC_KEY_CREDENTIAL_TYPE};
    credential.issuer_.id_ = env.contract_id_;
    credential.credentialSubject_.subject_.id_ = wallet_did;
    credential.credentialSubject_.claims_.set_string("key", session_key.c_str());

    ww::value::Object credential_object;
    if (! credential.serialize(credential_object))
    {
        error_msg.assign("unexpected error, failed to serialize the credential");
        return false;
    }

    const std::vector<std::string> context_path = {EXTERNAL_KEY_AUTHORITY_ISSUER_CONTEXT};
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
//   This authority's customization of signature_authority::sign_credential. It
//   binds an external session key to a wallet from a WalletVerifyingKeyCredential the
//   consumer got from a trusted wallet_key_authority:
//     - verify that credential against a registered trusted issuer, and take the
//       wallet's DID (its subject) and verifying key (its "verifying_key" claim);
//     - confirm the wallet and the session key signed the same payload -- the
//       wallet against its verifying key, the session key against the public half
//       the payload carries -- and that the payload names this wallet;
//     - issue a signed publicKeyCredential (subject = wallet DID, "key" = session key).
//
// JSON PARAMETERS:
//   EXTERNAL_KEY_AUTHORITY_SIGN_CREDENTIAL_PARAM_SCHEMA
//
// RETURNS:
//   VERIFIABLE_CREDENTIAL_SCHEMA -- the signed publicKeyCredential
// -----------------------------------------------------------------
bool ww::authority::external_key_authority::sign_credential(
    const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(EXTERNAL_KEY_AUTHORITY_SIGN_CREDENTIAL_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    // ---------- verify the WalletVerifyingKeyCredential against a trusted issuer ----
    ww::value::Object wskc_object;
    ASSERT_SUCCESS(rsp, msg.get_value("wallet_verifying_key_credential", wskc_object),
                   "invalid request, missing wallet_verifying_key_credential");

    ww::identity::VerifiableCredential wskc;
    ASSERT_SUCCESS(rsp, wskc.deserialize(wskc_object),
                   "invalid request, ill-formed wallet verifying key credential");
    ASSERT_SUCCESS(rsp, ! wskc.credential_.type_.empty() &&
                            wskc.credential_.type_[0] == WALLET_VERIFYING_KEY_CREDENTIAL_TYPE,
                   "invalid request, credential is not a WalletVerifyingKeyCredential");

    // verified against the trusted wallet_key_authority registered for this type
    ASSERT_SUCCESS(rsp, ww::identity::policy_agent::verify_credential(
                            wskc_object, wskc, WALLET_VERIFYING_KEY_CREDENTIAL_TYPE),
                   "invalid request, wallet verifying key credential is not from a trusted issuer");

    // the wallet's DID is the credential subject; its verifying key is the claim
    const std::string wallet_did(wskc.credential_.credentialSubject_.subject_.id_);
    const std::string verifying_key(wskc.credential_.credentialSubject_.claims_.get_string("verifying_key"));
    ASSERT_SUCCESS(rsp, ! verifying_key.empty(),
                   "invalid request, wallet verifying key credential has no verifying_key claim");

    // ---------- the wallet and the session key must have signed the same payload -
    const std::string wallet_payload(msg.get_string("wallet_attestation.payload"));
    const std::string wallet_signature(msg.get_string("wallet_attestation.signature"));
    const std::string session_payload(msg.get_string("session_key_attestation.payload"));
    const std::string session_signature(msg.get_string("session_key_attestation.signature"));

    ASSERT_SUCCESS(rsp, wallet_payload == session_payload,
                   "invalid request, the wallet and the session key signed different payloads");

    // the payload names the wallet and carries the session key's public half
    ww::value::Object payload;
    ASSERT_SUCCESS(rsp, payload.deserialize(wallet_payload.c_str()) &&
                            payload.validate_schema(EXTERNAL_KEY_PAYLOAD_SCHEMA),
                   "invalid request, ill-formed binding payload");
    const std::string identity(payload.get_string("identity"));
    const std::string session_key(payload.get_string("session_key"));

    ASSERT_SUCCESS(rsp, identity == wallet_did,
                   "invalid request, the payload identity does not match the wallet credential subject");

    // ---------- verify both signatures over the payload ----------
    // the wallet, using its verifying key from the credential; the session key,
    // proving possession
    ASSERT_SUCCESS(rsp, verify_ec_signature(wallet_payload, wallet_signature, verifying_key),
                   "invalid request, the wallet signature could not be verified");
    ASSERT_SUCCESS(rsp, verify_rsa_signature(session_payload, session_signature, session_key),
                   "invalid request, the session key signature could not be verified");

    // ---------- issue the publicKeyCredential ----------
    std::string error_msg;
    ww::value::Object serialized_vc_out;
    ASSERT_SUCCESS(rsp, build_public_key_credential(env, wallet_did, session_key, serialized_vc_out, error_msg),
                   error_msg.c_str());

    return rsp.value(serialized_vc_out, false);
}
