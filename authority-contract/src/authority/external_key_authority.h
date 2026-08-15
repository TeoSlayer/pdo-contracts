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

#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Util.h"

#include "identity/common/Credential.h" // VERIFIABLE_CREDENTIAL_SCHEMA

// The credential this authority issues: a publicKeyCredential whose subject is
// the wallet (named by its did:pdo DID) and whose "key" claim is the external
// session key, i.e. the issuer asserts the wallet controls that public key.
#define PUBLIC_KEY_CREDENTIAL_TYPE "publicKeyCredential"

// The signing context this authority signs the credentials it issues with.
#define EXTERNAL_KEY_AUTHORITY_ISSUER_CONTEXT "external_key_authority"

// The payload the wallet and the session key both sign to request a binding:
//   { "identity": "<wallet did>", "session_key": "<external public key>" }
#define EXTERNAL_KEY_PAYLOAD_SCHEMA             \
    "{"                                         \
        SCHEMA_KW(identity, "") ","             \
        SCHEMA_KW(session_key, "")              \
    "}"

// A signed attestation: the serialized payload string and a base64 signature over
// its bytes. The wallet and the session key each produce one over the same payload.
#define EXTERNAL_KEY_ATTESTATION_SCHEMA         \
    "{"                                         \
        SCHEMA_KW(payload, "") ","              \
        SCHEMA_KW(signature, "")                \
    "}"

// sign_credential inputs: a WalletVerifyingKeyCredential the consumer obtained from a
// wallet_key_authority this authority trusts (it carries the wallet's DID as its
// subject and the wallet's verifying key as a claim), plus the wallet's and the
// session key's attestations over the binding payload.
#define EXTERNAL_KEY_AUTHORITY_SIGN_CREDENTIAL_PARAM_SCHEMA             \
    "{"                                                                 \
        SCHEMA_KWS(wallet_verifying_key_credential, VERIFIABLE_CREDENTIAL_SCHEMA) "," \
        SCHEMA_KWS(wallet_attestation, EXTERNAL_KEY_ATTESTATION_SCHEMA) "," \
        SCHEMA_KWS(session_key_attestation, EXTERNAL_KEY_ATTESTATION_SCHEMA) \
    "}"

namespace ww
{
namespace authority
{
namespace external_key_authority
{
    // creation hook: identity signing contexts + the trusted-issuers map + the
    // issuer signing context this authority signs with
    bool initialize_contract(const Environment& env);

    // The customization of signature_authority's sign_credential. It verifies the
    // supplied WalletVerifyingKeyCredential against a registered trusted issuer (a
    // wallet_key_authority), takes the wallet's DID and verifying key from it,
    // confirms the wallet and the session key signed the same binding payload --
    // the wallet against that verifying key, the session key against the public half
    // carried in the payload -- and then issues a signed publicKeyCredential whose
    // subject is the wallet and whose "key" claim is the session key.
    bool sign_credential(const Message& msg, const Environment& env, Response& rsp);

}; // external_key_authority
}; // authority
}; // ww
