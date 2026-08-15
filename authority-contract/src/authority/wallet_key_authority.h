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

#include "contract/attestation.h"
#include "identity/common/did.h" // PDO_DID_PREFIX

// The credential this authority issues: its subject is the wallet (named by its
// did:pdo DID) and its "verifying_key" claim is the wallet contract's ledger-
// registered verifying key -- i.e. the issuer asserts the wallet is associated
// with that verifying key.
#define WALLET_VERIFYING_KEY_CREDENTIAL_TYPE "WalletVerifyingKeyCredential"

// The signing context this authority uses to sign the credentials it issues. The
// authority owner exports its verifying key/chain code for this path (via the
// inherited get_extended_verifying_key) and registers it as a trusted issuer for
// WalletVerifyingKeyCredential on any policy agent that should trust this authority.
#define WALLET_KEY_AUTHORITY_ISSUER_CONTEXT "wallet_key_authority"

// sign_credential inputs: the wallet contract's id and creator (both read from the
// ledger by the client), its ledger attestation, and its contract metadata. The
// creator is the id the ledger signed the attestation over; passing it explicitly
// (rather than assuming the caller is the creator) lets anyone request a credential
// for a wallet. contract_code_metadata is not needed here -- unlike add_endpoint,
// this authority does not re-check the code hash.
#define WALLET_KEY_AUTHORITY_SIGN_CREDENTIAL_PARAM_SCHEMA               \
    "{"                                                                 \
        SCHEMA_KW(contract_id, "") ","                                 \
        SCHEMA_KW(creator, "") ","                                     \
        SCHEMA_KWS(ledger_attestation, LEDGER_ATTESTATION_SCHEMA) ","  \
        SCHEMA_KWS(contract_metadata, CONTRACT_METADATA_SCHEMA)        \
    "}"

namespace ww
{
namespace authority
{
namespace wallet_key_authority
{
    // creation hook: identity signing contexts + the attestation ledger key +
    // the issuer signing context this authority signs with
    bool initialize_contract(const Environment& env);

    // sign_credential is this authority's customization of signature_authority's
    // sign_credential: instead of an owner manually signing an arbitrary
    // credential, it verifies a wallet contract's metadata against its ledger
    // attestation and then issues a signed WalletVerifyingKeyCredential binding the
    // wallet's DID to its ledger-registered verifying key. (A future authority --
    // e.g. an email authority gated on an ID token -- would customize the same
    // method differently.)
    bool sign_credential(const Message& msg, const Environment& env, Response& rsp);

}; // wallet_key_authority
}; // authority
}; // ww
