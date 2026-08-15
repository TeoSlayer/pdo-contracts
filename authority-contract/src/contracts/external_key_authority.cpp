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

#include <stddef.h>
#include <stdint.h>

#include "Dispatch.h"

#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Util.h"

#include "contract/base.h"
#include "identity/identity.h"
#include "identity/policy_agent.h"
#include "identity/signature_authority.h"
#include "authority/external_key_authority.h"

// -----------------------------------------------------------------
// METHOD: initialize_contract
//   Creation hook -- delegated to the external_key_authority initializer, which
//   sets up the inherited identity, the trusted-issuers map, and the issuer
//   signing context. It does NOT mark the contract initialized; the inherited
//   identity::initialize method does that.
// -----------------------------------------------------------------
bool initialize_contract(const Environment& env, Response& rsp)
{
    ASSERT_SUCCESS(rsp, ww::authority::external_key_authority::initialize_contract(env),
                   "unexpected error: failed to initialize the contract");
    return rsp.success(true);
}

// -----------------------------------------------------------------
// external_key_authority inherits from signature_authority (identity methods +
// verify_credential) AND from policy_agent (the trusted-issuer methods used to
// trust a wallet_key_authority). It customizes sign_credential to bind an external
// session key to a wallet from a trusted WalletVerifyingKeyCredential.
// -----------------------------------------------------------------
contract_method_reference_t contract_method_dispatch_table[] = {
    // mark the contract initialized (takes a description): inherited from identity
    CONTRACT_METHOD2(initialize, ww::identity::identity::initialize),

    // identity / signing-context management
    CONTRACT_METHOD2(get_verifying_key, ww::identity::identity::get_verifying_key),
    CONTRACT_METHOD2(get_extended_verifying_key, ww::identity::identity::get_extended_verifying_key),
    CONTRACT_METHOD2(register_signing_context, ww::identity::identity::register_signing_context),
    CONTRACT_METHOD2(describe_signing_context, ww::identity::identity::describe_signing_context),
    CONTRACT_METHOD2(list_signing_contexts, ww::identity::identity::list_signing_contexts),
    CONTRACT_METHOD2(sign, ww::identity::identity::sign),
    CONTRACT_METHOD2(sign_with_contract_key, ww::identity::identity::sign_with_contract_key),
    CONTRACT_METHOD2(verify, ww::identity::identity::verify),
    CONTRACT_METHOD2(add_vc, ww::identity::identity::add_vc),
    CONTRACT_METHOD2(get_vc_list, ww::identity::identity::get_vc_list),
    CONTRACT_METHOD2(get_vp, ww::identity::identity::get_vp),

    // credential verification (of this authority's own issued credentials) is
    // inherited from signature_authority; sign_credential is CUSTOMIZED below
    CONTRACT_METHOD2(verify_credential, ww::identity::signature_authority::verify_credential),

    // trusted-issuer management, inherited from policy_agent: register/list the
    // wallet_key_authority(ies) whose WalletVerifyingKeyCredentials this authority trusts
    CONTRACT_METHOD2(register_trusted_issuer, ww::identity::policy_agent::register_trusted_issuer),
    CONTRACT_METHOD2(list_trusted_issuers, ww::identity::policy_agent::list_trusted_issuers),

    // the customized sign_credential: bind an external session key to a wallet
    CONTRACT_METHOD2(sign_credential, ww::authority::external_key_authority::sign_credential),

    {NULL, NULL}};
