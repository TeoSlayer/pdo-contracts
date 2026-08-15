#include <string>
#include <map>

#include <stddef.h>
#include <stdint.h>

#include "Dispatch.h"

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
#include "identity/signature_authority.h"
#include "identity/policy_agent.h"

// Configure expected VCs schemas and policy data schema
#define MEMBERSHIP_CLAIMS_SCHEMA \
    "{" SCHEMA_KW(member_of, "") "}"

#define CONSENT_CLAIMS_SCHEMA \
    "{" SCHEMA_KW(document, "") "}"

#define KEY_CLAIMS_SCHEMA \
    "{" SCHEMA_KW(key, "") "}"

#define POLICY_AGENT_POLICY_DATA_SCHEMA \
    "{" SCHEMA_KW(consent_document, "") "," SCHEMA_KW(allowed_institutions, [""]) "}"

const std::map<std::string, const char *> ww::identity::policy_agent::get_claims_schemas()
{

    const std::map<std::string, const char *> claims_schemas = {
        {"membership", MEMBERSHIP_CLAIMS_SCHEMA},
        {"consent", CONSENT_CLAIMS_SCHEMA},
        {"public_key", KEY_CLAIMS_SCHEMA}};
    return claims_schemas;
}

const char *ww::identity::policy_agent::get_policy_data_schema()
{
    return POLICY_AGENT_POLICY_DATA_SCHEMA;
}

// end configuration

// start policy agent function logic

static bool is_institution_allowed(const std::string &institution_to_check, const ww::value::Array &allowed_institutions)
{
    size_t count = allowed_institutions.get_count();
    for (size_t i = 0; i < count; i++)
    {
        const char *institution = allowed_institutions.get_string(i);
        if (institution != NULL && institution_to_check == institution)
        {
            return true; // Found it!
        }
    }
    return false; // Not found
}

static bool verify_same_subject(
    const std::map<std::string, ww::identity::Credential> &credentials,
    std::string &error_msg)
{
    if (credentials.empty())
    {
        error_msg = "no credentials to verify";
        return false;
    }

    // Get the subject from the first credential
    auto it = credentials.begin();
    const std::string &first_subject = it->second.credentialSubject_.subject_.id_;

    // Check all other credentials have the same subject
    ++it; // Move to second element
    for (; it != credentials.end(); ++it)
    {
        const std::string &current_subject = it->second.credentialSubject_.subject_.id_;
        if (current_subject != first_subject)
        {
            error_msg = "credentials not issued to the same subject: " +
                        it->first + " differs from others";
            return false;
        }
    }

    return true;
}

bool ww::identity::policy_agent::policy_agent_function(
    const std::map<std::string, ww::identity::Credential> &credentials,
    const ww::value::Object &policy_data,
    ww::identity::Credential &credential_out)
{
    std::string error_msg;
    ERROR_IF_NOT(verify_same_subject(credentials, error_msg), error_msg.c_str());

    // -----------------------------------------------------------------
    // -----------------------------------------------------------------
    ww::identity::Credential membership_credential = credentials.at("membership");
    ww::identity::Credential consent_credential = credentials.at("consent");
    ww::identity::Credential public_key_credential = credentials.at("public_key");
    std::string subject = membership_credential.credentialSubject_.subject_.id_;
    credential_out.credentialSubject_.subject_.id_ = subject;
    credential_out.type_ = {"DownloadCredential"};

    // -----------------------------------------------------------------
    // Write your logic here
    // -----------------------------------------------------------------
    ww::value::Array allowed_institutions;
    ERROR_IF_NOT(policy_data.get_value("allowed_institutions", allowed_institutions),
                 "unexpected error, failed to get allowed institutions")

    const ww::value::Object &membership_claims = membership_credential.credentialSubject_.claims_;

    const char *institution = membership_claims.get_string("member_of");
    ERROR_IF_NOT(institution != NULL,
                 "membership credential missing member_of claim");

    std::string institution_str(institution);

    ERROR_IF_NOT(is_institution_allowed(institution_str, allowed_institutions),
                 "Institution is not allowed");

    // -----------------------------------------------------------------
    // -----------------------------------------------------------------
    const char *consent_document = policy_data.get_string("consent_document");
    ERROR_IF_NOT(consent_document != NULL,
                 "unexpected error, failed to get consent document");
    std::string consent_document_str(consent_document);

    const ww::value::Object &consent_claims = consent_credential.credentialSubject_.claims_;
    const char *signed_doc = consent_claims.get_string("document");
    ERROR_IF_NOT(signed_doc != NULL,
                 "consent credential missing document claim");

    std::string signed_doc_str(signed_doc);

    ERROR_IF_NOT(signed_doc_str == consent_document_str,
                 "Didn't consent");

    // -----------------------------------------------------------------
    // -----------------------------------------------------------------
    const char *channel_key = public_key_credential.credentialSubject_.claims_.get_string("key");
    ERROR_IF_NOT(channel_key != NULL,
                 "missing key claim");

    // -----------------------------------------------------------------
    // Build output credential
    // -----------------------------------------------------------------

    // Set the claims
    credential_out.credentialSubject_.claims_.set_string("operation", "get");
    credential_out.credentialSubject_.claims_.set_string("channel_key", channel_key);

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
bool initialize_contract(const Environment &env, Response &rsp)
{
    // ---------- initialize the base contract ----------
    ASSERT_SUCCESS(rsp, ww::identity::policy_agent::initialize_contract(env),
                   "unexpected error: failed to initialize the contract");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// -----------------------------------------------------------------
contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD2(initialize, ww::identity::identity::initialize),

    CONTRACT_METHOD2(get_verifying_key, ww::identity::identity::get_verifying_key),
    CONTRACT_METHOD2(get_extended_verifying_key, ww::identity::identity::get_extended_verifying_key),
    CONTRACT_METHOD2(register_signing_context, ww::identity::identity::register_signing_context),
    CONTRACT_METHOD2(describe_signing_context, ww::identity::identity::describe_signing_context),
    CONTRACT_METHOD2(list_signing_contexts, ww::identity::identity::list_signing_contexts),

    // Not sure if these are appropriate for this contract
    CONTRACT_METHOD2(sign, ww::identity::identity::sign),
    CONTRACT_METHOD2(verify, ww::identity::identity::verify),

    CONTRACT_METHOD2(register_trusted_issuer, ww::identity::policy_agent::register_trusted_issuer),
    CONTRACT_METHOD2(issue_policy_credential, ww::identity::policy_agent::issue_policy_credential),
    CONTRACT_METHOD2(set_policy_data, ww::identity::policy_agent::set_policy_data),
    CONTRACT_METHOD2(get_policy_data, ww::identity::policy_agent::get_policy_data),
    CONTRACT_METHOD2(list_trusted_issuers, ww::identity::policy_agent::list_trusted_issuers),
    CONTRACT_METHOD2(get_requirements, ww::identity::policy_agent::get_requirements),

    // This is used to verify credentials that are generated by the policy agent
    CONTRACT_METHOD2(verify_credential, ww::identity::signature_authority::verify_credential),

    {NULL, NULL}};
