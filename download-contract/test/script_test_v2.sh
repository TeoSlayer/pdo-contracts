#!/bin/bash
set -e

: "${F_GUARDIAN_HOST?Missing environment variable F_GUARDIAN_HOST}"

SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
source ${SCRIPTDIR}/setup_test.sh

TEST_ROOT=$(mktemp -d /tmp/test.XXXXXXXXX)

# -----------------------------------------------------------------
# setup the contexts that will be used later for the tests
# -----------------------------------------------------------------
cd "${SOURCE_ROOT}"

# create any necessary contexts here

# -----------------------------------------------------------------
# start the tests
# -----------------------------------------------------------------

# =================================================================

########### setup: membership_authority
yell create a membership_authority and register signing context

try pdo-context load ${OPTS} --import-file ${F_IDENTITY_TEMPLATES}/signature_authority.toml \
    --bind identity membership_authority --bind user user1

try id_signature_authority create ${OPTS} --contract identity.membership_authority.signature_authority \
    -d 'Membership Authority: issues institution membership credentials'

try id_signature_authority register ${OPTS} --contract identity.membership_authority.signature_authority \
    -d 'fixed key satest' --fixed --path membership


########### setup: consent_authority
yell create a consent_authority and register signing context

try pdo-context load ${OPTS} --import-file ${F_IDENTITY_TEMPLATES}/signature_authority.toml \
    --bind identity consent_authority --bind user user2

try id_signature_authority create ${OPTS} --contract identity.consent_authority.signature_authority \
    -d 'Consent Authority: issues consent credentials'

try id_signature_authority register ${OPTS} --contract identity.consent_authority.signature_authority \
    -d 'fixed key satest' --fixed --path consent


########### setup: public_key_authority
yell create a public_key_authority and register signing context

try pdo-context load ${OPTS} --import-file ${F_IDENTITY_TEMPLATES}/signature_authority.toml \
    --bind identity public_key_authority --bind user user3

try id_signature_authority create ${OPTS} --contract identity.public_key_authority.signature_authority \
    -d 'Public Key Authority: issues public key credentials'

try id_signature_authority register ${OPTS} --contract identity.public_key_authority.signature_authority \
    -d 'fixed key satest' --fixed --path public_key


########### setup: data_download policy agent and token

try pdo-context load ${OPTS} --import-file ${F_CONTEXT_TEMPLATES}/policy_agent.toml \
    --bind identity simple_download --bind user user4

try pdo-context load ${OPTS} --import-file ${F_CONTEXT_TEMPLATES}/tokens.toml \
    --bind token test1 --bind user user4 --bind url http://${F_GUARDIAN_HOST}:7900

try download_policy create ${OPTS} --contract identity.simple_download.policy_agent \
    -d 'data download policy agent: accepts membership, consent, and public key VCs.'

yell create a token issuer and mint the tokens
try ex_token_issuer create ${OPTS} --contract token.test1.token_issuer
try download_token mint_tokens ${OPTS} --contract token.test1.token_object

yell register a trusted VC issuer for token1
try download_token register ${OPTS}  --contract token.test1.token_object.token_1 \
    --issuer identity.simple_download.policy_agent --path __ISSUER__ --credential-types DownloadCredential

########### setup: data_download policy agent configuration

yell register issuer1 with the policy agent
try download_policy register ${OPTS} --contract identity.simple_download.policy_agent \
    --issuer identity.membership_authority.signature_authority --path membership --credential-types membership


yell register issuer2 with the policy agent
try download_policy register ${OPTS} --contract identity.simple_download.policy_agent \
    --issuer identity.consent_authority.signature_authority --path consent --credential-types consent


yell register issuer3 with the policy agent
try download_policy register ${OPTS} --contract identity.simple_download.policy_agent \
    --issuer identity.public_key_authority.signature_authority --path public_key --credential-types public_key

yell configure the policy agent
try download_policy set_policy ${OPTS} --contract identity.simple_download.policy_agent \
    --data ${SCRIPTDIR}/policy_data.json

########### setup: user wallet

try pdo-context load ${OPTS} --import-file ${F_IDENTITY_TEMPLATES}/identity.toml \
    --bind identity downloader --bind user user5

yell create an identity contract
try id_wallet create ${OPTS} --contract identity.downloader.wallet \
    -d 'idtest identity'

########### start
yell generating user channel key
python3 ${SCRIPTDIR}/python/generate_channel_key.py ${TEST_ROOT}/user_channel_key

yell sign membership credential
try id_signature_authority sign_credential ${OPTS} --contract identity.membership_authority.signature_authority \
    --path membership --credential ${SCRIPTDIR}/credential_membership.json --signed-credential ${TEST_ROOT}/membership_vc.json

yell sign consent credential
try id_signature_authority sign_credential ${OPTS} --contract identity.consent_authority.signature_authority \
    --path consent --credential ${SCRIPTDIR}/credential_consent.json --signed-credential ${TEST_ROOT}/consent_vc.json

yell sign public key credential
try id_signature_authority sign_credential ${OPTS} --contract identity.public_key_authority.signature_authority \
    --path public_key --credential ${TEST_ROOT}/user_channel_key/credential_key.json --signed-credential ${TEST_ROOT}/public_key_vc.json

yell add credentials to wallet
try id_wallet add_vc ${OPTS} --contract identity.downloader.wallet \
    --credential ${TEST_ROOT}/membership_vc.json
try id_wallet add_vc ${OPTS} --contract identity.downloader.wallet \
    --credential ${TEST_ROOT}/consent_vc.json
try id_wallet add_vc ${OPTS} --contract identity.downloader.wallet \
    --credential ${TEST_ROOT}/public_key_vc.json

yell generating a VP
try id_wallet get_vp ${OPTS} --contract identity.downloader.wallet \
    --types membership consent public_key --file ${TEST_ROOT}/vp.json

yell issue a credential
try download_policy issue_credential ${OPTS} --contract identity.simple_download.policy_agent \
    --presentation ${TEST_ROOT}/vp.json --issued-credential ${TEST_ROOT}/download_vc.json


yell download data
try download_token do_download ${OPTS}  --contract token.test1.token_object.token_1 \
    --vc-file ${TEST_ROOT}/download_vc.json \
    --output-file ${TEST_ROOT}/encrypted_data.bin

yell read data

python3 ${SCRIPTDIR}/python/read_data.py ${TEST_ROOT}/encrypted_data.bin \
    ${TEST_ROOT}/user_channel_key/private_key.pem ${TEST_ROOT}/decrypted_data.txt

cat ${TEST_ROOT}/decrypted_data.txt
echo

########### other tests
yell test some other endpoints
try download_token list_issuers ${OPTS} --contract token.test1.token_object.token_1

yell All tests passed
