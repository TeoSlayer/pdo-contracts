#!/bin/bash

# Copyright 2026 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------
# End-to-end CLI test for the wallet_key_authority.
#
# It creates a wallet key authority (which installs the ledger's verifying key as
# its root of trust) and a person's wallet (a plain identity contract), then asks
# the authority to sign_credential for that wallet: the authority gathers the
# wallet's ledger attestation and metadata, verifies the metadata against the
# attestation, and issues a WalletVerifyingKeyCredential binding the wallet's did:pdo
# DID to its ledger-registered verifying key. The issued credential is then verified
# against the authority.
#
# Requires a live PDO deployment (ledger + enclave/provisioning/storage services),
# exactly like the other families' script_test.sh.
# -----------------------------------------------------------------
: "${PDO_LEDGER_URL?Missing environment variable PDO_LEDGER_URL}"
: "${PDO_HOME?Missing environment variable PDO_HOME}"
: "${PDO_SOURCE_ROOT?Missing environment variable PDO_SOURCE_ROOT}"

source ${PDO_HOME}/bin/lib/common.sh
check_python_version

if ! command -v pdo-shell &> /dev/null ; then
    yell unable to locate pdo-shell
    exit 1
fi

if [ "${PDO_LEDGER_TYPE}" == "ccf" ]; then
    if [ ! -f "${PDO_LEDGER_KEY_ROOT}/networkcert.pem" ]; then
        die "CCF ledger keys are missing, please copy and try again"
    fi
fi

# -----------------------------------------------------------------
# Process command line arguments
# -----------------------------------------------------------------
SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SOURCE_ROOT="$(realpath ${SCRIPTDIR}/..)"

F_SCRIPT=$(basename ${BASH_SOURCE[-1]} )
F_SERVICE_HOST=${PDO_HOSTNAME}
F_LEDGER_URL=${PDO_LEDGER_URL}
F_LOGLEVEL=${PDO_LOG_LEVEL:-debug}
F_LOGFILE=${PDO_LOG_FILE:-__screen__}
F_CONTEXT_FILE=${SOURCE_ROOT}/test/test_context.toml
F_CONTEXT_TEMPLATES=${PDO_HOME}/contracts/authority/context
F_IDENTITY_TEMPLATES=${PDO_HOME}/contracts/identity/context
F_PREFERRED=http://localhost:7101

F_USAGE='--host service-host | --ledger url | --loglevel [debug|info|warn] | --logfile file | --preferred [host]'
SHORT_OPTS='h:l:p:'
LONG_OPTS='host:,ledger:,loglevel:,logfile:,preferred:'

TEMP=$(getopt -o ${SHORT_OPTS} --long ${LONG_OPTS} -n "${F_SCRIPT}" -- "$@")
if [ $? != 0 ] ; then echo "Usage: ${F_SCRIPT} ${F_USAGE}" >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -h|--host) F_SERVICE_HOST="$2" ; shift 2 ;;
        -l|--ledger) F_LEDGER_URL="$2" ; shift 2 ;;
        -p|--preferred) F_PREFERRED="$2" ; shift 2 ;;
        --loglevel) F_LOGLEVEL="$2" ; shift 2 ;;
        --logfile) F_LOGFILE="$2" ; shift 2 ;;
        --help) echo "Usage: ${F_SCRIPT} ${F_USAGE}"; exit 0 ;;
        --) shift ; break ;;
        *) echo "Internal error!" ; exit 1 ;;
    esac
done

F_SERVICE_SITE_FILE=${PDO_HOME}/etc/sites/${F_SERVICE_HOST}.toml
if [ ! -f ${F_SERVICE_SITE_FILE} ] ; then
    die unable to locate the service information file ${F_SERVICE_SITE_FILE}
fi

F_SERVICE_GROUPS_DB_FILE=${SOURCE_ROOT}/test/${F_SERVICE_HOST}_groups_db
F_SERVICE_DB_FILE=${SOURCE_ROOT}/test/${F_SERVICE_HOST}_db

_COMMON_=("--logfile ${F_LOGFILE}" "--loglevel ${F_LOGLEVEL}")
_COMMON_+=("--ledger ${F_LEDGER_URL}")
_COMMON_+=("--groups-db ${F_SERVICE_GROUPS_DB_FILE}")
_COMMON_+=("--service-db ${F_SERVICE_DB_FILE}")
SHORT_OPTS=${_COMMON_[@]}

_COMMON_+=("--context-file ${F_CONTEXT_FILE}")
OPTS=${_COMMON_[@]}

# -----------------------------------------------------------------
# Make sure the keys and eservice database are created and up to date
# -----------------------------------------------------------------
F_KEY_FILES=()
KEYGEN=${PDO_SOURCE_ROOT}/build/__tools__/make-keys

yell create keys for the contracts
for i in 1 2 3 4 5 ; do
    if [ ! -f ${PDO_HOME}/keys/user${i}_private.pem ] ; then
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/user${i} --format pem
        F_KEY_FILES+=(${PDO_HOME}/keys/user${i}_{private,public}.pem)
    fi
done

TEST_ROOT=$(mktemp -d /tmp/authority_test.XXXXXXXXX)

# -----------------------------------------------------------------
function cleanup {
    rm -f ${F_SERVICE_GROUPS_DB_FILE} ${F_SERVICE_GROUPS_DB_FILE}-lock
    rm -f ${F_SERVICE_DB_FILE} ${F_SERVICE_DB_FILE}-lock
    rm -f ${F_CONTEXT_FILE}
    rm -rf ${TEST_ROOT}
    for key_file in ${F_KEY_FILES[@]} ; do
        rm -f ${key_file}
    done
}
trap cleanup EXIT

# -----------------------------------------------------------------
# create the service and groups databases from the site file
# -----------------------------------------------------------------
yell create the service and groups database for host ${F_SERVICE_HOST}
try pdo-service-db import ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE}
try pdo-eservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default \
    --preferred ${F_PREFERRED}
try pdo-pservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default
try pdo-sservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default \
             --replicas 1 --duration 60

# -----------------------------------------------------------------
# setup the contexts; the authority and the "wallet" are both created by the
# same user so that the wallet's creator (which the ledger signs over) matches
# the identity that requests the credential
# -----------------------------------------------------------------
cd "${SOURCE_ROOT}"
rm -f ${F_CONTEXT_FILE}

try pdo-context load ${OPTS} --import-file ${F_CONTEXT_TEMPLATES}/wallet_key_authority.toml \
    --bind identity key_authority --bind user user2

try pdo-context load ${OPTS} --import-file ${F_IDENTITY_TEMPLATES}/identity.toml \
    --bind identity wallet --bind user user1

# =================================================================
# start the tests
# =================================================================

########### setup: the wallet key authority
yell create the wallet key authority and install the ledger root of trust
try wallet_key_authority create ${OPTS} --contract identity.key_authority.wallet_key_authority

yell export the authority issuer verifying key for its trusted-issuer registration
try wallet_key_authority get_verifying_key ${OPTS} \
    --contract identity.key_authority.wallet_key_authority

########### setup: the person's wallet (a plain identity contract)
yell create the wallet to be attested
try id_wallet create ${OPTS} --contract identity.wallet.wallet \
    -d 'the person''s pdo wallet'

########### issue the wallet verifying key credential
yell verify the wallet ledger attestation and issue a WalletVerifyingKeyCredential
try wallet_key_authority sign_credential ${OPTS} \
    --contract identity.key_authority.wallet_key_authority \
    --wallet identity.wallet.wallet \
    --credential ${TEST_ROOT}/wallet_verifying_key_vc.json

say issued credential:
cat ${TEST_ROOT}/wallet_verifying_key_vc.json
echo

if ! grep -q "WalletVerifyingKeyCredential" ${TEST_ROOT}/wallet_verifying_key_vc.json ; then
    die "issued credential is not a WalletVerifyingKeyCredential"
fi

########### verify the issued credential against the authority
yell verify the issued credential against the authority
try wallet_key_authority verify_credential ${OPTS} \
    --contract identity.key_authority.wallet_key_authority \
    --signed-credential ${TEST_ROOT}/wallet_verifying_key_vc.json

yell All tests passed
