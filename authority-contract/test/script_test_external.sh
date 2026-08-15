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
# End-to-end CLI test for the external_key_authority. It mirrors the use case: a
# person who owns a PDO wallet binds an external RSA key pair to it.
#
# Setup: the person creates a wallet_key_authority and an external_key_authority,
# and registers the wallet_key_authority as a trusted issuer of the external one,
# then creates the wallet (a plain identity contract).
#
# Binding is then driven by a single command, external_key_authority
# bind_external_key --wallet <context> --keys-dir <dir>, which:
#   1. generates the external rsa key pair and builds the payload
#      { identity: <wallet did>, session_key: <rsa pub> }
#   2. gets a WalletVerifyingKeyCredential for the wallet from the trusted
#      wallet_key_authority (discovered from the external_key_authority's trusted
#      issuers) and stores it in the wallet -- unless the wallet already holds one
#   3. has the wallet sign the payload with its contract key and signs the same
#      payload with the rsa private key
#   4. submits the credential + both signatures to the external_key_authority, which
#      issues a publicKeyCredential, and stores that credential in the wallet
#
# The test then confirms the wallet holds both credentials via get_vp.
#
# Requires a live PDO deployment (ledger + enclave/provisioning/storage services).
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
SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SOURCE_ROOT="$(realpath ${SCRIPTDIR}/..)"

F_SCRIPT=$(basename ${BASH_SOURCE[-1]} )
F_SERVICE_HOST=${PDO_HOSTNAME}
F_LEDGER_URL=${PDO_LEDGER_URL}
F_LOGLEVEL=${PDO_LOG_LEVEL:-debug}
F_LOGFILE=${PDO_LOG_FILE:-__screen__}
F_CONTEXT_FILE=${SOURCE_ROOT}/test/external_context.toml
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
F_KEY_FILES=()
KEYGEN=${PDO_SOURCE_ROOT}/build/__tools__/make-keys

yell create keys for the contracts
for i in 1 2 3 4 5 ; do
    if [ ! -f ${PDO_HOME}/keys/user${i}_private.pem ] ; then
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/user${i} --format pem
        F_KEY_FILES+=(${PDO_HOME}/keys/user${i}_{private,public}.pem)
    fi
done

TEST_ROOT=$(mktemp -d /tmp/external_test.XXXXXXXXX)

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
# service and groups databases
# -----------------------------------------------------------------
yell create the service and groups database for host ${F_SERVICE_HOST}
try pdo-service-db import ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE}
try pdo-eservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default \
    --preferred ${F_PREFERRED}
try pdo-pservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default
try pdo-sservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default \
             --replicas 1 --duration 60

# -----------------------------------------------------------------
# contexts: the operator (user1) runs the external key authority, whose context
# also carries its wallet key authority; the consumer (user2) owns the wallet.
# Because the wallet's creator is read from the ledger and passed to the authority,
# the operator can attest the consumer's wallet.
# -----------------------------------------------------------------
cd "${SOURCE_ROOT}"
rm -f ${F_CONTEXT_FILE}

try pdo-context load ${OPTS} --import-file ${F_CONTEXT_TEMPLATES}/external_key_authority.toml \
    --bind identity eka --bind user user1

try pdo-context load ${OPTS} --import-file ${F_IDENTITY_TEMPLATES}/identity.toml \
    --bind identity wallet --bind user user2

# =================================================================
# start the tests
# =================================================================

########### setup: the operator creates the external key authority
# creating the external key authority also creates the wallet key authority carried
# in its context and trusts it as an issuer of WalletVerifyingKeyCredentials
yell create the external key authority and its wallet key authority
try external_key_authority create ${OPTS} --contract identity.eka.external_key_authority

########### setup: the consumer's wallet
yell create the consumer wallet
try id_wallet create ${OPTS} --contract identity.wallet.wallet \
    -d 'the consumer pdo wallet'

########### bind an external rsa key to the wallet in one command
# bind_external_key runs as the wallet owner (user2): it generates the external
# rsa key, gets a WalletVerifyingKeyCredential from the trusted wallet key
# authority (storing it in the wallet), gets a publicKeyCredential from the
# external key authority, and stores it in the wallet.
yell bind an external rsa key to the consumer wallet
try external_key_authority bind_external_key ${OPTS} --identity user2 \
    --contract identity.eka.external_key_authority \
    --wallet identity.wallet.wallet \
    --keys-dir ${TEST_ROOT}/keys

########### the wallet now holds both credentials
# get_vp fails if either type is missing, so this confirms both were stored
yell confirm the wallet holds the verifying-key and the public-key credentials
try id_wallet get_vp ${OPTS} --identity user2 --contract identity.wallet.wallet \
    --types WalletVerifyingKeyCredential publicKeyCredential \
    --file ${TEST_ROOT}/wallet_vp.json

say wallet presentation:
cat ${TEST_ROOT}/wallet_vp.json
echo

########### a second bind reuses the stored WalletVerifyingKeyCredential
yell bind again to confirm the stored WalletVerifyingKeyCredential is reused
try external_key_authority bind_external_key ${OPTS} --identity user2 \
    --contract identity.eka.external_key_authority \
    --wallet identity.wallet.wallet \
    --keys-dir ${TEST_ROOT}/keys2

yell All tests passed
