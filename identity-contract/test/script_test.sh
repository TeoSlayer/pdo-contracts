#!/bin/bash

# Copyright 2023 Intel Corporation
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
# -----------------------------------------------------------------
: "${PDO_LEDGER_URL?Missing environment variable PDO_LEDGER_URL}"
: "${PDO_HOME?Missing environment variable PDO_HOME}"
: "${PDO_SOURCE_ROOT?Missing environment variable PDO_SOURCE_ROOT}"

# -----------------------------------------------------------------
# -----------------------------------------------------------------
source ${PDO_HOME}/bin/lib/common.sh
check_python_version

if ! command -v pdo-shell &> /dev/null ; then
    yell unable to locate pdo-shell
    exit 1
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
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
F_LOGLEVEL=${PDO_LOG_LEVEL:-info}
F_LOGFILE=${PDO_LOG_FILE:-__screen__}
F_CONTEXT_FILE=${SOURCE_ROOT}/test/test_context.toml
F_CONTEXT_TEMPLATES=${PDO_HOME}/contracts/identity/context
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
        -1|--ledger) F_LEDGER_URL="$2" ; shift 2 ;;
        -p|--preferred) F_PREFERRED="$2" ; shift 2 ;;
        --loglevel) F_LOGLEVEL="$2" ; shift 2 ;;
        --logfile) F_LOGFILE="$2" ; shift 2 ;;
        --help) echo "Usage: ${SCRIPT_NAME} ${F_USAGE}"; exit 0 ;;
        --) shift ; break ;;
        *) echo "Internal error!" ; exit 1 ;;
    esac
done

F_SERVICE_SITE_FILE=${PDO_HOME}/etc/sites/${F_SERVICE_HOST}.toml
if [ ! -f ${F_SERVICE_SITE_FILE} ] ; then
    die unable to locate the service information file ${F_SERVICE_SITE_FILE}; \
        please copy the site.toml file from the service host
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

TEST_ROOT=$(mktemp -d /tmp/test.XXXXXXXXX)

# -----------------------------------------------------------------
function cleanup {
    rm -f ${F_SERVICE_GROUPS_DB_FILE} ${F_SERVICE_GROUPS_DB_FILE}-lock
    rm -f ${F_SERVICE_DB_FILE} ${F_SERVICE_DB_FILE}-lock
    rm -f ${F_CONTEXT_FILE}
    for key_file in ${F_KEY_FILES[@]} ; do
        rm -f ${key_file}
    done

    # rm -rf ${TEST_ROOT}
}

trap cleanup EXIT

# -----------------------------------------------------------------
# create the service and groups databases from a site file; the site
# file is assumed to exist in ${PDO_HOME}/etc/sites/${SERVICE_HOST}.toml
#
# by default, the groups will include all available services from the
# service host
# -----------------------------------------------------------------
yell create the service and groups database for host ${F_SERVICE_HOST}
try pdo-service-db import ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE}
try pdo-eservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default \
    --preferred ${F_PREFERRED}
try pdo-pservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default
try pdo-sservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default \
             --replicas 1 --duration 60

# -----------------------------------------------------------------
# setup the contexts that will be used later for the tests
# -----------------------------------------------------------------
cd "${SOURCE_ROOT}"

rm -f ${F_CONTEXT_FILE}

# create any necessary contexts here
try pdo-context load ${OPTS} --import-file ${F_CONTEXT_TEMPLATES}/identity.toml \
    --bind identity idtest --bind user user1

try pdo-context load ${OPTS} --import-file ${F_CONTEXT_TEMPLATES}/identity.toml \
    --bind identity idtest2 --bind user user1

try pdo-context load ${OPTS} --import-file ${F_CONTEXT_TEMPLATES}/signature_authority.toml \
    --bind identity satest --bind user user2

try pdo-context load ${OPTS} --import-file ${F_CONTEXT_TEMPLATES}/policy_agent.toml \
    --bind identity patest --bind user user3

try pdo-context load ${OPTS} --import-file ${F_CONTEXT_TEMPLATES}/committee.toml \
    --bind user user1 --bind committee cotest

# -----------------------------------------------------------------
# start the tests
# -----------------------------------------------------------------

# =================================================================
yell create a identity contracts
try id_wallet create ${OPTS} --contract identity.idtest.wallet   \
    -d 'idtest identity'
try id_wallet create ${OPTS} --contract identity.idtest2.wallet   \
    -d 'idtest2 identity'

yell register keys and retrieve them
try id_wallet register ${OPTS} --contract identity.idtest.wallet \
    -d 'fixed key idtest.fixed' --fixed --path idtest
try id_wallet register ${OPTS} --contract identity.idtest.wallet \
    -d 'fixed key idtest.fixed' --fixed --path idtest fixed

try id_wallet register ${OPTS} --contract identity.idtest.wallet \
    -d 'extended key idtest.ext1' --extensible --path idtest ext1

try id_wallet get_verifying_key ${OPTS} --contract identity.idtest.wallet \
    --path idtest fixed --file ${TEST_ROOT}/idtest.fixed
try id_wallet get_verifying_key ${OPTS} --contract identity.idtest.wallet \
    --path idtest ext1 --file ${TEST_ROOT}/text1.ext1
try id_wallet get_verifying_key ${OPTS} --contract identity.idtest.wallet \
    --path idtest ext1 ext2 --file ${TEST_ROOT}/text1.ext1.ext2

try id_wallet get_verifying_key ${OPTS} --contract identity.idtest.wallet \
    --path idtest ext1 ext2 --extended --file ${TEST_ROOT}/idtest.ext1.ext2

yell sign message and verify signature, fixed key
try id_wallet sign ${OPTS} --contract identity.idtest.wallet \
    --path idtest fixed --message ${SCRIPTDIR}/credential1.json --signature ${TEST_ROOT}/fixed_credential1.sig
try id_wallet verify ${OPTS} --contract identity.idtest.wallet \
    --path idtest fixed --message ${SCRIPTDIR}/credential1.json --signature ${TEST_ROOT}/fixed_credential1.sig

yell sign message and verify signature, extended key
try id_wallet sign ${OPTS} --contract identity.idtest.wallet \
    --path idtest ext1 ext2 --message ${SCRIPTDIR}/credential1.json --signature ${TEST_ROOT}/ext_credential1.sig
try id_wallet verify ${OPTS} --contract identity.idtest.wallet \
    --path idtest ext1 ext2 --message ${SCRIPTDIR}/credential1.json --signature ${TEST_ROOT}/ext_credential1.sig

yell check invalid signatures, these should fail
id_wallet verify ${OPTS} --contract identity.idtest.wallet --abridged \
    --path idtest ext1 ext2 --message ${SCRIPTDIR}/credential2.json --signature ${TEST_ROOT}/ext_credential1.sig
if [ $? == 0 ]; then
    die verification should have failed
fi

id_wallet verify ${OPTS} --contract identity.idtest.wallet --abridged \
    --path idtest ext1 ext3 --message ${SCRIPTDIR}/credential1.json --signature ${TEST_ROOT}/ext_credential1.sig
if [ $? == 0 ]; then
    die verification should have failed
fi

# =================================================================
yell create a signature authority and register signing contexts
try id_signature_authority create ${OPTS} --contract identity.satest.signature_authority \
    -d 'satest signature authority'

try id_signature_authority register ${OPTS} --contract identity.satest.signature_authority \
    -d 'fixed key satest' --fixed --path satest
try id_signature_authority register ${OPTS} --contract identity.satest.signature_authority \
    -d 'fixed key satest.fixed' --fixed --path satest fixed
try id_signature_authority register ${OPTS} --contract identity.satest.signature_authority \
    -d 'extended key satest.ext1' --extensible --path satest ext1

yell sign a simple credential and verify signature
try id_signature_authority sign_credential ${OPTS} --contract identity.satest.signature_authority \
    --path satest ext1 --credential ${SCRIPTDIR}/credential1.json --signed-credential ${TEST_ROOT}/sa_credential1.json

say signed credential is:
say $(<${TEST_ROOT}/sa_credential1.json)

try id_signature_authority verify_credential ${OPTS} --contract identity.satest.signature_authority \
    --signed-credential ${TEST_ROOT}/sa_credential1.json

yell sign a complex credential and verify signature
try id_signature_authority sign_credential ${OPTS} --contract identity.satest.signature_authority \
    --path satest ext1 ext2 --credential ${SCRIPTDIR}/credential2.json --signed-credential ${TEST_ROOT}/sa_credential2.json

say signed credential is:
say $(< ${TEST_ROOT}/sa_credential2.json)

try id_signature_authority verify_credential ${OPTS} --contract identity.satest.signature_authority \
    --signed-credential ${TEST_ROOT}/sa_credential2.json

yell add VCs to the identity contracts
try id_wallet add_vc ${OPTS} --contract identity.idtest.wallet \
    --credential ${TEST_ROOT}/sa_credential1.json

try id_wallet add_vc ${OPTS} --contract identity.idtest2.wallet \
    --credential ${TEST_ROOT}/sa_credential2.json

# =================================================================
yell create a policy agent
try id_policy_agent create ${OPTS} --contract identity.patest.policy_agent \
    -d 'patest policy agent'

yell register issuer with the policy agent
try id_policy_agent register ${OPTS} --contract identity.patest.policy_agent \
    --issuer identity.satest.signature_authority --path satest ext1 --credential-types dummy

yell issue a simple credential
try id_wallet get_vp ${OPTS} --contract identity.idtest.wallet \
    --types dummy --file ${TEST_ROOT}/vp1.json

try id_policy_agent issue_credential ${OPTS} --contract identity.patest.policy_agent \
    --presentation ${TEST_ROOT}/vp1.json --issued-credential ${TEST_ROOT}/pa_credential1.json

say issued credential is:
say $(<${TEST_ROOT}/pa_credential1.json)

try id_policy_agent verify_credential ${OPTS} --contract identity.patest.policy_agent \
    --signed-credential ${TEST_ROOT}/pa_credential1.json

yell issue a complex credential
try id_wallet get_vp ${OPTS} --contract identity.idtest2.wallet \
    --types dummy --file ${TEST_ROOT}/vp2.json

try id_policy_agent issue_credential ${OPTS} --contract identity.patest.policy_agent \
    --presentation ${TEST_ROOT}/vp2.json --issued-credential ${TEST_ROOT}/pa_credential2.json

say issued verifiable credential is:
say $(<${TEST_ROOT}/pa_credential2.json)

say extracted credential
try id_credential extract --signed-credential ${TEST_ROOT}/pa_credential2.json

try id_policy_agent verify_credential ${OPTS} --contract identity.patest.policy_agent \
    --signed-credential ${TEST_ROOT}/pa_credential2.json

yell test policy agent public info endpoints
say policy data:
try id_policy_agent get_policy ${OPTS} --contract identity.patest.policy_agent
say issuers list:
try id_policy_agent list_issuers ${OPTS} --contract identity.patest.policy_agent
say requirements:
try id_policy_agent get_requirements ${OPTS} --contract identity.patest.policy_agent

# =================================================================
yell create a committee

try id_committee create ${OPTS} --contract identity.cotest.committee \
    -d 'cotest committee' --members user1 user2 user3

F_RESOLUTION1=$(try id_committee propose_resolution ${OPTS} --contract identity.cotest.committee \
    -c ${SCRIPTDIR}/credential1.json)
say proposed resolution is: $F_RESOLUTION1

try id_committee vote ${OPTS} --contract identity.cotest.committee \
    --identity user1 --resolution-id ${F_RESOLUTION1} --approve

try id_committee vote ${OPTS} --contract identity.cotest.committee \
    --identity user2 --resolution-id ${F_RESOLUTION1} --approve

F_RESOLUTION2=$(try id_committee propose_resolution ${OPTS} --contract identity.cotest.committee \
    -c ${SCRIPTDIR}/credential2.json)
say proposed resolution is: $F_RESOLUTION2

try id_committee vote ${OPTS} --contract identity.cotest.committee \
    --identity user2 --resolution-id ${F_RESOLUTION2} --disapprove

try id_committee vote ${OPTS} --contract identity.cotest.committee \
    --identity user3 --resolution-id ${F_RESOLUTION2} --disapprove

try id_committee list_resolutions ${OPTS} --contract identity.cotest.committee

try id_committee get_resolution ${OPTS} --contract identity.cotest.committee \
    --credential ${TEST_ROOT}/resolution1.json --resolution-id ${F_RESOLUTION1}
say resolution 1:
say $(<${TEST_ROOT}/resolution1.json)

try id_committee issue_credential ${OPTS} --contract identity.cotest.committee \
    --issued-credential ${TEST_ROOT}/resolution1_vc.json --resolution-id ${F_RESOLUTION1}
say verfied credential for resolution 1:
say $(<${TEST_ROOT}/resolution1_vc.json)

try id_committee verify_credential ${OPTS} --contract identity.cotest.committee \
    --signed-credential ${TEST_ROOT}/resolution1_vc.json

# =================================================================
yell All tests passed
