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
F_CONTEXT_FILE=${SOURCE_ROOT}/test/rego_test_context.toml
F_CONTEXT_TEMPLATES=${PDO_HOME}/contracts/rego/context
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

F_SERVICE_GROUPS_DB_FILE=${SOURCE_ROOT}/test/${F_SERVICE_HOST}_rego_groups_db
F_SERVICE_DB_FILE=${SOURCE_ROOT}/test/${F_SERVICE_HOST}_rego_db

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
for i in 1 2 3 ; do
    if [ ! -f ${PDO_HOME}/keys/user${i}_private.pem ] ; then
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/user${i} --format pem
        F_KEY_FILES+=(${PDO_HOME}/keys/user${i}_{private,public}.pem)
    fi
done

TEST_ROOT=$(mktemp -d /tmp/rego_test.XXXXXXXXX)

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
yell create the service and groups database for host ${F_SERVICE_HOST}
try pdo-service-db import ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE}
try pdo-eservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default \
    --preferred ${F_PREFERRED}
try pdo-pservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default
try pdo-sservice create_from_site ${SHORT_OPTS} --file ${F_SERVICE_SITE_FILE} --group default \
             --replicas 1 --duration 60

# -----------------------------------------------------------------
# setup the context for the rego_evaluator
# -----------------------------------------------------------------
cd "${SOURCE_ROOT}"
rm -f ${F_CONTEXT_FILE}

try pdo-context load ${OPTS} --import-file ${F_CONTEXT_TEMPLATES}/rego_evaluator.toml \
    --bind identity retest --bind user user1

# -----------------------------------------------------------------
# Test data: three small toy Rego policies and their inputs
# -----------------------------------------------------------------
F_NUMBERS_POLICY=${SCRIPTDIR}/policies/numbers.rego
F_NUMBERS_INPUT=${SCRIPTDIR}/policies/numbers_input.json
F_ACCESS_POLICY=${SCRIPTDIR}/policies/access.rego
F_ACCESS_ALLOW_INPUT=${SCRIPTDIR}/policies/access_allow_input.json
F_ACCESS_DENY_INPUT=${SCRIPTDIR}/policies/access_deny_input.json
F_GREETING_POLICY=${SCRIPTDIR}/policies/greeting.rego
F_GREETING_INPUT=${SCRIPTDIR}/policies/greeting_input.json

# =================================================================
yell create the rego_evaluator contract
try rego_evaluator create ${OPTS} --contract identity.retest.rego_evaluator

# =================================================================
# numbers policy: arithmetic over a list of values
yell evaluate numbers.total, expect 110
F_TOTAL=$(rego_evaluator evaluate ${OPTS} \
    --contract identity.retest.rego_evaluator \
    --rego-source ${F_NUMBERS_POLICY} --input ${F_NUMBERS_INPUT} --entrypoint "data.numbers.total")
say "numbers.total: ${F_TOTAL}"
if [[ "${F_TOTAL}" != *"110"* ]] ; then
    die "expected numbers.total=110, got: ${F_TOTAL}"
fi

yell evaluate numbers.large, expect true
F_LARGE=$(rego_evaluator evaluate ${OPTS} \
    --contract identity.retest.rego_evaluator \
    --rego-source ${F_NUMBERS_POLICY} --input ${F_NUMBERS_INPUT} --entrypoint "data.numbers.large")
say "numbers.large: ${F_LARGE}"
if [[ "${F_LARGE}" != *"true"* && "${F_LARGE}" != *"True"* ]] ; then
    die "expected numbers.large=true, got: ${F_LARGE}"
fi

# =================================================================
# access policy: role based allow rule
yell evaluate access.allow for an admin, expect true
F_ADMIN=$(rego_evaluator evaluate ${OPTS} \
    --contract identity.retest.rego_evaluator \
    --rego-source ${F_ACCESS_POLICY} --input ${F_ACCESS_ALLOW_INPUT} --entrypoint "data.access.allow")
say "access.allow admin: ${F_ADMIN}"
if [[ "${F_ADMIN}" != *"true"* && "${F_ADMIN}" != *"True"* ]] ; then
    die "expected access.allow=true for an admin, got: ${F_ADMIN}"
fi

yell evaluate access.allow for a guest, expect false
F_GUEST=$(rego_evaluator evaluate ${OPTS} \
    --contract identity.retest.rego_evaluator \
    --rego-source ${F_ACCESS_POLICY} --input ${F_ACCESS_DENY_INPUT} --entrypoint "data.access.allow")
say "access.allow guest: ${F_GUEST}"
if [[ "${F_GUEST}" != *"false"* && "${F_GUEST}" != *"False"* ]] ; then
    die "expected access.allow=false for a guest, got: ${F_GUEST}"
fi

# =================================================================
# greeting policy: string formatting
yell evaluate greeting.message, expect a greeting for rego
F_GREETING=$(rego_evaluator evaluate ${OPTS} \
    --contract identity.retest.rego_evaluator \
    --rego-source ${F_GREETING_POLICY} --input ${F_GREETING_INPUT} --entrypoint "data.greeting.message")
say "greeting.message: ${F_GREETING}"
if [[ "${F_GREETING}" != *"hello, rego"* ]] ; then
    die "expected greeting.message to contain 'hello, rego', got: ${F_GREETING}"
fi

# =================================================================
yell All rego_evaluator tests passed
