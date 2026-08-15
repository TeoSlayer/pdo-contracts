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

import json
import logging

from pdo.contract import invocation_request
from pdo.submitter.create import create_submitter

import pdo.client.builder as pbuilder
import pdo.client.builder.command as pcommand
import pdo.client.builder.contract as pcontract
import pdo.client.builder.shell as pshell
import pdo.client.commands.contract as pcontract_cmd

import pdo.client.plugins.common as common
import pdo.identity.plugins.signature_authority as signature_authority

logger = logging.getLogger(__name__)

__all__ = [
    'op_initialize',
    'op_get_verifying_key',
    'op_get_extended_verifying_key',
    'op_register_signing_context',
    'op_describe_signing_context',
    'op_list_signing_contexts',
    'op_add_vc',
    'op_get_vc_list',
    'op_get_vp',
    'op_sign_credential',
    'op_verify_credential',
    'op_get_ledger_key',
    'op_get_contract_metadata',
    'op_get_contract_code_metadata',
    'op_set_ledger_key',
    'cmd_register_signing_context',
    'cmd_list_signing_contexts',
    'cmd_get_verifying_key',
    'cmd_verify_credential',
    'cmd_create_wallet_key_authority',
    'cmd_sign_credential',
    'do_wallet_key_authority',
    'do_wallet_key_authority_contract',
    'load_commands',
]

# -----------------------------------------------------------------
# wallet_key_authority inherits from signature_authority, so its identity
# operations are reused verbatim. sign_credential is NOT reused: this authority
# customizes it (see op_sign_credential below) to issue from a ledger attestation
# rather than sign an owner-supplied credential. The attestation operations
# (ledger key + contract metadata) come from the shared client common plugin.
# -----------------------------------------------------------------
op_initialize = signature_authority.op_initialize
op_get_verifying_key = signature_authority.op_get_verifying_key
op_get_extended_verifying_key = signature_authority.op_get_extended_verifying_key
op_register_signing_context = signature_authority.op_register_signing_context
op_describe_signing_context = signature_authority.op_describe_signing_context
op_list_signing_contexts = signature_authority.op_list_signing_contexts
op_add_vc = signature_authority.op_add_vc
op_get_vc_list = signature_authority.op_get_vc_list
op_get_vp = signature_authority.op_get_vp
op_verify_credential = signature_authority.op_verify_credential

op_get_ledger_key = common.op_get_ledger_key
op_get_contract_metadata = common.op_get_contract_metadata
op_get_contract_code_metadata = common.op_get_contract_code_metadata

cmd_register_signing_context = signature_authority.cmd_register_signing_context
cmd_list_signing_contexts = signature_authority.cmd_list_signing_contexts
cmd_get_verifying_key = signature_authority.cmd_get_verifying_key
cmd_verify_credential = signature_authority.cmd_verify_credential


# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_set_ledger_key(pcontract.contract_op_base) :
    name = "set_ledger_key"
    help = "set the ledger verifying key used as the root of trust for attestations"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--ledger-key',
            help='the ledger verifying key',
            type=str, required=True)

    @classmethod
    def invoke(cls, state, session_params, ledger_key, **kwargs) :
        session_params['commit'] = True

        message = invocation_request('set_ledger_key', ledger_verifying_key=ledger_key)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result


# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_sign_credential(pcontract.contract_op_base) :
    name = "sign_credential"
    help = "verify a wallet's ledger attestation and issue a WalletVerifyingKeyCredential"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-i', '--contract-id',
            help='the wallet contract identifier',
            type=str, required=True)
        subparser.add_argument(
            '--creator',
            help='the wallet contract creator id (from the ledger)',
            type=str, required=True)
        subparser.add_argument(
            '-l', '--ledger-attestation',
            help='the wallet contract attestation from the ledger',
            type=pbuilder.invocation_parameter, required=True)
        subparser.add_argument(
            '-m', '--contract-metadata',
            help='the wallet contract metadata (verifying/encryption keys)',
            type=pbuilder.invocation_parameter, required=True)

    @classmethod
    def invoke(cls, state, session_params, contract_id, creator, ledger_attestation, contract_metadata, **kwargs) :
        session_params['commit'] = False

        message = invocation_request(
            'sign_credential',
            contract_id=contract_id,
            creator=creator,
            ledger_attestation=ledger_attestation,
            contract_metadata=contract_metadata)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result


# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_create_wallet_key_authority(pcommand.contract_command_base) :
    name = "create"
    help = "create a wallet key authority and install the ledger root of trust"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('-c', '--contract-class', help='Name of the contract class', type=str)
        subparser.add_argument('-e', '--eservice-group', help='Name of the enclave service group to use', type=str)
        subparser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str)
        subparser.add_argument('-p', '--pservice-group', help='Name of the provisioning service group to use', type=str)
        subparser.add_argument('-r', '--sservice-group', help='Name of the storage service group to use', type=str)
        subparser.add_argument('--source', help='File that contains contract source code', type=str)
        subparser.add_argument('--extra', help='Extra data associated with the contract file', nargs=2, action='append')

    @classmethod
    def invoke(cls, state, context, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if save_file :
            return save_file

        # create the wallet key authority contract
        save_file = pcontract_cmd.create_contract_from_context(state, context, 'wallet_key_authority', **kwargs)
        context['save_file'] = save_file

        session = pbuilder.SessionParameters(save_file=save_file)
        pcontract.invoke_contract_op(
            op_initialize,
            state, context, session,
            context['description'],
            **kwargs)

        # install the ledger's verifying key as the attestation root of trust
        ledger_submitter = create_submitter(state.get(['Ledger']))
        ledger_key = ledger_submitter.get_ledger_info()
        pcontract.invoke_contract_op(
            op_set_ledger_key,
            state, context, session,
            ledger_key=ledger_key,
            **kwargs)

        cls.display('created wallet key authority in {}'.format(save_file))
        return save_file


# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_sign_credential(pcommand.contract_command_base) :
    name = "sign_credential"
    help = "gather a wallet's ledger attestation and issue a WalletVerifyingKeyCredential"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-w', '--wallet',
            help='context of the wallet contract to attest',
            type=str, required=True)
        subparser.add_argument(
            '--credential',
            help='file where the issued verifiable credential will be written',
            type=str, required=True)

    @classmethod
    def invoke(cls, state, context, wallet, credential, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('wallet key authority contract must be created and initialized')

        # resolve the wallet from its context (like the trusted-issuer registration
        # resolves the issuer context) -- no .pdo file paths. Its id, creator, and
        # ledger attestation come from the ledger; its metadata from the contract.
        wallet_context = pbuilder.Context(state, wallet)
        wallet_save_file = pcontract_cmd.get_contract_from_context(state, wallet_context)
        wallet_contract = pcontract_cmd.get_contract(state, wallet_save_file)

        ledger_submitter = create_submitter(state.get(['Ledger']))
        ledger_attestation = ledger_submitter.get_contract_info(wallet_contract.contract_id)

        wallet_session = pbuilder.SessionParameters(save_file=wallet_save_file)
        contract_metadata = json.loads(pcontract.invoke_contract_op(
            op_get_contract_metadata, state, wallet_context, wallet_session, **kwargs))

        # ask the authority to verify the attestation and issue the credential
        session = pbuilder.SessionParameters(save_file=save_file)
        vc = pcontract.invoke_contract_op(
            op_sign_credential,
            state, context, session,
            contract_id=wallet_contract.contract_id,
            creator=wallet_contract.creator_id,
            ledger_attestation=ledger_attestation,
            contract_metadata=contract_metadata,
            **kwargs)

        with open(credential, "w") as fp :
            fp.write(vc)

        cls.display('saved wallet verifying key credential to {}'.format(credential))
        return True


# -----------------------------------------------------------------
# Create the generic, shell independent version of the aggregate command
# -----------------------------------------------------------------
__operations__ = [
    op_initialize,
    op_get_verifying_key,
    op_get_extended_verifying_key,
    op_register_signing_context,
    op_describe_signing_context,
    op_list_signing_contexts,
    op_add_vc,
    op_get_vc_list,
    op_get_vp,
    op_sign_credential,
    op_verify_credential,
    op_get_ledger_key,
    op_get_contract_metadata,
    op_get_contract_code_metadata,
    op_set_ledger_key,
]

do_wallet_key_authority_contract = pcontract.create_shell_command('wallet_key_authority_contract', __operations__)

__commands__ = [
    cmd_get_verifying_key,
    cmd_register_signing_context,
    cmd_list_signing_contexts,
    cmd_verify_credential,
    cmd_create_wallet_key_authority,
    cmd_sign_credential,
]

do_wallet_key_authority = pcommand.create_shell_command('wallet_key_authority', __commands__)


# -----------------------------------------------------------------
# Enable binding of the shell independent version to a pdo-shell command
# -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'wallet_key_authority', do_wallet_key_authority)
    pshell.bind_shell_command(cmdclass, 'wallet_key_authority_contract', do_wallet_key_authority_contract)
