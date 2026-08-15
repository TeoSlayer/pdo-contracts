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

import json
import logging

from pdo.contract import invocation_request

import pdo.client.builder as pbuilder
import pdo.client.builder.command as pcommand
import pdo.client.builder.contract as pcontract
import pdo.client.builder.shell as pshell
import pdo.client.commands.contract as pcontract_cmd

import pdo.client.plugins.common as common
import pdo.identity.plugins.identity as identity

__all__ = [
    'op_initialize',
    'op_get_verifying_key',
    'op_get_extended_verifying_key',
    'op_register_signing_context',
    'op_describe_signing_context',
    'op_list_signing_contexts',
    'op_sign',
    'op_verify',
    'op_add_vc',
    'op_get_vc_list',
    'op_get_vp',
    'op_sign_credential',
    'op_verify_credential',
    'cmd_sign_credential',
    'cmd_verify_credential',
    'cmd_register_signing_context',
    'cmd_list_signing_contexts',
    'cmd_get_verifying_key',
    'cmd_add_vc',
    'cmd_get_vc_list',
    'cmd_get_vp',
    'cmd_create_signature_authority',
    'do_signature_authority',
    'do_signature_authority_contract',
    'load_commands',
]

op_initialize = identity.op_initialize
op_get_verifying_key = identity.op_get_verifying_key
op_get_extended_verifying_key = identity.op_get_extended_verifying_key
op_register_signing_context = identity.op_register_signing_context
op_describe_signing_context = identity.op_describe_signing_context
op_list_signing_contexts = identity.op_list_signing_contexts
op_sign = identity.op_sign
op_verify = identity.op_verify
op_add_vc = identity.op_add_vc
op_get_vc_list = identity.op_get_vc_list
op_get_vp = identity.op_get_vp

cmd_register_signing_context = identity.cmd_register_signing_context
cmd_list_signing_contexts = identity.cmd_list_signing_contexts
cmd_get_verifying_key = identity.cmd_get_verifying_key
cmd_add_vc = identity.cmd_add_vc
cmd_get_vc_list = identity.cmd_get_vc_list
cmd_get_vp = identity.cmd_get_vp

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_sign_credential(pcontract.contract_op_base) :

    name = "sign_credential"
    help = "Sign a credential and generate the associated verifiable credential"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-c', '--credential',
            help='The credential to sign (JSON)',
            type=pbuilder.invocation_parameter,
            required=True)
        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)

    @classmethod
    def invoke(cls, state, session_params, credential, path, **kwargs) :
        session_params['commit'] = False

        params = {
            'credential' : credential,
            'context_path' : path,
        }

        message = invocation_request('sign_credential', **params)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_verify_credential(pcontract.contract_op_base) :

    name = "verify_credential"
    help = "Verify the signature on a signed (verifiable) credential"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-c', '--credential',
            help='The signed credential to verify (JSON)',
            type=pbuilder.invocation_parameter,
            required=True)

    @classmethod
    def invoke(cls, state, session_params, credential, **kwargs) :
        session_params['commit'] = False

        params = {
            'credential' : credential
        }

        message = invocation_request('verify_credential', **params)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_sign_credential(pcommand.contract_command_base) :
    name = "sign_credential"
    help = "Sign a credential and generate the associated verifiable credential"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-c', '--credential',
            help='The name of the file containing the credential to sign',
            type=str,
            required=True)
        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)
        subparser.add_argument(
            '--signed-credential',
            help='Name of the file where the signed credential will be saved',
            type=str,
            required=True)

    @classmethod
    def invoke(cls, state, context, credential, path, signed_credential, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('signature authority contract must be created and initialized')

        with open(credential, "r") as fp :
            credential_data = json.load(fp)

        session = pbuilder.SessionParameters(save_file=save_file)
        signed_credential_data = pcontract.invoke_contract_op(
            op_sign_credential,
            state, context, session,
            credential=credential_data,
            path=path,
            **kwargs)

        with open(signed_credential, "w") as fp :
            fp.write(signed_credential_data)

        cls.display('saved credential to {}'.format(signed_credential))
        return True

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_verify_credential(pcommand.contract_command_base) :
    name = "verify_credential"
    help = "Verify a signed credential"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--signed-credential',
            help='Name of the file where the signed credential will be saved',
            type=str,
            required=True)

    @classmethod
    def invoke(cls, state, context, signed_credential, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('signature authority contract must be created and initialized')

        with open(signed_credential, "r") as fp :
            signed_credential_data = json.load(fp)

        session = pbuilder.SessionParameters(save_file=save_file)
        try :
            result = pcontract.invoke_contract_op(
                op_verify_credential,
                state, context, session,
                credential=signed_credential_data,
                **kwargs)
            cls.display('credential signature verified')
        except Exception as e :
            cls.display('failed to verify credential signature')
            raise ValueError('credendtial signature verification failed') from e

        return True

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_create_signature_authority(pcommand.contract_command_base) :
    name = "create"
    help = "script to create a signature authority"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('-c', '--contract-class', help='Name of the contract class', type=str)
        subparser.add_argument('-e', '--eservice-group', help='Name of the enclave service group to use', type=str)
        subparser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str)
        subparser.add_argument('-p', '--pservice-group', help='Name of the provisioning service group to use', type=str)
        subparser.add_argument('-r', '--sservice-group', help='Name of the storage service group to use', type=str)
        subparser.add_argument('--source', help='File that contains contract source code', type=str)
        subparser.add_argument('--extra', help='Extra data associated with the contract file', nargs=2, action='append')

        subparser.add_argument(
            '-d', '--description',
            help='Description of the signature authority',
            type=str,
            required=True)

    @classmethod
    def invoke(cls, state, context, description, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if save_file :
            return save_file

        # create the signature authority contract
        save_file = pcontract_cmd.create_contract_from_context(state, context, 'signature_authority', **kwargs)
        context['save_file'] = save_file

        session = pbuilder.SessionParameters(save_file=save_file)
        pcontract.invoke_contract_op(
            op_initialize,
            state, context, session,
            description,
            **kwargs)

        cls.display('created signature authority in {}'.format(save_file))
        return save_file

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
    op_sign,
    op_verify,
    op_add_vc,
    op_get_vc_list,
    op_get_vp,
    op_sign_credential,
    op_verify_credential,
]

do_signature_authority_contract = pcontract.create_shell_command('signature_authority_contract', __operations__)

__commands__ = [
    cmd_get_verifying_key,
    cmd_register_signing_context,
    cmd_list_signing_contexts,
    cmd_add_vc,
    cmd_get_vc_list,
    cmd_get_vp,
    cmd_sign_credential,
    cmd_verify_credential,
    cmd_create_signature_authority,
]

do_signature_authority = pcommand.create_shell_command('signature_authority', __commands__)

# -----------------------------------------------------------------
# Enable binding of the shell independent version to a pdo-shell command
# -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'signature_authority', do_signature_authority)
    pshell.bind_shell_command(cmdclass, 'signature_authority_contract', do_signature_authority_contract)
