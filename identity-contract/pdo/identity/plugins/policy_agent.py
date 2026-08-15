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

import pdo.identity.plugins.identity as identity_plugin
import pdo.identity.plugins.signature_authority as signature_plugin

__all__ = [
    'op_initialize',
    'op_get_verifying_key',
    'op_get_extended_verifying_key',
    'op_register_signing_context',
    'op_describe_signing_context',
    'op_list_signing_contexts',
    'op_sign',
    'op_verify',
    'op_verify_credential',
    'op_register_trusted_issuer',
    'op_issue_policy_credential',
    'op_set_policy_data',
    'op_get_policy_data',
    'op_list_trusted_issuers',
    'op_get_requirements',
    'cmd_register_trusted_issuer',
    'cmd_issue_policy_credential',
    'cmd_verify_credential',
    'cmd_register_signing_context',
    'cmd_list_signing_contexts',
    'cmd_get_verifying_key',
    'cmd_create_policy_agent',
    'cmd_set_policy_data',
    'cmd_get_policy_data',
    'cmd_list_trusted_issuers',
    'cmd_get_requirements',
    'do_policy_agent',
    'do_policy_agent_contract',
    'load_commands',
]

op_initialize = identity_plugin.op_initialize
op_get_verifying_key = identity_plugin.op_get_verifying_key
op_get_extended_verifying_key = identity_plugin.op_get_extended_verifying_key
op_register_signing_context = identity_plugin.op_register_signing_context
op_describe_signing_context = identity_plugin.op_describe_signing_context
op_list_signing_contexts = identity_plugin.op_list_signing_contexts
op_sign = identity_plugin.op_sign
op_verify = signature_plugin.op_verify
op_verify_credential = signature_plugin.op_verify_credential

cmd_verify_credential = signature_plugin.cmd_verify_credential
cmd_register_signing_context = identity_plugin.cmd_register_signing_context
cmd_list_signing_contexts = identity_plugin.cmd_list_signing_contexts
cmd_get_verifying_key = identity_plugin.cmd_get_verifying_key

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_register_trusted_issuer(pcontract.contract_op_base) :

    name = "register_trusted_issuer"
    help = "register a trusted issuer of input credentials"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-c', '--chaincode',
            help='The chain code of the issuer to register (base64 encoded)',
            type=str,
            required=True)

        subparser.add_argument(
            '-i', '--issuer',
            help='The issuer to register (issuer contract identifier)',
            type=str,
            required=True)

        subparser.add_argument(
            '-k', '--key',
            help='The extended public key of the issuer to register',
            type=pbuilder.invocation_parameter,
            required=True)

        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='*',
            default=[],
            required=False)

        subparser.add_argument(
            "-t",
            "--credential-types",
            help="One or more types of credentials issued by the issuer",
            type=str,
            nargs='+',
            required=True,
        )


    @classmethod
    def invoke(cls, state, session_params, issuer, path, key, chaincode, credential_types, **kwargs) :
        session_params['commit'] = True

        params = {
            'chain_code' : chaincode,
            'issuer_identity' : issuer,
            'public_key' : key,
            'context_path' : path,
            'credential_types': credential_types,
        }

        message = invocation_request('register_trusted_issuer', **params)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_issue_policy_credential(pcontract.contract_op_base) :

    name = "issue_policy_credential"
    help = "process input credentials and issue a policy credential"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-p', '--presentation',
            help='Verifiable presentation containing input credentials (JSON)',
            type=pbuilder.invocation_parameter,
            required=True)

    @classmethod
    def invoke(cls, state, session_params, presentation, **kwargs) :
        session_params['commit'] = True

        message = invocation_request('issue_policy_credential', presentation=presentation)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------

class op_set_policy_data(pcontract.contract_op_base) :

    name = "set_policy_data"
    help = "set_policy_data"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-d', '--data',
            help='Data for the policy (JSON)',
            type=pbuilder.invocation_parameter,
            required=True)

    @classmethod
    def invoke(cls, state, session_params, data, **kwargs) :
        session_params['commit'] = True

        params = data

        message = invocation_request('set_policy_data', **params)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_get_policy_data(pcontract.contract_op_base) :

    name = "get_policy_data"
    help = "Get the current policy data"

    @classmethod
    def add_arguments(cls, subparser) :
        pass

    @classmethod
    def invoke(cls, state, session_params, **kwargs) :
        session_params['commit'] = False

        message = invocation_request('get_policy_data')
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_list_trusted_issuers(pcontract.contract_op_base) :

    name = "list_trusted_issuers"
    help = "List all registered trusted issuers and their credential types (owner only)"

    @classmethod
    def add_arguments(cls, subparser) :
        pass

    @classmethod
    def invoke(cls, state, session_params, **kwargs) :
        session_params['commit'] = False

        message = invocation_request('list_trusted_issuers')
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_get_requirements(pcontract.contract_op_base) :

    name = "get_requirements"
    help = "Get the list of credential types required by this policy agent"

    @classmethod
    def add_arguments(cls, subparser) :
        pass

    @classmethod
    def invoke(cls, state, session_params, **kwargs) :
        session_params['commit'] = False

        message = invocation_request('get_requirements')
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_register_trusted_issuer(pcommand.contract_command_base) :
    name = "register"
    help = "Register a trusted issuer of input credentials"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-i', '--issuer',
            help='The context path for the issuer to register',
            type=str,
            required=True)

        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='*',
            default=[],
            required=False)

        subparser.add_argument(
                "-t",
                "--credential-types",
                help="One or more types of credentials issued by the issuer",
                type=str,
                nargs='+',
                required=True,
            )

    @classmethod
    def invoke(cls, state, context, issuer, path, credential_types, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('signature authority contract must be created and initialized')

        # Query the issuer for the information we need for registration, this
        # includes the contract_id, and the extended public key and the chain code
        # associated with the path in the issuer
        issuer_context = pbuilder.Context(state, issuer)
        issuer_save_file = pcontract_cmd.get_contract_from_context(state, issuer_context)
        issuer_contract = pcontract_cmd.get_contract(state, issuer_save_file)

        issuer_session = pbuilder.SessionParameters(save_file=issuer_save_file)
        issuer_keys = pcontract.invoke_contract_op(
            op_get_extended_verifying_key,
            state, issuer_context, issuer_session,
            path=path,
            **kwargs)

        issuer_keys = json.loads(issuer_keys)
        key_data = issuer_keys['public_key']
        chaincode_data = issuer_keys['chain_code']

        # Now we should have everything we need to register the issuer
        session = pbuilder.SessionParameters(save_file=save_file)
        pcontract.invoke_contract_op(
            op_register_trusted_issuer,
            state, context, session,
            issuer=issuer_contract.contract_id,
            path=path,
            key=key_data,
            chaincode=chaincode_data,
            credential_types=credential_types,
            **kwargs)

        cls.display('registered trusted issuer {}'.format(issuer))
        return True

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_issue_policy_credential(pcommand.contract_command_base) :
    name = "issue_credential"
    help = "Issue a credential based on the current policy"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--presentation',
            help='The name of the file where the verifiable presentation is stored',
            type=str,
            required=True)
        subparser.add_argument(
            '--issued-credential',
            help='The name of the file where the issued credential will be stored',
            type=str,
            required=True)

    @classmethod
    def invoke(cls, state, context, presentation, issued_credential, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('policy agent contract must be created and initialized')

        with open(presentation, "r") as fp :
            presentation_data = json.load(fp)

        session = pbuilder.SessionParameters(save_file=save_file)
        issued_credential_data = pcontract.invoke_contract_op(
            op_issue_policy_credential,
            state, context, session,
            presentation=presentation_data,
            **kwargs)

        with open(issued_credential, "w") as fp :
            fp.write(issued_credential_data)

        cls.display('saved issued credential to {}'.format(issued_credential))
        return True


# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_set_policy_data(pcommand.contract_command_base) :
    name = "set_policy"
    help = "set_policy"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--data',
            help='The name of the file where the data is stored',
            type=str,
            required=True)

    @classmethod
    def invoke(cls, state, context, data, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('policy agent contract must be created and initialized')

        with open(data, "r") as fp :
            data = json.load(fp)

        session = pbuilder.SessionParameters(save_file=save_file)
        pcontract.invoke_contract_op(
            op_set_policy_data,
            state, context, session,
            data=data,
            **kwargs)

        cls.display('data set {}'.format(data))

        return True


# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_create_policy_agent(pcommand.contract_command_base) :
    name = "create"
    help = "script to create a new policy agent"

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
            help='Description of the asset described by the identity',
            type=str,
            required=True)

    @classmethod
    def invoke(cls, state, context, description, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if save_file :
            return save_file

        # create the policy agent contract
        save_file = pcontract_cmd.create_contract_from_context(state, context, 'policy_agent', **kwargs)
        context['save_file'] = save_file

        session = pbuilder.SessionParameters(save_file=save_file)
        pcontract.invoke_contract_op(
            op_initialize,
            state, context, session,
            description,
            **kwargs)

        cls.display('created policy agent in {}'.format(save_file))
        return save_file

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_get_policy_data(pcommand.contract_command_base) :
    name = "get_policy"
    help = "Get the current policy data"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--file',
            help='File where the policy data will be saved (optional)',
            type=str,
            required=False)

    @classmethod
    def invoke(cls, state, context, file=None, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('policy agent contract must be created and initialized')

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(
            op_get_policy_data, state, context, session,
            **kwargs)

        if file :
            with open(file, 'w') as fp :
                fp.write(result)

        cls.display(result)
        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_list_trusted_issuers(pcommand.contract_command_base) :
    name = "list_issuers"
    help = "List all registered trusted issuers and their credential types"

    @classmethod
    def add_arguments(cls, subparser) :
        pass

    @classmethod
    def invoke(cls, state, context, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('policy agent contract must be created and initialized')

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(
            op_list_trusted_issuers, state, context, session,
            **kwargs)

        cls.display(result)
        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_get_requirements(pcommand.contract_command_base) :
    name = "get_requirements"
    help = "Get the list of credential types required by this policy agent"

    @classmethod
    def add_arguments(cls, subparser) :
        pass

    @classmethod
    def invoke(cls, state, context, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('policy agent contract must be created and initialized')

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(
            op_get_requirements, state, context, session,
            **kwargs)
        result = json.loads(result)
        cls.display(result)
        return result

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
    op_verify_credential,
    op_register_trusted_issuer,
    op_issue_policy_credential,
    op_set_policy_data,
    op_get_policy_data,
    op_list_trusted_issuers,
    op_get_requirements,
]

do_policy_agent_contract = pcontract.create_shell_command('policy_agent_contract', __operations__)

__commands__ = [
    cmd_get_verifying_key,
    cmd_register_signing_context,
    cmd_list_signing_contexts,
    cmd_verify_credential,
    cmd_register_trusted_issuer,
    cmd_issue_policy_credential,
    cmd_create_policy_agent,
    cmd_set_policy_data,
    cmd_get_policy_data,
    cmd_list_trusted_issuers,
    cmd_get_requirements,
]

do_policy_agent = pcommand.create_shell_command('policy_agent', __commands__)

# -----------------------------------------------------------------
# Enable binding of the shell independent version to a pdo-shell command
# -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'policy_agent', do_policy_agent)
    pshell.bind_shell_command(cmdclass, 'policy_agent_contract', do_policy_agent_contract)
