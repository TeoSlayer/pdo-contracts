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

import pdo.common.crypto as pcrypto

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
    'cmd_get_verifying_key',
    'cmd_register_signing_context',
    'cmd_list_signing_contexts',
    'cmd_sign',
    'cmd_verify',
    'cmd_create_identity',
    'cmd_add_vc',
    'cmd_get_vc_list',
    'cmd_get_vp',
    'do_identity',
    'do_identity_contract',
    'load_commands',
]

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_initialize(pcontract.contract_op_base) :

    name = "initialize"
    help = "initialize an identity contract object"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-d', '--description',
            help='Description of the asset described by the identity',
            type=str,
            required=True)

    @classmethod
    def invoke(cls, state, session_params, description, **kwargs) :
        session_params['commit'] = True

        message = invocation_request('initialize', description=description)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_get_verifying_key(pcontract.contract_op_base) :

    name = "get_verifying_key"
    help = "Get the verifying key for a context"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)

    @classmethod
    def invoke(cls, state, session_params, path, **kwargs) :
        session_params['commit'] = True

        params = {
            'context_path' : path,
        }
        message = invocation_request('get_verifying_key', **params)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_get_extended_verifying_key(pcontract.contract_op_base) :

    name = "get_extended_verifying_key"
    help = "Get the verifying key and chain code for a context"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)

    @classmethod
    def invoke(cls, state, session_params, path, **kwargs) :
        session_params['commit'] = True

        params = {
            'context_path' : path,
        }
        message = invocation_request('get_extended_verifying_key', **params)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_register_signing_context(pcontract.contract_op_base) :

    name = "register_signing_context"
    help = "Register a signing context"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-d', '--description',
            help='Description of the asset described by the identity',
            type=str,
            required=True)
        subparser.add_argument(
            '--extensible',
            help='Allow unregistered contexts to be used from this context',
            action='store_true')
        subparser.add_argument(
            '--fixed',
            help='Only registered contexts may be used from this context',
            action='store_false',
            dest='extensible')
        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)

    @classmethod
    def invoke(cls, state, session_params, path, description, extensible, **kwargs) :
        session_params['commit'] = True

        params = {
            'context_path' : path,
            'description' : description,
            'extensible' : extensible,
        }
        message = invocation_request('register_signing_context', **params)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_describe_signing_context(pcontract.contract_op_base) :

    name = "describe_signing_context"
    help = "Describe a signing context"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)
        pass

    @classmethod
    def invoke(cls, state, session_params, path, **kwargs) :
        session_params['commit'] = True

        message = invocation_request('describe_signing_context', context_path=path)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_list_signing_contexts(pcontract.contract_op_base) :

    name = "list_signing_contexts"
    help = "List signing contexts under a path (owner only)"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-p', '--path',
            help='Subtree root to list (omit to list from root)',
            type=str,
            nargs='*',
            default=[],
            required=False)

    @classmethod
    def invoke(cls, state, session_params, path, **kwargs) :
        session_params['commit'] = False

        message = invocation_request('list_signing_contexts', context_path=path)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_sign(pcontract.contract_op_base) :

    name = "sign"
    help = "Sign message using specified signing context"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-m', '--message',
            help='Base64 encoded string to sign',
            type=str,
            required=True)
        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)

    @classmethod
    def invoke(cls, state, session_params, path, message, **kwargs) :
        session_params['commit'] = True

        bytes_message = pcrypto.string_to_byte_array(message)
        b64_message = pcrypto.byte_array_to_base64(pcrypto.string_to_byte_array(message))

        message = invocation_request('sign', context_path=path, message=b64_message)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_verify(pcontract.contract_op_base) :

    name = "verify"
    help = "Verify a signature using the specified signing context"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-m', '--message',
            help='Base64 encoded string to verify',
            type=str,
            required=True)
        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)
        subparser.add_argument(
            '--signature',
            help='Base64 encoded signature to verify',
            type=pbuilder.invocation_parameter,
            required=True)

    @classmethod
    def invoke(cls, state, session_params, path, message, signature, **kwargs) :
        session_params['commit'] = True

        bytes_message = pcrypto.string_to_byte_array(message)
        b64_message = pcrypto.byte_array_to_base64(bytes_message)

        params = {
            'message' : b64_message,
            'context_path' : path,
            'signature' : signature,
        }
        message = invocation_request('verify', **params)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_add_vc(pcontract.contract_op_base) :

    name = "add_vc"
    help = "Store a verifiable credential in the identity contract, indexed by its type"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-c', '--credential',
            help='Verifiable credential to store (JSON)',
            type=pbuilder.invocation_parameter,
            required=True)

    @classmethod
    def invoke(cls, state, session_params, credential, **kwargs) :
        session_params['commit'] = True

        message = invocation_request('add_vc', credential=credential)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_get_vp(pcontract.contract_op_base) :

    name = "get_vp"
    help = "Retrieve a verifiable presentation for given types"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-t', '--types',
            help='List of credential types to retrieve',
            type=str,
            nargs='+',
            required=True)

    @classmethod
    def invoke(cls, state, session_params, types, **kwargs) :
        session_params['commit'] = False

        message = invocation_request('get_vp', credential_types=types)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_get_vc_list(pcontract.contract_op_base) :

    name = "get_vc_list"
    help = "Retrieve all stored verifiable credentials as a type-to-VC mapping"

    @classmethod
    def add_arguments(cls, subparser) :
        pass

    @classmethod
    def invoke(cls, state, session_params, **kwargs) :
        session_params['commit'] = False

        message = invocation_request('get_vc_list')
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_get_verifying_key(pcommand.contract_command_base) :
    name = "get_verifying_key"
    help = "script to get the verifying key for a signing context"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-e', '--extended',
            help='Get the extended verifying key (verifying key + chain code)',
            action='store_true')

        subparser.add_argument(
            '-f', '--file',
            help='Base file name to save the results',
            dest='filename',
            type=str)

        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)

    @classmethod
    def invoke(cls, state, context, extended, filename, path, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)

        session = pbuilder.SessionParameters(save_file=save_file)

        op = op_get_extended_verifying_key if extended else op_get_verifying_key
        result = pcontract.invoke_contract_op(op, state, context, session, path, **kwargs)

        if filename is None :
            cls.display(f'verifying key for {path} is {result}')
        else :
            try :
                filename += '.json' if extended else '.pem'
                with open(filename, 'w') as f :
                    f.write(result)
                cls.display(f'verifying key for {path} saved to {filename}')
            except IOError as e :
                cls.display(f'Error saving verifying key to file {filename}: {e}')
                return False

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_register_signing_context(pcommand.contract_command_base) :
    name = "register"
    help = "script to register a signing context"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-d', '--description',
            help='Description of the asset described by the identity',
            type=str,
            required=True)
        subparser.add_argument(
            '--extensible',
            help='Allow unregistered contexts to be used from this context',
            action='store_true')
        subparser.add_argument(
            '--fixed',
            help='Only registered contexts may be used from this context',
            action='store_false',
            dest='extensible')
        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)

    @classmethod
    def invoke(cls, state, context, path, description, extensible, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(
            op_register_signing_context, state, context, session, path, description, extensible, **kwargs)

        cls.display(f'registered signing context {path}')
        return True

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_list_signing_contexts(pcommand.contract_command_base) :
    name = "list_signing_contexts"
    help = "List signing contexts under a path (owner only)"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-p', '--path',
            help='Subtree root to list (omit to list from root)',
            type=str,
            nargs='*',
            default=[],
            required=False)
        subparser.add_argument(
            '-f', '--file',
            help='File to save the result (JSON); omit to print to stdout',
            dest='output_file',
            type=str,
            required=False)

    @classmethod
    def invoke(cls, state, context, path, output_file=None, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('identity contract must be created and initialized')

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(
            op_list_signing_contexts, state, context, session, path, **kwargs)

        if output_file :
            with open(output_file, 'w') as fp :
                fp.write(result)
            cls.display('saved signing contexts to {}'.format(output_file))
        else :
            cls.display(result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_sign(pcommand.contract_command_base) :
    name = "sign"
    help = "script to sign a message using a signing context"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--message',
            help='Name of the file where the message is stored',
            dest='message_file',
            type=str,
            required=True)

        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)

        subparser.add_argument(
            '--signature',
            help='Name of the file where the signature will be saved',
            dest='signature_file',
            type=str,
            required=True)


    @classmethod
    def invoke(cls, state, context, message_file, path, signature_file, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)

        with open(message_file, 'r') as fp :
            message = fp.read().strip()

        b64_message = pcrypto.byte_array_to_base64(pcrypto.string_to_byte_array(message))

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(op_sign, state, context, session, path, b64_message, **kwargs)
        result = json.loads(result)

        with open(signature_file, 'w') as fp :
            fp.write(result)

        cls.display(f'saved signature to {signature_file}')
        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_verify(pcommand.contract_command_base) :
    name = "verify"
    help = "script to verify a signature using a signing context"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--message',
            help='Name of the file where the message is stored',
            dest='message_file',
            type=str,
            required=True)

        subparser.add_argument(
            '-p', '--path',
            help='Path to the signing context',
            type=str,
            nargs='+',
            required=True)

        subparser.add_argument(
            '--signature',
            help='Name of the file where the base64 encoded signature is stored',
            dest='signature_file',
            type=str,
            required=True)

    @classmethod
    def invoke(cls, state, context, message_file, path, signature_file, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)

        with open(message_file, 'r') as fp :
            message = fp.read().strip()

        b64_message = pcrypto.byte_array_to_base64(pcrypto.string_to_byte_array(message))

        with open(signature_file, 'r') as fp :
            signature = fp.read().strip()

        session = pbuilder.SessionParameters(save_file=save_file)

        try :
            result = pcontract.invoke_contract_op(op_verify, state, context, session, path, b64_message, signature, **kwargs)
            cls.display('signature verified')
        except Exception as e :
            cls.display('failed to verify signature')
            raise ValueError('signature verification failed') from e

        return True

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_create_identity(pcommand.contract_command_base) :
    name = "create"
    help = "script to create an identity"

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

        # create the identity contract
        save_file = pcontract_cmd.create_contract_from_context(state, context, 'identity', **kwargs)
        context['save_file'] = save_file

        session = pbuilder.SessionParameters(save_file=save_file)
        pcontract.invoke_contract_op(
            op_initialize,
            state, context, session,
            description,
            **kwargs)

        cls.display('created identity in {}'.format(save_file))
        return save_file

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_add_vc(pcommand.contract_command_base) :
    name = "add_vc"
    help = "Store a verifiable credential in the identity contract"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--credential',
            help='File containing the verifiable credential (JSON)',
            dest='credential_file',
            type=str,
            required=True)

    @classmethod
    def invoke(cls, state, context, credential_file, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('identity contract must be created and initialized')

        with open(credential_file, 'r') as fp :
            credential = json.load(fp)

        session = pbuilder.SessionParameters(save_file=save_file)
        pcontract.invoke_contract_op(
            op_add_vc, state, context, session,
            credential=credential,
            **kwargs)

        cls.display('stored credential from {}'.format(credential_file))
        return True

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_get_vc_list(pcommand.contract_command_base) :
    name = "get_vc_list"
    help = "Retrieve all stored verifiable credentials as a type-to-VC mapping"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-f', '--file',
            help='File to save the resulting VC map (JSON)',
            dest='output_file',
            type=str,
            required=False)

    @classmethod
    def invoke(cls, state, context, output_file=None, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('identity contract must be created and initialized')

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(
            op_get_vc_list, state, context, session, **kwargs)

        if output_file :
            with open(output_file, 'w') as fp :
                fp.write(result)
            cls.display('saved VC list to {}'.format(output_file))
        else :
            cls.display(result)

        return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_get_vp(pcommand.contract_command_base) :
    name = "get_vp"
    help = "Retrieve a verifiable presentation for given types"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-t', '--types',
            help='Credential types to retrieve',
            type=str,
            nargs='+',
            required=True)
        subparser.add_argument(
            '-f', '--file',
            help='File to save the resulting Verifiable Presentation (JSON)',
            dest='output_file',
            type=str,
            required=False)

    @classmethod
    def invoke(cls, state, context, types, output_file, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('identity contract must be created and initialized')

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(
            op_get_vp, state, context, session,
            types=types,
            **kwargs)

        if output_file :
            with open(output_file, 'w') as fp :
                fp.write(result)
            cls.display('saved VP to {}'.format(output_file))
        else :
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
    op_add_vc,
    op_get_vc_list,
    op_get_vp,
]

do_identity_contract = pcontract.create_shell_command('identity_contract', __operations__)

__commands__ = [
    cmd_get_verifying_key,
    cmd_register_signing_context,
    cmd_list_signing_contexts,
    cmd_sign,
    cmd_verify,
    cmd_create_identity,
    cmd_add_vc,
    cmd_get_vc_list,
    cmd_get_vp,
]

do_identity = pcommand.create_shell_command('identity', __commands__)

# -----------------------------------------------------------------
# Enable binding of the shell independent version to a pdo-shell command
# -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'identity_wallet', do_identity)
    pshell.bind_shell_command(cmdclass, 'identity_wallet_contract', do_identity_contract)
