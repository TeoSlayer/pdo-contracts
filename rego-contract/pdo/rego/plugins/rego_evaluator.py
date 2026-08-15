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

import pdo.client.builder as pbuilder
import pdo.client.builder.command as pcommand
import pdo.client.builder.contract as pcontract
import pdo.client.builder.shell as pshell
import pdo.client.commands.contract as pcontract_cmd

__all__ = [
    'op_evaluate',
    'cmd_create_rego_evaluator',
    'cmd_evaluate',
    'do_rego_evaluator',
    'do_rego_evaluator_contract',
    'load_commands',
]

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------
# op_evaluate
#   Evaluate an arbitrary Rego policy over an arbitrary input at an arbitrary
#   entrypoint and return the output. rego_source and input are strings (input
#   is arbitrary JSON text).
# -----------------------------------------------------------------
class op_evaluate(pcontract.contract_op_base) :

    name = "evaluate"
    help = "evaluate an arbitrary Rego policy over an input at an entrypoint"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--rego-source',
            help='the Rego source code, as a string',
            type=str,
            required=True)
        subparser.add_argument(
            '--entrypoint',
            help='the rule path to evaluate, e.g. data.policy.allow',
            type=str,
            required=True)
        subparser.add_argument(
            '--input',
            help='the input, as a JSON string',
            type=str,
            required=True)

    @classmethod
    def invoke(cls, state, session_params, rego_source, entrypoint, input, **kwargs) :
        session_params['commit'] = False
        message = invocation_request(
            'evaluate', rego_source=rego_source, entrypoint=entrypoint, input=input)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)
        return result


# -----------------------------------------------------------------
# cmd_create_rego_evaluator
#   Create the (stateless) rego evaluator contract. No initialization step is
#   needed -- the contract is ready to evaluate as soon as it is created.
# -----------------------------------------------------------------
class cmd_create_rego_evaluator(pcommand.contract_command_base) :
    name = "create"
    help = "create a rego evaluator contract"

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

        save_file = pcontract_cmd.create_contract_from_context(state, context, 'rego_evaluator', **kwargs)
        context['save_file'] = save_file

        cls.display('created rego evaluator in {}'.format(save_file))
        return save_file


# -----------------------------------------------------------------
# cmd_evaluate
#   Read the Rego source and input from files and evaluate the entrypoint.
# -----------------------------------------------------------------
class cmd_evaluate(pcommand.contract_command_base) :
    name = "evaluate"
    help = "evaluate a Rego policy file over an input file at an entrypoint"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--rego-source',
            help='file containing the Rego source code',
            type=str,
            required=True)
        subparser.add_argument(
            '--input',
            help='file containing the input JSON',
            type=str,
            required=True)
        subparser.add_argument(
            '--entrypoint',
            help='the rule path to evaluate, e.g. data.policy.allow',
            type=str,
            required=True)

    @classmethod
    def invoke(cls, state, context, rego_source, input, entrypoint, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('rego evaluator contract must be created')

        with open(rego_source, 'r') as fp :
            rego_source_text = fp.read()
        with open(input, 'r') as fp :
            input_text = json.dumps(json.load(fp))

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(
            op_evaluate, state, context, session,
            rego_source=rego_source_text, entrypoint=entrypoint, input=input_text, **kwargs)
        cls.display(result)
        return result


# -----------------------------------------------------------------
# Create the generic, shell independent version of the aggregate command
# -----------------------------------------------------------------
__operations__ = [
    op_evaluate,
]

do_rego_evaluator_contract = pcontract.create_shell_command(
    'rego_evaluator_contract', __operations__)

__commands__ = [
    cmd_create_rego_evaluator,
    cmd_evaluate,
]

do_rego_evaluator = pcommand.create_shell_command('rego_evaluator', __commands__)


# -----------------------------------------------------------------
# Enable binding of the shell independent version to a pdo-shell command
# -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'rego_evaluator', do_rego_evaluator)
    pshell.bind_shell_command(cmdclass, 'rego_evaluator_contract', do_rego_evaluator_contract)
