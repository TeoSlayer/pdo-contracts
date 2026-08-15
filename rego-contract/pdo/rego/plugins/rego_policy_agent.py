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

import logging

from pdo.contract import invocation_request

import pdo.client.builder as pbuilder
import pdo.client.builder.command as pcommand
import pdo.client.builder.contract as pcontract
import pdo.client.builder.shell as pshell
import pdo.client.commands.contract as pcontract_cmd

import pdo.identity.plugins.policy_agent as policy_agent_plugin

__all__ = [
    "op_initialize",
    "op_set_rego_policy",
    "op_get_rego_policy",
    "op_get_requirements",
    "op_register_trusted_issuer",
    "op_list_trusted_issuers",
    "op_set_policy_data",
    "op_get_policy_data",
    "op_issue_policy_credential",
    "cmd_create_rego_policy_agent",
    "cmd_set_rego_policy",
    "cmd_get_rego_policy",
    "cmd_get_requirements",
    "cmd_register_trusted_issuer",
    "cmd_list_trusted_issuers",
    "cmd_set_policy_data",
    "cmd_get_policy_data",
    "cmd_issue_policy_credential",
    "do_rego_policy_agent",
    "do_rego_policy_agent_contract",
    "load_commands",
]

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# Inherited from the policy_agent plugin -- the initialize, trusted-issuer, and
# policy-data methods are identical here (this contract reuses those C++
# methods). initialize just marks the contract ready; the Rego modules are set
# separately by set_rego_policy.
# -----------------------------------------------------------------
op_initialize = policy_agent_plugin.op_initialize
op_register_trusted_issuer = policy_agent_plugin.op_register_trusted_issuer
op_list_trusted_issuers = policy_agent_plugin.op_list_trusted_issuers
op_set_policy_data = policy_agent_plugin.op_set_policy_data
op_get_policy_data = policy_agent_plugin.op_get_policy_data
op_get_requirements = policy_agent_plugin.op_get_requirements
op_issue_policy_credential = policy_agent_plugin.op_issue_policy_credential

cmd_register_trusted_issuer = policy_agent_plugin.cmd_register_trusted_issuer
cmd_list_trusted_issuers = policy_agent_plugin.cmd_list_trusted_issuers
cmd_set_policy_data = policy_agent_plugin.cmd_set_policy_data
cmd_get_policy_data = policy_agent_plugin.cmd_get_policy_data
cmd_get_requirements = policy_agent_plugin.cmd_get_requirements
cmd_create_rego_policy_agent = policy_agent_plugin.cmd_create_policy_agent
cmd_issue_policy_credential = policy_agent_plugin.cmd_issue_policy_credential


# -----------------------------------------------------------------
# op_set_rego_policy
#   Set (or replace) the Rego policy: a list of [subpolicy_id, source] pairs. The
#   contract derives and stores the per-role requirements and input schema from
#   the subpolicies. May be called any number of times; each call replaces the policy.
# -----------------------------------------------------------------
class op_set_rego_policy(pcontract.contract_op_base):
    name = "set_rego_policy"
    help = "set or replace the Rego policy (a list of [subpolicy_id, source] pairs)"

    @classmethod
    def add_arguments(cls, subparser):
        subparser.add_argument(
            "--rego-modules",
            help="list of [subpolicy_id, source] pairs, as JSON",
            type=pbuilder.invocation_parameter,
            required=True,
        )

    @classmethod
    def invoke(cls, state, session_params, rego_modules, **kwargs):
        session_params["commit"] = True
        message = invocation_request("set_rego_policy", rego_modules=rego_modules)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)
        return result


# -----------------------------------------------------------------
# op_get_rego_policy
#   Fetch the whole list of [subpolicy_id, source] pairs.
# -----------------------------------------------------------------
class op_get_rego_policy(pcontract.contract_op_base):
    name = "get_rego_policy"
    help = "fetch the whole list of [subpolicy_id, source] pairs"

    @classmethod
    def add_arguments(cls, subparser):
        pass

    @classmethod
    def invoke(cls, state, session_params, **kwargs):
        session_params["commit"] = False
        message = invocation_request("get_rego_policy")
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)
        return result


# -----------------------------------------------------------------
# cmd_set_rego_policy
# -----------------------------------------------------------------
class cmd_set_rego_policy(pcommand.contract_command_base):
    # distinct from the inherited policy_agent "set_policy" (which sets policy DATA)
    name = "set_rego_policy"
    help = "set or replace the Rego policy (a list of [subpolicy_id, source] pairs)"

    @classmethod
    def add_arguments(cls, subparser):
        subparser.add_argument(
            "--module",
            help="a subpolicy id and the path to its Rego source file (repeatable)",
            nargs=2,
            action="append",
            metavar=("SUBPOLICY_ID", "FILE"),
            required=True,
        )

    @classmethod
    def invoke(cls, state, context, module, **kwargs):
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file:
            raise ValueError(
                "rego policy agent contract must be created and initialized"
            )

        rego_modules = []
        for subpolicy_id, path in module:
            with open(path, "r") as fp:
                rego_modules.append([subpolicy_id, fp.read()])

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(
            op_set_rego_policy,
            state,
            context,
            session,
            rego_modules=rego_modules,
            **kwargs,
        )
        cls.display(result)
        return result


# -----------------------------------------------------------------
# cmd_get_rego_policy
# -----------------------------------------------------------------
class cmd_get_rego_policy(pcommand.contract_command_base):
    # distinct from the inherited policy_agent "get_policy" (which gets policy DATA)
    name = "get_rego_policy"
    help = "fetch the whole list of [subpolicy_id, source] pairs"

    @classmethod
    def add_arguments(cls, subparser):
        pass

    @classmethod
    def invoke(cls, state, context, **kwargs):
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file:
            raise ValueError(
                "rego policy agent contract must be created and initialized"
            )

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(
            op_get_rego_policy, state, context, session, **kwargs
        )
        cls.display(result)
        return result


# -----------------------------------------------------------------
# Create the generic, shell independent version of the aggregate command
# -----------------------------------------------------------------
__operations__ = [
    op_initialize,
    op_set_rego_policy,
    op_get_rego_policy,
    op_get_requirements,
    op_register_trusted_issuer,
    op_list_trusted_issuers,
    op_set_policy_data,
    op_get_policy_data,
    op_issue_policy_credential,
]

do_rego_policy_agent_contract = pcontract.create_shell_command(
    "rego_policy_agent_contract", __operations__
)

__commands__ = [
    cmd_create_rego_policy_agent,
    cmd_set_rego_policy,
    cmd_get_rego_policy,
    cmd_get_requirements,
    cmd_register_trusted_issuer,
    cmd_list_trusted_issuers,
    cmd_set_policy_data,
    cmd_get_policy_data,
    cmd_issue_policy_credential,
]

do_rego_policy_agent = pcommand.create_shell_command("rego_policy_agent", __commands__)


# -----------------------------------------------------------------
# Enable binding of the shell independent version to a pdo-shell command
# -----------------------------------------------------------------
def load_commands(cmdclass):
    pshell.bind_shell_command(cmdclass, "rego_policy_agent", do_rego_policy_agent)
    pshell.bind_shell_command(
        cmdclass, "rego_policy_agent_contract", do_rego_policy_agent_contract
    )
