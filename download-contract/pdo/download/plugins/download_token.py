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

import base64
import json
import logging

from pdo.contract import invocation_request


import pdo.client.builder as pbuilder
import pdo.client.builder.command as pcommand
import pdo.client.builder.contract as pcontract
import pdo.client.builder.shell as pshell
import pdo.client.commands.contract as pcontract_cmd

import pdo.exchange.plugins.token_object as token_object
import pdo.identity.plugins.policy_agent as policy_agent
from pdo.contracts.guardian.common.guardian_service import GuardianServiceClient

__all__ = [
    "op_initialize",
    "op_get_verifying_key",
    "op_get_contract_metadata",
    "op_get_contract_code_metadata",
    "op_get_asset_type_identifier",
    "op_get_issuer_authority",
    "op_get_authority",
    "op_transfer",
    "op_escrow",
    "op_release",
    "op_claim",
    "op_do_download",
    "cmd_mint_tokens",
    "cmd_transfer_assets",
    "cmd_do_download",
    "do_download_token",
    "do_download_token_contract",
    "load_commands",
]

## -----------------------------------------------------------------
## inherited operations
## -----------------------------------------------------------------
op_get_verifying_key = token_object.op_get_verifying_key
op_get_contract_metadata = token_object.op_get_contract_metadata
op_get_contract_code_metadata = token_object.op_get_contract_code_metadata
op_get_asset_type_identifier = token_object.op_get_asset_type_identifier
op_get_issuer_authority = token_object.op_get_issuer_authority
op_get_authority = token_object.op_get_authority
op_transfer = token_object.op_transfer
op_escrow = token_object.op_escrow
op_release = token_object.op_release
op_claim = token_object.op_claim
op_initialize = token_object.op_initialize
op_register_trusted_issuer = policy_agent.op_register_trusted_issuer
op_list_trusted_issuers = policy_agent.op_list_trusted_issuers

cmd_mint_tokens = token_object.cmd_mint_tokens
cmd_transfer_assets = token_object.cmd_transfer_assets
cmd_register_trusted_issuer = policy_agent.cmd_register_trusted_issuer
cmd_list_trusted_issuers = policy_agent.cmd_list_trusted_issuers

logger = logging.getLogger(__name__)


## -----------------------------------------------------------------
## -----------------------------------------------------------------
class op_do_download(pcontract.contract_op_base):
    """op_download implements the full end-to-end download of an image using a openvino model

    The specific download operation depends on the model and the model script.
    """

    name = "op_download"
    help = "download using openvino model"

    @classmethod
    def add_arguments(cls, subparser):
        subparser.add_argument(
            "--vc",
            help="Input vc for the token",
            type=pbuilder.invocation_parameter,
            required=True,
        )

        subparser.add_argument(
            "-u", "--url", help="URL for the guardian service", type=str, required=True
        )

    @classmethod
    def invoke(cls, state, session_params, vc, url, **kwargs):
        session_params["commit"] = False

        # send the request to the contract to create a capability for the guardian
        params = {}
        params["download_vc"] = vc

        message = invocation_request("do_download", **params)
        capability = pcontract_cmd.send_to_contract(state, message, **session_params)

        capability = json.loads(capability)

        cls.log_invocation(message, capability)

        # process the capability that was created
        service_client = GuardianServiceClient(url)

        # send the capability to the guardian, this returns a dictionary
        result = service_client.process_capability(**capability)
        return base64.b64decode(result)


## -----------------------------------------------------------------
## -----------------------------------------------------------------
class cmd_do_download(pcommand.contract_command_base):
    """cmd_download implements the full end-to-end download of an image using a openvino model

    The specific download operation depends on the model and the model script.
    """

    name = "do_download"
    help = "download using openvino model"

    @classmethod
    def add_arguments(cls, subparser):
        subparser.add_argument(
            "--vc-file",
            help="Input vc file for the token",
            type=str,
            required=True,
        )
        subparser.add_argument(
            "--output-file",
            help="where to save the downloaded data",
            type=str,
            required=True,
        )
        subparser.add_argument(
            "-u", "--url", help="URL for the guardian service", type=str
        )

    @classmethod
    def invoke(cls, state, context, vc_file, output_file, url=None, **kwargs):
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file:
            raise ValueError("token has not been created")

        if url is None:
            guardian_context = context.get_context("data_guardian_context")
            url = guardian_context["url"]

        with open(vc_file, "r") as fp:
            signed_credential_data = json.load(fp)

        session = pbuilder.SessionParameters(save_file=save_file)
        result = pcontract.invoke_contract_op(
            op_do_download,
            state,
            context,
            session,
            vc=signed_credential_data,
            url=url,
            **kwargs,
        )
        with open(output_file, "wb") as fp:
            fp.write(result)

        return result


## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__operations__ = [
    op_initialize,
    op_get_verifying_key,
    op_get_contract_metadata,
    op_get_contract_code_metadata,
    op_get_asset_type_identifier,
    op_get_issuer_authority,
    op_get_authority,
    op_transfer,
    op_escrow,
    op_release,
    op_claim,
    op_do_download,
    op_register_trusted_issuer,
    op_list_trusted_issuers,
]

do_download_token_contract = pcontract.create_shell_command(
    "download_token_contract", __operations__
)

__commands__ = [
    cmd_mint_tokens,
    cmd_transfer_assets,
    cmd_do_download,
    cmd_register_trusted_issuer,
    cmd_list_trusted_issuers,
]

do_download_token = pcommand.create_shell_command("download_token", __commands__)


## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass):
    pshell.bind_shell_command(cmdclass, "download_token", do_download_token)
    pshell.bind_shell_command(
        cmdclass, "download_token_contract", do_download_token_contract
    )
