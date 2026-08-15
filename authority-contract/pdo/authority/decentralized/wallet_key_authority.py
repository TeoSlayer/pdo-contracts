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

# Programmatic (non-shell) API for the wallet key authority, mirroring the
# identity family's decentralized/signature_authority.py. It loads the contract
# context template and drives the plugin commands directly.

import os
import random
import string

from pdo.authority.plugins.wallet_key_authority import (
    cmd_get_verifying_key,
    cmd_register_signing_context,
    cmd_list_signing_contexts,
    cmd_verify_credential,
    cmd_create_wallet_key_authority,
    cmd_sign_credential,
)
from pdo.client.builder import Context
from pdo.client.commands import contract as pcontract_cmd
import pdo.client.builder.command as pcommand

CONTEXT_FILES = os.path.join(os.environ["PDO_HOME"], "contracts/authority/context")


def _generate_random_label(length=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _setup_context(state, user):
    label = _generate_random_label()
    bindings = {"user": user, "identity": label}
    context_file = os.path.join(CONTEXT_FILES, "wallet_key_authority.toml")
    Context.LoadContextFile(state, bindings, context_file)
    context = Context(state, prefix=f"identity.{label}.wallet_key_authority")
    return context


def _invoke_wallet_key_authority(state, contract_id, user, cmd_class, **cmd_args):
    context = _setup_context(state, user)
    context.set("contract_id", contract_id)
    return pcommand.invoke_contract_cmd(cmd_class, state, context, **cmd_args)


def register_signing_context(state, contract_id, user, **cmd_args):
    return _invoke_wallet_key_authority(
        state, contract_id, user, cmd_register_signing_context, **cmd_args
    )


def list_signing_contexts(state, contract_id, user, **cmd_args):
    return _invoke_wallet_key_authority(
        state, contract_id, user, cmd_list_signing_contexts, **cmd_args
    )


def get_verifying_key(state, contract_id, user, **cmd_args):
    return _invoke_wallet_key_authority(
        state, contract_id, user, cmd_get_verifying_key, **cmd_args
    )


def verify_credential(state, contract_id, user, **cmd_args):
    return _invoke_wallet_key_authority(
        state, contract_id, user, cmd_verify_credential, **cmd_args
    )


def sign_credential(state, contract_id, user, **cmd_args):
    return _invoke_wallet_key_authority(
        state, contract_id, user, cmd_sign_credential, **cmd_args
    )


def create_wallet_key_authority(state, user, **cmd_args):
    context = _setup_context(state, user)
    save_file = pcommand.invoke_contract_cmd(
        cmd_create_wallet_key_authority, state, context, **cmd_args
    )
    contract = pcontract_cmd.get_contract(state, save_file)
    return contract.contract_id
