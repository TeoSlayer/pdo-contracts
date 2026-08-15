from pdo.identity.plugins.signature_authority import (
    cmd_get_verifying_key,
    cmd_register_signing_context,
    cmd_list_signing_contexts,
    cmd_sign_credential,
    cmd_verify_credential,
    cmd_create_signature_authority,
    cmd_add_vc,
    cmd_get_vc_list,
    cmd_get_vp,
)
from pdo.client.builder import Context
from pdo.client.commands import contract as pcontract_cmd
import pdo.client.builder.command as pcommand
import random
import string
import os

CONTEXT_FILES = os.path.join(os.environ["PDO_HOME"], "contracts/identity/context")


def _generate_random_label(length=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _setup_context(state, user):
    label = _generate_random_label()
    bindings = {"user": user, "identity": label}
    context_file = os.path.join(CONTEXT_FILES, "signature_authority.toml")
    Context.LoadContextFile(state, bindings, context_file)
    context = Context(state, prefix=f"identity.{label}.signature_authority")
    return context


def _invoke_signature_authority(state, contract_id, user, cmd_class, **cmd_args):
    # setup context
    context = _setup_context(state, user)
    context.set("contract_id", contract_id)

    # run
    result = pcommand.invoke_contract_cmd(cmd_class, state, context, **cmd_args)
    return result


def register_signing_context(state, contract_id, user, **cmd_args):
    return _invoke_signature_authority(
        state, contract_id, user, cmd_register_signing_context, **cmd_args
    )


def list_signing_contexts(state, contract_id, user, **cmd_args):
    return _invoke_signature_authority(
        state, contract_id, user, cmd_list_signing_contexts, **cmd_args
    )


def get_verifying_key(state, contract_id, user, **cmd_args):
    return _invoke_signature_authority(
        state, contract_id, user, cmd_get_verifying_key, **cmd_args
    )


def sign_credential(state, contract_id, user, **cmd_args):
    return _invoke_signature_authority(
        state, contract_id, user, cmd_sign_credential, **cmd_args
    )


def verify_credential(state, contract_id, user, **cmd_args):
    return _invoke_signature_authority(
        state, contract_id, user, cmd_verify_credential, **cmd_args
    )


def add_vc(state, contract_id, user, **cmd_args):
    return _invoke_signature_authority(state, contract_id, user, cmd_add_vc, **cmd_args)


def get_vc_list(state, contract_id, user, **cmd_args):
    return _invoke_signature_authority(
        state, contract_id, user, cmd_get_vc_list, **cmd_args
    )


def get_vp(state, contract_id, user, **cmd_args):
    return _invoke_signature_authority(state, contract_id, user, cmd_get_vp, **cmd_args)


def create_signature_authority(state, user, **cmd_args):
    # setup context
    context = _setup_context(state, user)

    # run
    save_file = pcommand.invoke_contract_cmd(
        cmd_create_signature_authority, state, context, **cmd_args
    )
    contract = pcontract_cmd.get_contract(state, save_file)
    return contract.contract_id
