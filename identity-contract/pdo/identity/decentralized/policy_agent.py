from pdo.identity.plugins.policy_agent import (
    cmd_register_trusted_issuer,
    cmd_issue_policy_credential,
    cmd_set_policy_data,
    cmd_create_policy_agent,
    cmd_get_policy_data,
    cmd_list_trusted_issuers,
    cmd_get_requirements,
    cmd_list_signing_contexts,
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


def _setup_context(state, user, context_file=None):
    label = _generate_random_label()
    bindings = {"user": user, "identity": label}
    if context_file is None:
        context_file = os.path.join(CONTEXT_FILES, "policy_agent.toml")
    Context.LoadContextFile(state, bindings, context_file)
    context = Context(state, prefix=f"identity.{label}.policy_agent")
    return context


def _setup_register_issuer_context(state, user, issuer_contract_id):
    label = _generate_random_label()
    bindings = {"user": user, "identity": label}
    context_file = os.path.join(CONTEXT_FILES, "signature_authority.toml")
    Context.LoadContextFile(state, bindings, context_file)
    issuer_context_path = f"identity.{label}.signature_authority"
    state.set(
        ["context"] + issuer_context_path.split(".") + ["contract_id"],
        issuer_contract_id,
    )
    return issuer_context_path


def _invoke_policy_agent(state, contract_id, user, cmd_class, **cmd_args):
    # setup context
    context = _setup_context(state, user)
    context.set("contract_id", contract_id)

    # run
    result = pcommand.invoke_contract_cmd(cmd_class, state, context, **cmd_args)
    return result


def register_trusted_issuer(state, contract_id, issuer_contract_id, user, **cmd_args):
    issuer_context_path = _setup_register_issuer_context(
        state, user, issuer_contract_id
    )
    cmd_args["issuer"] = issuer_context_path
    return _invoke_policy_agent(
        state, contract_id, user, cmd_register_trusted_issuer, **cmd_args
    )


def list_trusted_issuers(state, contract_id, user, **cmd_args):
    return _invoke_policy_agent(
        state, contract_id, user, cmd_list_trusted_issuers, **cmd_args
    )


def list_signing_contexts(state, contract_id, user, **cmd_args):
    return _invoke_policy_agent(
        state, contract_id, user, cmd_list_signing_contexts, **cmd_args
    )


def set_policy_data(state, contract_id, user, **cmd_args):
    return _invoke_policy_agent(
        state, contract_id, user, cmd_set_policy_data, **cmd_args
    )


def get_policy_data(state, contract_id, user, **cmd_args):
    return _invoke_policy_agent(
        state, contract_id, user, cmd_get_policy_data, **cmd_args
    )


def get_requirements(state, contract_id, user, **cmd_args):
    return _invoke_policy_agent(
        state, contract_id, user, cmd_get_requirements, **cmd_args
    )


def issue_policy_credential(state, contract_id, user, **cmd_args):
    return _invoke_policy_agent(
        state, contract_id, user, cmd_issue_policy_credential, **cmd_args
    )


def create_policy_agent(state, user, custom_context_file=None, **cmd_args):
    # setup context
    context = _setup_context(state, user, custom_context_file)

    # run
    save_file = pcommand.invoke_contract_cmd(
        cmd_create_policy_agent, state, context, **cmd_args
    )
    contract = pcontract_cmd.get_contract(state, save_file)
    return contract.contract_id
