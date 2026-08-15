from pdo.rego.plugins.rego_token import (
    cmd_mint_tokens,
    cmd_do_operation,
    cmd_register_trusted_issuer,
    cmd_list_trusted_issuers,
)
from pdo.exchange.plugins.token_issuer import cmd_create_token_issuer
from pdo.client.builder import Context
from pdo.client.commands import contract as pcontract_cmd
import pdo.client.builder.command as pcommand
import random
import string
import os

CONTEXT_FILES = os.path.join(os.environ["PDO_HOME"], "contracts/rego/context")


def _generate_random_label(length=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _setup_context(state, user, url):
    label = _generate_random_label()
    bindings = {"user": user, "token": label, "url": url}
    context_file = os.path.join(CONTEXT_FILES, "tokens.toml")
    Context.LoadContextFile(state, bindings, context_file)
    issuer_context = Context(state, prefix=f"token.{label}.token_issuer")
    token_context = Context(state, prefix=f"token.{label}.token_object")
    return token_context, issuer_context


def _setup_register_issuer_context(state, user, issuer_contract_id):
    label = _generate_random_label()
    bindings = {"user": user, "identity": label}
    context_file = os.path.join(CONTEXT_FILES, "rego_policy_agent.toml")
    Context.LoadContextFile(state, bindings, context_file)
    issuer_context_path = f"identity.{label}.rego_policy_agent"
    state.set(
        ["context"] + issuer_context_path.split(".") + ["contract_id"],
        issuer_contract_id,
    )
    return issuer_context_path


def _invoke_rego_token(state, contract_id, user, url, cmd_class, **cmd_args):
    token_context, _ = _setup_context(state, user, url)
    token_context.set("contract_id", contract_id)

    # run
    result = pcommand.invoke_contract_cmd(cmd_class, state, token_context, **cmd_args)
    return result


def register_trusted_issuer(state, contract_id, issuer_contract_id, user, **cmd_args):
    issuer_context_path = _setup_register_issuer_context(
        state, user, issuer_contract_id
    )
    cmd_args["issuer"] = issuer_context_path
    return _invoke_rego_token(
        state, contract_id, user, "", cmd_register_trusted_issuer, **cmd_args
    )


def list_trusted_issuers(state, contract_id, user, **cmd_args):
    return _invoke_rego_token(
        state, contract_id, user, "", cmd_list_trusted_issuers, **cmd_args
    )


def do_operation(state, contract_id, user, url, **cmd_args):
    return _invoke_rego_token(
        state, contract_id, user, url, cmd_do_operation, **cmd_args
    )


def create_rego_token(state, user, url):
    # setup context for the token aggregate
    token_context, issuer_context = _setup_context(state, user, url)
    pcommand.invoke_contract_cmd(cmd_create_token_issuer, state, issuer_context)

    # mint tokens against the token_object context
    save_files = pcommand.invoke_contract_cmd(cmd_mint_tokens, state, token_context)
    save_file = save_files[0]
    contract = pcontract_cmd.get_contract(state, save_file)
    return contract.contract_id
