import pdo.identity.decentralized.policy_agent as policy_agent
from pdo.identity.decentralized.policy_agent import (  # noqa: F401
    register_trusted_issuer,
    list_trusted_issuers,
    set_policy_data,
    get_policy_data,
    get_requirements,
    issue_policy_credential,
    list_signing_contexts,
)
import os

CONTEXT_FILES = os.path.join(os.environ["PDO_HOME"], "contracts/download/context")


def create_policy_agent(state, user, **cmd_args):
    # setup context
    context_file = os.path.join(CONTEXT_FILES, "policy_agent.toml")
    return policy_agent.create_policy_agent(
        state, user, custom_context_file=context_file, **cmd_args
    )
