# Rego contract family

Contracts that evaluate Rego modules (with [regorus](https://github.com/microsoft/regorus))
over verifiable presentations, and sign what the modules decide.

| Contract | Output |
|----------|--------|
| `rego_policy_agent` | one credential of the type its policy names |
| `rego_token` | capabilities for the guardian that trusts it, from a policy agent's `policy_decision` |
| `rego_evaluator` | the output of any Rego source over any input; stateless |

A `rego_policy_agent` plays two roles, set by the type it issues:

- an asset's policy issues `policy_decision` credentials naming one guardian
  operation, `{name, parameters}`, which the asset's `rego_token` turns into a
  capability;
- a rule-based authority issues a fact, such as an ethics approval, that other
  policy agents accept from it.

Its policy -- its subpolicies, one of which declares the type it issues -- is
set once by `set_rego_policy` and never changes, so accepting a policy agent
means accepting one auditable policy, which anyone can read with
`get_rego_policy`. Its trusted issuers (`register_trusted_issuer`,
`unregister_trusted_issuer`, `list_trusted_issuers`) and policy data are the
identity family's `policy_agent`'s, and stay its owner's to manage. It has no
`sign` method: the only credentials its keys sign are the ones its policy allowed.

## Subpolicies

A subpolicy is a Rego module in `package subpolicy` with two rules:

- `requirements`, evaluated with no input: the credential types it reads, per role.
- `result`, evaluated over

  ```json
  {
    "presentations": { "<role>": [ { "type", "issuer", "signer", "trusted", "subject", "claims", "index" } ] },
    "holders": { "<role>": "<did of the role's presentation holder>" },
    "request": { },
    "trusted_issuers": { },
    "policy_data": { }
  }
  ```

  and returning `{decision, verification_tasks, vc_supplied_verification_tasks}`.
  A credential is `trusted` when its issuer is its signer and the agent trusts that
  signer for its type from a context its proof extends. `request` is what the
  requester declares; every call passes one, `{}` when there is nothing to declare.
  `policy_data` is the subpolicy's own slice, `policy_data[<subpolicy id>]`, which
  the owner must set for every subpolicy, `{}` for one with no parameters.
  Subpolicy ids are distinct.

Exactly one subpolicy -- an asset policy's delivery module, an authority's rule --
also declares `issues`, the type of credential the policy issues, which
`set_rego_policy` evaluates with no input; the others leave the rule out. That
subpolicy, and only it, adds `credential: {subject, claims}` to its result. The
agent allows only if every subpolicy allows and that one describes the
credential; it then verifies the credentials the subpolicies relied on, and signs
a credential of the declared type.

## Tests

`test/script_test.sh` (the CLI flow, through a guardian), `test/python/` (the
Python API: `stateless_test.py`, and `rego_policy_agent_test.py` for both roles of
the policy agent).
