"""The rego_policy_agent, against a live deployment.

    python startup.py && python rego_policy_agent_test.py && python cleanup.py

One contract plays both roles: an asset's policy, issuing policy decisions, and
a rule-based authority, issuing a fact other policy agents accept. Covers:

* a wallet holds several credentials of one type and presents them all;
* modules read input.holders, input.request, their own slice of the policy data,
  and each credential's signer;
* exactly one module declares the type issued, only it describes the
  credential, and a policy is locked once set;
* a credential whose issuer is not its signer is refused, and trust can be
  withdrawn;
* an authority issues the fact its policy describes, and a policy agent that
  trusts it accepts that fact.
"""

import base64
import json
import os
import time

import pdo.identity.decentralized.identity as identity
import pdo.identity.decentralized.signature_authority as signature_authority
import pdo.rego.decentralized.rego_policy_agent as policy_agent

from config import SCRATCH_DIR
from state import setup_pdo_state

ISSUER = "user1"
OWNER = "user2"
HOLDER = "user3"
OPERATOR = "user4"

MODULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.path.pardir, "modules")

state, _ = setup_pdo_state()
os.makedirs(SCRATCH_DIR, exist_ok=True)
passed = []


def check(label, condition, detail=""):
    if not condition:
        raise AssertionError(f"{label}: {detail}")
    passed.append(label)
    print(f"PASS  {label}")


def refused(fn, **kwargs):
    """The error a contract call failed with, or None if it succeeded."""
    try:
        fn(**kwargs)
    except Exception as error:
        return str(error)
    return None


def scratch(name):
    return os.path.join(SCRATCH_DIR, name)


def write_json(name, value):
    path = scratch(name)
    with open(path, "w") as fp:
        json.dump(value, fp)
    return path


def read_json(path):
    with open(path) as fp:
        return json.load(fp)


def did(contract_id):
    return f"did:pdo:{contract_id}"


def credential_of(vc):
    return json.loads(base64.b64decode(vc["serializedCredential"]))


def module(name):
    return os.path.join(MODULES, name)


def created(contract_id):
    """A new contract, once its initialization has committed."""
    time.sleep(1)
    return contract_id


def agent(user, description, modules, data):
    """A policy agent with its policy and policy data set."""
    contract_id = created(policy_agent.create_rego_policy_agent(state, user, description=description))
    policy_agent.set_rego_policy(
        state,
        contract_id,
        user,
        module=[[module_id, module(name)] for module_id, name in modules],
    )
    policy_agent.set_policy_data(state, contract_id, user, data=write_json(f"{description}_data.json", data))
    return contract_id


def issue(contract_id, presentation_file, request, name):
    """Ask a policy agent for its credential; the error it refused with, or the
    credential's contents."""
    error = refused(
        policy_agent.issue_policy_credential,
        state=state,
        contract_id=contract_id,
        user=HOLDER,
        presentation=presentation_file,
        request=request,
        issued_credential=scratch(name),
    )
    return error, (None if error else credential_of(read_json(scratch(name))))


# ---------------------------------------------------------------- the parties
authority = created(signature_authority.create_signature_authority(state, ISSUER, description="membership authority"))
signature_authority.register_signing_context(
    state, authority, ISSUER, path=["membership"], description="memberships", extensible=False
)
alice = created(identity.create_identity(state, HOLDER, description="alice"))
carol = created(identity.create_identity(state, HOLDER, description="carol"))


def membership(subject, institution, project, issuer):
    """A membership credential about subject, naming issuer, signed by the
    membership authority."""
    name = f"membership_{institution}_{project.rsplit(':', 1)[-1]}_{subject[-6:]}".replace("/", "_")
    unsigned = write_json(
        f"{name}.json",
        {
            "type": ["membership"],
            "issuer": {"id": issuer},
            "credentialSubject": {
                "subject": {"id": subject},
                "claims": {"institution": institution, "project": project},
            },
        },
    )
    signed = scratch(f"{name}_signed.json")
    signature_authority.sign_credential(
        state, authority, ISSUER, path=["membership"], credential=unsigned, signed_credential=signed
    )
    return signed


def presentation(wallet, types, request_name):
    """The applicant role, presented from wallet, as the contract expects it."""
    vp_path = scratch(f"{request_name}_vp.json")
    identity.get_vp(state, wallet, HOLDER, types=types, output_file=vp_path)
    return write_json(f"{request_name}_presentation.json", {"applicant": read_json(vp_path)})


def trust_memberships(contract_id, user):
    policy_agent.register_trusted_issuer(
        state, contract_id, authority, user, path=["membership"], credential_types=["membership"]
    )


# ------------------------------------------------- several credentials per type
for credential in (
    membership(did(alice), "Hyperledger", "did:example:p1", did(authority)),
    membership(did(alice), "Intel", "did:example:p2", did(authority)),
    membership(did(carol), "Intel", "did:example:p2", did(authority)),
):
    identity.add_vc(state, alice, HOLDER, credential_file=credential)
identity.add_vc(
    state, alice, HOLDER, credential_file=membership(did(alice), "Intel", "did:example:p2", did(authority))
)

stored = json.loads(identity.get_vc_list(state, alice, HOLDER))
check("a wallet keeps several credentials of one type, once each", len(stored) == 3, stored.keys())

vp_path = scratch("alice_vp.json")
identity.get_vp(state, alice, HOLDER, types=["membership"], output_file=vp_path)
presented = json.loads(base64.b64decode(read_json(vp_path)["serializedPresentation"]))
subjects = sorted(credential_of(vc)["credentialSubject"]["subject"]["id"] for vc in presented["verifiableCredential"])
check(
    "get_vp presents every stored credential of the type",
    subjects == sorted([did(alice), did(alice), did(carol)]),
    subjects,
)

# ------------------------------------------- an asset's policy: holders, request
fact_data = {"allowedInstitutions": ["Intel"], "membershipAuthority": did(authority)}
gate = created(policy_agent.create_rego_policy_agent(state, OWNER, description="gate"))
trust_memberships(gate, OWNER)
policy_agent.set_rego_policy(
    state,
    gate,
    OWNER,
    module=[["fact", module("holder_membership.rego")], ["delivery", module("delivery.rego")]],
)
policy_agent.set_policy_data(state, gate, OWNER, data=write_json("flat_data.json", fact_data))
alice_presentation = presentation(alice, ["membership"], "alice")
error, _ = issue(gate, alice_presentation, {"project": "did:example:p2"}, "flat.json")
check("every module needs policy data keyed by its own id", error is not None and "no policy data" in error, error)

policy_agent.set_policy_data(
    state, gate, OWNER, data=write_json("sliced_data.json", {"fact": fact_data, "delivery": {}})
)
error, decision = issue(gate, alice_presentation, {"project": "did:example:p2"}, "decision.json")
check(
    "the delivery module describes the decision, about the holder",
    error is None
    and decision["type"] == ["policy_decision"]
    and decision["issuer"]["id"] == did(gate)
    and decision["credentialSubject"]["subject"]["id"] == did(alice)
    and decision["credentialSubject"]["claims"] == {"name": "do_download", "parameters": {"holder": did(alice)}},
    error or decision,
)

error, _ = issue(gate, alice_presentation, {"project": "did:example:p1"}, "other_project.json")
check("the request's project must be the one the fact is about", error is not None and "a module denied" in error, error)

error, _ = issue(gate, alice_presentation, {}, "no_project.json")
check("a fact bound to the request's project denies when none is declared", error is not None and "a module denied" in error, error)

error = refused(
    policy_agent.set_rego_policy,
    state=state,
    contract_id=gate,
    user=OWNER,
    module=[["delivery", module("delivery.rego")]],
)
check("a policy is locked once set", error is not None and "already set" in error, error)

# ------------------------------------------------------- one described credential
unnamed = created(policy_agent.create_rego_policy_agent(state, OWNER, description="unnamed"))
error = refused(
    policy_agent.set_rego_policy,
    state=state,
    contract_id=unnamed,
    user=OWNER,
    module=[["fact", module("holder_membership.rego")], ["fact", module("delivery.rego")]],
)
check("module ids must be distinct", error is not None and "duplicate module id" in error, error)

error = refused(
    policy_agent.set_rego_policy,
    state=state,
    contract_id=unnamed,
    user=OWNER,
    module=[["fact", module("holder_membership.rego")]],
)
check("a policy must declare the type it issues", error is not None and "no module declares" in error, error)

error = refused(
    policy_agent.set_rego_policy,
    state=state,
    contract_id=unnamed,
    user=OWNER,
    module=[["delivery", module("delivery.rego")], ["rule", module("membership_attestation_rule.rego")]],
)
check(
    "only one module may declare the type issued",
    error is not None and "more than one module declares" in error,
    error,
)

doubled = agent(
    OWNER,
    "doubled",
    [("fact", "holder_membership.rego"), ("delivery", "delivery.rego"), ("other", "second_delivery.rego")],
    {"fact": fact_data, "delivery": {}, "other": {}},
)
trust_memberships(doubled, OWNER)
error, _ = issue(doubled, alice_presentation, {"project": "did:example:p2"}, "doubled.json")
check(
    "only the module that declares the type may describe the credential",
    error is not None and "does not declare its type" in error,
    error,
)

# ------------------------------------------------------------- issuer == signer
identity.add_vc(
    state, carol, HOLDER, credential_file=membership(did(carol), "Intel", "did:example:p2", did(alice))
)
error, _ = issue(gate, presentation(carol, ["membership"], "carol"), {"project": "did:example:p2"}, "forged.json")
check("a credential naming an issuer other than its signer is refused", error is not None, error)

# ------------------------------------------------------------- withdrawn trust
error = refused(
    policy_agent.unregister_trusted_issuer,
    state=state,
    contract_id=gate,
    user=OWNER,
    issuer=authority,
    credential_types=["public_key"],
)
check("withdrawing a type the issuer was never trusted for is refused", error is not None and "not trusted" in error, error)

policy_agent.unregister_trusted_issuer(state, gate, OWNER, issuer=authority, credential_types=["membership"])
issuers = json.loads(policy_agent.list_trusted_issuers(state, gate, OWNER))
check("unregistering removes the issuer", authority not in issuers, issuers)
error, _ = issue(gate, alice_presentation, {"project": "did:example:p2"}, "untrusted.json")
check("a credential from an issuer no longer trusted is refused", error is not None, error)

# ------------------------------------------------------- a rule-based authority
attest = agent(
    OPERATOR,
    "attestation",
    [("rule", "membership_attestation_rule.rego")],
    {"rule": {"allowedInstitutions": ["Intel"]}},
)
trust_memberships(attest, OPERATOR)

published = json.loads(policy_agent.get_rego_policy(state, attest, HOLDER))
check(
    "anyone can read a policy, with the type it declares",
    published["credential_type"] == "MembershipAttestation"
    and [m[0] for m in published["rego_modules"]] == ["rule"]
    and published["requirements"] == {"applicant": ["membership"]},
    published,
)

error, _ = issue(attest, alice_presentation, {"project": "did:example:p1"}, "attestation_p1.json")
check("the authority's policy can deny", error is not None and "a module denied" in error, error)

error, attestation = issue(attest, alice_presentation, {"project": "did:example:p2"}, "attestation.json")
check(
    "the authority issues the credential its policy describes",
    error is None
    and attestation["type"] == ["MembershipAttestation"]
    and attestation["issuer"]["id"] == did(attest)
    and attestation["credentialSubject"]["subject"]["id"] == did(alice)
    and attestation["credentialSubject"]["claims"] == {"institution": "Intel", "project": "did:example:p2"},
    error or attestation,
)

# --------------------------------------- the authority's fact, read by a policy
identity.add_vc(state, alice, HOLDER, credential_file=scratch("attestation.json"))
reader = agent(
    OWNER,
    "reader",
    [("fact", "holder_attestation.rego"), ("delivery", "delivery.rego")],
    {"fact": {}, "delivery": {}},
)
attested_presentation = presentation(alice, ["MembershipAttestation"], "attested")
error, _ = issue(reader, attested_presentation, {}, "unaccepted.json")
check(
    "a credential from an authority the policy agent does not trust is not a fact there",
    error is not None and "a module denied" in error,
    error,
)

policy_agent.register_trusted_issuer(
    state, reader, attest, OWNER, path=["__ISSUER__"], credential_types=["MembershipAttestation"]
)
error, decision = issue(reader, attested_presentation, {}, "attested_decision.json")
check(
    "a policy accepts a fact issued by an authority it trusts",
    error is None and decision["credentialSubject"]["claims"]["name"] == "do_download",
    error or decision,
)

print(f"\nPASSED: {len(passed)} checks")
