import json
import os

import pdo.identity.decentralized.identity as identity
import pdo.download.decentralized.policy_agent as policy_agent
import pdo.identity.decentralized.signature_authority as signature_authority
import pdo.download.decentralized.download_token as download_token
from state import setup_pdo_state, read_var, write_var
from config import SCRATCH_DIR, GUARDIAN_URL
from generate_channel_key import generate_keys, generate_credential
from read_data import read_data
import time

################################################################
issuer_user = "user1"
asset_owner = "user2"
asset_user = "user3"
guardian_url = GUARDIAN_URL
script_dir = os.path.dirname(os.path.abspath(__file__))
policy_data = os.path.join(script_dir, os.path.pardir, "policy_data.json")
membership_credential_path = os.path.join(
    script_dir, os.path.pardir, "credential_membership.json"
)
consent_credential_path = os.path.join(
    script_dir, os.path.pardir, "credential_consent.json"
)

public_pem_file, private_pem_file = generate_keys(
    os.path.join(SCRATCH_DIR, "channel_key")
)
public_key_credential_path = generate_credential(public_pem_file, SCRATCH_DIR)
signed_membership_credential_path = os.path.join(
    SCRATCH_DIR, "credential_membership_signed.json"
)
signed_consent_credential_path = os.path.join(
    SCRATCH_DIR, "credential_consent_signed.json"
)
signed_public_key_credential_path = os.path.join(
    SCRATCH_DIR, "credential_key_signed.json"
)

vp_output_file = os.path.join(SCRATCH_DIR, "vp.json")
download_credential_path = os.path.join(SCRATCH_DIR, "download_credential.json")
encrypted_data_path = os.path.join(SCRATCH_DIR, "output_data.bin")
output_data_path = os.path.join(SCRATCH_DIR, "decrypted_output_data.txt")
################################################################


state, _ = setup_pdo_state()


def issuer_setup():
    # setup membership authority
    print("Setting up membership signature authority...")
    membership_authority = signature_authority.create_signature_authority(
        state, issuer_user, description="membership authority"
    )
    write_var(membership_authority, "membership_authority")
    time.sleep(1)
    print("registering membership signing context...")
    signature_authority.register_signing_context(
        state,
        read_var("membership_authority"),
        issuer_user,
        path=["membership"],
        description="test",
        extensible=False,
    )

    # setup consent authority
    print("Setting up consent signature authority...")
    consent_authority = signature_authority.create_signature_authority(
        state, issuer_user, description="consent authority"
    )
    write_var(consent_authority, "consent_authority")
    time.sleep(1)
    print("registering consent signing context...")
    signature_authority.register_signing_context(
        state,
        read_var("consent_authority"),
        issuer_user,
        path=["consent"],
        description="test",
        extensible=False,
    )

    # setup key authority
    print("Setting up key signature authority...")
    key_authority = signature_authority.create_signature_authority(
        state, issuer_user, description="key authority"
    )
    write_var(key_authority, "key_authority")
    time.sleep(1)
    print("registering key signing context...")
    signature_authority.register_signing_context(
        state,
        read_var("key_authority"),
        issuer_user,
        path=["key"],
        description="test",
        extensible=False,
    )


def owner_setup():
    # policy setup
    print("Creating policy agent...")
    download_policy = policy_agent.create_policy_agent(
        state, asset_owner, description="test policy agent"
    )
    write_var(download_policy, "download_policy")

    print("Creating download token contract...")
    token = download_token.create_download_token(state, asset_owner, guardian_url)
    write_var(token, "token")
    time.sleep(1)

    print("Registering token trusted issuer...")
    download_token.register_trusted_issuer(
        state,
        read_var("token"),
        read_var("download_policy"),
        asset_owner,
        credential_types=["DownloadCredential"],
        path=["__ISSUER__"],
    )

    print("Registering policy agent trusted issuer 1...")
    policy_agent.register_trusted_issuer(
        state,
        read_var("download_policy"),
        read_var("membership_authority"),
        asset_owner,
        path=["membership"],
        credential_types=["membership"],
    )
    time.sleep(1)
    print("Registering policy agent trusted issuer 2...")
    policy_agent.register_trusted_issuer(
        state,
        read_var("download_policy"),
        read_var("consent_authority"),
        asset_owner,
        path=["consent"],
        credential_types=["consent"],
    )
    time.sleep(1)
    print("Registering policy agent trusted issuer 3...")
    policy_agent.register_trusted_issuer(
        state,
        read_var("download_policy"),
        read_var("key_authority"),
        asset_owner,
        path=["key"],
        credential_types=["public_key"],
    )
    time.sleep(1)

    print("setting policy data...")
    policy_agent.set_policy_data(
        state, read_var("download_policy"), asset_owner, data=policy_data
    )


def user_setup():
    # user wallet setup
    print("Creating user wallet...")
    user_wallet = identity.create_identity(state, asset_user, description="user wallet")
    write_var(user_wallet, "user_wallet")


# start interactions
def issuer_action():
    print("Issuing membership credential...")
    signature_authority.sign_credential(
        state,
        read_var("membership_authority"),
        issuer_user,
        path=["membership"],
        credential=membership_credential_path,
        signed_credential=signed_membership_credential_path,
    )
    print("Issuing consent credential...")
    signature_authority.sign_credential(
        state,
        read_var("consent_authority"),
        issuer_user,
        path=["consent"],
        credential=consent_credential_path,
        signed_credential=signed_consent_credential_path,
    )
    print("Issuing public key credential...")
    signature_authority.sign_credential(
        state,
        read_var("key_authority"),
        issuer_user,
        path=["key"],
        credential=public_key_credential_path,
        signed_credential=signed_public_key_credential_path,
    )


def user_action():
    print("Adding credentials to user wallet...")
    identity.add_vc(
        state,
        read_var("user_wallet"),
        asset_user,
        credential_file=signed_membership_credential_path,
    )
    identity.add_vc(
        state,
        read_var("user_wallet"),
        asset_user,
        credential_file=signed_consent_credential_path,
    )
    identity.add_vc(
        state,
        read_var("user_wallet"),
        asset_user,
        credential_file=signed_public_key_credential_path,
    )

    print("Getting token policy agent...")
    policy_agent_dict = download_token.list_trusted_issuers(
        state, read_var("token"), asset_user
    )
    retrieved_policy_agent = list(json.loads(policy_agent_dict).keys())[0]
    write_var(retrieved_policy_agent, "retrieved_policy_agent")

    print("Getting requirements for download...")
    creds_list = policy_agent.get_requirements(
        state, read_var("retrieved_policy_agent"), asset_user
    )

    print("generating vp...")
    identity.get_vp(
        state,
        read_var("user_wallet"),
        asset_user,
        save_file="vp.json",
        types=creds_list,
        output_file=vp_output_file,
    )
    print("Get download vc...")
    policy_agent.issue_policy_credential(
        state,
        read_var("retrieved_policy_agent"),
        asset_user,
        presentation=vp_output_file,
        issued_credential=download_credential_path,
    )

    print("Download data...")
    download_token.do_download(
        state,
        read_var("token"),
        asset_user,
        guardian_url,
        vc_file=download_credential_path,
        output_file=encrypted_data_path,
    )

    print("read downloaded data...")
    read_data(encrypted_data_path, private_pem_file, output_data_path)
    with open(output_data_path, "r") as f:
        print("Downloaded data:")
        print(f.read())


issuer_setup()
owner_setup()
user_setup()
issuer_action()
user_action()
