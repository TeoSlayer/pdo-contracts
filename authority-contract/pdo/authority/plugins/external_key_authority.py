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

import json
import logging

from pdo.contract import invocation_request
from pdo.submitter.create import create_submitter

import pdo.client.builder as pbuilder
import pdo.client.builder.command as pcommand
import pdo.client.builder.contract as pcontract
import pdo.client.builder.shell as pshell
import pdo.client.commands.contract as pcontract_cmd
import pdo.common.crypto as pcrypto

import pdo.client.plugins.common as common
import pdo.identity.plugins.signature_authority as signature_authority
import pdo.identity.plugins.policy_agent as policy_agent
import pdo.authority.plugins.wallet_key_authority as wallet_key_authority
import pdo.authority.session_key as session_key

logger = logging.getLogger(__name__)

WALLET_VERIFYING_KEY_CREDENTIAL_TYPE = "WalletVerifyingKeyCredential"
PDO_DID_PREFIX = "did:pdo:"

__all__ = [
    'op_initialize',
    'op_get_verifying_key',
    'op_get_extended_verifying_key',
    'op_register_signing_context',
    'op_describe_signing_context',
    'op_list_signing_contexts',
    'op_add_vc',
    'op_get_vc_list',
    'op_get_vp',
    'op_sign_credential',
    'op_verify_credential',
    'op_register_trusted_issuer',
    'op_list_trusted_issuers',
    'cmd_register_signing_context',
    'cmd_list_signing_contexts',
    'cmd_get_verifying_key',
    'cmd_verify_credential',
    'cmd_register_trusted_issuer',
    'cmd_list_trusted_issuers',
    'cmd_create_external_key_authority',
    'cmd_sign_credential',
    'cmd_bind_external_key',
    'do_external_key_authority',
    'do_external_key_authority_contract',
    'load_commands',
]

# -----------------------------------------------------------------
# external_key_authority inherits its identity operations from signature_authority
# and its trusted-issuer operations from policy_agent (used to trust a
# wallet_key_authority). sign_credential is customized (see op_sign_credential):
# it binds an external session key to a wallet from a trusted WalletVerifyingKeyCredential.
# -----------------------------------------------------------------
op_initialize = signature_authority.op_initialize
op_get_verifying_key = signature_authority.op_get_verifying_key
op_get_extended_verifying_key = signature_authority.op_get_extended_verifying_key
op_register_signing_context = signature_authority.op_register_signing_context
op_describe_signing_context = signature_authority.op_describe_signing_context
op_list_signing_contexts = signature_authority.op_list_signing_contexts
op_add_vc = signature_authority.op_add_vc
op_get_vc_list = signature_authority.op_get_vc_list
op_get_vp = signature_authority.op_get_vp
op_sign_with_contract_key = signature_authority.op_sign_with_contract_key
op_verify_credential = signature_authority.op_verify_credential

op_get_contract_metadata = common.op_get_contract_metadata
op_register_trusted_issuer = policy_agent.op_register_trusted_issuer
op_list_trusted_issuers = policy_agent.op_list_trusted_issuers

cmd_register_signing_context = signature_authority.cmd_register_signing_context
cmd_list_signing_contexts = signature_authority.cmd_list_signing_contexts
cmd_get_verifying_key = signature_authority.cmd_get_verifying_key
cmd_verify_credential = signature_authority.cmd_verify_credential
cmd_register_trusted_issuer = policy_agent.cmd_register_trusted_issuer
cmd_list_trusted_issuers = policy_agent.cmd_list_trusted_issuers


# -----------------------------------------------------------------
# -----------------------------------------------------------------
class op_sign_credential(pcontract.contract_op_base) :
    name = "sign_credential"
    help = "bind an external session key to a wallet and issue a publicKeyCredential for it"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--wallet-verifying-key-credential',
            help='the WalletVerifyingKeyCredential from a trusted wallet_key_authority',
            type=pbuilder.invocation_parameter, required=True)
        subparser.add_argument(
            '--wallet-attestation',
            help='the binding payload signed by the wallet ({payload, signature})',
            type=pbuilder.invocation_parameter, required=True)
        subparser.add_argument(
            '--session-key-attestation',
            help='the same binding payload signed by the session key ({payload, signature})',
            type=pbuilder.invocation_parameter, required=True)

    @classmethod
    def invoke(cls, state, session_params, wallet_verifying_key_credential, wallet_attestation,
               session_key_attestation, **kwargs) :
        session_params['commit'] = False

        message = invocation_request(
            'sign_credential',
            wallet_verifying_key_credential=wallet_verifying_key_credential,
            wallet_attestation=wallet_attestation,
            session_key_attestation=session_key_attestation)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result


# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_create_external_key_authority(pcommand.contract_command_base) :
    name = "create"
    help = "create an external key authority"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('-c', '--contract-class', help='Name of the contract class', type=str)
        subparser.add_argument('-e', '--eservice-group', help='Name of the enclave service group to use', type=str)
        subparser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str)
        subparser.add_argument('-p', '--pservice-group', help='Name of the provisioning service group to use', type=str)
        subparser.add_argument('-r', '--sservice-group', help='Name of the storage service group to use', type=str)
        subparser.add_argument('--source', help='File that contains contract source code', type=str)
        subparser.add_argument('--extra', help='Extra data associated with the contract file', nargs=2, action='append')

    @classmethod
    def invoke(cls, state, context, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if save_file :
            return save_file

        # create the contract
        save_file = pcontract_cmd.create_contract_from_context(state, context, 'external_key_authority', **kwargs)
        context['save_file'] = save_file

        session = pbuilder.SessionParameters(save_file=save_file)
        pcontract.invoke_contract_op(
            op_initialize,
            state, context, session,
            context['description'],
            **kwargs)

        # create the wallet key authority that issues the credentials this authority
        # consumes, unless it already exists
        wka_context = context.get_context('wallet_key_authority_context')
        wka_save_file = pcontract_cmd.get_contract_from_context(state, wka_context)
        if not wka_save_file :
            wka_save_file = pcommand.invoke_contract_cmd(
                wallet_key_authority.cmd_create_wallet_key_authority,
                state, wka_context,
                **kwargs)

        # trust the wallet key authority as an issuer of WalletVerifyingKeyCredentials
        pcommand.invoke_contract_cmd(
            cmd_register_trusted_issuer,
            state, context,
            issuer=wka_context.path,
            path=['wallet_key_authority'],
            credential_types=[WALLET_VERIFYING_KEY_CREDENTIAL_TYPE],
            **kwargs)

        cls.display('created external key authority in {}'.format(save_file))
        return save_file


# -----------------------------------------------------------------
# -----------------------------------------------------------------
class cmd_sign_credential(pcommand.contract_command_base) :
    name = "sign_credential"
    help = "bind an external session key to a wallet and issue a publicKeyCredential for the session key"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--wallet-verifying-key-credential',
            help='file with the WalletVerifyingKeyCredential from a trusted wallet_key_authority',
            type=str, required=True)
        subparser.add_argument(
            '--wallet-attestation',
            help='file with the binding payload signed by the wallet ({payload, signature})',
            type=str, required=True)
        subparser.add_argument(
            '--session-key-attestation',
            help='file with the same payload signed by the session key ({payload, signature})',
            type=str, required=True)
        subparser.add_argument(
            '--credential',
            help='file where the issued verifiable credential will be written',
            type=str, required=True)

    @classmethod
    def invoke(cls, state, context, wallet_verifying_key_credential, wallet_attestation,
               session_key_attestation, credential, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('external key authority contract must be created and initialized')

        with open(wallet_verifying_key_credential, "r") as fp :
            wskc = json.load(fp)
        with open(wallet_attestation, "r") as fp :
            wallet_attestation_data = json.load(fp)
        with open(session_key_attestation, "r") as fp :
            session_key_attestation_data = json.load(fp)

        session = pbuilder.SessionParameters(save_file=save_file)
        vc = pcontract.invoke_contract_op(
            op_sign_credential,
            state, context, session,
            wallet_verifying_key_credential=wskc,
            wallet_attestation=wallet_attestation_data,
            session_key_attestation=session_key_attestation_data,
            **kwargs)

        with open(credential, "w") as fp :
            fp.write(vc)

        cls.display('saved publicKeyCredential to {}'.format(credential))
        return True


## -----------------------------------------------------------------
## bind an external key to a wallet
## -----------------------------------------------------------------
class cmd_bind_external_key(pcommand.contract_command_base) :
    """Generate an external RSA key and bind it to a wallet
    The wallet must be created and the wallet key authority that issues its
    verifying key credential must be trusted by this external key authority.
    """

    name = "bind_external_key"
    help = "generate an external RSA key and bind it to a wallet"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-w', '--wallet',
            help='context of the wallet to bind the external key to',
            type=str, required=True)
        subparser.add_argument(
            '--keys-dir',
            help='directory where the generated external RSA key pair is written',
            type=str, required=True)

    @classmethod
    def get_wallet_credential(cls, state, context, wallet_context, wallet_session, wallet_contract, **kwargs) :
        """Get a WalletVerifyingKeyCredential for the wallet and store it in the wallet

        The credential comes from the wallet key authority wired into this external
        key authority's context as the wallet_key_authority_context.
        """

        wka_context = context.get_context('wallet_key_authority_context')
        wka_save_file = pcontract_cmd.get_contract_from_context(state, wka_context)
        if wka_save_file is None :
            # A caller may have built a fresh context tree that never carried
            # the wka's contract_id into wallet_key_authority_context (e.g.
            # one generated per call, disconnected from the tree used at
            # creation time). Recover it from this eka's own trusted-issuer
            # list, which always trusts exactly one issuer for
            # WalletVerifyingKeyCredential (registered by
            # cmd_create_external_key_authority).
            save_file = pcontract_cmd.get_contract_from_context(state, context)
            session = pbuilder.SessionParameters(save_file=save_file)
            raw_issuers = pcontract.invoke_contract_op(
                op_list_trusted_issuers, state, context, session, **kwargs)
            issuers = json.loads(raw_issuers) if isinstance(raw_issuers, str) else (raw_issuers or {})
            wka_id = next(
                (issuer_id for issuer_id, entries in issuers.items()
                 for entry in (entries or [])
                 if WALLET_VERIFYING_KEY_CREDENTIAL_TYPE in (entry.get('credential_types') or [])),
                None)
            if wka_id is None :
                raise ValueError('external key authority has no trusted wallet_key_authority registered')
            wka_context.set('contract_id', wka_id)
            wka_save_file = pcontract_cmd.get_contract_from_context(state, wka_context)
            if wka_save_file is None :
                raise ValueError('unable to locate wallet key authority contract on the ledger')
        wka_session = pbuilder.SessionParameters(save_file=wka_save_file)

        # the authority attests the wallet's verifying key from its ledger attestation
        # and metadata, so we collect both from the ledger and the wallet contract
        ledger_submitter = create_submitter(state.get(['Ledger']))
        ledger_attestation = ledger_submitter.get_contract_info(wallet_contract.contract_id)

        contract_metadata = pcontract.invoke_contract_op(
            op_get_contract_metadata,
            state, wallet_context, wallet_session,
            **kwargs)
        contract_metadata = json.loads(contract_metadata)

        wallet_credential = pcontract.invoke_contract_op(
            wallet_key_authority.op_sign_credential,
            state, wka_context, wka_session,
            wallet_contract.contract_id,
            wallet_contract.creator_id,
            ledger_attestation,
            contract_metadata,
            **kwargs)
        wallet_credential = json.loads(wallet_credential)

        # store the credential in the wallet so a later bind can reuse it
        pcontract.invoke_contract_op(
            op_add_vc,
            state, wallet_context, wallet_session,
            wallet_credential,
            **kwargs)

        return wallet_credential

    @classmethod
    def invoke(cls, state, context, wallet, keys_dir, **kwargs) :
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file :
            raise ValueError('external key authority contract must be created and initialized')
        session = pbuilder.SessionParameters(save_file=save_file)

        # resolve the wallet from its context; its contract id is the DID that the
        # binding payload and the issued credentials are all anchored to
        wallet_context = pbuilder.Context(state, wallet)
        wallet_save_file = pcontract_cmd.get_contract_from_context(state, wallet_context)
        wallet_contract = pcontract_cmd.get_contract(state, wallet_save_file)
        wallet_did = PDO_DID_PREFIX + wallet_contract.contract_id
        wallet_session = pbuilder.SessionParameters(save_file=wallet_save_file)

        # generate the external key pair that will be bound to the wallet
        session_key.generate_rsa_keypair(keys_dir)
        session_public_pem = session_key.load_public_pem(keys_dir)

        # the binding needs a WalletVerifyingKeyCredential; reuse the one the wallet
        # already holds, otherwise get a fresh one from the trusted authority
        vc_map = json.loads(pcontract.invoke_contract_op(
            op_get_vc_list,
            state, wallet_context, wallet_session,
            **kwargs))
        wallet_credential = vc_map.get(WALLET_VERIFYING_KEY_CREDENTIAL_TYPE)
        if wallet_credential is None :
            wallet_credential = cls.get_wallet_credential(
                state, context,
                wallet_context, wallet_session, wallet_contract,
                **kwargs)

        # the wallet and the session key sign the same binding payload; the wallet
        # signs with its contract key so the signature verifies against its ledger key
        payload = session_key.build_payload(wallet_did, session_public_pem)
        b64_payload = pcrypto.byte_array_to_base64(pcrypto.string_to_byte_array(payload))
        wallet_signature = pcontract.invoke_contract_op(
            op_sign_with_contract_key,
            state, wallet_context, wallet_session,
            b64_payload,
            **kwargs)
        wallet_attestation = { 'payload' : payload, 'signature' : json.loads(wallet_signature) }
        session_key_attestation = { 'payload' : payload, 'signature' : session_key.sign_payload_b64(keys_dir, payload) }

        # the authority checks the credential and both signatures and issues a
        # publicKeyCredential for the session key
        public_key_credential = pcontract.invoke_contract_op(
            op_sign_credential,
            state, context, session,
            wallet_credential,
            wallet_attestation,
            session_key_attestation,
            **kwargs)
        public_key_credential = json.loads(public_key_credential)

        # store the issued credential in the wallet
        pcontract.invoke_contract_op(
            op_add_vc,
            state, wallet_context, wallet_session,
            public_key_credential,
            **kwargs)

        cls.display('bound external key to wallet {}'.format(wallet_contract.contract_id))
        return public_key_credential


# -----------------------------------------------------------------
# Create the generic, shell independent version of the aggregate command
# -----------------------------------------------------------------
__operations__ = [
    op_initialize,
    op_get_verifying_key,
    op_get_extended_verifying_key,
    op_register_signing_context,
    op_describe_signing_context,
    op_list_signing_contexts,
    op_add_vc,
    op_get_vc_list,
    op_get_vp,
    op_sign_credential,
    op_verify_credential,
    op_register_trusted_issuer,
    op_list_trusted_issuers,
]

do_external_key_authority_contract = pcontract.create_shell_command('external_key_authority_contract', __operations__)

__commands__ = [
    cmd_get_verifying_key,
    cmd_register_signing_context,
    cmd_list_signing_contexts,
    cmd_verify_credential,
    cmd_register_trusted_issuer,
    cmd_list_trusted_issuers,
    cmd_create_external_key_authority,
    cmd_sign_credential,
    cmd_bind_external_key,
]

do_external_key_authority = pcommand.create_shell_command('external_key_authority', __commands__)


# -----------------------------------------------------------------
# Enable binding of the shell independent version to a pdo-shell command
# -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'external_key_authority', do_external_key_authority)
    pshell.bind_shell_command(cmdclass, 'external_key_authority_contract', do_external_key_authority_contract)
