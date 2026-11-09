"""Exercise registration without requiring an SGX installation or live ledger.

The PDO native crypto and WSGI adapters are replaced at the import boundary;
attestations use real ECDSA signatures and production request/registry code.
"""
import base64
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import jsonschema
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

ROOT = Path(__file__).resolve().parents[1] / 'common-contract/pdo/contracts/guardian'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


attestation = load('guardian_attestation', 'common/attestation.py')


def b64(value):
    return base64.b64encode(value).decode('ascii')


def pem(key):
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('ascii')


class LedgerKey:
    def __init__(self, public_key):
        self.key = serialization.load_pem_public_key(public_key.encode())

    def VerifySignature(self, message, signature):
        try:
            self.key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return 1
        except InvalidSignature:
            return 0


class EndpointKeys:
    def __init__(self, verifying_key, encryption_key):
        self.verifying_key = serialization.load_pem_public_key(verifying_key.encode())
        self.encryption_key = serialization.load_pem_public_key(encryption_key.encode())


class RegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = ec.generate_private_key(ec.SECP384R1())
        cls.verifying_key = pem(ec.generate_private_key(ec.SECP384R1()).public_key())
        cls.encryption_key = pem(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())

    def setUp(self):
        self.request = {
            'contract_id': b64(hashlib.sha256(b'contract').digest()),
            'contract_metadata': {'verifying_key': self.verifying_key, 'encryption_key': self.encryption_key},
            'contract_code_metadata': {'code_hash': b64(hashlib.sha256(b'code').digest()), 'code_nonce': 'nonce'},
        }
        code = self.request['contract_code_metadata']
        self.request['ledger_attestation'] = {
            'pdo_contract_creator_pem_key': pem(self.ledger.public_key()),
            'contract_family': 'example.family',
            'storage_policy': '{"max_retention":30}',
            'contract_code_hash': b64(hashlib.sha256(
                base64.b64decode(code['code_hash']) + hashlib.sha256(code['code_nonce'].encode()).digest()
            ).digest()),
            'metadata_hash': b64(hashlib.sha256(
                base64.b64decode(self.request['contract_id']) + self.verifying_key.encode() + self.encryption_key.encode()
            ).digest()),
        }
        a = self.request['ledger_attestation']
        # Protocol vector for the repository's pinned PDO revision 6c07f678:
        # get_contract_info appends b64(SHA256(family)) and b64(SHA256(policy)).
        # Keep the expected digest bytes independent of the implementation under test.
        suffix = 'KK5p2/AIvXtT/cMD+EO/oOHU9FJerihycf0GVXdBGRM=DiQW4WmzFBKTbvCxQUTaF0JSOfniuyN2YhOKsEZtXwo='
        message = (self.request['contract_id'] + a['pdo_contract_creator_pem_key']
                   + a['contract_code_hash'] + a['metadata_hash'] + suffix).encode()
        a['signature'] = b64(self.ledger.sign(message, ec.ECDSA(hashes.SHA256())))
        self.key = LedgerKey(pem(self.ledger.public_key()))

    def test_valid_attestation(self):
        attestation.verify_endpoint_attestation(self.request, self.key)

    def test_each_bound_field_rejects_tampering(self):
        fields = (
            ('contract_id',), ('ledger_attestation', 'pdo_contract_creator_pem_key'),
            ('ledger_attestation', 'contract_code_hash'), ('ledger_attestation', 'metadata_hash'),
            ('ledger_attestation', 'signature'), ('ledger_attestation', 'contract_family'),
            ('ledger_attestation', 'storage_policy'), ('contract_metadata', 'verifying_key'),
            ('contract_metadata', 'encryption_key'), ('contract_code_metadata', 'code_hash'),
            ('contract_code_metadata', 'code_nonce'),
        )
        for path in fields:
            with self.subTest(path=path):
                request = copy.deepcopy(self.request)
                target = request if len(path) == 1 else request[path[0]]
                target[path[-1]] += 'tampered'
                with self.assertRaises((ValueError, TypeError)):
                    attestation.verify_endpoint_attestation(request, self.key)

    def test_family_policy_boundaries_cannot_shift(self):
        # Same concatenated text, different fields: their separate digests must bind.
        request = copy.deepcopy(self.request)
        info = request['ledger_attestation']
        info['contract_family'] = 'example.famil'
        info['storage_policy'] = 'y' + info['storage_policy']
        with self.assertRaises(ValueError):
            attestation.verify_endpoint_attestation(request, self.key)

    def test_signature_failure_codes_fail_closed(self):
        for result in (0, -1):
            with self.subTest(result=result), self.assertRaises(ValueError):
                attestation.verify_endpoint_attestation(
                    self.request, SimpleNamespace(VerifySignature=lambda *_: result)
                )

    def test_different_ledger_is_rejected(self):
        other_key = LedgerKey(pem(ec.generate_private_key(ec.SECP384R1()).public_key()))
        with self.assertRaises(ValueError):
            attestation.verify_endpoint_attestation(self.request, other_key)

    def test_request_policy_and_schema_before_registration(self):
        def validate(request, schema):
            return jsonschema.Draft7Validator(schema).is_valid(request)
        stubs = {
            'pdo.contracts.guardian.common.utility': SimpleNamespace(ValidateJSON=validate),
            'pdo.contracts.guardian.common.attestation': attestation,
            'pdo.common.wsgi': SimpleNamespace(
                UnpackJSONRequest=lambda e: e, ErrorResponse=lambda *_: ['rejected']
            ),
            'pdo.common': SimpleNamespace(crypto=SimpleNamespace(SIG_PublicKey=LedgerKey)),
        }
        with patch.dict(sys.modules, stubs):
            handler = load('guardian_add_endpoint', 'wsgi/add_endpoint.py')
            from unittest.mock import Mock
            registry = Mock()
            valid_config = {'TokenIssuer': {
                'LedgerKey': pem(self.ledger.public_key()), 'ContractIDs': [self.request['contract_id']],
            }}
            for config in ({}, {'TokenIssuer': {'LedgerKey': pem(self.ledger.public_key())}},
                           {'TokenIssuer': {'LedgerKey': pem(self.ledger.public_key()), 'ContractIDs': ['other']}}):
                self.assertEqual(handler.AddEndpointApp(config, None, registry)(self.request, Mock()), ['rejected'])
                registry.set_endpoint.assert_not_called()
            app = handler.AddEndpointApp(valid_config, None, registry)
            for field in ('signature', 'contract_family', 'storage_policy'):
                incomplete = copy.deepcopy(self.request)
                del incomplete['ledger_attestation'][field]
                self.assertEqual(app(incomplete, Mock()), ['rejected'])
            modified = copy.deepcopy(self.request)
            modified['contract_metadata']['encryption_key'] = self.verifying_key
            self.assertEqual(app(modified, Mock()), ['rejected'])
            registry.set_endpoint.assert_not_called()
            app(self.request, Mock())
            registry.set_endpoint.assert_called_once_with(self.request['contract_id'], self.verifying_key, self.encryption_key)

    def test_registry_rejects_key_replacement_and_invalid_keys(self):
        with patch.dict(sys.modules, {'pdo.common.keys': SimpleNamespace(EnclaveKeys=EndpointKeys)}):
            registry_module = load('guardian_endpoint_registry', 'common/endpoint_registry.py')
        with tempfile.TemporaryDirectory() as directory:
            registry = registry_module.EndpointRegistry(str(Path(directory) / 'endpoints'))
            try:
                registry.set_endpoint('contract', self.verifying_key, self.encryption_key)
                registry.set_endpoint('contract', self.verifying_key, self.encryption_key)
                with self.assertRaises(ValueError):
                    registry.set_endpoint('contract', self.encryption_key, self.verifying_key)
                with self.assertRaises(ValueError):
                    registry.set_endpoint('new-contract', 'invalid', self.encryption_key)
                self.assertNotIn('new-contract', registry._registry)
                self.assertEqual(registry._registry['contract'], (self.verifying_key, self.encryption_key))
            finally:
                registry.close()


if __name__ == '__main__':
    unittest.main()
