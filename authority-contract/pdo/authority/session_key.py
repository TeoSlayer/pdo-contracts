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

# Client-side helpers for an external session key that gets bound to a wallet by
# the external_key_authority. The signing scheme here must match what the contract
# verifies: RSASSA-PKCS1-v1_5 over SHA-256 (RSAPublicKey::VerifySignature).

import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_PRIVATE = "session_rsa_private.pem"
RSA_PUBLIC = "session_rsa_public.pem"


def generate_rsa_keypair(out_dir):
    """Generate the external RSA key pair and write it to out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(os.path.join(out_dir, RSA_PRIVATE), "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    with open(os.path.join(out_dir, RSA_PUBLIC), "wb") as f:
        f.write(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))


def load_public_pem(out_dir):
    with open(os.path.join(out_dir, RSA_PUBLIC), "r") as f:
        return f.read()


def _load_private(out_dir):
    with open(os.path.join(out_dir, RSA_PRIVATE), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def build_payload(wallet_did, session_public_pem):
    """The binding payload both the wallet and the session key sign. It is a plain
    string so signing and verifying happen over identical bytes."""
    return json.dumps({"identity": wallet_did, "session_key": session_public_pem})


def sign_payload_b64(out_dir, payload):
    """Sign the payload with the external RSA private key and return the base64
    signature (RSASSA-PKCS1-v1_5 / SHA-256)."""
    signature = _load_private(out_dir).sign(payload.encode(), padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode()
