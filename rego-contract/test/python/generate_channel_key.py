from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
import sys
import os


def generate_keys(out_dir):
    # Generate private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Get public key
    public_key = private_key.public_key()

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    os.makedirs(out_dir, exist_ok=True)
    public_key_path = os.path.join(out_dir, "public_key.pem")
    private_key_path = os.path.join(out_dir, "private_key.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    with open(public_key_path, "wb") as f:
        f.write(public_pem)
    return public_key_path, private_key_path


def generate_credential(public_pem_file, out_dir):
    with open(public_pem_file, "rb") as f:
        public_pem = f.read()
    cred = {
        "type": ["public_key"],
        "issuer": {"id": "A6QBclbcAayAvw7BggM7iMz_Xa6NEn_YGT94mpkQmEk="},
        "credentialSubject": {
            "subject": {"id": "SMeYjWc5IOdvI3KJtPbx4WHlRvkdL5A__xcHayDj9+0="},
            "claims": {"key": public_pem.decode()},
        },
        "name": "credential3",
        "description": "test credential",
    }
    output_path = os.path.join(out_dir, "credential_key.json")
    os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(cred, f, indent=4)
    return output_path


if __name__ == "__main__":
    out_dir = sys.argv[1]
    public_pem, _ = generate_keys(out_dir)
    generate_credential(public_pem, out_dir)
