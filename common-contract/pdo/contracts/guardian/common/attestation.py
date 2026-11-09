"""Validate the CCF get_contract_info attestation and its endpoint bindings."""
import base64
import hashlib
import hmac


def verify_endpoint_attestation(request, ledger_key):
    """Raise ValueError unless the ledger authenticates every supplied endpoint field.

    The signed bytes follow PDO's CCF get_contract_info protocol, including the
    contract ID and creator PEM. Hashing follows contract::attestation::add_endpoint.
    ledger_key is a PDO SIG_PublicKey (VerifySignature returns 1 on success).
    """
    contract_id = request["contract_id"]
    attestation = request["ledger_attestation"]
    metadata = request["contract_metadata"]
    code = request["contract_code_metadata"]
    message = (
        contract_id + attestation["pdo_contract_creator_pem_key"]
        + attestation["contract_code_hash"] + attestation["metadata_hash"]
    ).encode("utf-8")
    signature = base64.b64decode(attestation["signature"], validate=True)
    if ledger_key.VerifySignature(message, signature) != 1:
        raise ValueError("invalid ledger signature")

    code_hash = base64.b64decode(code["code_hash"], validate=True)
    if len(code_hash) != hashlib.sha256().digest_size:
        raise ValueError("invalid code hash")
    nonce_hash = hashlib.sha256(code["code_nonce"].encode("utf-8")).digest()
    expected_code_hash = hashlib.sha256(code_hash + nonce_hash).digest()
    if not hmac.compare_digest(
        expected_code_hash, base64.b64decode(attestation["contract_code_hash"], validate=True)
    ):
        raise ValueError("code hash does not match ledger attestation")

    expected_metadata_hash = hashlib.sha256(
        base64.b64decode(contract_id, validate=True)
        + metadata["verifying_key"].encode("utf-8")
        + metadata["encryption_key"].encode("utf-8")
    ).digest()
    if not hmac.compare_digest(
        expected_metadata_hash, base64.b64decode(attestation["metadata_hash"], validate=True)
    ):
        raise ValueError("endpoint keys do not match ledger attestation")
