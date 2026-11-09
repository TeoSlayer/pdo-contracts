# Guardian endpoint registration

Endpoint registration requires both `TokenIssuer.LedgerKey` (the trusted ledger's
PEM public key, not a filename) and a nonempty `TokenIssuer.ContractIDs` allowlist.
The shipped empty configuration disables registration. Configure these out of band;
never trust a public key supplied by a registration request. `CodeHash` optionally
restricts the pre-nonce contract code hash in addition to the allowlist.

The request includes the unmodified `get_contract_info` response as
`ledger_attestation`, including `pdo_contract_creator_pem_key`. Its signature binds
contract ID, creator PEM, ledger code hash, and ledger metadata hash, followed by
base64-encoded SHA-256 digests of `contract_family` and the serialized `storage_policy`.
Both fields must be carried unchanged from the ledger response; do not parse and
reserialize the storage policy before verifying. This matches the pinned PDO
revision `6c07f678d1a13fef0302926b788e1d1f750a4c93`.
Code metadata is checked against the nonce-bound code hash. Endpoint public keys
are checked against the ledger metadata hash, which also binds the contract ID.
See the PDO ledger client's `get_contract_info` verification and the contract
attestation `add_endpoint` implementation for the corresponding wire format.

Identical re-registration is idempotent. Different keys for an existing contract
are rejected; key rotation requires an operator-controlled registry migration,
not an unauthenticated overwrite. Review existing registry entries before enabling
the hardened service: entries admitted by the previous implementation have not
been authenticated retroactively. Back up the database before replacing entries.

The isolated regression suite uses real ECDSA signatures and covers altered signed
fields, substituted keys/code metadata, missing trust configuration, missing schema
fields, invalid verification return codes, and overwrite prevention. Run:

```sh
python -m pip install cryptography jsonschema
python -m unittest discover -s tests -p test_guardian_registration.py
```

The native PDO crypto/WSGI adapters are replaced at the test import boundary.
A configured PDO/CCF deployment is still needed to verify the native integration.
