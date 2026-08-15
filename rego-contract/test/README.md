# Tests

- Legacy-style CLI test (useful for quick tests):
  - Script: `script_test.sh`
  - How to run:
    - Run the ledger and the services containers
    - Copy ledger root cert and services site.toml to the correct locations.
    - Run `TEST_LIST=^system-identity-script make -C ${PDO_CONTRACTS_ROOT} test`

- Setup-decoupled CLI test:
  - Script: `script_test_v2.sh`. It sources `setup_test.sh`. No auto-cleanup.
  - One can run `setup_test.sh` alone then run arbitrary commands then run `cleanup.sh`.
  - How to run:
    - Run the ledger and the services containers
    - Run a guardian
    - Generate keys
    - Export necessary env vars
    - Run `script_test_v2.sh`
    - Run `cleanup.sh`

- Python test:
  - Folder: `python`
