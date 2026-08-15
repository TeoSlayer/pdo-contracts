import os
import sys

from pdo.client.builder.shell import parse_shell_command_line

from config import (
    F_LOGFILE,
    F_LOGLEVEL,
    F_SERVICE_DB_FILE,
    F_SERVICE_GROUPS_DB_FILE,
    PDO_LEDGER_URL,
    SCRATCH_DIR,
)


def setup_pdo_state():
    _env = parse_shell_command_line(
        [
            "--logfile",
            F_LOGFILE,
            "--loglevel",
            F_LOGLEVEL,
            "--ledger",
            PDO_LEDGER_URL,
            "--groups-db",
            F_SERVICE_GROUPS_DB_FILE,
            "--service-db",
            F_SERVICE_DB_FILE,
            "--data-dir",
            SCRATCH_DIR,
        ]
    )
    if _env is None:
        sys.exit("failed to initialize PDO environment")

    state, bindings, _ = _env
    return state, bindings


def write_var(value, name):
    with open(os.path.join(SCRATCH_DIR, f"{name}.txt"), "w") as fp:
        fp.write(str(value))


def read_var(name):
    with open(os.path.join(SCRATCH_DIR, f"{name}.txt"), "r") as fp:
        return fp.read().strip()


# def load_site():
#     return toml.load(SITE_TOML_PATH)


# def get_ledger_config(state):
#     return state.get(["Ledger"])
