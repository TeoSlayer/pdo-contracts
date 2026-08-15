import logging
import os
import shutil

from pdo.client.commands.eservice import do_eservice
from pdo.client.commands.pservice import do_pservice
from pdo.client.commands.service_db import do_service_db
from pdo.client.commands.sservice import do_sservice

from config import (
    F_SERVICE_SITE_FILE,
    LEDGER_CERT_PATH,
    PDO_HOME,
    PDO_LEDGER_KEY_ROOT,
    PREFERRED_ESERVICE_URL,
    SCRATCH_DIR,
    USER_KEYS_FOLDER,
    SITE_TOML_SOURCE,
)
from state import setup_pdo_state


def setup_pdo_local_databases(state, bindings):
    do_service_db(state, bindings, ["import", "--file", F_SERVICE_SITE_FILE])
    do_eservice(
        state,
        bindings,
        [
            "create_from_site",
            "--file",
            F_SERVICE_SITE_FILE,
            "--group",
            "default",
            "--preferred",
            PREFERRED_ESERVICE_URL,
        ],
    )
    do_pservice(
        state,
        bindings,
        ["create_from_site", "--file", F_SERVICE_SITE_FILE, "--group", "default"],
    )
    do_sservice(
        state,
        bindings,
        [
            "create_from_site",
            "--file",
            F_SERVICE_SITE_FILE,
            "--group",
            "default",
            "--replicas",
            "1",
            "--duration",
            "60",
        ],
    )


# -----------------------------------------------------------------
# Bootstrap files (replicates setup_test.sh:33-37, 91)
# -----------------------------------------------------------------
os.makedirs(SCRATCH_DIR, exist_ok=True)

os.makedirs(PDO_LEDGER_KEY_ROOT, exist_ok=True)
shutil.copy(LEDGER_CERT_PATH, PDO_LEDGER_KEY_ROOT)

os.makedirs(f"{PDO_HOME}/etc/sites", exist_ok=True)
shutil.copy(SITE_TOML_SOURCE, F_SERVICE_SITE_FILE)
# shutil.copy(f"{LEDGER_WS}/services/etc/site.toml", F_SERVICE_SITE_FILE)

os.makedirs(f"{PDO_HOME}/keys", exist_ok=True)
for _f in os.listdir(USER_KEYS_FOLDER):
    shutil.copy(os.path.join(USER_KEYS_FOLDER, _f), f"{PDO_HOME}/keys/")

logging.basicConfig(level=logging.WARNING, format="%(message)s")


# -----------------------------------------------------------------
# Bootstrap PDO local databases
# -----------------------------------------------------------------
state, bindings = setup_pdo_state()
setup_pdo_local_databases(state, bindings)
