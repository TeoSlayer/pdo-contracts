import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# -----------------------------------------------------------------
# Required environment variables (mirrors setup_test.sh)
# -----------------------------------------------------------------
required_env_vars = [
    "LEDGER_CERT_PATH",
    "SITE_TOML_SOURCE",
    "PDO_LEDGER_URL",
    "F_SERVICE_HOST",
    "USER_KEYS_FOLDER",
    "PDO_INSTALL_ROOT",
    "GUARDIAN_URL",
]
for var in required_env_vars:
    if var not in os.environ:
        raise Exception(f"{var} environment variable is required")

# -----------------------------------------------------------------
# Defaults for environment variables our helpers depend on
# -----------------------------------------------------------------

os.environ["PDO_HOME"] = f"{os.environ['PDO_INSTALL_ROOT']}/opt/pdo"
os.environ["PDO_LEDGER_KEY_ROOT"] = f"{os.environ['PDO_HOME']}/etc/keys/ledger"
os.environ["PDO_LEDGER_TYPE"] = "ccf"


# -----------------------------------------------------------------
# Paths and runtime config
# -----------------------------------------------------------------
PDO_HOME = os.environ["PDO_HOME"]
PDO_LEDGER_KEY_ROOT = os.environ["PDO_LEDGER_KEY_ROOT"]
PDO_LEDGER_URL = os.environ["PDO_LEDGER_URL"]
F_SERVICE_HOST = os.environ["F_SERVICE_HOST"]
LEDGER_CERT_PATH = os.environ["LEDGER_CERT_PATH"]
SITE_TOML_SOURCE = os.environ["SITE_TOML_SOURCE"]
USER_KEYS_FOLDER = os.environ["USER_KEYS_FOLDER"]

SCRATCH_DIR = f"{SCRIPT_DIR}/scratch"

F_SERVICE_SITE_FILE = f"{PDO_HOME}/etc/sites/{F_SERVICE_HOST}.toml"
F_SERVICE_GROUPS_DB_FILE = f"{SCRATCH_DIR}/groups_db"
F_SERVICE_DB_FILE = f"{SCRATCH_DIR}/service_db"
F_LOGFILE = os.environ.get("PDO_LOG_FILE", "__screen__")
F_LOGLEVEL = os.environ.get("PDO_LOG_LEVEL", "warn")


# -----------------------------------------------------------------
# CLI knobs
# -----------------------------------------------------------------
PREFERRED_ESERVICE_URL = os.environ.get("PREFERRED_ESERVICE_URL", "random")
GUARDIAN_URL = os.environ["GUARDIAN_URL"]
