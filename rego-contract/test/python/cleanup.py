import shutil
from config import SCRATCH_DIR

shutil.rmtree(SCRATCH_DIR, ignore_errors=True)
