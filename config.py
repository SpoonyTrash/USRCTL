from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "usrctl.log"

BACKUP_DIR = BASE_DIR / "backups"
DEFAULT_DRY_RUN = True