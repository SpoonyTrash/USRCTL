from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "usrctl.log"
USE_SYSLOG = False

BACKUP_DIR = BASE_DIR / "backups"
DEFAULT_DRY_RUN = True

TEMPLATES_DIR = BASE_DIR / "templates"
TEMPLATE_USER_PATH = TEMPLATES_DIR / "user.conf.j2"
TEMPLATE_GROUP_PATH = TEMPLATES_DIR / "group.conf.j2"

LIMITS_D_DIR = Path("/etc/security/limits.d")