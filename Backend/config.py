
"""Central configuration for WAVS backend."""

import os
from pathlib import Path


# ==================================================
# PROJECT PATHS
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

DATABASE_PATH = Path(
    os.getenv(
        "WAVS_DATABASE",
        str(BASE_DIR / "database" / "scan_results.db"),
    )
).expanduser()

REPORT_DIR = BASE_DIR / "Reports" / "generated"


# ==================================================
# CONFIGURATION HELPERS
# ==================================================

def _get_int_env(name, default, minimum=1, maximum=None):
    """Read and validate an integer environment variable."""

    try:
        value = int(os.getenv(name, str(default)))

    except (TypeError, ValueError):
        value = default

    value = max(minimum, value)

    if maximum is not None:
        value = min(maximum, value)

    return value


def _get_float_env(name, default, minimum=0.1, maximum=None):
    """Read and validate a float environment variable."""

    try:
        value = float(os.getenv(name, str(default)))

    except (TypeError, ValueError):
        value = default

    if value <= 0:
        value = default

    value = max(minimum, value)

    if maximum is not None:
        value = min(maximum, value)

    return value


# ==================================================
# HTTP CONFIGURATION
# ==================================================

USER_AGENT = "WAVS/1.0 (authorized security assessment)"

REQUEST_TIMEOUT = _get_float_env(
    "WAVS_TIMEOUT",
    default=8.0,
    minimum=0.5,
    maximum=30.0,
)


# ==================================================
# SCANNER LIMITS
# ==================================================

MAX_CRAWL_PAGES = _get_int_env(
    "WAVS_MAX_PAGES",
    default=30,
    minimum=1,
    maximum=500,
)

MAX_SCAN_REQUESTS = _get_int_env(
    "WAVS_MAX_REQUESTS",
    default=120,
    minimum=1,
    maximum=5000,
)

MAX_PORTS = _get_int_env(
    "WAVS_MAX_PORTS",
    default=100,
    minimum=1,
    maximum=65535,
)


# ==================================================
# DEFAULT TCP PORTS
# ==================================================

DEFAULT_PORTS = [
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    3306,
    5432,
    8080,
    8443,
]


# ==================================================
# ALLOWED URL SCHEMES
# ==================================================

ALLOWED_SCHEMES = {
    "http",
    "https",
}
