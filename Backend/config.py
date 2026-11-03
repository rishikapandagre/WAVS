
"""Central configuration for WAVS backend."""

import os
from pathlib import Path

from dotenv import load_dotenv


# ==================================================
# PROJECT PATHS
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from the project root.
load_dotenv(BASE_DIR.parent / ".env")

DATABASE_PATH = Path(
    os.getenv(
        "WAVS_DATABASE",
        str(BASE_DIR / "database" / "scan_results.db"),
    )
).expanduser().resolve()

REPORT_DIR = Path(
    os.getenv(
        "WAVS_REPORT_DIR",
        str(BASE_DIR / "Reports" / "generated"),
    )
).expanduser().resolve()


# ==================================================
# CONFIGURATION HELPERS
# ==================================================

def _get_int_env(
    name,
    default,
    minimum=1,
    maximum=None,
):
    """Read and validate an integer environment variable."""

    raw_value = os.getenv(name)

    if raw_value is None:
        value = default

    else:
        try:
            value = int(raw_value.strip())

        except (TypeError, ValueError):
            value = default

    value = max(minimum, value)

    if maximum is not None:
        value = min(maximum, value)

    return value


def _get_float_env(
    name,
    default,
    minimum=0.1,
    maximum=None,
):
    """Read and validate a float environment variable."""

    raw_value = os.getenv(name)

    if raw_value is None:
        value = default

    else:
        try:
            value = float(raw_value.strip())

        except (TypeError, ValueError):
            value = default

    if not 0 < value < float("inf"):
        value = default

    value = max(minimum, value)

    if maximum is not None:
        value = min(maximum, value)

    return value


def _get_bool_env(name, default=False):
    """Read a boolean environment variable."""

    raw_value = os.getenv(name)

    if raw_value is None:
        return default

    return raw_value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _get_list_env(name, default=None):
    """Read a comma-separated environment variable."""

    raw_value = os.getenv(name)

    if not raw_value:
        return default or []

    return [
        item.strip()
        for item in raw_value.split(",")
        if item.strip()
    ]


# ==================================================
# APPLICATION CONFIGURATION
# ==================================================

APP_NAME = os.getenv(
    "WAVS_APP_NAME",
    "WAVS - Web Application Vulnerability Scanner",
)

APP_VERSION = os.getenv(
    "WAVS_VERSION",
    "1.0.0",
)

DEBUG = _get_bool_env(
    "FLASK_DEBUG",
    default=False,
)

TESTING = _get_bool_env(
    "FLASK_TESTING",
    default=False,
)

HOST = os.getenv(
    "HOST",
    "127.0.0.1",
)

PORT = _get_int_env(
    "PORT",
    default=5000,
    minimum=1,
    maximum=65535,
)


# ==================================================
# SECURITY CONFIGURATION
# ==================================================

SECRET_KEY = os.getenv(
    "WAVS_SECRET_KEY",
    "dev-only-change-this-secret",
)

MAX_CONTENT_LENGTH = _get_int_env(
    "MAX_CONTENT_LENGTH",
    default=1 * 1024 * 1024,
    minimum=1024,
    maximum=10 * 1024 * 1024,
)

CORS_ORIGINS = _get_list_env(
    "CORS_ORIGINS",
    default=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
)


# ==================================================
# HTTP CONFIGURATION
# ==================================================

USER_AGENT = os.getenv(
    "WAVS_USER_AGENT",
    "WAVS/1.0 (authorized security assessment)",
)

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

MAX_CONCURRENT_REQUESTS = _get_int_env(
    "WAVS_CONCURRENCY",
    default=5,
    minimum=1,
    maximum=50,
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
