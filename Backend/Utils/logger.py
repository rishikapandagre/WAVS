
"""Centralized logging configuration for WAVS backend."""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


# ==================================================
# LOG DIRECTORY
# ==================================================

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"

LOG_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ==================================================
# LOGGER CONFIGURATION
# ==================================================

logger = logging.getLogger("WAVS")

logger.setLevel(logging.INFO)

# Prevent duplicate messages from propagating
# to the root logger.
logger.propagate = False


# ==================================================
# FILE HANDLER
# ==================================================

if not logger.handlers:

    handler = RotatingFileHandler(
        LOG_DIR / "wavs.log",
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    handler.setFormatter(formatter)

    logger.addHandler(handler)


# ==================================================
# CONSOLE HANDLER (OPTIONAL)
# ==================================================

if not any(
    isinstance(handler, logging.StreamHandler)
    and not isinstance(handler, RotatingFileHandler)
    for handler in logger.handlers
):

    console_handler = logging.StreamHandler()

    console_handler.setFormatter(
        logging.Formatter(
            "%(levelname)s | %(message)s"
        )
    )

    logger.addHandler(console_handler)
