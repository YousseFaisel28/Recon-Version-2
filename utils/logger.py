"""
Centralized Logging Configuration for ReconX
=============================================
Provides a consistent logger factory for all modules.

Usage in any module:
    from utils.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Something happened")
"""

import os
import logging
import sys


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Format: [2026-04-08 12:00:00] [INFO] [module_name] Message
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging():
    """Configure root logger once at app startup."""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format=LOG_FORMAT,
        datefmt=DATE_FORMAT,
        stream=sys.stdout,
    )
    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("pymongo").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger with the app's log format."""
    return logging.getLogger(name)
