"""
log.py — Structured logging for the audit toolkit.

Provides a pre-configured logger that writes to both stderr (for terminal
output) and an optional log file. All modules should use:

    from lib.log import logger
    logger.info("message")

Log levels:
    DEBUG   — verbose detail (DNS queries, API responses)
    INFO    — progress updates (what the user sees)
    WARNING — non-fatal issues (zone not found, RDAP unavailable)
    ERROR   — failures that skip a domain or check
    CRITICAL — failures that abort the audit
"""

import logging
import sys

LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(message)s"
LOG_DATE   = "%H:%M:%S"

logger = logging.getLogger("cloudflare-reporting")


def setup_logging(verbose: bool = False, log_file: str = None) -> None:
    """Configure the root logger. Call once at startup."""
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    # Clear any existing handlers (prevents duplicate output on re-init)
    logger.handlers.clear()

    # Console handler (stderr)
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE))
    logger.addHandler(console)

    # Optional file handler
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)  # Always verbose in log file
        fh.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-8s  [%(module)s]  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(fh)
