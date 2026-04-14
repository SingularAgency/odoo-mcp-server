"""Logging configuration using Loguru."""

import os
import sys
from pathlib import Path
from typing import Optional
from loguru import logger


def setup_logging(log_file: Optional[str] = None) -> None:
    """Setup Loguru logging with stdout always enabled and optional file sink.

    In containerised / cloud environments (e.g. Hostinger Easy Deploy) the
    process runs as a non-root user and the log volume may be owned by root.
    We therefore attempt file logging but silently fall back to stdout-only
    when any permission problem is encountered.
    """
    log_level = os.environ.get("MCP_LOG_LEVEL", "INFO").upper()

    # Remove default handler
    logger.remove()

    # ── Stdout handler (always active) ──────────────────────────────────────
    logger.add(
        sys.stderr,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
        level=log_level,
        colorize=True,
    )

    # ── File handler (optional – skipped on any OS/permission error) ─────────
    try:
        log_path = Path("logs/odoo_mcp_server.log")
        log_path.parent.mkdir(parents=True, exist_ok=True)

        logger.add(
            log_path,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            level="DEBUG",
            rotation="10 MB",
            retention="7 days",
            compression="gz",
        )
    except Exception:
        # File logging is nice-to-have; stdout is enough in containers.
        pass


def get_logger(name: str):
    """Get a logger instance for the given name."""
    return logger.bind(name=name)


# Initialize logging on import
setup_logging()
