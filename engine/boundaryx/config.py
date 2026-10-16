import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional

import yaml

from boundaryx.security.redaction import RedactionEngine


def get_default_data_dir() -> Path:
    """Returns the default OS-specific application data directory."""
    if sys.platform == "win32":
        app_data = os.environ.get("LOCALAPPDATA")
        if app_data:
            base = Path(app_data)
        else:
            base = Path.home() / "AppData" / "Local"
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        # Linux / POSIX
        xdg_data = os.environ.get("XDG_DATA_HOME")
        if xdg_data:
            base = Path(xdg_data)
        else:
            base = Path.home() / ".local" / "share"

    data_dir = base / "BoundaryX"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


class RedactingFormatter(logging.Formatter):
    """Logging formatter that scrubs secrets from all log messages."""

    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None):
        super().__init__(fmt, datefmt)
        self.redactor = RedactionEngine()

    def format(self, record: logging.LogRecord) -> str:
        orig = super().format(record)
        return self.redactor.redact_text(orig)


def setup_engine_logging(log_dir: Path, log_level: int = logging.INFO) -> Path:
    """
    Sets up rotating file logger and stderr handler with secret redaction.
    STDOUT is intentionally NOT touched because it is reserved for IPC JSON messages.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "boundaryx_engine.log"

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear existing handlers
    root_logger.handlers.clear()

    formatter = RedactingFormatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotating file handler (10 MB max, 5 backups)
    file_handler = RotatingFileHandler(
        str(log_file),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # STDERR handler (safe for terminal, does not collide with STDOUT IPC)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    root_logger.addHandler(stderr_handler)

    return log_file


class AppConfig:
    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        self.config = config_dict or {}

    @classmethod
    def load_from_yaml(cls, yaml_path: Path) -> "AppConfig":
        if not yaml_path.exists():
            return cls({})
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return cls(data)
        except Exception:
            return cls({})
