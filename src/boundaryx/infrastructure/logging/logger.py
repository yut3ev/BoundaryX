"""Structured logging infrastructure and diagnostic bundle generator for BoundaryX."""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import sys
import tempfile
import zipfile
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from boundaryx.infrastructure.exports.report_exporter import ReportExporter

logger = logging.getLogger(__name__)

# Active log directory tracking
_ACTIVE_LOG_DIR: Path | None = None


class SecretFilter(logging.Filter):
    """Logging filter that scrubs tokens, passwords, authorization headers, and secrets."""

    PATTERNS = [
        # Bearer tokens
        (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.\+\/=]{10,}"), "Bearer [REDACTED]"),
        # Basic auth
        (re.compile(r"(?i)\bBasic\s+[A-Za-z0-9_\-\.\+\/=]{10,}"), "Basic [REDACTED]"),
        # JWT pattern
        (
            re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            "[REDACTED_JWT]",
        ),
        # Key-value secret patterns (e.g. password=..., api_key: "...")
        (
            re.compile(
                r"""(?i)(password|passwd|pwd|secret|token|api_key|access_token|client_secret)\s*[:=]\s*["']?([^"',\s&]+)["']?"""
            ),
            r"\1=[REDACTED]",
        ),
        # Session cookies
        (
            re.compile(r"(?i)(PHPSESSID|JSESSIONID|connect\.sid|session_id|sessionid)=([a-zA-Z0-9_\-\.]{10,})"),
            r"\1=[REDACTED]",
        ),
    ]

    def scrub(self, text: str) -> str:
        """Scrub known secret and token patterns from text."""
        if not text or not isinstance(text, str):
            return text
        result = text
        for pattern, repl in self.PATTERNS:
            result = pattern.sub(repl, result)
        return result

    def filter(self, record: logging.LogRecord) -> bool:
        """Scrub log record message and arguments in-place."""
        try:
            if record.args:
                # Format complete message first to avoid broken format placeholders
                formatted = record.getMessage()
                record.msg = self.scrub(formatted)
                record.args = ()
            elif isinstance(record.msg, str):
                record.msg = self.scrub(record.msg)
        except Exception:
            if isinstance(record.msg, str):
                record.msg = self.scrub(record.msg)

        return True


def setup_logging(
    log_dir: Path | str,
    level: str = "INFO",
    rotation: bool = True,
) -> None:
    """Configure application-wide structured logging with secret scrubbing.

    Args:
        log_dir: Directory where log files should be stored.
        level: Minimum log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        rotation: Whether to rotate log files when reaching maxBytes.
    """
    global _ACTIVE_LOG_DIR
    resolved_dir = Path(log_dir).resolve()
    resolved_dir.mkdir(parents=True, exist_ok=True)
    _ACTIVE_LOG_DIR = resolved_dir

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Clear existing handlers to prevent duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s:%(threadName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    secret_filter = SecretFilter()

    # 1. Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(secret_filter)
    root_logger.addHandler(console_handler)

    # 2. File handler
    log_file = resolved_dir / "boundaryx.log"
    if rotation:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8",
        )
    else:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")

    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(secret_filter)
    root_logger.addHandler(file_handler)

    logger.info("Structured logging initialized at %s with level %s", resolved_dir, level.upper())


def get_logger(name: str) -> logging.Logger:
    """Return a logger instance configured for BoundaryX."""
    return logging.getLogger(name)


class DiagnosticBundle:
    """Creates redacted diagnostic bundles for troubleshooting and support."""

    @classmethod
    def create_bundle(
        cls,
        output_path: Path | str,
        include_logs: bool = True,
        include_config: bool = True,
        app_info: dict[str, Any] | None = None,
    ) -> Path:
        """Create a compressed ZIP containing sanitized diagnostic data.

        Args:
            output_path: Target path for the diagnostic ZIP file.
            include_logs: Whether to include application log files.
            include_config: Whether to include non-sensitive configuration settings.
            app_info: Optional custom application status dictionary.

        Returns:
            Resolved output Path of the generated bundle.
        """
        target = ReportExporter._sanitize_path(output_path)
        if target.suffix.lower() != ".zip":
            target = target.with_suffix(".zip")

        scrubber = SecretFilter()

        system_details = {
            "timestamp": datetime.now(UTC).isoformat(),
            "os_name": os.name,
            "platform": sys.platform,
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "python_version": sys.version,
            "executable": sys.executable,
            "app_info": app_info or {},
        }

        with tempfile.TemporaryDirectory(prefix="boundaryx_diag_") as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)

            # Write system information
            with (tmp_dir / "system_info.json").open("w", encoding="utf-8") as f:
                json.dump(system_details, f, indent=2)

            # Write configuration if requested
            if include_config:
                try:
                    from boundaryx.config.settings import get_settings

                    settings = get_settings()
                    dump_settings = settings.model_dump(mode="json")
                    # Scrub proxy credentials or potential secrets
                    if dump_settings.get("proxy_url"):
                        dump_settings["proxy_url"] = scrubber.scrub(str(dump_settings["proxy_url"]))
                    with (tmp_dir / "config.json").open("w", encoding="utf-8") as f:
                        json.dump(dump_settings, f, indent=2, default=str)
                except Exception as exc:
                    with (tmp_dir / "config_error.txt").open("w", encoding="utf-8") as f:
                        f.write(f"Failed to dump settings: {exc}")

            # Collect logs if requested
            if include_logs and _ACTIVE_LOG_DIR and _ACTIVE_LOG_DIR.is_dir():
                logs_dir = tmp_dir / "logs"
                logs_dir.mkdir(parents=True, exist_ok=True)
                for log_file in _ACTIVE_LOG_DIR.glob("*.log*"):
                    if log_file.is_file():
                        try:
                            with log_file.open("r", encoding="utf-8", errors="replace") as f_in:
                                content = f_in.read()
                            scrubbed = scrubber.scrub(content)
                            with (logs_dir / log_file.name).open("w", encoding="utf-8") as f_out:
                                f_out.write(scrubbed)
                        except Exception as exc:
                            logger.warning("Could not include log file %s in bundle: %s", log_file, exc)

            # Package into ZIP archive
            with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zipf:
                for file_path in tmp_dir.rglob("*"):
                    if file_path.is_file():
                        archive_name = file_path.relative_to(tmp_dir).as_posix()
                        zipf.write(file_path, arcname=archive_name)

        logger.info("Diagnostic bundle created at %s", target)
        return target
