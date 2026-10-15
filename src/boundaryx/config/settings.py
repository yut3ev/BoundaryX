"""BoundaryX application configuration and settings.

Provides centralized Pydantic BaseSettings management, portable mode path resolution,
and persistence (load/save) from JSON configuration files.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Central configuration for BoundaryX desktop application.

    Supports environment variable overrides (prefixed with BOUNDARYX_),
    persistence to JSON configuration files, and path resolution for both
    installed (AppData) and portable runtime modes.
    """

    model_config = SettingsConfigDict(
        env_prefix="BOUNDARYX_",
        case_sensitive=False,
        extra="ignore",
        from_attributes=True,
    )

    # Application metadata
    app_name: str = Field(default="BoundaryX", description="Application display name")
    version: str = Field(default="0.1.0", description="Application version")

    # Storage and file paths
    db_path: Path = Field(
        default=Path("boundaryx.db"),
        description="Path to SQLite database file",
    )
    backup_dir: Path = Field(
        default=Path("backups"),
        description="Directory for automated project and database backups",
    )
    export_dir: Path = Field(
        default=Path("exports"),
        description="Directory for exported reports, findings, and evidence",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    log_dir: Path = Field(
        default=Path("logs"),
        description="Directory for application log files",
    )

    # UI Preferences
    theme: Literal["dark", "light"] = Field(
        default="dark",
        description="UI theme mode (dark or light)",
    )
    font_scale: float = Field(
        default=1.0,
        ge=0.7,
        le=2.0,
        description="UI font scale factor (0.7 to 2.0)",
    )
    table_density: Literal["compact", "normal", "spacious"] = Field(
        default="normal",
        description="Table row density in data views",
    )

    # Network & HTTP engine settings
    default_timeout: float = Field(
        default=30.0,
        gt=0,
        description="Default request timeout in seconds",
    )
    connection_timeout: float = Field(
        default=10.0,
        gt=0,
        description="Network connection establishment timeout in seconds",
    )
    max_response_size: int = Field(
        default=10 * 1024 * 1024,
        gt=0,
        description="Maximum response size to buffer in bytes (default 10MB)",
    )
    max_redirects: int = Field(
        default=5,
        ge=0,
        description="Maximum HTTP redirects to follow automatically",
    )
    rate_limit_rps: float = Field(
        default=20.0,
        gt=0,
        description="Maximum requests per second limit across worker threads",
    )
    max_concurrency: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum concurrent HTTP testing threads/tasks",
    )
    tls_verify: bool = Field(
        default=True,
        description="Whether to verify TLS certificates during active testing",
    )
    proxy_url: str | None = Field(
        default=None,
        description="Upstream HTTP/SOCKS proxy URL (e.g. http://127.0.0.1:8080)",
    )

    # Execution & analysis policy
    default_execution_mode: Literal["offline", "preview", "active"] = Field(
        default="preview",
        description="Default execution mode for authorization tests (offline, preview, active)",
    )
    autosave_interval: int = Field(
        default=60,
        ge=5,
        description="Interval in seconds between automated project state saves",
    )
    evidence_retention_days: int = Field(
        default=90,
        ge=1,
        description="Retention period in days for raw HTTP request/response evidence",
    )

    # Runtime mode
    portable_mode: bool = Field(
        default=False,
        description="When True, store all data/logs locally next to the executable/project",
    )

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        upper_val = value.strip().upper()
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if upper_val not in valid:
            raise ValueError(f"Invalid log_level '{value}'. Must be one of: {', '.join(sorted(valid))}")
        return upper_val

    @classmethod
    def get_app_data_dir(cls) -> Path:
        """Get the platform-appropriate user data directory for installed mode.

        On Windows: %APPDATA%/BoundaryX or ~/.boundaryx
        On Linux/macOS: ~/.boundaryx or XDG_DATA_HOME/BoundaryX
        """
        app_data = os.getenv("APPDATA")
        if app_data and sys.platform.startswith("win"):
            base = Path(app_data) / "BoundaryX"
        else:
            xdg_data = os.getenv("XDG_DATA_HOME")
            base = Path(xdg_data) / "boundaryx" if xdg_data else Path.home() / ".boundaryx"
        return base

    @classmethod
    def get_portable_base_dir(cls) -> Path:
        """Get the base directory for portable mode execution."""
        # Use executable directory if frozen, otherwise current working directory
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            return Path(sys.executable).parent.resolve()
        return Path.cwd().resolve()

    def get_base_dir(self) -> Path:
        """Return the effective base directory depending on portable_mode."""
        if self.portable_mode:
            return self.get_portable_base_dir()
        return self.get_app_data_dir()

    def resolve_path(self, target: Path | str) -> Path:
        """Resolve a file or directory path based on portable mode.

        If target is already an absolute path, it is returned normalized.
        If target is relative, it is resolved against either the portable base
        directory (if portable_mode is True) or the platform user app data
        directory (if portable_mode is False).
        """
        path = Path(target)
        if path.is_absolute():
            return path.resolve()
        base = self.get_base_dir()
        return (base / path).resolve()

    @property
    def resolved_db_path(self) -> Path:
        """Return the absolute, resolved path to the SQLite database."""
        return self.resolve_path(self.db_path)

    @property
    def resolved_backup_dir(self) -> Path:
        """Return the absolute, resolved path to the backup directory."""
        return self.resolve_path(self.backup_dir)

    @property
    def resolved_export_dir(self) -> Path:
        """Return the absolute, resolved path to the export directory."""
        return self.resolve_path(self.export_dir)

    @property
    def resolved_log_dir(self) -> Path:
        """Return the absolute, resolved path to the log directory."""
        return self.resolve_path(self.log_dir)

    def ensure_directories(self) -> None:
        """Create all required runtime directories if they do not already exist."""
        self.resolved_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.resolved_backup_dir.mkdir(parents=True, exist_ok=True)
        self.resolved_export_dir.mkdir(parents=True, exist_ok=True)
        self.resolved_log_dir.mkdir(parents=True, exist_ok=True)

    def save_to_file(self, file_path: Path | str) -> None:
        """Save settings to a JSON configuration file.

        Creates parent directories if necessary.
        """
        path = Path(file_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        dump_data = self.model_dump(mode="json")
        # Ensure Path fields are serialized to strings
        for key, value in dump_data.items():
            if isinstance(value, Path):
                dump_data[key] = str(value)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(dump_data, f, indent=2, sort_keys=True)

    @classmethod
    def load_from_file(cls, file_path: Path | str) -> AppSettings:
        """Load settings from a JSON configuration file.

        Raises FileNotFoundError if the target file does not exist.
        Raises ValueError if the JSON content is invalid or does not match schema.
        """
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(path, encoding="utf-8") as f:
            raw_data = json.load(f)

        if not isinstance(raw_data, dict):
            raise ValueError(f"Invalid JSON format in {path}: expected a dictionary root")

        return cls.model_validate(raw_data)


_settings_instance: AppSettings | None = None


def get_settings() -> AppSettings:
    """Return the global cached AppSettings instance or initialize a new default."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = AppSettings()
    return _settings_instance


def set_settings(settings: AppSettings) -> None:
    """Set the global AppSettings instance."""
    global _settings_instance
    _settings_instance = settings
