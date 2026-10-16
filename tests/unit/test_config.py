"""Unit tests for BoundaryX configuration and AppSettings."""

import json
from pathlib import Path

import pytest

from boundaryx.config.settings import AppSettings, get_settings, set_settings


def test_app_settings_defaults() -> None:
    """Test default values for AppSettings."""
    settings = AppSettings()
    assert settings.app_name == "BoundaryX"
    assert settings.version == "0.1.1"
    assert settings.log_level == "INFO"
    assert settings.theme == "dark"
    assert settings.font_scale == 1.0
    assert settings.table_density == "normal"
    assert settings.default_timeout == 30.0
    assert settings.connection_timeout == 10.0
    assert settings.max_response_size == 10 * 1024 * 1024
    assert settings.max_redirects == 5
    assert settings.rate_limit_rps == 20.0
    assert settings.max_concurrency == 10
    assert settings.tls_verify is True
    assert settings.proxy_url is None
    assert settings.default_execution_mode == "preview"
    assert settings.autosave_interval == 60
    assert settings.evidence_retention_days == 90
    assert settings.portable_mode is False


def test_app_settings_log_level_validation() -> None:
    """Test log level case-insensitivity and validation."""
    settings = AppSettings(log_level="debug")
    assert settings.log_level == "DEBUG"

    with pytest.raises(ValueError, match="Invalid log_level"):
        AppSettings(log_level="NONEXISTENT")


def test_app_settings_portable_mode_path_resolution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test path resolution differences between portable and installed modes."""
    # Portable mode resolves relative to portable base dir
    monkeypatch.chdir(tmp_path)
    portable_settings = AppSettings(
        portable_mode=True,
        db_path=Path("my_data.db"),
        backup_dir=Path("my_backups"),
    )
    resolved_db = portable_settings.resolved_db_path
    assert resolved_db == (tmp_path / "my_data.db").resolve()
    assert portable_settings.resolved_backup_dir == (tmp_path / "my_backups").resolve()

    # Absolute path should remain absolute in either mode
    abs_path = (tmp_path / "custom" / "custom.db").resolve()
    settings_abs = AppSettings(portable_mode=True, db_path=abs_path)
    assert settings_abs.resolved_db_path == abs_path


def test_app_settings_save_and_load(tmp_path: Path) -> None:
    """Test serializing AppSettings to JSON and reloading it."""
    config_file = tmp_path / "subdir" / "settings.json"
    original = AppSettings(
        app_name="BoundaryX Test",
        log_level="DEBUG",
        theme="light",
        font_scale=1.2,
        max_concurrency=25,
        proxy_url="http://127.0.0.1:8080",
        portable_mode=True,
    )

    original.save_to_file(config_file)
    assert config_file.exists()

    # Verify JSON structure
    with open(config_file, encoding="utf-8") as f:
        data = json.load(f)
    assert data["app_name"] == "BoundaryX Test"
    assert data["theme"] == "light"
    assert data["max_concurrency"] == 25
    assert data["proxy_url"] == "http://127.0.0.1:8080"
    assert data["portable_mode"] is True

    # Reload from file
    loaded = AppSettings.load_from_file(config_file)
    assert loaded.app_name == original.app_name
    assert loaded.log_level == original.log_level
    assert loaded.theme == original.theme
    assert loaded.font_scale == original.font_scale
    assert loaded.max_concurrency == original.max_concurrency
    assert loaded.proxy_url == original.proxy_url
    assert loaded.portable_mode == original.portable_mode


def test_app_settings_load_nonexistent_file(tmp_path: Path) -> None:
    """Test loading from a nonexistent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        AppSettings.load_from_file(tmp_path / "does_not_exist.json")


def test_app_settings_ensure_directories(tmp_path: Path) -> None:
    """Test that ensure_directories creates required directories."""
    settings = AppSettings(
        portable_mode=True,
        db_path=tmp_path / "test_data" / "boundaryx.db",
        backup_dir=tmp_path / "test_backups",
        export_dir=tmp_path / "test_exports",
        log_dir=tmp_path / "test_logs",
    )
    settings.ensure_directories()
    assert (tmp_path / "test_data").is_dir()
    assert (tmp_path / "test_backups").is_dir()
    assert (tmp_path / "test_exports").is_dir()
    assert (tmp_path / "test_logs").is_dir()


def test_get_and_set_settings() -> None:
    """Test global settings getter and setter functions."""
    custom = AppSettings(app_name="CustomBoundaryX")
    set_settings(custom)
    assert get_settings().app_name == "CustomBoundaryX"
