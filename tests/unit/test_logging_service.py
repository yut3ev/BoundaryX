"""Unit tests for structured logging, SecretFilter, and DiagnosticBundle."""

import json
import logging
import zipfile
from pathlib import Path

from boundaryx.infrastructure.logging import (
    DiagnosticBundle,
    SecretFilter,
    get_logger,
    setup_logging,
)


def test_secret_filter_scrubs_sensitive_strings():
    filter_obj = SecretFilter()

    # Bearer token
    assert (
        filter_obj.scrub("Authorization: Bearer my-secret-jwt-token-value-12345") == "Authorization: Bearer [REDACTED]"
    )

    # Basic auth
    assert filter_obj.scrub("Auth: Basic dXNlcjpwYXNzd29yZDEyMzQ1") == "Auth: Basic [REDACTED]"

    # Password key-value
    assert "password=[REDACTED]" in filter_obj.scrub("Connecting with password=SuperSecretPassword123!")

    # JWT
    jwt_sample = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4B_TEST_SIGNATURE_DATA"
    assert filter_obj.scrub(f"Received JWT {jwt_sample}") == "Received JWT [REDACTED_JWT]"


def test_secret_filter_log_record():
    filter_obj = SecretFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Login with password=%s",
        args=("MySecretPass123",),
        exc_info=None,
    )
    filter_obj.filter(record)
    # Args should be scrubbed
    formatted = record.getMessage()
    assert "MySecretPass123" not in formatted
    assert "[REDACTED]" in formatted


def test_setup_logging_and_file_creation(tmp_path: Path):
    log_dir = tmp_path / "logs"
    setup_logging(log_dir=log_dir, level="DEBUG", rotation=True)

    test_logger = get_logger("boundaryx.test_logger")
    test_logger.info("Test log entry with token=SuperSecret123")

    log_file = log_dir / "boundaryx.log"
    assert log_file.exists()

    content = log_file.read_text(encoding="utf-8")
    assert "Test log entry with token=[REDACTED]" in content
    assert "SuperSecret123" not in content


def test_diagnostic_bundle_generation(tmp_path: Path):
    log_dir = tmp_path / "logs"
    setup_logging(log_dir=log_dir, level="INFO")
    test_logger = get_logger("test")
    test_logger.info("Diagnostic log line")

    bundle_path = tmp_path / "diag.zip"
    created = DiagnosticBundle.create_bundle(
        output_path=bundle_path,
        include_logs=True,
        include_config=True,
        app_info={"custom_status": "ok"},
    )
    assert created.exists()

    with zipfile.ZipFile(created, "r") as z:
        names = z.namelist()
        assert "system_info.json" in names
        assert "config.json" in names
        info = json.loads(z.read("system_info.json").decode("utf-8"))
        assert info["app_info"]["custom_status"] == "ok"
