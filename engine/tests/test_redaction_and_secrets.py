from pathlib import Path
import tempfile

from boundaryx.security.redaction import RedactionEngine
from boundaryx.security.secrets import SecretStore


def test_redaction_engine_headers():
    redactor = RedactionEngine()
    headers = {
        "Host": "api.example.com",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDN",
        "Cookie": "session=abc123xyz; secure_token=supersecret",
        "X-Custom-Header": "Bearer secret_custom_token",
    }
    redacted = redactor.redact_headers(headers)
    assert redacted["Host"] == "api.example.com"
    assert "Bearer [REDACTED_TOKEN]" in redacted["Authorization"]
    assert redacted["Cookie"] == "[REDACTED]"
    assert "[REDACTED_TOKEN]" in redacted["X-Custom-Header"]


def test_redaction_engine_json_body():
    redactor = RedactionEngine()
    payload = {
        "username": "pentester",
        "password": "ClearTextPassword123!",
        "api_key": "AIzaSyFakeKey1234567890",
        "profile": {
            "access_token": "sk-12345678901234567890123456789012",
            "email": "user@target.com",
        },
    }
    redacted = redactor.redact_data(payload)
    assert redacted["username"] == "pentester"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["profile"]["access_token"] == "[REDACTED]"
    assert redacted["profile"]["email"] == "user@target.com"


def test_secret_store_encrypted_vault():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SecretStore(Path(tmpdir))

        store.store_secret("gemini", "api_key", "test-api-key-value-123")
        val = store.get_secret("gemini", "api_key")
        assert val == "test-api-key-value-123"

        # Check raw vault file on disk is encrypted, does not leak plain text
        raw_bytes = (Path(tmpdir) / "secrets.enc").read_bytes()
        assert b"test-api-key-value-123" not in raw_bytes

        # Delete
        assert store.delete_secret("gemini", "api_key") is True
        assert store.get_secret("gemini", "api_key") is None
