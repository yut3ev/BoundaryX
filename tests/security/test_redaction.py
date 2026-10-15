"""Tests for RedactionEngine data sanitization and rule processing."""

import json

from boundaryx.security.redaction import RedactionEngine, RedactionRule


def test_default_rules_exist() -> None:
    engine = RedactionEngine()
    rules = engine.get_rules()
    names = {r.name for r in rules}

    assert "authorization_header" in names
    assert "cookie_header" in names
    assert "set_cookie_header" in names
    assert "x_api_key_header" in names
    assert "password_field" in names
    assert "bearer_token" in names


def test_redact_headers() -> None:
    engine = RedactionEngine()
    headers = {
        "Authorization": "Bearer eyJhbGciOi...",
        "Cookie": "sessionid=xyz123; theme=dark",
        "Set-Cookie": "sessionid=deleted; Secure",
        "X-API-Key": "my-secret-key-12345",
        "Content-Type": "application/json",
        "X-Custom-Header": "harmless_value",
    }

    sanitized = engine.redact_headers(headers)

    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["Cookie"] == "[REDACTED]"
    assert sanitized["Set-Cookie"] == "[REDACTED]"
    assert sanitized["X-API-Key"] == "[REDACTED]"
    assert sanitized["Content-Type"] == "application/json"
    assert sanitized["X-Custom-Header"] == "harmless_value"


def test_redact_headers_bearer_in_custom_header() -> None:
    engine = RedactionEngine()
    headers = {
        "X-Forwarded-Auth": "Bearer secret_jwt_token_value_abc",
        "Accept": "*/*",
    }
    sanitized = engine.redact_headers(headers)
    assert sanitized["X-Forwarded-Auth"] == "Bearer [REDACTED]"
    assert sanitized["Accept"] == "*/*"


def test_redact_body_json() -> None:
    engine = RedactionEngine()
    payload = {
        "username": "admin",
        "password": "SuperSecretPassword123!",
        "token": "tok_99887766",
        "nested": {
            "secret": "top_secret_data",
            "public_key": "pub_key_123",
            "notes": "User logged in with Bearer my_token_456",
        },
    }
    raw_json = json.dumps(payload)

    sanitized_str = engine.redact_body(raw_json, content_type="application/json")
    sanitized = json.loads(sanitized_str)

    assert sanitized["username"] == "admin"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["token"] == "[REDACTED]"
    assert sanitized["nested"]["secret"] == "[REDACTED]"
    assert sanitized["nested"]["public_key"] == "pub_key_123"
    assert "Bearer [REDACTED]" in sanitized["nested"]["notes"]


def test_redact_body_form_urlencoded() -> None:
    engine = RedactionEngine()
    form_data = "username=admin&password=my_password_xyz&client_id=12345"

    sanitized = engine.redact_body(form_data, content_type="application/x-www-form-urlencoded")
    assert "password=%5BREDACTED%5D" in sanitized or "password=[REDACTED]" in sanitized
    assert "username=admin" in sanitized
    assert "my_password_xyz" not in sanitized


def test_redact_url() -> None:
    engine = RedactionEngine()

    # Embedded credentials
    url_with_creds = "https://alice:secret_pass@example.com/api"
    sanitized = engine.redact_url(url_with_creds)
    assert "secret_pass" not in sanitized
    assert "[REDACTED]:[REDACTED]" in sanitized

    # Query parameters
    url_with_params = "https://example.com/api?user=john&token=tok_abc123&session_id=sess_456&page=2"
    sanitized_params = engine.redact_url(url_with_params)
    assert "tok_abc123" not in sanitized_params
    assert "sess_456" not in sanitized_params
    assert "user=john" in sanitized_params
    assert "page=2" in sanitized_params


def test_redact_evidence() -> None:
    engine = RedactionEngine()
    evidence = {
        "request_url": "https://admin:pass@example.com/v1/auth?token=my_secret_token",
        "headers": {
            "Authorization": "Bearer abc.def.ghi",
            "Cookie": "PHPSESSID=session1234567890123456",
        },
        "response_body": json.dumps(
            {
                "status": "ok",
                "access_token": "bearer_secret_xyz",
                "expires_in": 3600,
            }
        ),
        "content_type": "application/json",
        "custom_secret": "my_confidential_value",
    }

    # Add a custom rule for custom_secret field
    engine.add_rule(RedactionRule("custom_secret_field", "field_name", "custom_secret"))

    sanitized = engine.redact_evidence(evidence)

    assert "pass" not in sanitized["request_url"]
    assert "my_secret_token" not in sanitized["request_url"]
    assert sanitized["headers"]["Authorization"] == "[REDACTED]"
    assert sanitized["headers"]["Cookie"] == "[REDACTED]"
    assert sanitized["custom_secret"] == "[REDACTED]"

    parsed_body = json.loads(sanitized["response_body"])
    assert parsed_body["access_token"] == "[REDACTED]"
    assert parsed_body["expires_in"] == 3600


def test_preview_redaction() -> None:
    engine = RedactionEngine()
    data = {
        "headers": {
            "Authorization": "Bearer secret123",
        },
        "body": '{"password": "secret_password"}',
    }

    preview = engine.preview_redaction(data)
    assert preview["redactions_found"] >= 1
    assert "original" in preview
    assert preview["original"]["headers"]["Authorization"] == "Bearer secret123"
    assert preview["preview"]["headers"]["Authorization"] == "[REDACTED]"


def test_rule_management() -> None:
    engine = RedactionEngine(rules=[])
    assert len(engine.get_rules()) == 0

    rule = RedactionRule("custom_token", "regex", r"\bXYZ_[0-9]+\b", replacement="[XYZ_MASKED]")
    engine.add_rule(rule)
    assert len(engine.get_rules()) == 1

    text = "Found secret XYZ_123456 here"
    assert engine.redact_body(text) == "Found secret [XYZ_MASKED] here"

    # Disable rule
    assert engine.disable_rule("custom_token") is True
    assert engine.redact_body(text) == text

    # Re-enable rule
    assert engine.enable_rule("custom_token") is True
    assert engine.redact_body(text) == "Found secret [XYZ_MASKED] here"

    # Remove rule
    assert engine.remove_rule("custom_token") is True
    assert len(engine.get_rules()) == 0
    assert engine.redact_body(text) == text
