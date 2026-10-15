"""Unit tests for NormalizationEngine and NormalizationConfig."""

from boundaryx.application.analysis.normalization import NormalizationConfig, NormalizationEngine


def test_normalize_json_sorting() -> None:
    engine = NormalizationEngine()
    raw = '{"z": 1, "a": {"c": 3, "b": 2}}'
    normalized = engine.normalize_json(raw)
    expected_order = '{\n  "a": {\n    "b": 2,\n    "c": 3\n  },\n  "z": 1\n}'
    assert normalized == expected_order


def test_normalize_response_headers_and_body() -> None:
    engine = NormalizationEngine()
    response = {
        "status_code": 200,
        "headers": {
            "Date": "Wed, 21 Oct 2026 07:28:00 GMT",
            "X-Request-Id": "123e4567-e89b-12d3-a456-426614174000",
            "Set-Cookie": "session=secret_123; Path=/",
            "Authorization": "Bearer my-secret-token",
            "Content-Type": "application/json",
        },
        "body": '{"created_at": "2026-10-15T12:00:00Z", "trace_id": "123e4567-e89b-12d3-a456-426614174000", "role": "admin"}',
    }

    norm = engine.normalize_response(response)

    # Ignored headers stripped
    assert "Date" not in norm["headers"]
    assert "X-Request-Id" not in norm["headers"]
    assert "Set-Cookie" not in norm["headers"]

    # Token masked in headers
    assert norm["headers"]["Authorization"] == "<TOKEN_MASKED>"
    assert norm["headers"]["Content-Type"] == "application/json"

    # Body values normalized
    assert "<TIMESTAMP_NORMALIZED>" in norm["body"]
    assert "<UUID_NORMALIZED>" in norm["body"]
    assert '"role": "admin"' in norm["body"]


def test_diff_responses_status_and_body() -> None:
    engine = NormalizationEngine()
    resp_a = {
        "status_code": 200,
        "headers": {"Content-Type": "application/json"},
        "body": '{"user": {"name": "Alice", "role": "admin"}}',
    }
    resp_b = {
        "status_code": 403,
        "headers": {"Content-Type": "application/json"},
        "body": '{"user": {"name": "Alice", "role": "user"}}',
    }

    diffs = engine.diff_responses(resp_a, resp_b)
    fields = [d["field"] for d in diffs]
    assert "status_code" in fields
    assert "body.user.role" in fields

    role_diff = next(d for d in diffs if d["field"] == "body.user.role")
    assert role_diff["value_a"] == "admin"
    assert role_diff["value_b"] == "user"
    assert role_diff["difference_type"] == "VALUE_MISMATCH"


def test_diff_responses_identical_after_normalization() -> None:
    engine = NormalizationEngine()
    resp_a = {
        "status_code": 200,
        "headers": {
            "Date": "Wed, 21 Oct 2026 07:28:00 GMT",
            "Content-Type": "application/json",
        },
        "body": '{"timestamp": "2026-10-15T10:00:00Z", "count": 5}',
    }
    resp_b = {
        "status_code": 200,
        "headers": {
            "Date": "Wed, 21 Oct 2026 09:30:00 GMT",
            "Content-Type": "application/json",
        },
        "body": '{"count": 5, "timestamp": "2026-10-15T11:45:00Z"}',
    }

    diffs = engine.diff_responses(resp_a, resp_b)
    assert len(diffs) == 0


def test_diff_responses_compare_fields_restriction() -> None:
    engine = NormalizationEngine()
    resp_a = {"status_code": 200, "headers": {"X-Custom": "A"}, "body": "Same"}
    resp_b = {"status_code": 500, "headers": {"X-Custom": "B"}, "body": "Same"}

    config = NormalizationConfig(compare_fields=["body"])
    diffs = engine.diff_responses(resp_a, resp_b, config=config)
    assert len(diffs) == 0
