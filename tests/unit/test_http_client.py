"""Unit tests for HttpClient, Scope checking, rate limiting, and response handling."""

import pytest

from boundaryx.infrastructure.http import (
    HttpClient,
    HttpRequestConfig,
    HttpResponse,
    RequestCancelledError,
    ScopeViolationError,
)


def test_http_request_config_defaults():
    config = HttpRequestConfig()
    assert config.timeout == 30.0
    assert config.connect_timeout == 10.0
    assert config.max_response_size == 10 * 1024 * 1024
    assert config.max_redirects == 5
    assert config.verify_tls is True
    assert config.rate_limit_rps == 5.0
    assert config.follow_redirects is False


def test_http_response_attributes():
    resp = HttpResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"status": "ok"}',
        content_type="application/json",
        url="https://api.target.com/test",
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"
    assert resp.body == '{"status": "ok"}'
    assert resp.truncated is False
    assert resp.error is None
    d = resp.to_dict()
    assert d["status_code"] == 200
    assert d["url"] == "https://api.target.com/test"


def test_http_client_scope_violation():
    def scope_checker(url: str):
        if "forbidden.com" in url:
            return False, "Target host is out of scope"
        return True, "Allowed"

    client = HttpClient(scope_checker=scope_checker)
    with pytest.raises(ScopeViolationError) as exc_info:
        client.send_request("GET", "https://forbidden.com/api/data")
    assert "out of scope" in str(exc_info.value)


def test_http_client_cancellation():
    client = HttpClient()
    assert client.is_cancelled is False

    client.cancel()
    assert client.is_cancelled is True

    with pytest.raises(RequestCancelledError):
        client.send_request("GET", "https://example.com")

    client.reset_cancel()
    assert client.is_cancelled is False


def test_http_client_response_truncation():
    config = HttpRequestConfig(max_response_size=20)
    client = HttpClient(config=config)

    long_body = b"A" * 100
    body_str, truncated = client._process_response_body(long_body, "text/plain")
    assert truncated is True
    assert len(body_str) == 20


def test_http_client_rate_limiter_sync():
    config = HttpRequestConfig(rate_limit_rps=50.0)
    client = HttpClient(config=config)
    # Applying rate limit multiple times should replenish and succeed without raising
    for _ in range(5):
        client._apply_rate_limit()


@pytest.mark.asyncio
async def test_http_client_rate_limiter_async():
    config = HttpRequestConfig(rate_limit_rps=50.0)
    client = HttpClient(config=config)
    for _ in range(5):
        await client._apply_rate_limit_async()


def test_http_client_connection_error_handling():
    # Attempting to connect to an invalid unroutable address should catch error and return HttpResponse with error field
    config = HttpRequestConfig(timeout=1.0, connect_timeout=1.0)
    client = HttpClient(config=config)
    resp = client.send_request("GET", "http://127.0.0.1:59999/unreachable")
    assert resp.status_code == 0
    assert resp.error is not None
