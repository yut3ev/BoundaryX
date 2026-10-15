"""HTTP Client module for BoundaryX security testing.

Provides thread-safe and async HTTP execution with token-bucket rate limiting,
strict scope validation, manual redirect enforcement, response size bounding,
and cancellation support.
"""

from __future__ import annotations

import asyncio
import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock, Semaphore
from typing import TYPE_CHECKING, Any

import httpx

from boundaryx.security.exceptions import ScopeViolationError

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


class RequestCancelledError(Exception):
    """Raised when an HTTP request operation is cancelled by the user or system."""


@dataclass
class HttpRequestConfig:
    """Configuration options for HTTP request execution."""

    timeout: float = 30.0
    connect_timeout: float = 10.0
    max_response_size: int = 10 * 1024 * 1024  # 10MB
    max_redirects: int = 5
    verify_tls: bool = True
    proxy_url: str | None = None
    rate_limit_rps: float = 5.0
    max_concurrency: int = 3
    follow_redirects: bool = False  # We handle redirects manually for scope checking
    extra_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class HttpResponse:
    """Encapsulates the result of an HTTP execution."""

    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str
    url: str
    redirected_from: str | None = None
    elapsed_ms: float = 0.0
    error: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert HttpResponse to dictionary."""
        return {
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "body": self.body,
            "content_type": self.content_type,
            "url": self.url,
            "redirected_from": self.redirected_from,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
            "truncated": self.truncated,
        }


class HttpClient:
    """Security-focused HTTP client using HTTPX.

    Guarantees:
    - Never follows redirects blindly (each redirect target must pass scope validation).
    - Respects max_response_size (truncates body and flags `truncated=True`).
    - Thread-safe token bucket rate limiting.
    - Concurrency bounding using semaphores.
    - TLS verification enabled by default.
    - Cancellation checks before and during execution hops.
    """

    def __init__(
        self,
        config: HttpRequestConfig | None = None,
        scope_checker: Callable[[str], tuple[bool, str] | bool] | None = None,
    ) -> None:
        """Initialize HttpClient with request configuration and scope validator.

        Args:
            config: HttpRequestConfig instance or default if None.
            scope_checker: Optional callable taking URL and returning either
                (is_in_scope: bool, reason: str) or is_in_scope: bool.
        """
        self.config = config or HttpRequestConfig()
        self.scope_checker = scope_checker

        self._cancelled = False
        self._lock = Lock()
        self._sync_semaphore = Semaphore(max(1, self.config.max_concurrency))
        self._async_semaphore: asyncio.Semaphore | None = None

        # Token bucket state
        self._rate_limit = max(0.1, float(self.config.rate_limit_rps))
        self._tokens = float(self._rate_limit)
        self._last_refill = time.monotonic()

        # Clients (lazily initialized)
        self._sync_client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None

    @property
    def is_cancelled(self) -> bool:
        """Return True if cancellation has been requested."""
        return self._cancelled

    def cancel(self) -> None:
        """Request cancellation of active and subsequent requests."""
        self._cancelled = True
        logger.info("HttpClient cancellation requested")

    def reset_cancel(self) -> None:
        """Reset the cancellation flag to resume normal execution."""
        self._cancelled = False

    def _check_scope(self, url: str) -> None:
        """Validate URL against scope_checker.

        Raises:
            ScopeViolationError: If URL is out of scope.
        """
        if self.scope_checker is None:
            return

        result = self.scope_checker(url)
        if isinstance(result, tuple):
            allowed, reason = result
        else:
            allowed = bool(result)
            reason = "Target URL rejected by scope checker"

        if not allowed:
            logger.warning("Scope violation detected for URL: %s (Reason: %s)", url, reason)
            raise ScopeViolationError(f"Scope violation for URL {url}: {reason}")

    def _apply_rate_limit(self) -> None:
        """Apply token bucket rate limiting synchronously."""
        while True:
            if self._cancelled:
                raise RequestCancelledError("Request cancelled prior to rate limit clearance")

            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._last_refill = now
                self._tokens = min(self._rate_limit, self._tokens + elapsed * self._rate_limit)

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Calculate sleep duration needed for 1 token
                sleep_needed = (1.0 - self._tokens) / self._rate_limit

            time.sleep(min(sleep_needed, 0.5))

    async def _apply_rate_limit_async(self) -> None:
        """Apply token bucket rate limiting asynchronously."""
        while True:
            if self._cancelled:
                raise RequestCancelledError("Request cancelled prior to rate limit clearance")

            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._last_refill = now
                self._tokens = min(self._rate_limit, self._tokens + elapsed * self._rate_limit)

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                sleep_needed = (1.0 - self._tokens) / self._rate_limit

            await asyncio.sleep(min(sleep_needed, 0.5))

    def _get_sync_client(self) -> httpx.Client:
        """Return or create thread-safe httpx Client."""
        with self._lock:
            if self._sync_client is None or self._sync_client.is_closed:
                timeout = httpx.Timeout(
                    self.config.timeout,
                    connect=self.config.connect_timeout,
                )
                self._sync_client = httpx.Client(
                    verify=self.config.verify_tls,
                    proxy=self.config.proxy_url,
                    timeout=timeout,
                    follow_redirects=False,
                )
            return self._sync_client

    async def _get_async_client(self) -> httpx.AsyncClient:
        """Return or create async httpx Client."""
        if self._async_semaphore is None:
            self._async_semaphore = asyncio.Semaphore(max(1, self.config.max_concurrency))

        if self._async_client is None or self._async_client.is_closed:
            timeout = httpx.Timeout(
                self.config.timeout,
                connect=self.config.connect_timeout,
            )
            self._async_client = httpx.AsyncClient(
                verify=self.config.verify_tls,
                proxy=self.config.proxy_url,
                timeout=timeout,
                follow_redirects=False,
            )
        return self._async_client

    def _merge_headers(
        self,
        headers: dict[str, str] | None = None,
        auth_headers: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Merge default headers, user headers, and authentication headers."""
        merged: dict[str, str] = {}
        merged.update(self.config.extra_headers)
        if headers:
            merged.update(headers)
        if auth_headers:
            merged.update(auth_headers)
        return merged

    def _process_response_body(
        self,
        raw_bytes: bytes,
        content_type: str,
    ) -> tuple[str, bool]:
        """Decode and safely bound response body.

        Returns:
            Tuple of (body_str, truncated_bool).
        """
        truncated = False
        if len(raw_bytes) > self.config.max_response_size:
            raw_bytes = raw_bytes[: self.config.max_response_size]
            truncated = True

        # Extract charset if available in content-type
        encoding = "utf-8"
        if "charset=" in content_type.lower():
            try:
                parts = content_type.lower().split("charset=")
                encoding = parts[-1].split(";")[0].strip().strip("\"'")
            except Exception:
                encoding = "utf-8"

        try:
            body = raw_bytes.decode(encoding, errors="replace")
        except Exception:
            body = raw_bytes.decode("utf-8", errors="replace")

        return body, truncated

    def send_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        auth_headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Send an HTTP request synchronously with scope validation and manual redirect handling.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.).
            url: Target URL string.
            headers: Optional request headers dictionary.
            body: Optional request payload string or bytes.
            auth_headers: Optional authentication headers to inject.

        Returns:
            HttpResponse object.

        Raises:
            ScopeViolationError: If target or redirect URL violates scope.
            RequestCancelledError: If request was cancelled.
        """
        if self._cancelled:
            raise RequestCancelledError("Request cancelled before start")

        self._check_scope(url)

        merged_headers = self._merge_headers(headers, auth_headers)
        current_method = method.upper()
        current_url = url
        current_body = body
        redirected_from: str | None = None
        redirect_count = 0

        client = self._get_sync_client()

        with self._sync_semaphore:
            start_total = time.monotonic()
            while True:
                if self._cancelled:
                    raise RequestCancelledError("Request cancelled during execution")

                # Validate scope on current URL hop
                self._check_scope(current_url)

                # Rate limiting
                self._apply_rate_limit()

                try:
                    req_content = current_body.encode("utf-8") if isinstance(current_body, str) else current_body
                    httpx_response = client.request(
                        method=current_method,
                        url=current_url,
                        headers=merged_headers,
                        content=req_content,
                    )
                    resp_headers = {k: v for k, v in httpx_response.headers.items()}
                    content_type = resp_headers.get("content-type", "")

                    # Check for redirects manually
                    status = httpx_response.status_code
                    if status in (301, 302, 303, 307, 308) and "location" in httpx_response.headers:
                        if redirect_count >= self.config.max_redirects:
                            logger.warning("Maximum redirects reached for %s", url)
                            body_str, truncated = self._process_response_body(httpx_response.content, content_type)
                            return HttpResponse(
                                status_code=status,
                                headers=resp_headers,
                                body=body_str,
                                content_type=content_type,
                                url=current_url,
                                redirected_from=redirected_from,
                                elapsed_ms=(time.monotonic() - start_total) * 1000.0,
                                truncated=truncated,
                            )

                        location = httpx_response.headers["location"]
                        next_url = urllib.parse.urljoin(current_url, location)

                        # Check scope of next redirect target URL BEFORE following
                        self._check_scope(next_url)

                        if redirected_from is None:
                            redirected_from = current_url

                        current_url = next_url
                        redirect_count += 1

                        # Adjust method and body for HTTP redirect conventions
                        if status == 303 or (status in (301, 302) and current_method != "GET"):
                            current_method = "GET"
                            current_body = None

                        continue

                    # Non-redirect response: extract body and return
                    body_str, truncated = self._process_response_body(httpx_response.content, content_type)

                    return HttpResponse(
                        status_code=status,
                        headers=resp_headers,
                        body=body_str,
                        content_type=content_type,
                        url=current_url,
                        redirected_from=redirected_from,
                        elapsed_ms=(time.monotonic() - start_total) * 1000.0,
                        truncated=truncated,
                    )

                except (ScopeViolationError, RequestCancelledError):
                    raise
                except httpx.TimeoutException as exc:
                    return HttpResponse(
                        status_code=0,
                        headers={},
                        body="",
                        content_type="",
                        url=current_url,
                        redirected_from=redirected_from,
                        elapsed_ms=(time.monotonic() - start_total) * 1000.0,
                        error=f"Request timeout: {exc}",
                    )
                except httpx.HTTPError as exc:
                    return HttpResponse(
                        status_code=0,
                        headers={},
                        body="",
                        content_type="",
                        url=current_url,
                        redirected_from=redirected_from,
                        elapsed_ms=(time.monotonic() - start_total) * 1000.0,
                        error=f"HTTP connection error: {exc}",
                    )
                except Exception as exc:
                    return HttpResponse(
                        status_code=0,
                        headers={},
                        body="",
                        content_type="",
                        url=current_url,
                        redirected_from=redirected_from,
                        elapsed_ms=(time.monotonic() - start_total) * 1000.0,
                        error=f"Unexpected request error: {exc}",
                    )

    async def send_request_async(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        auth_headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Send an HTTP request asynchronously with scope validation and manual redirect handling.

        Args:
            method: HTTP method.
            url: Target URL string.
            headers: Optional request headers.
            body: Optional request body.
            auth_headers: Optional authentication headers.

        Returns:
            HttpResponse object.

        Raises:
            ScopeViolationError: If target or redirect URL violates scope.
            RequestCancelledError: If request was cancelled.
        """
        if self._cancelled:
            raise RequestCancelledError("Request cancelled before start")

        self._check_scope(url)

        merged_headers = self._merge_headers(headers, auth_headers)
        current_method = method.upper()
        current_url = url
        current_body = body
        redirected_from: str | None = None
        redirect_count = 0

        client = await self._get_async_client()
        sem = self._async_semaphore or asyncio.Semaphore(max(1, self.config.max_concurrency))

        async with sem:
            start_total = time.monotonic()
            while True:
                if self._cancelled:
                    raise RequestCancelledError("Request cancelled during execution")

                # Validate scope on current URL hop
                self._check_scope(current_url)

                # Async rate limiting
                await self._apply_rate_limit_async()

                try:
                    req_content = current_body.encode("utf-8") if isinstance(current_body, str) else current_body
                    httpx_response = await client.request(
                        method=current_method,
                        url=current_url,
                        headers=merged_headers,
                        content=req_content,
                    )
                    resp_headers = {k: v for k, v in httpx_response.headers.items()}
                    content_type = resp_headers.get("content-type", "")

                    status = httpx_response.status_code
                    if status in (301, 302, 303, 307, 308) and "location" in httpx_response.headers:
                        if redirect_count >= self.config.max_redirects:
                            logger.warning("Maximum redirects reached for %s", url)
                            body_str, truncated = self._process_response_body(httpx_response.content, content_type)
                            return HttpResponse(
                                status_code=status,
                                headers=resp_headers,
                                body=body_str,
                                content_type=content_type,
                                url=current_url,
                                redirected_from=redirected_from,
                                elapsed_ms=(time.monotonic() - start_total) * 1000.0,
                                truncated=truncated,
                            )

                        location = httpx_response.headers["location"]
                        next_url = urllib.parse.urljoin(current_url, location)

                        # Scope check redirect URL
                        self._check_scope(next_url)

                        if redirected_from is None:
                            redirected_from = current_url

                        current_url = next_url
                        redirect_count += 1

                        if status == 303 or (status in (301, 302) and current_method != "GET"):
                            current_method = "GET"
                            current_body = None

                        continue

                    body_str, truncated = self._process_response_body(httpx_response.content, content_type)

                    return HttpResponse(
                        status_code=status,
                        headers=resp_headers,
                        body=body_str,
                        content_type=content_type,
                        url=current_url,
                        redirected_from=redirected_from,
                        elapsed_ms=(time.monotonic() - start_total) * 1000.0,
                        truncated=truncated,
                    )

                except (ScopeViolationError, RequestCancelledError):
                    raise
                except httpx.TimeoutException as exc:
                    return HttpResponse(
                        status_code=0,
                        headers={},
                        body="",
                        content_type="",
                        url=current_url,
                        redirected_from=redirected_from,
                        elapsed_ms=(time.monotonic() - start_total) * 1000.0,
                        error=f"Request timeout: {exc}",
                    )
                except httpx.HTTPError as exc:
                    return HttpResponse(
                        status_code=0,
                        headers={},
                        body="",
                        content_type="",
                        url=current_url,
                        redirected_from=redirected_from,
                        elapsed_ms=(time.monotonic() - start_total) * 1000.0,
                        error=f"HTTP connection error: {exc}",
                    )
                except Exception as exc:
                    return HttpResponse(
                        status_code=0,
                        headers={},
                        body="",
                        content_type="",
                        url=current_url,
                        redirected_from=redirected_from,
                        elapsed_ms=(time.monotonic() - start_total) * 1000.0,
                        error=f"Unexpected request error: {exc}",
                    )

    def close(self) -> None:
        """Close underlying HTTP clients and release resources."""
        with self._lock:
            if self._sync_client is not None and not self._sync_client.is_closed:
                self._sync_client.close()
                self._sync_client = None

    async def aclose(self) -> None:
        """Close underlying async HTTP client."""
        if self._async_client is not None and not self._async_client.is_closed:
            await self._async_client.aclose()
            self._async_client = None

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()
        self.close()
