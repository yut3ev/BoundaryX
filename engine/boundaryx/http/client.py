"""Hardened HTTP client with engine-level scope enforcement and redirect validation."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.parse
import urllib.request

from boundaryx.domain.models import ScopeRule
from boundaryx.scope.guard import ScopeGuard

logger = logging.getLogger(__name__)


class ScopeDenialError(Exception):
    """Raised when an HTTP request or redirect violates the program scope guard."""
    pass


class HardenedHttpResponse:
    """Represents a sanitized HTTP response."""

    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: bytes,
        url: str,
    ) -> None:
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.url = url

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class HardenedHttpClient:
    """
    HTTP client that strictly validates scope at the engine level before dispatching
    any packet. Intercepts every redirect hop to prevent open redirect and SSRF escapes.
    """

    def __init__(
        self,
        scope_rules: List[ScopeRule],
        timeout: float = 10.0,
        max_redirects: int = 5,
        verify_tls: bool = True,
        user_agent: str = "BoundaryX-Security-Engine/1.0",
    ) -> None:
        self.guard = ScopeGuard(scope_rules)
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.verify_tls = verify_tls
        self.user_agent = user_agent

    def validate_url_in_scope(self, url: str) -> None:
        """Validates that a URL is in scope. Raises ScopeDenialError if blocked."""
        decision = self.guard.validate_target(url)
        if not decision.is_in_scope:
            reason = decision.denial_reason or "Target out of scope"
            raise ScopeDenialError(f"Request blocked by engine ScopeGuard: {reason}")

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        follow_redirects: bool = True,
    ) -> HardenedHttpResponse:
        """Executes an HTTP request with mandatory scope check on initial request and every redirect hop."""
        current_url = url
        self.validate_url_in_scope(current_url)

        req_headers = dict(headers or {})
        if "User-Agent" not in req_headers:
            req_headers["User-Agent"] = self.user_agent

        redirect_count = 0

        # Custom handler or loop to track redirects
        while True:
            parsed = urllib.parse.urlparse(current_url)
            if parsed.scheme not in ("http", "https"):
                raise ScopeDenialError(f"Unsupported scheme: {parsed.scheme}")

            req = urllib.request.Request(
                url=current_url,
                data=data if (method.upper() in ("POST", "PUT", "PATCH") and redirect_count == 0) else None,
                headers=req_headers,
                method=method.upper() if redirect_count == 0 else "GET",
            )

            # Use Opener with redirect handling disabled so we manually inspect each hop
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            opener = urllib.request.build_opener(NoRedirectHandler)

            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    resp_headers = dict(resp.headers.items())
                    body = resp.read()
                    return HardenedHttpResponse(
                        status_code=resp.status,
                        headers=resp_headers,
                        body=body,
                        url=current_url,
                    )
            except urllib.error.HTTPError as e:
                # Check if it's a redirect (301, 302, 303, 307, 308)
                if e.code in (301, 302, 303, 307, 308) and follow_redirects:
                    if redirect_count >= self.max_redirects:
                        raise ScopeDenialError(f"Too many redirects (exceeded limit of {self.max_redirects})")

                    location = e.headers.get("Location")
                    if not location:
                        raise ScopeDenialError("Redirect response missing Location header")

                    # Handle relative redirects
                    next_url = urllib.parse.urljoin(current_url, location)

                    # Validate redirect hop against scope guard
                    hop_decision = self.guard.validate_redirect(current_url, next_url)
                    if not hop_decision.is_in_scope:
                        reason = hop_decision.denial_reason or "Redirect target out of scope"
                        raise ScopeDenialError(f"Request blocked by engine ScopeGuard: {reason}")

                    current_url = next_url
                    redirect_count += 1
                    continue
                else:
                    resp_headers = dict(e.headers.items()) if e.headers else {}
                    body = e.read() if hasattr(e, "read") else b""
                    return HardenedHttpResponse(
                        status_code=e.code,
                        headers=resp_headers,
                        body=body,
                        url=current_url,
                    )

    def get(self, url: str, **kwargs: Any) -> HardenedHttpResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, data: Optional[bytes] = None, **kwargs: Any) -> HardenedHttpResponse:
        return self.request("POST", url, data=data, **kwargs)
