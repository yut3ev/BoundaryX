import re
from typing import Any, Dict


class RedactionEngine:
    """
    Multi-vector sensitive data scrubbing engine.
    Scrubs Authorization tokens, API keys, passwords, cookies, and session IDs
    before persistence, UI display, export, or AI analysis.
    """

    SENSITIVE_HEADER_KEYS = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "apikey",
        "token",
        "secret",
        "private-key",
    }

    SENSITIVE_FIELD_PATTERNS = [
        re.compile(r"password", re.IGNORECASE),
        re.compile(r"passwd", re.IGNORECASE),
        re.compile(r"secret", re.IGNORECASE),
        re.compile(r"token", re.IGNORECASE),
        re.compile(r"api[_-]?key", re.IGNORECASE),
        re.compile(r"access[_-]?token", re.IGNORECASE),
        re.compile(r"auth[_-]?token", re.IGNORECASE),
        re.compile(r"private[_-]?key", re.IGNORECASE),
        re.compile(r"session[_-]?id", re.IGNORECASE),
        re.compile(r"credential", re.IGNORECASE),
    ]

    BEARER_PATTERN = re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
    BASIC_PATTERN = re.compile(r"(Basic\s+)[A-Za-z0-9+/=]+", re.IGNORECASE)
    JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

    def redact_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Redacts sensitive headers from a dictionary."""
        redacted = {}
        for key, value in headers.items():
            lower_key = key.lower()
            if lower_key in self.SENSITIVE_HEADER_KEYS:
                if lower_key == "authorization" and self.BEARER_PATTERN.search(value):
                    redacted[key] = "Bearer [REDACTED_TOKEN]"
                elif lower_key == "authorization" and self.BASIC_PATTERN.search(value):
                    redacted[key] = "Basic [REDACTED_CREDENTIALS]"
                else:
                    redacted[key] = "[REDACTED]"
            else:
                # Still check value for embedded JWTs or Bearer tokens
                val_scrubbed = self.BEARER_PATTERN.sub(r"\1[REDACTED_TOKEN]", value)
                val_scrubbed = self.JWT_PATTERN.sub("[REDACTED_JWT]", val_scrubbed)
                redacted[key] = val_scrubbed
        return redacted

    def redact_data(self, data: Any) -> Any:
        """Recursively traverses JSON-compatible data and redacts sensitive keys."""
        if isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                if any(pat.search(k) for pat in self.SENSITIVE_FIELD_PATTERNS):
                    new_dict[k] = "[REDACTED]"
                else:
                    new_dict[k] = self.redact_data(v)
            return new_dict
        elif isinstance(data, list):
            return [self.redact_data(item) for item in data]
        elif isinstance(data, str):
            # Check for JWT pattern
            scrubbed = self.JWT_PATTERN.sub("[REDACTED_JWT]", data)
            scrubbed = self.BEARER_PATTERN.sub(r"\1[REDACTED_TOKEN]", scrubbed)
            return scrubbed
        return data

    def redact_url(self, url: str) -> str:
        """Redacts sensitive query parameters like ?token=... or ?api_key=..."""
        scrubbed = re.sub(
            r"([?&](?:token|access_token|key|api_key|secret|password|auth)=)[^&]*",
            r"\1[REDACTED]",
            url,
            flags=re.IGNORECASE,
        )
        return scrubbed

    def redact_text(self, text: str) -> str:
        """Redacts raw text blocks (e.g. logs or stdout)."""
        scrubbed = self.BEARER_PATTERN.sub(r"\1[REDACTED_TOKEN]", text)
        scrubbed = self.JWT_PATTERN.sub("[REDACTED_JWT]", scrubbed)
        # Redact common API key patterns (e.g. AIzaSy... or sk-...)
        scrubbed = re.sub(r"AIzaSy[A-Za-z0-9_-]{33}", "[REDACTED_GOOGLE_API_KEY]", scrubbed)
        scrubbed = re.sub(r"sk-[A-Za-z0-9]{32,}", "[REDACTED_API_KEY]", scrubbed)
        return scrubbed
