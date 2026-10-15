"""Data redaction engine for scrubbing credentials, tokens, and sensitive data from evidence."""

from __future__ import annotations

import copy
import json
import logging
import re
import threading
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

logger = logging.getLogger(__name__)


@dataclass
class RedactionRule:
    """Defines a rule for identifying and sanitizing sensitive content."""

    name: str
    pattern_type: str  # 'header_name', 'field_name', 'regex', 'value_pattern'
    pattern: str
    replacement: str = "[REDACTED]"
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert rule to dictionary representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RedactionRule:
        """Construct rule from dictionary representation."""
        return cls(
            name=data["name"],
            pattern_type=data["pattern_type"],
            pattern=data["pattern"],
            replacement=data.get("replacement", "[REDACTED]"),
            enabled=data.get("enabled", True),
        )


class RedactionEngine:
    """Configurable, best-effort engine for scrubbing sensitive data.

    Note:
        This engine is a best-effort helper. It does not guarantee that all
        possible forms of secrets or sensitive data are caught.
    """

    DEFAULT_SENSITIVE_PARAMS: set[str] = {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "key",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "pwd",
        "auth",
        "session",
        "session_id",
        "sessionid",
        "sig",
        "signature",
    }

    def __init__(self, rules: list[RedactionRule] | None = None) -> None:
        """Initialize the RedactionEngine with optional custom rules.

        If rules is None, standard default security redaction rules are loaded.
        """
        self._lock = threading.RLock()
        self._rules: dict[str, RedactionRule] = {}
        self._compiled_regexes: dict[str, re.Pattern] = {}

        if rules is not None:
            for rule in rules:
                self.add_rule(rule)
        else:
            self._load_default_rules()

    def _load_default_rules(self) -> None:
        """Load default set of redaction rules."""
        defaults = [
            # Headers
            RedactionRule("authorization_header", "header_name", "authorization"),
            RedactionRule("proxy_authorization_header", "header_name", "proxy-authorization"),
            RedactionRule("cookie_header", "header_name", "cookie"),
            RedactionRule("set_cookie_header", "header_name", "set-cookie"),
            RedactionRule("x_api_key_header", "header_name", "x-api-key"),
            RedactionRule("api_key_header", "header_name", "api-key"),
            RedactionRule("x_auth_token_header", "header_name", "x-auth-token"),
            # Field names (JSON keys / form inputs)
            RedactionRule("password_field", "field_name", "password"),
            RedactionRule("passwd_field", "field_name", "passwd"),
            RedactionRule("secret_field", "field_name", "secret"),
            RedactionRule("token_field", "field_name", "token"),
            RedactionRule("access_token_field", "field_name", "access_token"),
            RedactionRule("refresh_token_field", "field_name", "refresh_token"),
            RedactionRule("client_secret_field", "field_name", "client_secret"),
            RedactionRule("private_key_field", "field_name", "private_key"),
            RedactionRule("session_id_field", "field_name", "session_id"),
            RedactionRule("sessionid_field", "field_name", "sessionid"),
            RedactionRule("phpsessid_field", "field_name", "phpsessid"),
            RedactionRule("jsessionid_field", "field_name", "jsessionid"),
            # Regex patterns for values
            RedactionRule(
                "bearer_token",
                "regex",
                r"(?i)\bBearer\s+[A-Za-z0-9_\-\.\+\/=]+",
                replacement="Bearer [REDACTED]",
            ),
            RedactionRule(
                "session_cookie_pattern",
                "regex",
                r"(?i)\b(PHPSESSID|JSESSIONID|connect\.sid|session_id|sessionid)=([a-zA-Z0-9_\-\.]{16,})",
                replacement=r"\1=[REDACTED]",
            ),
            RedactionRule(
                "jwt_pattern",
                "regex",
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                replacement="[REDACTED_JWT]",
            ),
        ]
        for rule in defaults:
            self.add_rule(rule)

    def add_rule(self, rule: RedactionRule) -> None:
        """Add or replace a redaction rule."""
        with self._lock:
            self._rules[rule.name] = rule
            if rule.pattern_type == "regex" and rule.enabled:
                try:
                    self._compiled_regexes[rule.name] = re.compile(rule.pattern)
                except re.error as exc:
                    logger.warning("Failed to compile regex for rule %s: %s", rule.name, exc)
            elif rule.name in self._compiled_regexes:
                del self._compiled_regexes[rule.name]

    def remove_rule(self, name: str) -> bool:
        """Remove a redaction rule by name.

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            if name in self._rules:
                del self._rules[name]
                self._compiled_regexes.pop(name, None)
                return True
            return False

    def get_rules(self) -> list[RedactionRule]:
        """Return all registered redaction rules."""
        with self._lock:
            return list(self._rules.values())

    def enable_rule(self, name: str) -> bool:
        """Enable an existing rule by name."""
        with self._lock:
            rule = self._rules.get(name)
            if rule:
                rule.enabled = True
                if rule.pattern_type == "regex":
                    try:
                        self._compiled_regexes[name] = re.compile(rule.pattern)
                    except re.error as exc:
                        logger.warning("Failed to compile regex for rule %s: %s", name, exc)
                return True
            return False

    def disable_rule(self, name: str) -> bool:
        """Disable an existing rule by name."""
        with self._lock:
            rule = self._rules.get(name)
            if rule:
                rule.enabled = False
                self._compiled_regexes.pop(name, None)
                return True
            return False

    def redact_headers(self, headers: dict[str, Any]) -> dict[str, Any]:
        """Apply header redaction rules to an HTTP headers dictionary.

        Args:
            headers: Key-value mapping of HTTP headers.

        Returns:
            Sanitized copy of the headers dictionary.
        """
        if not headers:
            return {}

        result: dict[str, Any] = {}
        with self._lock:
            header_rules = [r for r in self._rules.values() if r.enabled and r.pattern_type == "header_name"]
            regex_rules = [
                (r, self._compiled_regexes[r.name])
                for r in self._rules.values()
                if r.enabled and r.pattern_type == "regex" and r.name in self._compiled_regexes
            ]

            for key, val in headers.items():
                lower_key = str(key).strip().lower()
                matched_header_rule = None

                for rule in header_rules:
                    if rule.pattern.lower() == lower_key:
                        matched_header_rule = rule
                        break

                if matched_header_rule:
                    result[key] = matched_header_rule.replacement
                else:
                    str_val = str(val) if val is not None else ""
                    # Apply regex rules to non-redacted header value
                    for rule, comp in regex_rules:
                        str_val = comp.sub(rule.replacement, str_val)
                    result[key] = str_val

        return result

    def redact_url(self, url: str, sensitive_params: set[str] | None = None) -> str:
        """Scrub embedded credentials and sensitive query parameters from a URL.

        Args:
            url: Target URL string.
            sensitive_params: Optional custom set of parameter names to redact.

        Returns:
            Sanitized URL string.
        """
        if not url or not isinstance(url, str):
            return ""

        try:
            parsed = urlparse(url)
        except Exception:
            return url

        # 1. Scrub credentials (user:pass@host)
        netloc = parsed.netloc
        if parsed.username or parsed.password or "@" in netloc:
            host_and_port = netloc.split("@")[-1]
            netloc = f"[REDACTED]:[REDACTED]@{host_and_port}"

        # 2. Scrub sensitive query parameters
        param_targets = set(sensitive_params or self.DEFAULT_SENSITIVE_PARAMS)
        with self._lock:
            for rule in self._rules.values():
                if rule.enabled and rule.pattern_type == "field_name":
                    param_targets.add(rule.pattern.lower())

        clean_query = parsed.query
        if parsed.query:
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            sanitized_pairs = []
            for k, v in query_pairs:
                if k.lower() in param_targets:
                    sanitized_pairs.append((k, "[REDACTED]"))
                else:
                    # Apply value regex rules to parameter values
                    val = v
                    for rule_name, comp in self._compiled_regexes.items():
                        rule = self._rules.get(rule_name)
                        if rule and rule.enabled:
                            val = comp.sub(rule.replacement, val)
                    sanitized_pairs.append((k, val))
            clean_query = urlencode(sanitized_pairs)

        return urlunparse(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                clean_query,
                parsed.fragment,
            )
        )

    def _redact_json_value(
        self,
        value: Any,
        field_rules: list[RedactionRule],
        regex_rules: list[tuple[RedactionRule, re.Pattern]],
    ) -> Any:
        """Recursively redact JSON structures."""
        if isinstance(value, dict):
            new_dict = {}
            for k, v in value.items():
                lower_k = str(k).lower()
                matched_rule = None
                for rule in field_rules:
                    if rule.pattern.lower() == lower_k:
                        matched_rule = rule
                        break

                if matched_rule:
                    new_dict[k] = matched_rule.replacement
                else:
                    new_dict[k] = self._redact_json_value(v, field_rules, regex_rules)
            return new_dict

        if isinstance(value, list):
            return [self._redact_json_value(item, field_rules, regex_rules) for item in value]

        if isinstance(value, str):
            res = value
            for rule, comp in regex_rules:
                res = comp.sub(rule.replacement, res)
            return res

        return value

    def redact_body(self, body: str, content_type: str | None = None) -> str:
        """Redact sensitive data from an HTTP body string.

        Supports JSON structures, form-urlencoded payloads, and unstructured text.

        Args:
            body: Body payload string.
            content_type: Optional Content-Type header string.

        Returns:
            Sanitized body string.
        """
        if not body or not isinstance(body, str):
            return body

        ct = (content_type or "").lower()

        with self._lock:
            field_rules = [r for r in self._rules.values() if r.enabled and r.pattern_type == "field_name"]
            regex_rules = [
                (r, self._compiled_regexes[r.name])
                for r in self._rules.values()
                if r.enabled and r.pattern_type == "regex" and r.name in self._compiled_regexes
            ]

        # 1. Attempt JSON parsing if indicated or formatted as JSON
        trimmed = body.strip()
        is_json = "application/json" in ct or (
            (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]"))
        )

        if is_json:
            try:
                parsed_json = json.loads(trimmed)
                redacted_json = self._redact_json_value(parsed_json, field_rules, regex_rules)
                indent = 2 if "\n" in body else None
                return json.dumps(redacted_json, indent=indent)
            except Exception:
                pass  # Fallback to text scrubbing

        # 2. Form URL-encoded
        if "application/x-www-form-urlencoded" in ct:
            try:
                pairs = parse_qsl(body, keep_blank_values=True)
                field_names = {r.pattern.lower() for r in field_rules}
                new_pairs = []
                for k, v in pairs:
                    if k.lower() in field_names:
                        new_pairs.append((k, "[REDACTED]"))
                    else:
                        val = v
                        for rule, comp in regex_rules:
                            val = comp.sub(rule.replacement, val)
                        new_pairs.append((k, val))
                return urlencode(new_pairs)
            except Exception:
                pass

        # 3. Plain text / fallback: apply regex rules
        res = body
        for rule, comp in regex_rules:
            res = comp.sub(rule.replacement, res)
        return res

    def redact_evidence(self, evidence_dict: dict[str, Any]) -> dict[str, Any]:
        """Apply comprehensive redaction to a security test evidence dictionary.

        Args:
            evidence_dict: Snapshot dictionary containing request, response, headers, etc.

        Returns:
            Sanitized copy of the evidence dictionary.
        """
        if not evidence_dict:
            return {}

        data = copy.deepcopy(evidence_dict)

        def _traverse(node: Any) -> Any:
            if isinstance(node, dict):
                new_dict = {}
                # Determine content type if present in this dict
                content_type = ""
                for k, v in node.items():
                    if str(k).lower() in ("content-type", "content_type") and isinstance(v, str):
                        content_type = v
                        break

                for k, v in node.items():
                    lower_k = str(k).lower()

                    # Check headers
                    if lower_k in ("headers", "request_headers", "response_headers") and isinstance(v, dict):
                        new_dict[k] = self.redact_headers(v)
                    # Check URL
                    elif lower_k in ("url", "target_url", "redirect_url", "request_url") and isinstance(v, str):
                        new_dict[k] = self.redact_url(v)
                    # Check body
                    elif lower_k in ("body", "request_body", "response_body") and isinstance(v, str):
                        new_dict[k] = self.redact_body(v, content_type=content_type)
                    # Check field name match
                    elif any(
                        r.enabled and r.pattern_type == "field_name" and r.pattern.lower() == lower_k
                        for r in self._rules.values()
                    ):
                        new_dict[k] = "[REDACTED]"
                    else:
                        new_dict[k] = _traverse(v)
                return new_dict

            if isinstance(node, list):
                return [_traverse(item) for item in node]

            if isinstance(node, str):
                res = node
                with self._lock:
                    for rule_name, comp in self._compiled_regexes.items():
                        rule = self._rules.get(rule_name)
                        if rule and rule.enabled:
                            res = comp.sub(rule.replacement, res)
                return res

            return node

        return _traverse(data)

    def preview_redaction(self, data: dict[str, Any]) -> dict[str, Any]:
        """Preview redaction effects on data without modifying the original.

        Returns:
            Dictionary with redacted preview, original data, and identified redactions.
        """
        redacted = self.redact_evidence(data)

        # Count redaction replacements
        serialized_redacted = json.dumps(redacted)
        redaction_count = serialized_redacted.count("[REDACTED]") + serialized_redacted.count("[REDACTED_JWT]")

        return {
            "redactions_found": redaction_count,
            "preview": redacted,
            "original": data,
        }
