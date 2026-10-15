"""Scope management module for target URL validation and boundary enforcement."""

from __future__ import annotations

import ipaddress
import logging
import posixpath
import threading
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlparse

import idna

logger = logging.getLogger(__name__)


@dataclass
class ScopeRule:
    """Defines an authorization boundary rule for security testing."""

    hostname: str
    port: int | None = None
    scheme: str | None = "https"
    path_prefix: str | None = None
    excluded_paths: list[str] = field(default_factory=list)
    is_exclusion: bool = False
    notes: str = ""

    def to_dict(self) -> dict:
        """Convert rule to dictionary representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> ScopeRule:
        """Create ScopeRule from dictionary representation."""
        return cls(
            hostname=data["hostname"],
            port=data.get("port"),
            scheme=data.get("scheme", "https"),
            path_prefix=data.get("path_prefix"),
            excluded_paths=list(data.get("excluded_paths") or []),
            is_exclusion=bool(data.get("is_exclusion", False)),
            notes=str(data.get("notes", "")),
        )


def normalize_hostname(hostname: str) -> str:
    """Normalize a hostname or IP address for exact security comparison.

    Performs:
    1. Whitespace stripping and lowercase conversion.
    2. Stripping trailing DNS root dot.
    3. Stripping IPv6 enclosing brackets if present.
    4. Canonical IP representation if an IPv4 or IPv6 address.
    5. IDN/punycode encoding (ACE) to prevent homograph attacks.

    Args:
        hostname: Raw hostname string.

    Returns:
        Canonical normalized hostname string.
    """
    if not hostname:
        return ""

    host = hostname.strip().rstrip(".").lower()

    # Handle IPv6 bracketed format e.g. [::1]
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    # Check if host is an IP address (IPv4 or IPv6)
    try:
        ip = ipaddress.ip_address(host)
        return str(ip)
    except ValueError:
        pass

    # Handle wildcard prefix if present
    is_wildcard = False
    if host.startswith("*."):
        is_wildcard = True
        host = host[2:]

    # IDN punycode normalization
    try:
        encoded = idna.encode(host).decode("ascii")
        return f"*.{encoded}" if is_wildcard else encoded
    except idna.IDNAError:
        return f"*.{host}" if is_wildcard else host


def normalize_path(path: str) -> str:
    """Normalize URL path resolving dot segments and ensuring leading slash."""
    if not path:
        return "/"
    # Ensure starting slash
    if not path.startswith("/"):
        path = "/" + path
    normalized = posixpath.normpath(path)
    if path.endswith("/") and not normalized.endswith("/"):
        normalized += "/"
    return normalized


class ScopeManager:
    """Thread-safe scope validator enforcing strict application security testing boundaries."""

    def __init__(self, rules: list[ScopeRule] | None = None) -> None:
        """Initialize ScopeManager with an optional list of ScopeRule objects.

        Args:
            rules: Initial list of ScopeRules.
        """
        self._lock = threading.RLock()
        self._rules: list[ScopeRule] = []
        if rules:
            for rule in rules:
                self.add_rule(rule)

    def add_rule(self, rule: ScopeRule) -> None:
        """Add a ScopeRule to the active scope configuration.

        Args:
            rule: ScopeRule instance to append.
        """
        with self._lock:
            self._rules.append(rule)

    def remove_rule(self, index: int) -> ScopeRule:
        """Remove a ScopeRule by index.

        Args:
            index: Zero-based rule index.

        Returns:
            The removed ScopeRule.

        Raises:
            IndexError: If index is out of bounds.
        """
        with self._lock:
            return self._rules.pop(index)

    def get_rules(self) -> list[ScopeRule]:
        """Return a copy of the current list of ScopeRules."""
        with self._lock:
            return list(self._rules)

    def clear_rules(self) -> None:
        """Clear all active scope rules."""
        with self._lock:
            self._rules.clear()

    def set_rules(self, rules: list[ScopeRule]) -> None:
        """Replace all current scope rules with a new list of rules."""
        with self._lock:
            self._rules = list(rules)

    def _effective_port(self, port: int | None, scheme: str | None) -> int | None:
        """Determine effective port taking scheme defaults into account."""
        if port is not None:
            return port
        if scheme == "http":
            return 80
        if scheme == "https":
            return 443
        return None

    def _matches_hostname(self, rule_host_normalized: str, target_host_normalized: str) -> bool:
        """Strictly match target hostname against rule hostname without substring flaws."""
        if rule_host_normalized.startswith("*."):
            base_domain = rule_host_normalized[2:]
            return target_host_normalized.endswith("." + base_domain)
        return target_host_normalized == rule_host_normalized

    def _path_matches_prefix(self, target_path: str, prefix: str) -> bool:
        """Check if target path matches the specified path prefix boundary."""
        norm_prefix = normalize_path(prefix)
        norm_target = normalize_path(target_path)

        if norm_prefix == "/":
            return True
        if norm_target == norm_prefix:
            return True
        clean_prefix = norm_prefix.rstrip("/")
        return norm_target.startswith(clean_prefix + "/")

    def _path_matches_exclusion(self, target_path: str, excluded_path: str) -> bool:
        """Check if target path matches an excluded path boundary."""
        norm_excl = normalize_path(excluded_path)
        norm_target = normalize_path(target_path)

        if norm_target == norm_excl:
            return True
        clean_excl = norm_excl.rstrip("/")
        return norm_target.startswith(clean_excl + "/")

    def is_in_scope(self, url: str) -> tuple[bool, str]:
        """Determine whether a given URL is within authorized scope boundaries.

        Evaluation order:
        1. Validate URL structure and reject credentials (user:pass@host).
        2. Normalize hostname and scheme.
        3. Match against explicit exclusion rules first.
        4. Match against allow rules (hostname exact match, scheme, port, path prefix, excluded paths).
        5. Reject if no allow rule matches.

        Args:
            url: Full URL string to evaluate.

        Returns:
            Tuple of (is_allowed: bool, reason: str).
        """
        if not url or not isinstance(url, str):
            return False, "URL must be a non-empty string"

        try:
            parsed = urlparse(url.strip())
        except Exception as exc:
            return False, f"Failed to parse URL: {exc}"

        # 1. Reject URLs with credentials (user:pass@host)
        if parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
            return False, "URL contains embedded credentials (user:pass@host), which is prohibited for security"

        if not parsed.scheme:
            return False, "URL lacks a scheme (http/https)"

        target_scheme = parsed.scheme.lower()
        if target_scheme not in ("http", "https"):
            return False, f"Unsupported scheme '{target_scheme}'. Only http and https are permitted."

        raw_hostname = parsed.hostname
        if not raw_hostname:
            return False, "URL lacks a valid hostname"

        target_host = normalize_hostname(raw_hostname)
        target_port = self._effective_port(parsed.port, target_scheme)
        target_path = parsed.path or "/"

        with self._lock:
            # 5. Check against exclusion rules first
            for rule in self._rules:
                if not rule.is_exclusion:
                    continue

                rule_host = normalize_hostname(rule.hostname)
                if not self._matches_hostname(rule_host, target_host):
                    continue

                # Check scheme if specified in exclusion rule
                if rule.scheme and rule.scheme.lower() != target_scheme:
                    continue

                # Check port if specified in exclusion rule
                if rule.port is not None:
                    rule_port = self._effective_port(rule.port, rule.scheme.lower() if rule.scheme else None)
                    if rule_port != target_port:
                        continue

                # Check path prefix if specified in exclusion rule
                if rule.path_prefix and not self._path_matches_prefix(target_path, rule.path_prefix):
                    continue

                return False, f"URL is blocked by exclusion rule: {rule.notes or rule.hostname}"

            # 4. Check against allow rules
            for rule in self._rules:
                if rule.is_exclusion:
                    continue

                rule_host = normalize_hostname(rule.hostname)
                # 6. Check hostname EXACTLY - no substring matching
                if not self._matches_hostname(rule_host, target_host):
                    continue

                # 3. Check scheme matches (default https)
                rule_scheme = rule.scheme.lower() if rule.scheme else "https"
                if rule_scheme != target_scheme:
                    continue

                # 4. Check port matches
                rule_port = self._effective_port(rule.port, rule_scheme)
                if rule_port != target_port:
                    continue

                # 7. Check path prefix if specified
                if rule.path_prefix and not self._path_matches_prefix(target_path, rule.path_prefix):
                    continue

                # 8. Check excluded paths on the allow rule
                path_excluded = False
                for excl in rule.excluded_paths:
                    if self._path_matches_exclusion(target_path, excl):
                        path_excluded = True
                        break

                if path_excluded:
                    return False, f"URL path '{target_path}' is explicitly excluded by rule for {rule.hostname}"

                return True, f"URL matches authorized scope rule for {rule.hostname}"

            # 9. Reject if no matching allow rule
            return False, "URL does not match any authorized scope rule"

    def validate_redirect(self, original_url: str, redirect_url: str) -> tuple[bool, str]:
        """Validate if a redirection target is authorized within scope boundaries.

        Treats each redirect target as a new destination requiring independent verification.
        Resolves relative redirection URLs against the original request URL.

        Args:
            original_url: The URL that initiated the request.
            redirect_url: The Location header URL target.

        Returns:
            Tuple of (is_allowed: bool, reason: str).
        """
        orig_allowed, orig_reason = self.is_in_scope(original_url)
        if not orig_allowed:
            return False, f"Original URL is out of scope: {orig_reason}"

        # Resolve relative redirect URLs against the original URL
        try:
            target_url = urljoin(original_url, redirect_url)
        except Exception as exc:
            return False, f"Failed to resolve redirect target '{redirect_url}': {exc}"

        redir_allowed, redir_reason = self.is_in_scope(target_url)
        if not redir_allowed:
            return False, f"Redirect target '{target_url}' is out of scope: {redir_reason}"

        return True, f"Redirect target '{target_url}' is within authorized scope"

    def validate_all_urls(self, urls: list[str]) -> list[tuple[str, bool, str]]:
        """Validate a batch of URLs against the scope rules.

        Args:
            urls: List of URL strings.

        Returns:
            List of tuples: (url, is_allowed, reason).
        """
        results: list[tuple[str, bool, str]] = []
        for url in urls:
            allowed, reason = self.is_in_scope(url)
            results.append((url, allowed, reason))
        return results

    def preview_scope(self) -> dict:
        """Return a structured summary of current scope rules and target hostnames.

        Returns:
            Dictionary containing rule counts, rule details, and target hosts.
        """
        with self._lock:
            allow_rules = [r for r in self._rules if not r.is_exclusion]
            exclusion_rules = [r for r in self._rules if r.is_exclusion]

            return {
                "total_rules": len(self._rules),
                "allow_rules_count": len(allow_rules),
                "exclusion_rules_count": len(exclusion_rules),
                "rules": [r.to_dict() for r in self._rules],
                "authorized_hostnames": sorted(list({r.hostname for r in allow_rules})),
                "excluded_hostnames": sorted(list({r.hostname for r in exclusion_rules})),
            }
