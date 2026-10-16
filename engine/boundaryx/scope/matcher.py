import ipaddress
from typing import Optional

from boundaryx.domain.enums import MatcherType
from boundaryx.domain.models import ScopeRule
from boundaryx.scope.canonicalizer import canonicalize_host, parse_and_canonicalize_target


def matches_domain(target_host: str, pattern: str, wildcard: bool) -> bool:
    """
    Boundary-aware hostname matching.
    Protects against deceptive prefix/suffix collisions like:
    'evil-example.com' or 'example.com.evil.test'.
    """
    canon_target = canonicalize_host(target_host)
    raw_pattern = pattern.strip().lower()
    if raw_pattern.startswith("*."):
        wildcard = True
        raw_pattern = raw_pattern[2:]
    canon_pattern = canonicalize_host(raw_pattern)

    # Exact match
    if canon_target == canon_pattern:
        return True

    if wildcard:
        # Must end with dot + pattern to be a valid subdomain
        if canon_target.endswith("." + canon_pattern):
            return True

    return False


def matches_ip_or_cidr(target_host: str, pattern: str) -> bool:
    """
    Matches IP literal or CIDR range.
    """
    clean_target = target_host.strip("[]")
    clean_pattern = pattern.strip().strip("[]")

    try:
        target_ip = ipaddress.ip_address(clean_target)
    except ValueError:
        return False

    # Check if pattern is a CIDR network
    if "/" in clean_pattern:
        try:
            network = ipaddress.ip_network(clean_pattern, strict=False)
            return target_ip in network
        except ValueError:
            return False
    else:
        try:
            pattern_ip = ipaddress.ip_address(clean_pattern)
            return target_ip == pattern_ip
        except ValueError:
            return False


def matches_scope_rule(rule: ScopeRule, target_host: str, scheme: Optional[str] = None, port: Optional[int] = None, path: str = "/") -> bool:
    """
    Evaluates whether a target matches a specific ScopeRule.
    """
    # Check scheme if specified in rule
    if rule.scheme:
        if scheme and scheme.lower() != rule.scheme.lower():
            return False

    # Check port if specified in rule
    if rule.port is not None:
        if port is not None and port != rule.port:
            return False

    if rule.matcher_type == MatcherType.DOMAIN:
        return matches_domain(target_host, rule.pattern, rule.wildcard)

    elif rule.matcher_type in (MatcherType.IP, MatcherType.CIDR):
        return matches_ip_or_cidr(target_host, rule.pattern)

    elif rule.matcher_type == MatcherType.URL_PREFIX:
        # Pattern can be full URL prefix or host + path prefix
        p_host, p_scheme, p_port, p_path = parse_and_canonicalize_target(rule.pattern)
        if not matches_domain(target_host, p_host, rule.wildcard):
            return False

        if p_scheme and scheme and p_scheme != scheme:
            return False

        if p_port is not None and port is not None and p_port != port:
            return False

        # Path prefix check
        clean_target_path = path if path.startswith("/") else "/" + path
        clean_pattern_path = p_path if p_path.startswith("/") else "/" + p_path

        if clean_pattern_path == "/":
            return True

        if clean_target_path == clean_pattern_path:
            return True

        if clean_target_path.startswith(clean_pattern_path.rstrip("/") + "/"):
            return True

        return False

    return False
