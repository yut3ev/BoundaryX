import pytest

from boundaryx.domain.enums import MatcherType, ScopeRuleType, ScopeStatus
from boundaryx.domain.models import ScopeRule
from boundaryx.http.client import HardenedHttpClient, ScopeDenialError
from boundaryx.scope.canonicalizer import (
    canonicalize_host,
)
from boundaryx.scope.guard import ScopeGuard


def test_scope_guard_suffix_and_prefix_spoofing():
    """
    Test that malicious domains attempting prefix/suffix spoofing are strictly denied.
    """
    rules = [
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.DOMAIN,
            pattern="target.com",
            wildcard=True,
        )
    ]
    guard = ScopeGuard(rules)

    # Deceptive domains that must be rejected
    deceptive_targets = [
        "evil-target.com",
        "target.com.attacker.org",
        "nottarget.com",
        "target.com-phish.net",
        "target.com.evil.com",
        "https://target.com.evil.com/path",
        "https://evil-target.com:443/api",
    ]

    for dt in deceptive_targets:
        decision = guard.evaluate(dt)
        assert decision.is_in_scope is False, f"Expected {dt} to be OUT OF SCOPE, but got IN_SCOPE"
        assert decision.status == ScopeStatus.OUT_OF_SCOPE


def test_scope_guard_idna_homograph_defense():
    """
    Test IDNA normalization defends against visual homographs and punycode spoofing.
    """
    # Program authorizes arabic domain 'مثال.مصر'
    arabic_pattern = "مثال.مصر"
    punycode_pattern = canonicalize_host(arabic_pattern)

    rules = [
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.DOMAIN,
            pattern=arabic_pattern,
            wildcard=False,
        )
    ]
    guard = ScopeGuard(rules)

    # Both unicode and punycode representations must match
    assert guard.evaluate(arabic_pattern).is_in_scope is True
    assert guard.evaluate(punycode_pattern).is_in_scope is True
    assert guard.evaluate(f"https://{punycode_pattern}/api").is_in_scope is True

    # Homograph attack: Cyrillic 'а' replacing Latin 'a' in 'target.com'
    # Cyrillic small letter a is \u0430
    cyrillic_target = "t\u0430rget.com"
    cyrillic_punycode = canonicalize_host(cyrillic_target)
    assert cyrillic_punycode.startswith("xn--")

    latin_rules = [
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.DOMAIN,
            pattern="target.com",
            wildcard=False,
        )
    ]
    latin_guard = ScopeGuard(latin_rules)
    # The Cyrillic homograph MUST NOT match target.com
    assert latin_guard.evaluate(cyrillic_target).is_in_scope is False


def test_scope_guard_embedded_credentials_and_userinfo_rejection():
    """
    SSRF Defense: URLs containing userinfo/embedded credentials must be blocked.
    """
    rules = [
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.DOMAIN,
            pattern="target.com",
            wildcard=True,
        )
    ]
    guard = ScopeGuard(rules)

    malicious_inputs = [
        "https://admin:secret@target.com/api",
        "https://target.com@attacker.com/",
        "user:pass@target.com",
    ]

    for mi in malicious_inputs:
        decision = guard.evaluate(mi)
        assert decision.is_in_scope is False
        assert "Canonicalization failure" in decision.denial_reason or "Target did not match" in decision.denial_reason


def test_scope_guard_ip_and_cidr_boundaries():
    """
    Verifies IP and CIDR rule evaluation.
    """
    rules = [
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.CIDR,
            pattern="192.168.10.0/24",
        ),
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.IP,
            pattern="10.0.0.1",
        ),
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.EXCLUDE,
            matcher_type=MatcherType.IP,
            pattern="192.168.10.254",  # Gateway excluded
        ),
    ]
    guard = ScopeGuard(rules)

    # In-scope CIDR members
    assert guard.evaluate("192.168.10.1").is_in_scope is True
    assert guard.evaluate("http://192.168.10.55:8080/test").is_in_scope is True

    # Excluded IP inside CIDR must be denied (exclusion precedence)
    assert guard.evaluate("192.168.10.254").is_in_scope is False

    # Out of CIDR range
    assert guard.evaluate("192.168.11.1").is_in_scope is False

    # Exact IP
    assert guard.evaluate("10.0.0.1").is_in_scope is True
    assert guard.evaluate("10.0.0.2").is_in_scope is False


def test_scope_guard_redirect_chain_validation():
    """
    Verifies that redirect chains are independently audited at every single hop.
    """
    rules = [
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.DOMAIN,
            pattern="app.target.com",
            wildcard=False,
        )
    ]
    guard = ScopeGuard(rules)

    # Hop 1: Relative redirect on same site -> Allowed
    h1 = guard.validate_redirect("https://app.target.com/login", "/dashboard")
    assert h1.is_in_scope is True

    # Hop 2: Subdomain not in scope -> Denied
    h2 = guard.validate_redirect("https://app.target.com/login", "https://accounts.target.com/auth")
    assert h2.is_in_scope is False
    assert "blocked by scope guard" in h2.denial_reason

    # Hop 3: External OAuth provider -> Denied
    h3 = guard.validate_redirect("https://app.target.com/auth", "https://github.com/login/oauth/authorize")
    assert h3.is_in_scope is False
    assert "blocked by scope guard" in h3.denial_reason

    # Hop 4: Open redirect attempt to deceptive suffix -> Denied
    h4 = guard.validate_redirect("https://app.target.com/go", "https://app.target.com.attacker.org")
    assert h4.is_in_scope is False


def test_engine_level_http_client_scope_enforcement():
    """
    Verifies that HardenedHttpClient in the engine enforces scope before sending packets,
    raising ScopeDenialError when bypassed by callers.
    """
    rules = [
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.DOMAIN,
            pattern="safe.target.com",
            wildcard=False,
        )
    ]
    client = HardenedHttpClient(rules)

    # Out-of-scope URL must immediately raise ScopeDenialError without network I/O
    with pytest.raises(ScopeDenialError, match="Request blocked by engine ScopeGuard"):
        client.get("https://evil-attacker.com/steal")
