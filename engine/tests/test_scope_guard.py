import pytest

from boundaryx.domain.enums import MatcherType, ScopeRuleType, ScopeStatus
from boundaryx.domain.models import ScopeRule
from boundaryx.scope.guard import ScopeGuard


def test_scope_guard_exact_matching():
    rules = [
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.DOMAIN,
            pattern="example.com",
            wildcard=False,
        )
    ]
    guard = ScopeGuard(rules)

    # Exact match is in scope
    d1 = guard.evaluate("https://example.com/test")
    assert d1.is_in_scope is True
    assert d1.status == ScopeStatus.IN_SCOPE

    # Subdomain is NOT in scope when wildcard is False
    d2 = guard.evaluate("https://sub.example.com/test")
    assert d2.is_in_scope is False
    assert d2.status == ScopeStatus.OUT_OF_SCOPE


def test_scope_guard_prevents_suffix_confusion():
    """
    Critical security test:
    evil-example.com or example.com.attacker.com MUST NOT match example.com!
    """
    rules = [
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.DOMAIN,
            pattern="example.com",
            wildcard=True,
        )
    ]
    guard = ScopeGuard(rules)

    # Deceptive prefix / suffix hosts
    assert guard.evaluate("evil-example.com").is_in_scope is False
    assert guard.evaluate("notexample.com").is_in_scope is False
    assert guard.evaluate("example.com.evil.test").is_in_scope is False
    assert guard.evaluate("https://evil-example.com/").is_in_scope is False

    # Valid wildcard subdomains
    assert guard.evaluate("sub.example.com").is_in_scope is True
    assert guard.evaluate("api.v1.example.com").is_in_scope is True
    assert guard.evaluate("example.com").is_in_scope is True


def test_scope_guard_exclusion_precedence():
    """
    Exclusion rules must always override inclusion rules.
    """
    rules = [
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.DOMAIN,
            pattern="example.com",
            wildcard=True,
        ),
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.EXCLUDE,
            matcher_type=MatcherType.DOMAIN,
            pattern="admin.example.com",
            wildcard=False,
        ),
    ]
    guard = ScopeGuard(rules)

    assert guard.evaluate("https://api.example.com").is_in_scope is True
    # admin.example.com is explicitly excluded
    admin_decision = guard.evaluate("https://admin.example.com")
    assert admin_decision.is_in_scope is False
    assert "Target matched explicit exclusion rule" in admin_decision.denial_reason


def test_scope_guard_redirect_validation():
    rules = [
        ScopeRule(
            program_id="p1",
            rule_type=ScopeRuleType.INCLUDE,
            matcher_type=MatcherType.DOMAIN,
            pattern="target.com",
            wildcard=False,
        )
    ]
    guard = ScopeGuard(rules)

    # In-scope redirect (relative path)
    r1 = guard.validate_redirect("https://target.com/login", "/dashboard")
    assert r1.is_in_scope is True

    # In-scope redirect (same domain absolute)
    r2 = guard.validate_redirect("https://target.com/login", "https://target.com/profile")
    assert r2.is_in_scope is True

    # Out-of-scope redirect to external OAuth provider
    r3 = guard.validate_redirect("https://target.com/login", "https://accounts.google.com/oauth")
    assert r3.is_in_scope is False
    assert "blocked by scope guard" in r3.denial_reason
