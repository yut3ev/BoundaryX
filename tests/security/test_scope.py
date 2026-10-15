"""Tests for ScopeManager URL validation, boundary enforcement, and security rules."""

import threading

from boundaryx.security.scope import ScopeManager, ScopeRule, normalize_hostname, normalize_path


def test_normalize_hostname_cases() -> None:
    # Basic domain normalization
    assert normalize_hostname("Example.COM.") == "example.com"
    # IPv4
    assert normalize_hostname("192.168.1.1") == "192.168.1.1"
    # IPv6 canonical normalization
    assert normalize_hostname("[0:0:0:0:0:0:0:1]") == "::1"
    assert normalize_hostname("::1") == "::1"
    # IDN punycode
    assert normalize_hostname("bühler.com") == "xn--bhler-kva.com"
    assert normalize_hostname("xn--bhler-kva.com") == "xn--bhler-kva.com"


def test_normalize_path_cases() -> None:
    assert normalize_path("") == "/"
    assert normalize_path("api/v1") == "/api/v1"
    assert normalize_path("/api/../admin") == "/admin"
    assert normalize_path("/api/v1/") == "/api/v1/"


def test_exact_hostname_matching_no_substring() -> None:
    rule = ScopeRule(hostname="target.com")
    mgr = ScopeManager(rules=[rule])

    # Exact match succeeds
    allowed, _ = mgr.is_in_scope("https://target.com/profile")
    assert allowed is True

    # Subdomain does NOT match (no substring match!)
    allowed, reason = mgr.is_in_scope("https://evil.target.com/profile")
    assert allowed is False
    assert "does not match" in reason

    # Suffix domain does NOT match
    allowed, reason = mgr.is_in_scope("https://target.com.attacker.com/profile")
    assert allowed is False
    assert "does not match" in reason

    # Substring in domain name does NOT match
    allowed, reason = mgr.is_in_scope("https://nottarget.com/profile")
    assert allowed is False
    assert "does not match" in reason


def test_wildcard_subdomain_matching() -> None:
    rule = ScopeRule(hostname="*.target.com")
    mgr = ScopeManager(rules=[rule])

    # Valid subdomains match
    allowed, _ = mgr.is_in_scope("https://api.target.com/test")
    assert allowed is True

    allowed, _ = mgr.is_in_scope("https://sub.domain.target.com/test")
    assert allowed is True

    # Base domain does NOT match *.target.com
    allowed, _ = mgr.is_in_scope("https://target.com/test")
    assert allowed is False

    # Phishing domain does NOT match
    allowed, _ = mgr.is_in_scope("https://evil-target.com/test")
    assert allowed is False


def test_scheme_and_port_matching() -> None:
    # Rule with https and default port 443
    rule_https = ScopeRule(hostname="target.com", scheme="https")
    mgr = ScopeManager(rules=[rule_https])

    # HTTPS matches
    allowed, _ = mgr.is_in_scope("https://target.com/login")
    assert allowed is True

    # HTTP rejected due to scheme mismatch
    allowed, _ = mgr.is_in_scope("http://target.com/login")
    assert allowed is False

    # HTTPS with non-standard port 8443 rejected when expecting default
    allowed, _ = mgr.is_in_scope("https://target.com:8443/login")
    assert allowed is False

    # Rule with explicit custom port
    rule_custom_port = ScopeRule(hostname="target.com", port=8080, scheme="http")
    mgr2 = ScopeManager(rules=[rule_custom_port])

    allowed, _ = mgr2.is_in_scope("http://target.com:8080/api")
    assert allowed is True

    allowed, _ = mgr2.is_in_scope("http://target.com:80/api")
    assert allowed is False


def test_rejection_of_embedded_credentials() -> None:
    rule = ScopeRule(hostname="target.com")
    mgr = ScopeManager(rules=[rule])

    allowed, reason = mgr.is_in_scope("https://admin:secret@target.com/dashboard")
    assert allowed is False
    assert "embedded credentials" in reason


def test_exclusion_rule_priority() -> None:
    allow_rule = ScopeRule(hostname="target.com")
    excl_rule = ScopeRule(hostname="target.com", path_prefix="/admin", is_exclusion=True, notes="Admin is forbidden")
    mgr = ScopeManager(rules=[allow_rule, excl_rule])

    # General path allowed
    allowed, _ = mgr.is_in_scope("https://target.com/user/profile")
    assert allowed is True

    # Excluded path blocked even though allow_rule matches hostname
    allowed, reason = mgr.is_in_scope("https://target.com/admin/settings")
    assert allowed is False
    assert "blocked by exclusion rule" in reason


def test_path_prefix_and_excluded_paths() -> None:
    rule = ScopeRule(
        hostname="target.com",
        path_prefix="/api/v1",
        excluded_paths=["/api/v1/internal", "/api/v1/logout"],
    )
    mgr = ScopeManager(rules=[rule])

    # Valid prefix
    allowed, _ = mgr.is_in_scope("https://target.com/api/v1/users")
    assert allowed is True

    # Prefix mismatch
    allowed, reason = mgr.is_in_scope("https://target.com/api/v2/users")
    assert allowed is False

    # Partial prefix match that is not a boundary (/api/v1-legacy)
    allowed, reason = mgr.is_in_scope("https://target.com/api/v1-legacy/users")
    assert allowed is False

    # Excluded path
    allowed, reason = mgr.is_in_scope("https://target.com/api/v1/internal/debug")
    assert allowed is False
    assert "explicitly excluded" in reason


def test_ipv4_and_ipv6_scope() -> None:
    mgr = ScopeManager(
        rules=[
            ScopeRule(hostname="127.0.0.1", scheme="http", port=8080),
            ScopeRule(hostname="::1", scheme="http", port=9000),
        ]
    )

    # IPv4 match
    allowed, _ = mgr.is_in_scope("http://127.0.0.1:8080/status")
    assert allowed is True

    # IPv6 bracketed match
    allowed, _ = mgr.is_in_scope("http://[::1]:9000/status")
    assert allowed is True

    # Different port
    allowed, _ = mgr.is_in_scope("http://127.0.0.1:8081/status")
    assert allowed is False


def test_idn_punycode_scope() -> None:
    mgr = ScopeManager(rules=[ScopeRule(hostname="bühler.com")])

    # Test with Unicode URL
    allowed1, _ = mgr.is_in_scope("https://bühler.com/products")
    assert allowed1 is True

    # Test with Punycode URL
    allowed2, _ = mgr.is_in_scope("https://xn--bhler-kva.com/products")
    assert allowed2 is True


def test_validate_redirect() -> None:
    mgr = ScopeManager(
        rules=[
            ScopeRule(hostname="auth.target.com"),
            ScopeRule(hostname="app.target.com"),
        ]
    )

    orig = "https://auth.target.com/login"

    # In-scope relative redirect
    allowed, _ = mgr.validate_redirect(orig, "/dashboard")
    assert allowed is True

    # In-scope absolute redirect
    allowed, _ = mgr.validate_redirect(orig, "https://app.target.com/welcome")
    assert allowed is True

    # Out-of-scope open redirect attempt
    allowed, reason = mgr.validate_redirect(orig, "https://evil.com/phish")
    assert allowed is False
    assert "out of scope" in reason


def test_validate_all_urls_and_preview() -> None:
    mgr = ScopeManager(
        rules=[
            ScopeRule(hostname="target.com"),
            ScopeRule(hostname="target.com", path_prefix="/secret", is_exclusion=True),
        ]
    )

    urls = [
        "https://target.com/api",
        "https://target.com/secret",
        "https://unauthorized.org",
    ]
    results = mgr.validate_all_urls(urls)
    assert len(results) == 3
    assert results[0][1] is True
    assert results[1][1] is False
    assert results[2][1] is False

    preview = mgr.preview_scope()
    assert preview["total_rules"] == 2
    assert preview["allow_rules_count"] == 1
    assert preview["exclusion_rules_count"] == 1
    assert "target.com" in preview["authorized_hostnames"]


def test_scope_manager_thread_safety() -> None:
    mgr = ScopeManager()
    errors = []

    def worker(worker_id: int) -> None:
        try:
            for i in range(50):
                host = f"host-{worker_id}-{i}.com"
                mgr.add_rule(ScopeRule(hostname=host))
                mgr.is_in_scope(f"https://{host}/test")
                mgr.preview_scope()
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(mgr.get_rules()) == 250
