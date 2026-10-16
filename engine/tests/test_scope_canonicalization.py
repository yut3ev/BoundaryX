import pytest

from boundaryx.scope.canonicalizer import (
    ScopeCanonicalizationError,
    canonicalize_host,
    parse_and_canonicalize_target,
)


def test_canonicalize_host_lowercasing_and_trailing_dot():
    assert canonicalize_host("EXAMPLE.COM.") == "example.com"
    assert canonicalize_host("  Api.Target.Net  ") == "api.target.net"


def test_canonicalize_host_idn_punycode():
    # Arabic domain: مثال.مصر
    arabic_domain = "مثال.مصر"
    punycode = canonicalize_host(arabic_domain)
    assert punycode.startswith("xn--")
    assert punycode == canonicalize_host(punycode)  # Idempotent


def test_canonicalize_host_ipv4_and_ipv6():
    assert canonicalize_host("192.168.1.1") == "192.168.1.1"
    assert canonicalize_host("[2001:db8::1]") == "[2001:db8::1]"
    assert canonicalize_host("::1") == "[::1]"


def test_canonicalize_host_rejects_embedded_credentials():
    with pytest.raises(ScopeCanonicalizationError, match="embedded userinfo"):
        canonicalize_host("admin:password@target.com")


def test_canonicalize_empty_host_raises():
    with pytest.raises(ScopeCanonicalizationError, match="cannot be empty"):
        canonicalize_host("   ")


def test_parse_and_canonicalize_target_url():
    host, scheme, port, path = parse_and_canonicalize_target("https://API.Example.com:8443/v1/users?id=1")
    assert host == "api.example.com"
    assert scheme == "https"
    assert port == 8443
    assert path == "/v1/users"


def test_parse_and_canonicalize_target_bare_host_and_port():
    host, scheme, port, path = parse_and_canonicalize_target("staging.example.com:8080/api//docs")
    assert host == "staging.example.com"
    assert scheme is None
    assert port == 8080
    assert path == "/api/docs"
