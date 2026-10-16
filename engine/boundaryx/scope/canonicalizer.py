import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import unquote, urlsplit

import idna


class ScopeCanonicalizationError(ValueError):
    """Raised when an input cannot be safely canonicalized or contains deceptive tokens."""
    pass


def canonicalize_host(host_str: str) -> str:
    """
    Safely canonicalize a hostname or IP address string.
    - Strips whitespace and trailing DNS root dots
    - Rejects embedded credentials/userinfo (@)
    - Normalizes IPv4 and bracketed IPv6
    - Converts Unicode hostnames to lowercased IDNA/Punycode
    """
    if not host_str or not host_str.strip():
        raise ScopeCanonicalizationError("Host cannot be empty")

    cleaned = host_str.strip().lower()

    # Reject embedded userinfo
    if "@" in cleaned:
        raise ScopeCanonicalizationError("Host contains embedded userinfo/credentials (@), rejected for SSRF defense")

    # Remove trailing dot (DNS root)
    if cleaned.endswith("."):
        cleaned = cleaned[:-1]

    # Handle bracketed IPv6 literals
    if cleaned.startswith("[") and cleaned.endswith("]"):
        raw_ip = cleaned[1:-1]
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
            return f"[{ip_obj.compressed}]"
        except ValueError as err:
            raise ScopeCanonicalizationError(f"Invalid bracketed IPv6 address: {raw_ip}") from err

    # Check unbracketed IP
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            return f"[{ip_obj.compressed}]"
        return ip_obj.compressed
    except ValueError:
        pass

    # IDNA encode to prevent punycode confusion / homograph attacks
    try:
        encoded = idna.encode(cleaned, uts46=True).decode("ascii")
        return encoded.lower()
    except Exception as err:
        raise ScopeCanonicalizationError(f"Failed to encode hostname through IDNA/Punycode: {cleaned}") from err


def parse_and_canonicalize_target(target: str) -> Tuple[str, Optional[str], Optional[int], str]:
    """
    Parses a target string (which could be a URL or a bare host) into:
    (canonical_host, scheme, port, canonical_path)
    """
    raw = target.strip()
    if not raw:
        raise ScopeCanonicalizationError("Target string cannot be empty")

    # Check for embedded credentials/userinfo (@) in URL authority or bare host
    if "@" in raw:
        if "://" in raw:
            parts_check = urlsplit(raw)
            if parts_check.username or parts_check.password or ("@" in (parts_check.netloc or "")):
                raise ScopeCanonicalizationError("Target contains embedded credentials/userinfo (@), rejected for SSRF defense")
        else:
            authority = raw.split("/")[0]
            if "@" in authority:
                raise ScopeCanonicalizationError("Target contains embedded credentials/userinfo (@), rejected for SSRF defense")

    if "://" in raw:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower() if parts.scheme else None
        if not parts.hostname:
            raise ScopeCanonicalizationError(f"Could not extract hostname from URL: {target}")
        host = canonicalize_host(parts.hostname)
        port = parts.port
        path = unquote(parts.path) if parts.path else "/"
        # Normalize double slashes
        path = re.sub(r"/+", "/", path)
        return host, scheme, port, path
    else:
        # Bare host with possible port or path
        # Split path if present
        if "/" in raw:
            host_port, path_part = raw.split("/", 1)
            path = "/" + re.sub(r"/+", "/", unquote(path_part))
        else:
            host_port = raw
            path = "/"

        # Check port
        if ":" in host_port and not (host_port.startswith("[") and host_port.endswith("]")):
            # If IPv6 literal like [::1]:8080
            if host_port.startswith("["):
                idx = host_port.find("]:")
                if idx != -1:
                    host_part = host_port[: idx + 1]
                    port_str = host_port[idx + 2 :]
                    port = int(port_str)
                    host = canonicalize_host(host_part)
                    return host, None, port, path

            host_part, port_str = host_port.rsplit(":", 1)
            try:
                port = int(port_str)
                if not (1 <= port <= 65535):
                    raise ScopeCanonicalizationError(f"Port out of range: {port}")
            except ValueError as e:
                raise ScopeCanonicalizationError(f"Invalid port in target: {port_str}") from e
            host = canonicalize_host(host_part)
            return host, None, port, path
        else:
            host = canonicalize_host(host_port)
            return host, None, None, path
