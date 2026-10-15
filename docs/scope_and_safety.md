# Scope Enforcement & Safety Architecture

BoundaryX is engineered with a strict **security-first safety model**. Because authorization testing involves interacting with web applications and APIs, BoundaryX provides deterministic, fail-safe guardrails to ensure requests are strictly confined to authorized targets, sensitive credentials are never leaked, and testing activities never inadvertently disrupt infrastructure.

---

## 1. Scope Rule Matching & Evaluation Algorithm

The `ScopeManager` module (`boundaryx.security.scope`) enforces strict boundary checking. Every target URL must pass validation before any HTTP request is dispatched.

### 1.1 Hostname Canonicalization & Normalization

To prevent canonicalization bypasses and homograph attacks, hostnames undergo rigorous normalization:

```python
def normalize_hostname(hostname: str) -> str:
    # 1. Strip whitespace, convert to lowercase, remove trailing DNS root dot
    host = hostname.strip().rstrip(".").lower()
    
    # 2. Strip IPv6 bracket notation: "[::1]" -> "::1"
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
        
    # 3. Canonicalize IPv4 and IPv6 addresses via ipaddress library
    try:
        ip = ipaddress.ip_address(host)
        return str(ip)
    except ValueError:
        pass
        
    # 4. Punycode (IDNA) encoding to neutralize Unicode homograph confusion
    # Example: "tаrget.com" (with Cyrillic 'а') becomes "xn--trget-7qa.com"
    return idna.encode(host).decode("ascii")
```

### 1.2 Path Normalization

Paths are normalized using POSIX path semantics (`posixpath.normpath`):
- Resolves dot segments (`/api/v1/../v2/` -> `/api/v2/`).
- Resolves redundant slashes (`//api///v1/` -> `/api/v1/`).
- Enforces leading slashes and preserves trailing slashes.

### 1.3 Evaluation Order

When evaluating a URL via `ScopeManager.is_in_scope(url)`:

1. **Reject Embedded Credentials**: If the URL contains username/password delimiters (e.g. `https://attacker:secret@target.com/`), it is immediately rejected to prevent credential leakage and spoofing.
2. **Scheme Validation**: Only `http` and `https` schemes are permitted. Unsupported schemes (`file://`, `ftp://`, `gopher://`, `javascript:`) are rejected.
3. **Exclusion Rules Checked First**: All explicit exclusion rules are evaluated. If a target matches any exclusion rule (by hostname, scheme, port, or path prefix), the request is immediately denied.
4. **Allow Rules Checked**:
   - **Hostname Matching**: Must match the rule hostname exactly. Substring matching is strictly prohibited (`target.com` will NEVER match `attacker-target.com` or `target.com.attacker.org`). Explicit wildcards (`*.target.com`) match any valid subdomain (e.g. `sub.target.com`).
   - **Effective Port Matching**: Accounts for scheme defaults (HTTP defaults to port 80, HTTPS defaults to port 443).
   - **Path Prefix Matching**: Target path must match or be a subpath of the authorized prefix (e.g., prefix `/api/v1` matches `/api/v1/orders` and `/api/v1/` but does NOT match `/api/v10/orders`).
   - **Path Exclusions**: Path-level exclusions on the allow rule are verified.
5. **Default Deny**: If no allow rule matches, the URL is denied.

---

## 2. SSRF Protection & Redirect Safety

A common risk during automated security testing is **Server-Side Request Forgery (SSRF) and Client-Side Open Redirection**: an authorized target returns an HTTP redirect (`302 Found`, `301 Moved Permanently`) pointing to an internal infrastructure host (e.g. `http://169.254.169.254/latest/meta-data/` or `http://localhost:8080/admin`).

### 2.1 Disabling Blind Redirects
Standard HTTP clients follow redirects automatically. BoundaryX explicitly configures HTTPX with:
```python
follow_redirects = False
```

### 2.2 Independent Hop Verification
When an HTTP response returns a `3xx` redirect status code:
1. BoundaryX inspects the `Location` header.
2. Relative redirect targets are resolved against the original URL using `urllib.parse.urljoin`:
   ```python
   target_url = urljoin(original_url, redirect_location)
   ```
3. The resolved `target_url` is passed through `ScopeManager.validate_redirect(original_url, target_url)`.
4. If the destination is outside the authorized scope, the execution immediately halts, logs a `ScopeViolationError`, and marks the test as `BLOCKED_BY_SCOPE`.
5. Under no circumstances will BoundaryX follow a redirect to an unverified third-party host or private IP address unless explicitly declared in the scope rules.

---

## 3. Token-Bucket Rate Limiting & Concurrency Control

To prevent degrading target systems or triggering anti-automation rate limits, BoundaryX implements a thread-safe token-bucket rate limiter in `boundaryx.infrastructure.http.client.HttpClient`.

### 3.1 Token Bucket Algorithm
- **Capacity & Refill Rate**: Defined by `rate_limit_rps` (default: 5.0 to 20.0 requests per second).
- **Refill Mechanics**: On each request attempt, the elapsed time since the last refill is calculated, adding tokens proportionally up to the bucket capacity.
- **Backpressure**: If tokens are exhausted (`tokens < 1.0`), the thread sleeps until a token is replenished.
- **Cooperative Multitasking**: Supports both synchronous (`time.sleep`) and asynchronous (`await asyncio.sleep`) waiting.

### 3.2 Semaphore Concurrency Bounding
- Active HTTP testing requests are guarded by a `threading.Semaphore(max_concurrency)`.
- Prevents socket exhaustion and ensures test suites execute predictably without overwhelming local system resources.

### 3.3 Cancellation Support
- Cancellation tokens (`HttpClient.cancel()`) are checked at every lifecycle step:
  - Prior to rate-limit clearance.
  - Prior to establishing socket connections.
  - Before following redirects.
  - During response body streaming.

---

## 4. Automated Redaction & Credential Scrubbing

The `RedactionEngine` (`boundaryx.security.redaction`) ensures sensitive credentials, session tokens, and passwords are not leaked into test evidence, reports, or logs.

### 4.1 Redacted Headers
The following HTTP headers are scrubbed by default:
- `Authorization` (Bearer tokens, Basic auth, Digest)
- `Proxy-Authorization`
- `Cookie` and `Set-Cookie`
- `X-API-Key`, `api-key`, `x-auth-token`

### 4.2 Redacted Query Parameters & JSON Fields
Query parameters and JSON request/response body keys matching sensitive naming patterns are masked with `[REDACTED]`:
- `password`, `passwd`, `pwd`
- `token`, `access_token`, `refresh_token`, `id_token`
- `secret`, `client_secret`
- `session`, `session_id`, `sessionid`
- `api_key`, `apikey`, `key`
- `sig`, `signature`

### 4.3 Log Stream Scrubbing (`SecretFilter`)
Application logs pass through `SecretFilter` (`boundaryx.infrastructure.logging`), which matches and replaces:
- Bearer tokens: `Bearer [REDACTED]`
- Basic auth: `Basic [REDACTED]`
- JSON Web Tokens (JWT): `[REDACTED_JWT]`
- Key-value assignments: `password=[REDACTED]`, `api_key=[REDACTED]`
