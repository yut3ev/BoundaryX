"""Security layer exception definitions for BoundaryX."""


class SecurityError(Exception):
    """Base exception for all security-related errors in BoundaryX."""


class KeyManagementError(SecurityError):
    """Raised when encryption key generation, storage, or permissions fail."""


class DecryptionError(SecurityError):
    """Raised when decrypting secret data fails or data is corrupted."""


class ScopeViolationError(SecurityError):
    """Raised when an operation violates target scope boundary rules."""


class RedactionError(SecurityError):
    """Raised when data redaction processing encounters an unrecoverable error."""


class AuditLoggingError(SecurityError):
    """Raised when audit log persistence fails."""
