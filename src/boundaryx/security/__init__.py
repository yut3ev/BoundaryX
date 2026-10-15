"""Security layer package for BoundaryX."""

from boundaryx.security.audit import (
    BACKUP_CREATED,
    BACKUP_RESTORED,
    CREDENTIAL_CHANGED,
    FINDING_STATUS_CHANGED,
    IDENTITY_MODIFIED,
    POLICY_CHANGED,
    PROJECT_CREATED,
    PROJECT_MODIFIED,
    REPORT_EXPORTED,
    SCOPE_CHANGED,
    SECURITY_ERROR,
    TEST_STARTED,
    TEST_STOPPED,
    AuditLogger,
)
from boundaryx.security.exceptions import (
    AuditLoggingError,
    DecryptionError,
    KeyManagementError,
    RedactionError,
    ScopeViolationError,
    SecurityError,
)
from boundaryx.security.redaction import RedactionEngine, RedactionRule
from boundaryx.security.scope import ScopeManager, ScopeRule
from boundaryx.security.secrets import SecretManager

__all__ = [
    "SecretManager",
    "ScopeManager",
    "ScopeRule",
    "RedactionEngine",
    "RedactionRule",
    "AuditLogger",
    "SecurityError",
    "KeyManagementError",
    "DecryptionError",
    "ScopeViolationError",
    "RedactionError",
    "AuditLoggingError",
    "PROJECT_CREATED",
    "PROJECT_MODIFIED",
    "SCOPE_CHANGED",
    "IDENTITY_MODIFIED",
    "CREDENTIAL_CHANGED",
    "POLICY_CHANGED",
    "TEST_STARTED",
    "TEST_STOPPED",
    "FINDING_STATUS_CHANGED",
    "REPORT_EXPORTED",
    "BACKUP_CREATED",
    "BACKUP_RESTORED",
    "SECURITY_ERROR",
]
