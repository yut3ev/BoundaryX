"""Identity and authentication profile domain models for BoundaryX.

Defines subjects (users, service accounts, roles) participating in authorization tests.
Sensitive credentials/secrets are intentionally decoupled and managed exclusively
through the security layer (keyring/vault).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> datetime:
    """Return the current timestamp in UTC timezone."""
    return datetime.now(UTC)


class RoleType(StrEnum):
    """Standardized identity role categories."""

    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    READ_ONLY = "READ_ONLY"
    EDITOR = "EDITOR"
    ADMIN = "ADMIN"
    TENANT_MEMBER = "TENANT_MEMBER"
    TENANT_OWNER = "TENANT_OWNER"
    CUSTOM = "CUSTOM"


class IdentityStatus(StrEnum):
    """Operational status of an identity profile."""

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    ARCHIVED = "ARCHIVED"


class AuthMethod(StrEnum):
    """Authentication mechanism utilized by the identity profile."""

    COOKIE = "COOKIE"
    BEARER_TOKEN = "BEARER_TOKEN"
    CUSTOM_HEADER = "CUSTOM_HEADER"
    BASIC_AUTH = "BASIC_AUTH"
    IMPORTED = "IMPORTED"


class AuthenticationProfile(BaseModel):
    """Profile describing authentication protocol and metadata.

    IMPORTANT: Plaintext secrets, tokens, and credentials are NEVER stored
    in this profile model. Secrets are managed and resolved dynamically
    via the BoundaryX Security Layer (keyring/encrypted vault).
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique profile identifier")
    name: str = Field(description="Descriptive profile name (e.g. 'Admin Bearer Auth')")
    auth_method: AuthMethod = Field(description="Authentication protocol used")
    header_name: str | None = Field(
        default=None,
        description="Custom header name if auth_method is CUSTOM_HEADER (e.g. 'X-API-Key')",
    )
    description: str = Field(default="", description="Profile documentation notes")
    created_at: datetime = Field(default_factory=_utc_now, description="Creation timestamp (UTC)")
    updated_at: datetime = Field(default_factory=_utc_now, description="Last update timestamp (UTC)")


class Identity(BaseModel):
    """Subject identity used for authorization matrix and boundary evaluation."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique identity identifier")
    name: str = Field(description="Identity username, email, or principal identifier")
    description: str = Field(default="", description="Role or identity context description")
    role_type: RoleType = Field(
        default=RoleType.AUTHENTICATED,
        description="Assigned role category for authorization checks",
    )
    custom_role_name: str | None = Field(
        default=None,
        description="Custom role designation when role_type is CUSTOM",
    )
    tenant_ids: list[UUID] = Field(
        default_factory=list,
        description="IDs of tenants this identity is associated with",
    )
    auth_profile_id: UUID | None = Field(
        default=None,
        description="Linked authentication profile ID (optional)",
    )
    status: IdentityStatus = Field(
        default=IdentityStatus.ACTIVE,
        description="Current status of the identity",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Categorical tags for filtering and batch execution",
    )
    notes: str = Field(default="", description="Analyst testing notes")
    created_at: datetime = Field(default_factory=_utc_now, description="Creation timestamp (UTC)")
    updated_at: datetime = Field(default_factory=_utc_now, description="Last update timestamp (UTC)")

    @property
    def is_active(self) -> bool:
        """Return True if identity is in ACTIVE status."""
        return self.status == IdentityStatus.ACTIVE

    @property
    def is_anonymous(self) -> bool:
        """Return True if identity role is ANONYMOUS."""
        return self.role_type == RoleType.ANONYMOUS

    @property
    def is_admin(self) -> bool:
        """Return True if identity has ADMIN role."""
        return self.role_type == RoleType.ADMIN

    def has_tenant(self, tenant_id: UUID) -> bool:
        """Return True if identity belongs to the specified tenant ID."""
        return tenant_id in self.tenant_ids


class RoleAssignment(BaseModel):
    """Explicit mapping linking an identity to a scoped role."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique assignment identifier")
    identity_id: UUID = Field(description="ID of the identity")
    role_name: str = Field(description="Name of the role assigned")
    scope_description: str = Field(
        default="",
        description="Scope or project boundary where the role applies",
    )
    assigned_at: datetime = Field(default_factory=_utc_now, description="Assignment timestamp (UTC)")
