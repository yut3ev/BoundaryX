"""Resource and tenant membership domain models for BoundaryX.

Defines target assets, documents, API objects, and tenant memberships
subject to access control and boundary enforcement.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> datetime:
    """Return the current timestamp in UTC timezone."""
    return datetime.now(UTC)


class ResourceType(StrEnum):
    """Classification of target resources tested in authorization boundaries."""

    USER_PROFILE = "USER_PROFILE"
    PROJECT = "PROJECT"
    DOCUMENT = "DOCUMENT"
    ORDER = "ORDER"
    INVOICE = "INVOICE"
    API_RESOURCE = "API_RESOURCE"
    ORGANIZATION = "ORGANIZATION"
    CUSTOM = "CUSTOM"


class SensitivityLevel(StrEnum):
    """Information sensitivity classification for resources."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class Resource(BaseModel):
    """An application asset, entity, or endpoint target subject to access control."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique resource identifier")
    display_name: str = Field(description="Human-readable resource name")
    resource_type: ResourceType = Field(description="Classification of the resource")
    custom_type_name: str | None = Field(
        default=None,
        description="Custom resource type string if resource_type is CUSTOM",
    )
    owning_identity_id: UUID | None = Field(
        default=None,
        description="ID of the identity that owns or created this resource",
    )
    owning_tenant_id: UUID | None = Field(
        default=None,
        description="ID of the tenant partition this resource belongs to",
    )
    parent_resource_id: UUID | None = Field(
        default=None,
        description="Parent resource ID for hierarchical resource trees",
    )
    sensitivity: SensitivityLevel = Field(
        default=SensitivityLevel.INTERNAL,
        description="Sensitivity classification level",
    )
    associated_endpoints: list[str] = Field(
        default_factory=list,
        description="HTTP route templates or URLs accessing this resource (e.g. '/api/v1/orders/{id}')",
    )
    external_id: str = Field(
        description="External/application-level ID passed in HTTP requests/parameters (e.g. '1001', 'inv_xyz')",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary attributes, schema fields, or request parameters",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags for filtering and test categorization",
    )
    notes: str = Field(default="", description="Analyst notes and context")
    created_at: datetime = Field(default_factory=_utc_now, description="Creation timestamp (UTC)")
    updated_at: datetime = Field(default_factory=_utc_now, description="Last update timestamp (UTC)")


class TenantMembership(BaseModel):
    """Associates an identity with a specific tenant under a designated tenant role."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique membership record ID")
    tenant_id: UUID = Field(description="Tenant ID")
    identity_id: UUID = Field(description="Identity ID")
    role_in_tenant: str = Field(
        default="MEMBER",
        description="Designation within tenant (e.g. 'MEMBER', 'ADMIN', 'GUEST', 'BILLING')",
    )
    joined_at: datetime = Field(default_factory=_utc_now, description="Membership inception timestamp (UTC)")
