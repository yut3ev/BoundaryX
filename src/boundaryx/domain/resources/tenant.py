"""Tenant domain model for BoundaryX multi-tenant authorization testing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> datetime:
    """Return the current timestamp in UTC timezone."""
    return datetime.now(UTC)


class Tenant(BaseModel):
    """Multi-tenant boundary container.

    Represents an organizational tenant or workspace partition. Used to verify
    tenant isolation boundaries and detect cross-tenant data leaks.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique tenant identifier")
    name: str = Field(description="Tenant or organization name")
    description: str = Field(default="", description="Tenant notes or description")
    owner_identity_id: UUID | None = Field(
        default=None,
        description="ID of the identity that owns or administers this tenant",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary tenant metadata (e.g. slug, tier, domain)",
    )
    created_at: datetime = Field(default_factory=_utc_now, description="Creation timestamp (UTC)")
    updated_at: datetime = Field(default_factory=_utc_now, description="Last update timestamp (UTC)")
