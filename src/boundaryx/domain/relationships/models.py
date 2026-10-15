"""Relationship graph domain models for BoundaryX.

Represents directional authorization links, ownership, group memberships,
observed access, and violation edges between entities.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> datetime:
    """Return the current timestamp in UTC timezone."""
    return datetime.now(UTC)


class RelationshipType(StrEnum):
    """Categorization of edges in authorization and boundary graphs."""

    OWNS = "OWNS"
    MEMBER_OF = "MEMBER_OF"
    HAS_ACCESS = "HAS_ACCESS"
    DENIED_ACCESS = "DENIED_ACCESS"
    MANAGES = "MANAGES"
    PARENT_OF = "PARENT_OF"
    TESTED_BY = "TESTED_BY"
    VIOLATES = "VIOLATES"


class RelationshipConfidence(StrEnum):
    """Confidence level in the validity of a relationship edge."""

    CONFIRMED = "CONFIRMED"
    USER_DEFINED = "USER_DEFINED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    SUSPECTED_VIOLATION = "SUSPECTED_VIOLATION"


class Relationship(BaseModel):
    """Directional relationship edge linking two domain entities."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique relationship edge identifier")
    source_type: str = Field(
        description="Type category of source node (e.g. 'identity', 'resource', 'tenant')",
    )
    source_id: UUID = Field(description="Unique ID of the source entity")
    target_type: str = Field(
        description="Type category of target node (e.g. 'resource', 'tenant', 'policy')",
    )
    target_id: UUID = Field(description="Unique ID of the target entity")
    relationship_type: RelationshipType = Field(
        description="Classification of relationship between source and target",
    )
    confidence: RelationshipConfidence = Field(
        default=RelationshipConfidence.USER_DEFINED,
        description="Confidence level or source of this relationship mapping",
    )
    evidence_ids: list[UUID] = Field(
        default_factory=list,
        description="Linked evidence records supporting this relationship",
    )
    description: str = Field(
        default="",
        description="Contextual notes explaining the relationship",
    )
    created_at: datetime = Field(
        default_factory=_utc_now,
        description="Relationship record creation timestamp (UTC)",
    )
