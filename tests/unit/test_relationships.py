"""Unit tests for Relationship graph models."""

from uuid import UUID, uuid4

from boundaryx.domain.relationships.models import (
    Relationship,
    RelationshipConfidence,
    RelationshipType,
)


def test_relationship_enums() -> None:
    """Verify RelationshipType and RelationshipConfidence enum members."""
    assert RelationshipType.OWNS == "OWNS"
    assert RelationshipType.MEMBER_OF == "MEMBER_OF"
    assert RelationshipType.HAS_ACCESS == "HAS_ACCESS"
    assert RelationshipType.DENIED_ACCESS == "DENIED_ACCESS"
    assert RelationshipType.MANAGES == "MANAGES"
    assert RelationshipType.PARENT_OF == "PARENT_OF"
    assert RelationshipType.TESTED_BY == "TESTED_BY"
    assert RelationshipType.VIOLATES == "VIOLATES"

    assert RelationshipConfidence.CONFIRMED == "CONFIRMED"
    assert RelationshipConfidence.USER_DEFINED == "USER_DEFINED"
    assert RelationshipConfidence.INFERRED == "INFERRED"
    assert RelationshipConfidence.UNKNOWN == "UNKNOWN"
    assert RelationshipConfidence.SUSPECTED_VIOLATION == "SUSPECTED_VIOLATION"


def test_relationship_model() -> None:
    """Test Relationship model creation and defaults."""
    src_id = uuid4()
    dst_id = uuid4()
    ev_id = uuid4()

    rel = Relationship(
        source_type="identity",
        source_id=src_id,
        target_type="resource",
        target_id=dst_id,
        relationship_type=RelationshipType.OWNS,
        confidence=RelationshipConfidence.CONFIRMED,
        evidence_ids=[ev_id],
        description="User explicitly provisioned as resource creator",
    )

    assert isinstance(rel.id, UUID)
    assert rel.source_type == "identity"
    assert rel.source_id == src_id
    assert rel.target_type == "resource"
    assert rel.target_id == dst_id
    assert rel.relationship_type == RelationshipType.OWNS
    assert rel.confidence == RelationshipConfidence.CONFIRMED
    assert rel.evidence_ids == [ev_id]
    assert rel.created_at is not None
