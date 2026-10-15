"""Unit tests for Resource and Tenant domain models."""

from uuid import UUID, uuid4

from boundaryx.domain.resources.models import (
    Resource,
    ResourceType,
    SensitivityLevel,
    TenantMembership,
)
from boundaryx.domain.resources.tenant import Tenant


def test_resource_type_enum() -> None:
    """Verify all required ResourceType enum members exist."""
    assert ResourceType.USER_PROFILE == "USER_PROFILE"
    assert ResourceType.PROJECT == "PROJECT"
    assert ResourceType.DOCUMENT == "DOCUMENT"
    assert ResourceType.ORDER == "ORDER"
    assert ResourceType.INVOICE == "INVOICE"
    assert ResourceType.API_RESOURCE == "API_RESOURCE"
    assert ResourceType.ORGANIZATION == "ORGANIZATION"
    assert ResourceType.CUSTOM == "CUSTOM"


def test_sensitivity_level_enum() -> None:
    """Verify all required SensitivityLevel enum members exist."""
    assert SensitivityLevel.PUBLIC == "PUBLIC"
    assert SensitivityLevel.INTERNAL == "INTERNAL"
    assert SensitivityLevel.CONFIDENTIAL == "CONFIDENTIAL"
    assert SensitivityLevel.RESTRICTED == "RESTRICTED"


def test_tenant_creation() -> None:
    """Test Tenant model instantiation and defaults."""
    owner_id = uuid4()
    tenant = Tenant(
        name="Cyberdyne Systems",
        description="R&D Tenant",
        owner_identity_id=owner_id,
        metadata={"region": "us-east-1", "tier": "enterprise"},
    )
    assert isinstance(tenant.id, UUID)
    assert tenant.name == "Cyberdyne Systems"
    assert tenant.owner_identity_id == owner_id
    assert tenant.metadata["region"] == "us-east-1"
    assert tenant.created_at is not None
    assert tenant.updated_at is not None


def test_resource_creation() -> None:
    """Test Resource model instantiation and relationships."""
    owner_id = uuid4()
    tenant_id = uuid4()
    parent_id = uuid4()

    resource = Resource(
        display_name="Confidential Financial Report 2026",
        resource_type=ResourceType.DOCUMENT,
        owning_identity_id=owner_id,
        owning_tenant_id=tenant_id,
        parent_resource_id=parent_id,
        sensitivity=SensitivityLevel.CONFIDENTIAL,
        associated_endpoints=["/api/v1/documents/{id}", "/api/v1/documents/{id}/export"],
        external_id="DOC-9921",
        metadata={"file_format": "pdf", "size_kb": 1024},
        tags=["finance", "q3"],
        notes="Subject to Sarbanes-Oxley controls",
    )

    assert isinstance(resource.id, UUID)
    assert resource.display_name == "Confidential Financial Report 2026"
    assert resource.resource_type == ResourceType.DOCUMENT
    assert resource.owning_identity_id == owner_id
    assert resource.owning_tenant_id == tenant_id
    assert resource.parent_resource_id == parent_id
    assert resource.sensitivity == SensitivityLevel.CONFIDENTIAL
    assert resource.external_id == "DOC-9921"
    assert len(resource.associated_endpoints) == 2
    assert resource.tags == ["finance", "q3"]


def test_tenant_membership() -> None:
    """Test TenantMembership association model."""
    tenant_id = uuid4()
    user_id = uuid4()

    membership = TenantMembership(
        tenant_id=tenant_id,
        identity_id=user_id,
        role_in_tenant="ADMIN",
    )
    assert isinstance(membership.id, UUID)
    assert membership.tenant_id == tenant_id
    assert membership.identity_id == user_id
    assert membership.role_in_tenant == "ADMIN"
    assert membership.joined_at is not None
