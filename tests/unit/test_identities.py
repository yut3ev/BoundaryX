"""Unit tests for Identity domain models."""

from uuid import UUID, uuid4

from boundaryx.domain.identities.models import (
    AuthenticationProfile,
    AuthMethod,
    Identity,
    IdentityStatus,
    RoleAssignment,
    RoleType,
)


def test_role_type_enum_members() -> None:
    """Verify all required RoleType enum members exist."""
    assert RoleType.ANONYMOUS == "ANONYMOUS"
    assert RoleType.AUTHENTICATED == "AUTHENTICATED"
    assert RoleType.READ_ONLY == "READ_ONLY"
    assert RoleType.EDITOR == "EDITOR"
    assert RoleType.ADMIN == "ADMIN"
    assert RoleType.TENANT_MEMBER == "TENANT_MEMBER"
    assert RoleType.TENANT_OWNER == "TENANT_OWNER"
    assert RoleType.CUSTOM == "CUSTOM"


def test_identity_status_enum_members() -> None:
    """Verify all required IdentityStatus enum members exist."""
    assert IdentityStatus.ACTIVE == "ACTIVE"
    assert IdentityStatus.INACTIVE == "INACTIVE"
    assert IdentityStatus.ARCHIVED == "ARCHIVED"


def test_auth_method_enum_members() -> None:
    """Verify all required AuthMethod enum members exist."""
    assert AuthMethod.COOKIE == "COOKIE"
    assert AuthMethod.BEARER_TOKEN == "BEARER_TOKEN"
    assert AuthMethod.CUSTOM_HEADER == "CUSTOM_HEADER"
    assert AuthMethod.BASIC_AUTH == "BASIC_AUTH"
    assert AuthMethod.IMPORTED == "IMPORTED"


def test_authentication_profile_creation() -> None:
    """Test creation and default fields of AuthenticationProfile."""
    profile = AuthenticationProfile(
        name="API Key Auth",
        auth_method=AuthMethod.CUSTOM_HEADER,
        header_name="X-API-Key",
        description="Used for external integrations",
    )
    assert isinstance(profile.id, UUID)
    assert profile.name == "API Key Auth"
    assert profile.auth_method == AuthMethod.CUSTOM_HEADER
    assert profile.header_name == "X-API-Key"
    assert profile.description == "Used for external integrations"
    assert profile.created_at is not None
    assert profile.updated_at is not None


def test_identity_creation_and_properties() -> None:
    """Test creation and helper properties of Identity model."""
    tenant_id = uuid4()
    profile_id = uuid4()

    identity = Identity(
        name="bob_operator",
        description="Operator user in primary tenant",
        role_type=RoleType.ADMIN,
        tenant_ids=[tenant_id],
        auth_profile_id=profile_id,
        tags=["production", "tier1"],
        notes="High privilege account",
    )

    assert isinstance(identity.id, UUID)
    assert identity.name == "bob_operator"
    assert identity.status == IdentityStatus.ACTIVE
    assert identity.is_active is True
    assert identity.is_admin is True
    assert identity.is_anonymous is False
    assert identity.has_tenant(tenant_id) is True
    assert identity.has_tenant(uuid4()) is False
    assert identity.tags == ["production", "tier1"]


def test_anonymous_identity() -> None:
    """Test anonymous identity behavior."""
    anon = Identity(name="unauthenticated_visitor", role_type=RoleType.ANONYMOUS)
    assert anon.is_anonymous is True
    assert anon.is_admin is False


def test_role_assignment() -> None:
    """Test RoleAssignment model."""
    user_id = uuid4()
    assignment = RoleAssignment(
        identity_id=user_id,
        role_name="ProjectLead",
        scope_description="Workspace Alpha",
    )
    assert isinstance(assignment.id, UUID)
    assert assignment.identity_id == user_id
    assert assignment.role_name == "ProjectLead"
    assert assignment.scope_description == "Workspace Alpha"
    assert assignment.assigned_at is not None
