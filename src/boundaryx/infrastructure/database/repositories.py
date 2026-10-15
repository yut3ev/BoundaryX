"""Repository classes for BoundaryX database infrastructure layer.

This module provides specialized repository classes implementing CRUD operations,
filtering, bulk ingestion, hash verification, and relationships for all
underlying database models.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from boundaryx.infrastructure.database.models import (
    AppSettingModel,
    AuditEventModel,
    AuthenticationProfileModel,
    EvidenceModel,
    FindingModel,
    IdentityModel,
    PolicyModel,
    ProjectModel,
    ResourceModel,
    ScopeRuleModel,
    TenantMembershipModel,
    TenantModel,
    TestCaseModel,
    TestExecutionModel,
    TrafficRecordModel,
    utcnow,
)

logger = logging.getLogger(__name__)


def handle_session(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to allow passing session explicitly as first positional arg,
    keyword arg 'session', or falling back to self._session."""

    @functools.wraps(func)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        session = kwargs.pop("session", None)
        if session is None and args and isinstance(args[0], Session):
            session = args[0]
            args = args[1:]
        if session is None:
            session = getattr(self, "_session", None)
        if session is None:
            raise ValueError(
                f"A database Session must be provided to {func.__name__} either as the "
                "first argument, as 'session' kwarg, or via repository initialization."
            )
        return func(self, session, *args, **kwargs)

    return wrapper


class BaseRepository:
    """Base repository class providing session storage and helper utilities."""

    def __init__(self, session: Session | None = None) -> None:
        """Initialize the repository optionally bound to a default session.

        Args:
            session: Optional SQLAlchemy session.
        """
        self._session = session


class ProjectRepository(BaseRepository):
    """Repository managing ProjectModel persistence and lifecycle."""

    @handle_session
    def create(
        self,
        session: Session,
        name: str,
        description: str | None = None,
        settings: dict[str, Any] | None = None,
        project_id: str | None = None,
        **kwargs: Any,
    ) -> ProjectModel:
        """Create a new project.

        Args:
            session: Database session.
            name: Project name.
            description: Optional project description.
            settings: Optional configuration settings dictionary.
            project_id: Optional specific UUID string.
            **kwargs: Additional parameters, supports 'id' alias.

        Returns:
            Created ProjectModel instance.
        """
        project = ProjectModel(
            name=name,
            description=description,
            settings=settings or {},
        )
        target_id = project_id or kwargs.get("id")
        if target_id is not None:
            project.id = str(target_id)
        session.add(project)
        session.flush()
        return project

    @handle_session
    def get_by_id(self, session: Session, project_id: str) -> ProjectModel | None:
        """Retrieve a project by its unique ID.

        Args:
            session: Database session.
            project_id: Project UUID string.

        Returns:
            ProjectModel if found, None otherwise.
        """
        return session.get(ProjectModel, str(project_id))

    @handle_session
    def list_all(
        self,
        session: Session,
        include_archived: bool = False,
    ) -> list[ProjectModel]:
        """List all projects.

        Args:
            session: Database session.
            include_archived: Whether to include archived projects.

        Returns:
            List of ProjectModel instances.
        """
        stmt = select(ProjectModel)
        if not include_archived:
            stmt = stmt.where(ProjectModel.archived.is_(False))
        stmt = stmt.order_by(ProjectModel.created_at.desc())
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def update(
        self,
        session: Session,
        project_id: str,
        **kwargs: Any,
    ) -> ProjectModel | None:
        """Update fields on an existing project.

        Args:
            session: Database session.
            project_id: Project UUID string.
            **kwargs: Attributes to update.

        Returns:
            Updated ProjectModel if found, None otherwise.
        """
        project = session.get(ProjectModel, str(project_id))
        if project is None:
            return None
        for key, value in kwargs.items():
            if hasattr(project, key):
                setattr(project, key, value)
        project.updated_at = utcnow()
        session.flush()
        return project

    @handle_session
    def archive(self, session: Session, project_id: str) -> ProjectModel | None:
        """Archive a project by setting archived=True.

        Args:
            session: Database session.
            project_id: Project UUID string.

        Returns:
            Archived ProjectModel if found, None otherwise.
        """
        project = session.get(ProjectModel, str(project_id))
        if project is None:
            return None
        project.archived = True
        project.updated_at = utcnow()
        session.flush()
        return project

    @handle_session
    def delete(self, session: Session, project_id: str) -> bool:
        """Hard-delete a project and cascade to all related records.

        Args:
            session: Database session.
            project_id: Project UUID string.

        Returns:
            True if deleted, False if project was not found.
        """
        project = session.get(ProjectModel, str(project_id))
        if project is None:
            return False
        session.delete(project)
        session.flush()
        return True


class ScopeRuleRepository(BaseRepository):
    """Repository managing ScopeRuleModel inclusion/exclusion rules."""

    @handle_session
    def create(
        self,
        session: Session,
        project_id: str,
        hostname: str,
        port: int | None = None,
        scheme: str | None = None,
        path_prefix: str | None = None,
        path_exclusions: list[str] | None = None,
        is_excluded: bool = False,
        notes: str | None = None,
        rule_id: str | None = None,
        **kwargs: Any,
    ) -> ScopeRuleModel:
        """Create a new scope rule."""
        rule = ScopeRuleModel(
            project_id=str(project_id),
            hostname=hostname,
            port=port,
            scheme=scheme,
            path_prefix=path_prefix,
            path_exclusions=path_exclusions or [],
            is_excluded=is_excluded,
            notes=notes,
        )
        target_id = rule_id or kwargs.get("id")
        if target_id is not None:
            rule.id = str(target_id)
        session.add(rule)
        session.flush()
        return rule

    @handle_session
    def get_by_id(self, session: Session, rule_id: str) -> ScopeRuleModel | None:
        """Retrieve a scope rule by ID."""
        return session.get(ScopeRuleModel, str(rule_id))

    @handle_session
    def list_by_project(self, session: Session, project_id: str) -> list[ScopeRuleModel]:
        """List all scope rules for a project."""
        stmt = (
            select(ScopeRuleModel)
            .where(ScopeRuleModel.project_id == str(project_id))
            .order_by(ScopeRuleModel.created_at.asc())
        )
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def update(
        self,
        session: Session,
        rule_id: str,
        **kwargs: Any,
    ) -> ScopeRuleModel | None:
        """Update a scope rule."""
        rule = session.get(ScopeRuleModel, str(rule_id))
        if rule is None:
            return None
        for key, value in kwargs.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        session.flush()
        return rule

    @handle_session
    def delete(self, session: Session, rule_id: str) -> bool:
        """Delete a scope rule."""
        rule = session.get(ScopeRuleModel, str(rule_id))
        if rule is None:
            return False
        session.delete(rule)
        session.flush()
        return True


class IdentityRepository(BaseRepository):
    """Repository managing IdentityModel subjects."""

    @handle_session
    def create(
        self,
        session: Session,
        project_id: str,
        name: str,
        role_type: str,
        description: str | None = None,
        custom_role_name: str | None = None,
        status: str = "active",
        tags: list[str] | None = None,
        notes: str | None = None,
        identity_id: str | None = None,
        **kwargs: Any,
    ) -> IdentityModel:
        """Create a new identity/role subject."""
        identity = IdentityModel(
            project_id=str(project_id),
            name=name,
            role_type=role_type,
            description=description,
            custom_role_name=custom_role_name,
            status=status,
            tags=tags or [],
            notes=notes,
        )
        target_id = identity_id or kwargs.get("id")
        if target_id is not None:
            identity.id = str(target_id)
        session.add(identity)
        session.flush()
        return identity

    @handle_session
    def get_by_id(self, session: Session, identity_id: str) -> IdentityModel | None:
        """Retrieve an identity by ID."""
        return session.get(IdentityModel, str(identity_id))

    @handle_session
    def list_by_project(
        self,
        session: Session,
        project_id: str,
        filters: dict[str, Any] | None = None,
    ) -> list[IdentityModel]:
        """List identities for a project, optionally filtered by attributes."""
        stmt = select(IdentityModel).where(IdentityModel.project_id == str(project_id))
        if filters:
            if "role_type" in filters:
                stmt = stmt.where(IdentityModel.role_type == filters["role_type"])
            if "status" in filters:
                stmt = stmt.where(IdentityModel.status == filters["status"])
            if "name" in filters:
                stmt = stmt.where(IdentityModel.name == filters["name"])
        stmt = stmt.order_by(IdentityModel.name.asc())
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def update(
        self,
        session: Session,
        identity_id: str,
        **kwargs: Any,
    ) -> IdentityModel | None:
        """Update an identity."""
        identity = session.get(IdentityModel, str(identity_id))
        if identity is None:
            return None
        for key, value in kwargs.items():
            if hasattr(identity, key):
                setattr(identity, key, value)
        identity.updated_at = utcnow()
        session.flush()
        return identity

    @handle_session
    def delete(self, session: Session, identity_id: str) -> bool:
        """Delete an identity."""
        identity = session.get(IdentityModel, str(identity_id))
        if identity is None:
            return False
        session.delete(identity)
        session.flush()
        return True


class AuthProfileRepository(BaseRepository):
    """Repository managing AuthenticationProfileModel configurations."""

    @handle_session
    def create(
        self,
        session: Session,
        project_id: str,
        name: str,
        auth_method: str,
        header_name: str | None = None,
        description: str | None = None,
        profile_id: str | None = None,
        **kwargs: Any,
    ) -> AuthenticationProfileModel:
        """Create a new authentication profile."""
        profile = AuthenticationProfileModel(
            project_id=str(project_id),
            name=name,
            auth_method=auth_method,
            header_name=header_name,
            description=description,
        )
        target_id = profile_id or kwargs.get("id")
        if target_id is not None:
            profile.id = str(target_id)
        session.add(profile)
        session.flush()
        return profile

    @handle_session
    def get_by_id(self, session: Session, profile_id: str) -> AuthenticationProfileModel | None:
        """Retrieve an authentication profile by ID."""
        return session.get(AuthenticationProfileModel, str(profile_id))

    @handle_session
    def list_by_project(self, session: Session, project_id: str) -> list[AuthenticationProfileModel]:
        """List all authentication profiles for a project."""
        stmt = (
            select(AuthenticationProfileModel)
            .where(AuthenticationProfileModel.project_id == str(project_id))
            .order_by(AuthenticationProfileModel.name.asc())
        )
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def update(
        self,
        session: Session,
        profile_id: str,
        **kwargs: Any,
    ) -> AuthenticationProfileModel | None:
        """Update an authentication profile."""
        profile = session.get(AuthenticationProfileModel, str(profile_id))
        if profile is None:
            return None
        for key, value in kwargs.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
        profile.updated_at = utcnow()
        session.flush()
        return profile

    @handle_session
    def delete(self, session: Session, profile_id: str) -> bool:
        """Delete an authentication profile."""
        profile = session.get(AuthenticationProfileModel, str(profile_id))
        if profile is None:
            return False
        session.delete(profile)
        session.flush()
        return True


class TenantRepository(BaseRepository):
    """Repository managing TenantModel and TenantMembershipModel."""

    @handle_session
    def create_tenant(
        self,
        session: Session,
        project_id: str,
        name: str,
        description: str | None = None,
        owner_identity_id: str | None = None,
        metadata_json: dict[str, Any] | None = None,
        tenant_id: str | None = None,
        **kwargs: Any,
    ) -> TenantModel:
        """Create a new tenant."""
        tenant = TenantModel(
            project_id=str(project_id),
            name=name,
            description=description,
            owner_identity_id=str(owner_identity_id) if owner_identity_id else None,
            metadata_json=metadata_json or {},
        )
        target_id = tenant_id or kwargs.get("id")
        if target_id is not None:
            tenant.id = str(target_id)
        session.add(tenant)
        session.flush()
        return tenant

    create = create_tenant

    @handle_session
    def get_tenant_by_id(self, session: Session, tenant_id: str) -> TenantModel | None:
        """Retrieve a tenant by ID."""
        return session.get(TenantModel, str(tenant_id))

    get_by_id = get_tenant_by_id

    @handle_session
    def list_tenants_by_project(self, session: Session, project_id: str) -> list[TenantModel]:
        """List all tenants in a project."""
        stmt = select(TenantModel).where(TenantModel.project_id == str(project_id)).order_by(TenantModel.name.asc())
        return list(session.execute(stmt).scalars().all())

    list_by_project = list_tenants_by_project

    @handle_session
    def update_tenant(
        self,
        session: Session,
        tenant_id: str,
        **kwargs: Any,
    ) -> TenantModel | None:
        """Update tenant properties."""
        tenant = session.get(TenantModel, str(tenant_id))
        if tenant is None:
            return None
        for key, value in kwargs.items():
            if hasattr(tenant, key):
                setattr(tenant, key, value)
        tenant.updated_at = utcnow()
        session.flush()
        return tenant

    update = update_tenant

    @handle_session
    def delete_tenant(self, session: Session, tenant_id: str) -> bool:
        """Delete a tenant."""
        tenant = session.get(TenantModel, str(tenant_id))
        if tenant is None:
            return False
        session.delete(tenant)
        session.flush()
        return True

    delete = delete_tenant

    @handle_session
    def add_member(
        self,
        session: Session,
        tenant_id: str,
        identity_id: str,
        role_in_tenant: str = "member",
        membership_id: str | None = None,
        **kwargs: Any,
    ) -> TenantMembershipModel:
        """Add an identity to a tenant with an assigned role."""
        membership = TenantMembershipModel(
            tenant_id=str(tenant_id),
            identity_id=str(identity_id),
            role_in_tenant=role_in_tenant,
        )
        target_id = membership_id or kwargs.get("id")
        if target_id is not None:
            membership.id = str(target_id)
        session.add(membership)
        session.flush()
        return membership

    @handle_session
    def get_membership(
        self,
        session: Session,
        tenant_id: str,
        identity_id: str,
    ) -> TenantMembershipModel | None:
        """Retrieve specific membership linking tenant and identity."""
        stmt = select(TenantMembershipModel).where(
            TenantMembershipModel.tenant_id == str(tenant_id),
            TenantMembershipModel.identity_id == str(identity_id),
        )
        return session.execute(stmt).scalars().first()

    @handle_session
    def list_members(self, session: Session, tenant_id: str) -> list[TenantMembershipModel]:
        """List all memberships belonging to a tenant."""
        stmt = (
            select(TenantMembershipModel)
            .where(TenantMembershipModel.tenant_id == str(tenant_id))
            .order_by(TenantMembershipModel.joined_at.asc())
        )
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def list_tenants_for_identity(
        self,
        session: Session,
        identity_id: str,
    ) -> list[TenantMembershipModel]:
        """List all tenant memberships for a specific identity."""
        stmt = select(TenantMembershipModel).where(TenantMembershipModel.identity_id == str(identity_id))
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def update_member_role(
        self,
        session: Session,
        tenant_id: str,
        identity_id: str,
        role_in_tenant: str,
    ) -> TenantMembershipModel | None:
        """Update the role of an identity within a tenant."""
        membership = self.get_membership(session, tenant_id, identity_id)
        if membership is None:
            return None
        membership.role_in_tenant = role_in_tenant
        session.flush()
        return membership

    @handle_session
    def remove_member(
        self,
        session: Session,
        tenant_id: str,
        identity_id: str,
    ) -> bool:
        """Remove an identity from a tenant."""
        membership = self.get_membership(session, tenant_id, identity_id)
        if membership is None:
            return False
        session.delete(membership)
        session.flush()
        return True


class ResourceRepository(BaseRepository):
    """Repository managing ResourceModel objects and parent/child hierarchies."""

    @handle_session
    def create(
        self,
        session: Session,
        project_id: str,
        display_name: str,
        resource_type: str,
        custom_type_name: str | None = None,
        owning_identity_id: str | None = None,
        owning_tenant_id: str | None = None,
        parent_resource_id: str | None = None,
        sensitivity: str = "medium",
        external_id: str | None = None,
        associated_endpoints: list[str] | None = None,
        metadata_json: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        notes: str | None = None,
        resource_id: str | None = None,
        **kwargs: Any,
    ) -> ResourceModel:
        """Create a new resource entity."""
        resource = ResourceModel(
            project_id=str(project_id),
            display_name=display_name,
            resource_type=resource_type,
            custom_type_name=custom_type_name,
            owning_identity_id=str(owning_identity_id) if owning_identity_id else None,
            owning_tenant_id=str(owning_tenant_id) if owning_tenant_id else None,
            parent_resource_id=str(parent_resource_id) if parent_resource_id else None,
            sensitivity=sensitivity,
            external_id=external_id,
            associated_endpoints=associated_endpoints or [],
            metadata_json=metadata_json or {},
            tags=tags or [],
            notes=notes,
        )
        target_id = resource_id or kwargs.get("id")
        if target_id is not None:
            resource.id = str(target_id)
        session.add(resource)
        session.flush()
        return resource

    @handle_session
    def get_by_id(self, session: Session, resource_id: str) -> ResourceModel | None:
        """Retrieve a resource by ID."""
        return session.get(ResourceModel, str(resource_id))

    @handle_session
    def list_by_project(
        self,
        session: Session,
        project_id: str,
        parent_id: str | None = None,
        resource_type: str | None = None,
    ) -> list[ResourceModel]:
        """List resources for a project with optional hierarchy and type filtering."""
        stmt = select(ResourceModel).where(ResourceModel.project_id == str(project_id))
        if parent_id is not None:
            stmt = stmt.where(ResourceModel.parent_resource_id == str(parent_id))
        if resource_type is not None:
            stmt = stmt.where(ResourceModel.resource_type == resource_type)
        stmt = stmt.order_by(ResourceModel.display_name.asc())
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def get_children(self, session: Session, parent_resource_id: str) -> list[ResourceModel]:
        """Retrieve immediate children of a parent resource."""
        stmt = (
            select(ResourceModel)
            .where(ResourceModel.parent_resource_id == str(parent_resource_id))
            .order_by(ResourceModel.display_name.asc())
        )
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def get_root_resources(self, session: Session, project_id: str) -> list[ResourceModel]:
        """Retrieve top-level resources without a parent resource."""
        stmt = (
            select(ResourceModel)
            .where(
                ResourceModel.project_id == str(project_id),
                ResourceModel.parent_resource_id.is_(None),
            )
            .order_by(ResourceModel.display_name.asc())
        )
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def update(
        self,
        session: Session,
        resource_id: str,
        **kwargs: Any,
    ) -> ResourceModel | None:
        """Update resource fields."""
        resource = session.get(ResourceModel, str(resource_id))
        if resource is None:
            return None
        for key, value in kwargs.items():
            if hasattr(resource, key):
                setattr(resource, key, value)
        resource.updated_at = utcnow()
        session.flush()
        return resource

    @handle_session
    def delete(self, session: Session, resource_id: str) -> bool:
        """Delete a resource."""
        resource = session.get(ResourceModel, str(resource_id))
        if resource is None:
            return False
        session.delete(resource)
        session.flush()
        return True


class PolicyRepository(BaseRepository):
    """Repository managing authorization PolicyModel rules."""

    @handle_session
    def create(
        self,
        session: Session,
        project_id: str,
        name: str,
        action: str,
        expected_decision: str,
        description: str | None = None,
        subject_selector: dict[str, Any] | None = None,
        resource_selector: dict[str, Any] | None = None,
        preconditions: dict[str, Any] | None = None,
        confidence_source: str | None = None,
        evidence_notes: str | None = None,
        enabled: bool = True,
        policy_id: str | None = None,
        **kwargs: Any,
    ) -> PolicyModel:
        """Create an authorization policy."""
        policy = PolicyModel(
            project_id=str(project_id),
            name=name,
            action=action,
            expected_decision=expected_decision,
            description=description,
            subject_selector=subject_selector or {},
            resource_selector=resource_selector or {},
            preconditions=preconditions or {},
            confidence_source=confidence_source,
            evidence_notes=evidence_notes,
            enabled=enabled,
        )
        target_id = policy_id or kwargs.get("id")
        if target_id is not None:
            policy.id = str(target_id)
        session.add(policy)
        session.flush()
        return policy

    @handle_session
    def get_by_id(self, session: Session, policy_id: str) -> PolicyModel | None:
        """Retrieve a policy by ID."""
        return session.get(PolicyModel, str(policy_id))

    @handle_session
    def list_by_project(
        self,
        session: Session,
        project_id: str,
        enabled_only: bool = False,
        action: str | None = None,
    ) -> list[PolicyModel]:
        """List policies for a project."""
        stmt = select(PolicyModel).where(PolicyModel.project_id == str(project_id))
        if enabled_only:
            stmt = stmt.where(PolicyModel.enabled.is_(True))
        if action is not None:
            stmt = stmt.where(PolicyModel.action == action)
        stmt = stmt.order_by(PolicyModel.name.asc())
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def update(
        self,
        session: Session,
        policy_id: str,
        **kwargs: Any,
    ) -> PolicyModel | None:
        """Update a policy."""
        policy = session.get(PolicyModel, str(policy_id))
        if policy is None:
            return None
        for key, value in kwargs.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        policy.updated_at = utcnow()
        session.flush()
        return policy

    @handle_session
    def delete(self, session: Session, policy_id: str) -> bool:
        """Delete a policy."""
        policy = session.get(PolicyModel, str(policy_id))
        if policy is None:
            return False
        session.delete(policy)
        session.flush()
        return True


class TrafficRecordRepository(BaseRepository):
    """Repository managing TrafficRecordModel HTTP records."""

    @handle_session
    def create(
        self,
        session: Session,
        project_id: str,
        method: str,
        url: str,
        host: str,
        path: str,
        scheme: str = "https",
        query_params: dict[str, Any] | None = None,
        request_headers: dict[str, Any] | None = None,
        request_content_type: str | None = None,
        request_body: str | None = None,
        response_status: int | None = None,
        response_headers: dict[str, Any] | None = None,
        response_body: str | None = None,
        timing_ms: float | None = None,
        source_file: str | None = None,
        import_batch_id: str | None = None,
        identity_id: str | None = None,
        resource_id: str | None = None,
        annotations: dict[str, Any] | None = None,
        record_id: str | None = None,
        **kwargs: Any,
    ) -> TrafficRecordModel:
        """Create a single traffic record."""
        record = TrafficRecordModel(
            project_id=str(project_id),
            method=method,
            url=url,
            scheme=scheme,
            host=host,
            path=path,
            query_params=query_params or {},
            request_headers=request_headers or {},
            request_content_type=request_content_type,
            request_body=request_body,
            response_status=response_status,
            response_headers=response_headers or {},
            response_body=response_body,
            timing_ms=timing_ms,
            source_file=source_file,
            import_batch_id=import_batch_id,
            identity_id=str(identity_id) if identity_id else None,
            resource_id=str(resource_id) if resource_id else None,
            annotations=annotations or {},
        )
        target_id = record_id or kwargs.get("id")
        if target_id is not None:
            record.id = str(target_id)
        session.add(record)
        session.flush()
        return record

    @handle_session
    def bulk_create(
        self,
        session: Session,
        records: list[dict[str, Any] | TrafficRecordModel],
    ) -> int:
        """Bulk insert traffic records.

        Args:
            session: Database session.
            records: List of model instances or dictionary attribute maps.

        Returns:
            Count of created records.
        """
        if not records:
            return 0

        instances: list[TrafficRecordModel] = []
        for item in records:
            if isinstance(item, TrafficRecordModel):
                instances.append(item)
            elif isinstance(item, dict):
                instances.append(TrafficRecordModel(**item))
            else:
                raise TypeError(f"Unsupported record type: {type(item)}")

        session.add_all(instances)
        session.flush()
        return len(instances)

    @handle_session
    def list_by_project(
        self,
        session: Session,
        project_id: str,
        offset: int = 0,
        limit: int = 100,
        host: str | None = None,
        method: str | None = None,
    ) -> list[TrafficRecordModel]:
        """List traffic records with pagination and filtering."""
        stmt = select(TrafficRecordModel).where(TrafficRecordModel.project_id == str(project_id))
        if host is not None:
            stmt = stmt.where(TrafficRecordModel.host == host)
        if method is not None:
            stmt = stmt.where(TrafficRecordModel.method == method.upper())
        stmt = stmt.order_by(TrafficRecordModel.created_at.asc()).offset(offset).limit(limit)
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def get_by_id(self, session: Session, record_id: str) -> TrafficRecordModel | None:
        """Retrieve a traffic record by ID."""
        return session.get(TrafficRecordModel, str(record_id))

    @handle_session
    def annotate(
        self,
        session: Session,
        record_id: str,
        annotations: dict[str, Any],
    ) -> TrafficRecordModel | None:
        """Update or merge annotations on a traffic record."""
        record = session.get(TrafficRecordModel, str(record_id))
        if record is None:
            return None
        current = dict(record.annotations or {})
        current.update(annotations)
        record.annotations = current
        session.flush()
        return record

    @handle_session
    def link_identity(
        self,
        session: Session,
        record_id: str,
        identity_id: str | None,
    ) -> TrafficRecordModel | None:
        """Link or unlink an identity to a traffic record."""
        record = session.get(TrafficRecordModel, str(record_id))
        if record is None:
            return None
        record.identity_id = str(identity_id) if identity_id else None
        session.flush()
        return record

    @handle_session
    def link_resource(
        self,
        session: Session,
        record_id: str,
        resource_id: str | None,
    ) -> TrafficRecordModel | None:
        """Link or unlink a resource to a traffic record."""
        record = session.get(TrafficRecordModel, str(record_id))
        if record is None:
            return None
        record.resource_id = str(resource_id) if resource_id else None
        session.flush()
        return record

    @handle_session
    def delete(self, session: Session, record_id: str) -> bool:
        """Delete a traffic record."""
        record = session.get(TrafficRecordModel, str(record_id))
        if record is None:
            return False
        session.delete(record)
        session.flush()
        return True


class TestCaseRepository(BaseRepository):
    """Repository managing TestCaseModel entities."""

    __test__ = False

    @handle_session
    def create(
        self,
        session: Session,
        project_id: str,
        name: str,
        subject_identity_id: str,
        action: str,
        expected_decision: str,
        target_resource_id: str | None = None,
        request_template: dict[str, Any] | None = None,
        preconditions: dict[str, Any] | None = None,
        auth_profile_id: str | None = None,
        execution_mode: str = "automated",
        evidence_ids: list[str] | None = None,
        result_status: str = "pending",
        case_id: str | None = None,
        **kwargs: Any,
    ) -> TestCaseModel:
        """Create a new test case."""
        case = TestCaseModel(
            project_id=str(project_id),
            name=name,
            subject_identity_id=str(subject_identity_id),
            target_resource_id=str(target_resource_id) if target_resource_id else None,
            action=action,
            expected_decision=expected_decision,
            request_template=request_template or {},
            preconditions=preconditions or {},
            auth_profile_id=str(auth_profile_id) if auth_profile_id else None,
            execution_mode=execution_mode,
            evidence_ids=evidence_ids or [],
            result_status=result_status,
        )
        target_id = case_id or kwargs.get("id")
        if target_id is not None:
            case.id = str(target_id)
        session.add(case)
        session.flush()
        return case

    @handle_session
    def get_by_id(self, session: Session, test_case_id: str) -> TestCaseModel | None:
        """Retrieve a test case by ID."""
        return session.get(TestCaseModel, str(test_case_id))

    @handle_session
    def list_by_project(
        self,
        session: Session,
        project_id: str,
        result_status: str | None = None,
        execution_mode: str | None = None,
    ) -> list[TestCaseModel]:
        """List test cases for a project."""
        stmt = select(TestCaseModel).where(TestCaseModel.project_id == str(project_id))
        if result_status is not None:
            stmt = stmt.where(TestCaseModel.result_status == result_status)
        if execution_mode is not None:
            stmt = stmt.where(TestCaseModel.execution_mode == execution_mode)
        stmt = stmt.order_by(TestCaseModel.name.asc())
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def update(
        self,
        session: Session,
        test_case_id: str,
        **kwargs: Any,
    ) -> TestCaseModel | None:
        """Update test case properties."""
        case = session.get(TestCaseModel, str(test_case_id))
        if case is None:
            return None
        for key, value in kwargs.items():
            if hasattr(case, key):
                setattr(case, key, value)
        case.updated_at = utcnow()
        session.flush()
        return case

    @handle_session
    def delete(self, session: Session, test_case_id: str) -> bool:
        """Delete a test case."""
        case = session.get(TestCaseModel, str(test_case_id))
        if case is None:
            return False
        session.delete(case)
        session.flush()
        return True


class TestExecutionRepository(BaseRepository):
    """Repository managing TestExecutionModel instances."""

    __test__ = False

    @handle_session
    def create(
        self,
        session: Session,
        test_case_id: str,
        project_id: str,
        status: str = "running",
        request_snapshot: dict[str, Any] | None = None,
        response_snapshot: dict[str, Any] | None = None,
        actual_status_code: int | None = None,
        actual_decision: str | None = None,
        error_message: str | None = None,
        evidence_id: str | None = None,
        started_at: datetime | None = None,
        execution_id: str | None = None,
        **kwargs: Any,
    ) -> TestExecutionModel:
        """Record a test execution start."""
        execution = TestExecutionModel(
            test_case_id=str(test_case_id),
            project_id=str(project_id),
            started_at=started_at or utcnow(),
            status=status,
            request_snapshot=request_snapshot or {},
            response_snapshot=response_snapshot or {},
            actual_status_code=actual_status_code,
            actual_decision=actual_decision,
            error_message=error_message,
            evidence_id=str(evidence_id) if evidence_id else None,
        )
        target_id = execution_id or kwargs.get("id")
        if target_id is not None:
            execution.id = str(target_id)
        session.add(execution)
        session.flush()
        return execution

    @handle_session
    def get_by_id(self, session: Session, execution_id: str) -> TestExecutionModel | None:
        """Retrieve a test execution by ID."""
        return session.get(TestExecutionModel, str(execution_id))

    @handle_session
    def list_by_test_case(self, session: Session, test_case_id: str) -> list[TestExecutionModel]:
        """List executions for a specific test case."""
        stmt = (
            select(TestExecutionModel)
            .where(TestExecutionModel.test_case_id == str(test_case_id))
            .order_by(TestExecutionModel.started_at.desc())
        )
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def list_by_project(
        self,
        session: Session,
        project_id: str,
        status: str | None = None,
    ) -> list[TestExecutionModel]:
        """List executions for a project."""
        stmt = select(TestExecutionModel).where(TestExecutionModel.project_id == str(project_id))
        if status is not None:
            stmt = stmt.where(TestExecutionModel.status == status)
        stmt = stmt.order_by(TestExecutionModel.started_at.desc())
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def complete(
        self,
        session: Session,
        execution_id: str,
        status: str,
        actual_status_code: int | None = None,
        actual_decision: str | None = None,
        response_snapshot: dict[str, Any] | None = None,
        error_message: str | None = None,
        evidence_id: str | None = None,
    ) -> TestExecutionModel | None:
        """Mark an execution as completed with final outcomes."""
        execution = session.get(TestExecutionModel, str(execution_id))
        if execution is None:
            return None
        execution.completed_at = utcnow()
        execution.status = status
        if actual_status_code is not None:
            execution.actual_status_code = actual_status_code
        if actual_decision is not None:
            execution.actual_decision = actual_decision
        if response_snapshot is not None:
            execution.response_snapshot = response_snapshot
        if error_message is not None:
            execution.error_message = error_message
        if evidence_id is not None:
            execution.evidence_id = str(evidence_id)
        session.flush()
        return execution

    @handle_session
    def update(
        self,
        session: Session,
        execution_id: str,
        **kwargs: Any,
    ) -> TestExecutionModel | None:
        """Update test execution fields."""
        execution = session.get(TestExecutionModel, str(execution_id))
        if execution is None:
            return None
        for key, value in kwargs.items():
            if hasattr(execution, key):
                setattr(execution, key, value)
        session.flush()
        return execution

    @handle_session
    def delete(self, session: Session, execution_id: str) -> bool:
        """Delete an execution record."""
        execution = session.get(TestExecutionModel, str(execution_id))
        if execution is None:
            return False
        session.delete(execution)
        session.flush()
        return True


class FindingRepository(BaseRepository):
    """Repository managing FindingModel authorization findings."""

    @handle_session
    def create(
        self,
        session: Session,
        project_id: str,
        title: str,
        category: str,
        affected_endpoint: str,
        expected_decision: str,
        observed_decision: str,
        affected_resource_id: str | None = None,
        subject_identity_id: str | None = None,
        severity: str = "medium",
        confidence_data: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
        reproduction_steps: list[str] | None = None,
        status: str = "open",
        reviewer_notes: str | None = None,
        related_test_case_ids: list[str] | None = None,
        finding_id: str | None = None,
        **kwargs: Any,
    ) -> FindingModel:
        """Create a new authorization finding."""
        finding = FindingModel(
            project_id=str(project_id),
            title=title,
            category=category,
            affected_endpoint=affected_endpoint,
            expected_decision=expected_decision,
            observed_decision=observed_decision,
            affected_resource_id=str(affected_resource_id) if affected_resource_id else None,
            subject_identity_id=str(subject_identity_id) if subject_identity_id else None,
            severity=severity,
            confidence_data=confidence_data or {},
            evidence_ids=evidence_ids or [],
            reproduction_steps=reproduction_steps or [],
            status=status,
            reviewer_notes=reviewer_notes,
            related_test_case_ids=related_test_case_ids or [],
        )
        target_id = finding_id or kwargs.get("id")
        if target_id is not None:
            finding.id = str(target_id)
        session.add(finding)
        session.flush()
        return finding

    @handle_session
    def get_by_id(self, session: Session, finding_id: str) -> FindingModel | None:
        """Retrieve a finding by ID."""
        return session.get(FindingModel, str(finding_id))

    @handle_session
    def list_by_project(
        self,
        session: Session,
        project_id: str,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
    ) -> list[FindingModel]:
        """List findings for a project with optional filters."""
        stmt = select(FindingModel).where(FindingModel.project_id == str(project_id))
        if status is not None:
            stmt = stmt.where(FindingModel.status == status)
        if severity is not None:
            stmt = stmt.where(FindingModel.severity == severity)
        if category is not None:
            stmt = stmt.where(FindingModel.category == category)
        stmt = stmt.order_by(FindingModel.created_at.desc())
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def update_status(
        self,
        session: Session,
        finding_id: str,
        status: str,
        reviewer_notes: str | None = None,
    ) -> FindingModel | None:
        """Update finding status and reviewer notes."""
        finding = session.get(FindingModel, str(finding_id))
        if finding is None:
            return None
        finding.status = status
        if reviewer_notes is not None:
            finding.reviewer_notes = reviewer_notes
        finding.last_verified = utcnow()
        finding.updated_at = utcnow()
        session.flush()
        return finding

    @handle_session
    def update(
        self,
        session: Session,
        finding_id: str,
        **kwargs: Any,
    ) -> FindingModel | None:
        """Update finding fields."""
        finding = session.get(FindingModel, str(finding_id))
        if finding is None:
            return None
        for key, value in kwargs.items():
            if hasattr(finding, key):
                setattr(finding, key, value)
        finding.updated_at = utcnow()
        session.flush()
        return finding

    @handle_session
    def delete(self, session: Session, finding_id: str) -> bool:
        """Delete a finding."""
        finding = session.get(FindingModel, str(finding_id))
        if finding is None:
            return False
        session.delete(finding)
        session.flush()
        return True


class EvidenceRepository(BaseRepository):
    """Repository managing EvidenceModel artifacts with SHA-256 hash verification."""

    def compute_hash(self, evidence_data: dict[str, Any] | EvidenceModel) -> str:
        """Compute deterministic SHA-256 hash for evidence payload."""
        if isinstance(evidence_data, EvidenceModel):
            payload = {
                "title": evidence_data.title,
                "evidence_type": evidence_data.evidence_type,
                "request_snapshot": evidence_data.request_snapshot,
                "response_snapshot": evidence_data.response_snapshot,
                "policy_eval_snapshot": evidence_data.policy_eval_snapshot,
                "identity_context": evidence_data.identity_context,
                "resource_context": evidence_data.resource_context,
            }
        else:
            payload = {
                "title": evidence_data.get("title"),
                "evidence_type": evidence_data.get("evidence_type"),
                "request_snapshot": evidence_data.get("request_snapshot"),
                "response_snapshot": evidence_data.get("response_snapshot"),
                "policy_eval_snapshot": evidence_data.get("policy_eval_snapshot"),
                "identity_context": evidence_data.get("identity_context"),
                "resource_context": evidence_data.get("resource_context"),
            }
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @handle_session
    def create(
        self,
        session: Session,
        project_id: str,
        evidence_type: str,
        title: str,
        description: str | None = None,
        request_snapshot: dict[str, Any] | None = None,
        response_snapshot: dict[str, Any] | None = None,
        policy_eval_snapshot: dict[str, Any] | None = None,
        identity_context: dict[str, Any] | None = None,
        resource_context: dict[str, Any] | None = None,
        test_execution_id: str | None = None,
        sanitization_applied: list[str] | None = None,
        metadata_json: dict[str, Any] | None = None,
        content_hash: str | None = None,
        evidence_id: str | None = None,
        **kwargs: Any,
    ) -> EvidenceModel:
        """Create an evidence record with cryptographic content hash."""
        if content_hash is None:
            content_hash = self.compute_hash(
                {
                    "title": title,
                    "evidence_type": evidence_type,
                    "request_snapshot": request_snapshot,
                    "response_snapshot": response_snapshot,
                    "policy_eval_snapshot": policy_eval_snapshot,
                    "identity_context": identity_context,
                    "resource_context": resource_context,
                }
            )

        evidence = EvidenceModel(
            project_id=str(project_id),
            evidence_type=evidence_type,
            title=title,
            description=description,
            request_snapshot=request_snapshot,
            response_snapshot=response_snapshot,
            policy_eval_snapshot=policy_eval_snapshot,
            identity_context=identity_context,
            resource_context=resource_context,
            test_execution_id=str(test_execution_id) if test_execution_id else None,
            content_hash=content_hash,
            sanitization_applied=sanitization_applied or [],
            metadata_json=metadata_json or {},
        )
        target_id = evidence_id or kwargs.get("id")
        if target_id is not None:
            evidence.id = str(target_id)
        session.add(evidence)
        session.flush()
        return evidence

    @handle_session
    def get_by_id(self, session: Session, evidence_id: str) -> EvidenceModel | None:
        """Retrieve evidence by ID."""
        return session.get(EvidenceModel, str(evidence_id))

    @handle_session
    def list_by_project(
        self,
        session: Session,
        project_id: str,
        evidence_type: str | None = None,
    ) -> list[EvidenceModel]:
        """List evidence for a project."""
        stmt = select(EvidenceModel).where(EvidenceModel.project_id == str(project_id))
        if evidence_type is not None:
            stmt = stmt.where(EvidenceModel.evidence_type == evidence_type)
        stmt = stmt.order_by(EvidenceModel.timestamp.desc())
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def verify_hash(self, session: Session, evidence_id: str) -> bool:
        """Verify the content hash against recorded snapshot data.

        Returns:
            True if hash matches, False if mismatch or record not found.
        """
        evidence = session.get(EvidenceModel, str(evidence_id))
        if evidence is None:
            return False
        expected_hash = self.compute_hash(evidence)
        return expected_hash == evidence.content_hash

    @handle_session
    def update(
        self,
        session: Session,
        evidence_id: str,
        **kwargs: Any,
    ) -> EvidenceModel | None:
        """Update evidence fields and recalculate hash if payloads modified."""
        evidence = session.get(EvidenceModel, str(evidence_id))
        if evidence is None:
            return None
        for key, value in kwargs.items():
            if hasattr(evidence, key):
                setattr(evidence, key, value)
        # Refresh hash if content fields modified and no explicit hash provided
        if "content_hash" not in kwargs:
            evidence.content_hash = self.compute_hash(evidence)
        session.flush()
        return evidence

    @handle_session
    def delete(self, session: Session, evidence_id: str) -> bool:
        """Delete an evidence record."""
        evidence = session.get(EvidenceModel, str(evidence_id))
        if evidence is None:
            return False
        session.delete(evidence)
        session.flush()
        return True


class AuditEventRepository(BaseRepository):
    """Repository managing AuditEventModel logging and queries."""

    @handle_session
    def create(
        self,
        session: Session,
        event_type: str,
        description: str,
        project_id: str | None = None,
        details: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
        event_id: str | None = None,
        **kwargs: Any,
    ) -> AuditEventModel:
        """Create an audit event entry."""
        event = AuditEventModel(
            event_type=event_type,
            description=description,
            project_id=str(project_id) if project_id else None,
            details=details or {},
            timestamp=timestamp or utcnow(),
        )
        target_id = event_id or kwargs.get("id")
        if target_id is not None:
            event.id = str(target_id)
        session.add(event)
        session.flush()
        return event

    @handle_session
    def get_by_id(self, session: Session, event_id: str) -> AuditEventModel | None:
        """Retrieve an audit event by ID."""
        return session.get(AuditEventModel, str(event_id))

    @handle_session
    def list_by_project(
        self,
        session: Session,
        project_id: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEventModel]:
        """Query audit events with filtering by project, type, and date range."""
        stmt = select(AuditEventModel)
        if project_id is not None:
            stmt = stmt.where(AuditEventModel.project_id == str(project_id))
        if event_type is not None:
            stmt = stmt.where(AuditEventModel.event_type == event_type)
        if start_time is not None:
            stmt = stmt.where(AuditEventModel.timestamp >= start_time)
        if end_time is not None:
            stmt = stmt.where(AuditEventModel.timestamp <= end_time)
        stmt = stmt.order_by(AuditEventModel.timestamp.desc()).offset(offset).limit(limit)
        return list(session.execute(stmt).scalars().all())

    @handle_session
    def delete(self, session: Session, event_id: str) -> bool:
        """Delete an audit event."""
        event = session.get(AuditEventModel, str(event_id))
        if event is None:
            return False
        session.delete(event)
        session.flush()
        return True


class SettingsRepository(BaseRepository):
    """Repository managing AppSettingModel key-value pairs."""

    @handle_session
    def get(
        self,
        session: Session,
        key: str,
        default: str | None = None,
    ) -> str | None:
        """Retrieve setting value by key, returning default if not found."""
        stmt = select(AppSettingModel).where(AppSettingModel.key == key)
        setting = session.execute(stmt).scalars().first()
        if setting is None or setting.value is None:
            return default
        return setting.value

    @handle_session
    def set(
        self,
        session: Session,
        key: str,
        value: str | None,
    ) -> AppSettingModel:
        """Set or update a configuration key."""
        stmt = select(AppSettingModel).where(AppSettingModel.key == key)
        setting = session.execute(stmt).scalars().first()
        if setting is None:
            setting = AppSettingModel(key=key, value=str(value) if value is not None else None)
            session.add(setting)
        else:
            setting.value = str(value) if value is not None else None
            setting.updated_at = utcnow()
        session.flush()
        return setting

    @handle_session
    def delete(self, session: Session, key: str) -> bool:
        """Delete a setting key."""
        stmt = select(AppSettingModel).where(AppSettingModel.key == key)
        setting = session.execute(stmt).scalars().first()
        if setting is None:
            return False
        session.delete(setting)
        session.flush()
        return True

    @handle_session
    def list_all(self, session: Session) -> dict[str, str | None]:
        """Retrieve all application settings as a dictionary."""
        stmt = select(AppSettingModel).order_by(AppSettingModel.key.asc())
        settings = session.execute(stmt).scalars().all()
        return {s.key: s.value for s in settings}
