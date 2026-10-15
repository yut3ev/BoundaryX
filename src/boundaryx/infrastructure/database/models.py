"""SQLAlchemy ORM models for BoundaryX database infrastructure layer.

This module maps all domain entities to relational database tables using
SQLAlchemy 2.x declarative mapping with strict typing, relationships,
indexes, and cascading deletion configurations.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from boundaryx.infrastructure.database.base import Base


def utcnow() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


def generate_uuid() -> str:
    """Generate a random UUID v4 string."""
    return str(uuid.uuid4())


class ProjectModel(Base):
    """Top-level project entity containing security assessment data."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
    archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Relationships
    scope_rules: Mapped[list[ScopeRuleModel]] = relationship(
        "ScopeRuleModel", back_populates="project", cascade="all, delete-orphan"
    )
    identities: Mapped[list[IdentityModel]] = relationship(
        "IdentityModel", back_populates="project", cascade="all, delete-orphan"
    )
    auth_profiles: Mapped[list[AuthenticationProfileModel]] = relationship(
        "AuthenticationProfileModel", back_populates="project", cascade="all, delete-orphan"
    )
    tenants: Mapped[list[TenantModel]] = relationship(
        "TenantModel", back_populates="project", cascade="all, delete-orphan"
    )
    resources: Mapped[list[ResourceModel]] = relationship(
        "ResourceModel", back_populates="project", cascade="all, delete-orphan"
    )
    policies: Mapped[list[PolicyModel]] = relationship(
        "PolicyModel", back_populates="project", cascade="all, delete-orphan"
    )
    traffic_records: Mapped[list[TrafficRecordModel]] = relationship(
        "TrafficRecordModel", back_populates="project", cascade="all, delete-orphan"
    )
    test_cases: Mapped[list[TestCaseModel]] = relationship(
        "TestCaseModel", back_populates="project", cascade="all, delete-orphan"
    )
    test_executions: Mapped[list[TestExecutionModel]] = relationship(
        "TestExecutionModel", back_populates="project", cascade="all, delete-orphan"
    )
    findings: Mapped[list[FindingModel]] = relationship(
        "FindingModel", back_populates="project", cascade="all, delete-orphan"
    )
    evidence_records: Mapped[list[EvidenceModel]] = relationship(
        "EvidenceModel", back_populates="project", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list[AuditEventModel]] = relationship(
        "AuditEventModel", back_populates="project", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<ProjectModel(id={self.id!r}, name={self.name!r}, archived={self.archived})>"


class ScopeRuleModel(Base):
    """Scope inclusion and exclusion rules for project assessment."""

    __tablename__ = "scope_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_index: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scheme: Mapped[str | None] = mapped_column(String(10), nullable=True)
    path_prefix: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    path_exclusions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    is_excluded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    project: Mapped[ProjectModel] = relationship("ProjectModel", back_populates="scope_rules")

    @property
    def excluded_paths(self) -> list[str]:
        return self.path_exclusions

    @excluded_paths.setter
    def excluded_paths(self, value: list[str]) -> None:
        self.path_exclusions = value

    @property
    def is_exclusion(self) -> bool:
        return self.is_excluded

    @is_exclusion.setter
    def is_exclusion(self, value: bool) -> None:
        self.is_excluded = value

    def to_dict(self) -> dict[str, Any]:
        """Convert scope rule model to dictionary representation."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "rule_index": self.rule_index,
            "hostname": self.hostname,
            "port": self.port,
            "scheme": self.scheme,
            "path_prefix": self.path_prefix,
            "excluded_paths": list(self.path_exclusions or []),
            "is_exclusion": self.is_excluded,
            "notes": self.notes or "",
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<ScopeRuleModel(id={self.id!r}, hostname={self.hostname!r}, is_excluded={self.is_excluded})>"


class IdentityModel(Base):
    """Subject identity / role definition in authorization testing."""

    __tablename__ = "identities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    role_type: Mapped[str] = mapped_column(String(100), nullable=False)
    custom_role_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active", nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    project: Mapped[ProjectModel] = relationship("ProjectModel", back_populates="identities")
    tenant_memberships: Mapped[list[TenantMembershipModel]] = relationship(
        "TenantMembershipModel", back_populates="identity", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<IdentityModel(id={self.id!r}, name={self.name!r}, role_type={self.role_type!r})>"


class AuthenticationProfileModel(Base):
    """Authentication configuration profile for executing tests."""

    __tablename__ = "authentication_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_method: Mapped[str] = mapped_column(String(100), nullable=False)
    header_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    project: Mapped[ProjectModel] = relationship("ProjectModel", back_populates="auth_profiles")

    def __repr__(self) -> str:
        return f"<AuthenticationProfileModel(id={self.id!r}, name={self.name!r}, auth_method={self.auth_method!r})>"


class TenantModel(Base):
    """Tenant/Organization boundary entity for multi-tenancy tests."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner_identity_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="SET NULL"), nullable=True
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    project: Mapped[ProjectModel] = relationship("ProjectModel", back_populates="tenants")
    owner: Mapped[IdentityModel | None] = relationship("IdentityModel")
    memberships: Mapped[list[TenantMembershipModel]] = relationship(
        "TenantMembershipModel", back_populates="tenant", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<TenantModel(id={self.id!r}, name={self.name!r})>"


class TenantMembershipModel(Base):
    """Association linking identities to tenants with assigned roles."""

    __tablename__ = "tenant_memberships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_in_tenant: Mapped[str] = mapped_column(String(100), default="member", nullable=False)
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("tenant_id", "identity_id", name="uq_tenant_memberships_tenant_identity"),)

    tenant: Mapped[TenantModel] = relationship("TenantModel", back_populates="memberships")
    identity: Mapped[IdentityModel] = relationship("IdentityModel", back_populates="tenant_memberships")

    def __repr__(self) -> str:
        return (
            f"<TenantMembershipModel(id={self.id!r}, tenant_id={self.tenant_id!r}, identity_id={self.identity_id!r})>"
        )


class ResourceModel(Base):
    """Resource entity representing objects evaluated under access control policies."""

    __tablename__ = "resources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    custom_type_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    owning_identity_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="SET NULL"), nullable=True
    )
    owning_tenant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True
    )
    parent_resource_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("resources.id", ondelete="SET NULL"), nullable=True
    )
    sensitivity: Mapped[str] = mapped_column(String(50), default="medium", nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    associated_endpoints: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    project: Mapped[ProjectModel] = relationship("ProjectModel", back_populates="resources")
    owning_identity: Mapped[IdentityModel | None] = relationship("IdentityModel")
    owning_tenant: Mapped[TenantModel | None] = relationship("TenantModel")
    parent: Mapped[ResourceModel | None] = relationship(
        "ResourceModel", remote_side="ResourceModel.id", back_populates="children"
    )
    children: Mapped[list[ResourceModel]] = relationship("ResourceModel", back_populates="parent")

    def __repr__(self) -> str:
        return (
            f"<ResourceModel(id={self.id!r}, display_name={self.display_name!r}, resource_type={self.resource_type!r})>"
        )


class PolicyModel(Base):
    """Authorization policy or invariant expected by the system."""

    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    subject_selector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    resource_selector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    expected_decision: Mapped[str] = mapped_column(String(50), nullable=False)
    preconditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    confidence_source: Mapped[str | None] = mapped_column(String(100), nullable=True)
    evidence_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    project: Mapped[ProjectModel] = relationship("ProjectModel", back_populates="policies")

    def __repr__(self) -> str:
        return f"<PolicyModel(id={self.id!r}, name={self.name!r}, action={self.action!r}, decision={self.expected_decision!r})>"


class TrafficRecordModel(Base):
    """HTTP request/response record imported from proxy capture or Burp Suite."""

    __tablename__ = "traffic_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    method: Mapped[str] = mapped_column(String(20), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    scheme: Mapped[str] = mapped_column(String(10), default="https", nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    query_params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    request_headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    request_content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    timing_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    source_file: Mapped[str | None] = mapped_column(String(500), nullable=True)
    import_batch_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    identity_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="SET NULL"), nullable=True
    )
    resource_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("resources.id", ondelete="SET NULL"), nullable=True
    )
    annotations: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (Index("ix_traffic_records_host_path", "host", "path"),)

    project: Mapped[ProjectModel] = relationship("ProjectModel", back_populates="traffic_records")
    identity: Mapped[IdentityModel | None] = relationship("IdentityModel")
    resource: Mapped[ResourceModel | None] = relationship("ResourceModel")

    def __repr__(self) -> str:
        return f"<TrafficRecordModel(id={self.id!r}, method={self.method!r}, host={self.host!r}, path={self.path!r})>"


class TestCaseModel(Base):
    """Authorization test case defining subject, target resource, and expected decision."""

    __test__ = False
    __tablename__ = "test_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    subject_identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )
    target_resource_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("resources.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    expected_decision: Mapped[str] = mapped_column(String(50), nullable=False)
    request_template: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    preconditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    auth_profile_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("authentication_profiles.id", ondelete="SET NULL"), nullable=True
    )
    execution_mode: Mapped[str] = mapped_column(String(50), default="automated", nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    result_status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    project: Mapped[ProjectModel] = relationship("ProjectModel", back_populates="test_cases")
    subject_identity: Mapped[IdentityModel] = relationship("IdentityModel")
    target_resource: Mapped[ResourceModel | None] = relationship("ResourceModel")
    auth_profile: Mapped[AuthenticationProfileModel | None] = relationship("AuthenticationProfileModel")
    executions: Mapped[list[TestExecutionModel]] = relationship(
        "TestExecutionModel", back_populates="test_case", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<TestCaseModel(id={self.id!r}, name={self.name!r}, action={self.action!r}, status={self.result_status!r})>"


class TestExecutionModel(Base):
    """Historical execution of a test case with observed result."""

    __test__ = False
    __tablename__ = "test_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    test_case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("test_cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="running", nullable=False)
    request_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    response_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    actual_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actual_decision: Mapped[str | None] = mapped_column(String(50), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("evidence.id", ondelete="SET NULL", use_alter=True), nullable=True
    )

    project: Mapped[ProjectModel] = relationship("ProjectModel", back_populates="test_executions")
    test_case: Mapped[TestCaseModel] = relationship("TestCaseModel", back_populates="executions")
    evidence: Mapped[EvidenceModel | None] = relationship("EvidenceModel", foreign_keys=[evidence_id], post_update=True)

    def __repr__(self) -> str:
        return f"<TestExecutionModel(id={self.id!r}, test_case_id={self.test_case_id!r}, status={self.status!r})>"


class FindingModel(Base):
    """Authorization finding / vulnerability discovered during testing."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    affected_endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    affected_resource_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("resources.id", ondelete="SET NULL"), nullable=True
    )
    subject_identity_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="SET NULL"), nullable=True
    )
    expected_decision: Mapped[str] = mapped_column(String(50), nullable=False)
    observed_decision: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="medium", nullable=False)
    confidence_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    reproduction_steps: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False, index=True)
    reviewer_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_verified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    related_test_case_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    project: Mapped[ProjectModel] = relationship("ProjectModel", back_populates="findings")
    affected_resource: Mapped[ResourceModel | None] = relationship("ResourceModel")
    subject_identity: Mapped[IdentityModel | None] = relationship("IdentityModel")

    def __repr__(self) -> str:
        return (
            f"<FindingModel(id={self.id!r}, title={self.title!r}, severity={self.severity!r}, status={self.status!r})>"
        )


class EvidenceModel(Base):
    """Immutable evidence artefact supporting test results or findings."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    response_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    policy_eval_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    identity_context: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    resource_context: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    test_execution_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("test_executions.id", ondelete="SET NULL"), nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    sanitization_applied: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    project: Mapped[ProjectModel] = relationship("ProjectModel", back_populates="evidence_records")
    test_execution: Mapped[TestExecutionModel | None] = relationship(
        "TestExecutionModel", foreign_keys=[test_execution_id]
    )

    def __repr__(self) -> str:
        return f"<EvidenceModel(id={self.id!r}, title={self.title!r}, evidence_type={self.evidence_type!r})>"


class AuditEventModel(Base):
    """Audit log entry capturing actions and integrity transitions."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (Index("ix_audit_events_type_timestamp", "event_type", "timestamp"),)

    project: Mapped[ProjectModel | None] = relationship("ProjectModel", back_populates="audit_events")

    def to_dict(self) -> dict[str, Any]:
        """Convert the audit event model to a dictionary representation."""
        return {
            "id": str(self.id),
            "event_type": self.event_type,
            "description": self.description,
            "project_id": str(self.project_id) if self.project_id else None,
            "details": self.details,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }

    def __repr__(self) -> str:
        return (
            f"<AuditEventModel(id={self.id!r}, event_type={self.event_type!r}, timestamp={self.timestamp.isoformat()})>"
        )


class AppSettingModel(Base):
    """Key-value application settings storage."""

    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    def __repr__(self) -> str:
        return f"<AppSettingModel(key={self.key!r})>"


# Convenient domain aliases
Project = ProjectModel
ScopeRule = ScopeRuleModel
Identity = IdentityModel
AuthenticationProfile = AuthenticationProfileModel
Tenant = TenantModel
TenantMembership = TenantMembershipModel
Resource = ResourceModel
Policy = PolicyModel
TrafficRecord = TrafficRecordModel
TestCase = TestCaseModel
TestExecution = TestExecutionModel
Finding = FindingModel
Evidence = EvidenceModel
AuditEvent = AuditEventModel
AppSetting = AppSettingModel
