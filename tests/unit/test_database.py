"""Unit tests for BoundaryX database infrastructure layer.

Tests all SQLAlchemy ORM models, DatabaseManager lifecycle, pragmas,
and all repository operations including cascade deletions, hierarchy traversal,
bulk ingestion, and evidence hash verification.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from sqlalchemy.orm import Session

from boundaryx.infrastructure.database import (
    AuditEventRepository,
    AuthProfileRepository,
    DatabaseManager,
    EvidenceRepository,
    FindingRepository,
    IdentityRepository,
    PolicyRepository,
    ProjectRepository,
    ResourceRepository,
    ScopeRuleRepository,
    SettingsRepository,
    TenantRepository,
    TestCaseRepository,
    TestExecutionRepository,
    TrafficRecordRepository,
)


@pytest.fixture
def db_manager() -> Generator[DatabaseManager, None, None]:
    """Provide an in-memory database manager for testing."""
    manager = DatabaseManager(":memory:")
    manager.create_tables()
    yield manager
    manager.close()


@pytest.fixture
def session(db_manager: DatabaseManager) -> Generator[Session, None, None]:
    """Provide a database session fixture."""
    with db_manager.get_session() as sess:
        yield sess


def test_database_manager_integrity_and_version(db_manager: DatabaseManager):
    """Test PRAGMA integrity check and schema user version methods."""
    assert db_manager.verify_integrity() is True
    assert db_manager.get_schema_version() == 0
    db_manager.set_schema_version(5)
    assert db_manager.get_schema_version() == 5


def test_database_backup_and_restore(tmp_path: Path):
    """Test online backup and restore functionality."""
    db_path = tmp_path / "primary.db"
    backup_path = tmp_path / "primary_backup.db"

    manager = DatabaseManager(db_path)
    manager.create_tables()

    proj_repo = ProjectRepository()
    with manager.get_session() as s:
        proj_repo.create(s, name="Original Project", description="Before backup")

    # Run backup
    manager.backup(backup_path)
    assert backup_path.exists()
    assert backup_path.stat().st_size > 0

    # Modify primary DB
    with manager.get_session() as s:
        proj_repo.create(s, name="New Project After Backup")
        all_projs = proj_repo.list_all(s)
        assert len(all_projs) == 2

    # Restore from backup
    manager.restore(backup_path)

    # Verify restoration
    with manager.get_session() as s:
        restored_projs = proj_repo.list_all(s)
        assert len(restored_projs) == 1
        assert restored_projs[0].name == "Original Project"

    manager.close()


def test_project_repository(session: Session):
    """Test ProjectRepository CRUD, archive, and hard delete."""
    repo = ProjectRepository(session)

    # Create
    project = repo.create(
        name="Fintech Assessment",
        description="Core banking API authorization audit",
        settings={"target_env": "staging", "max_threads": 4},
    )
    assert project.id is not None
    assert project.name == "Fintech Assessment"
    assert project.archived is False
    assert project.settings["max_threads"] == 4

    # Get by ID
    fetched = repo.get_by_id(project.id)
    assert fetched is not None
    assert fetched.id == project.id

    # List all
    all_projects = repo.list_all()
    assert len(all_projects) == 1

    # Update
    updated = repo.update(project.id, description="Updated banking audit")
    assert updated is not None
    assert updated.description == "Updated banking audit"

    # Archive
    archived = repo.archive(project.id)
    assert archived is not None
    assert archived.archived is True

    # List active excludes archived
    active_projects = repo.list_all(include_archived=False)
    assert len(active_projects) == 0
    with_archived = repo.list_all(include_archived=True)
    assert len(with_archived) == 1

    # Delete
    deleted = repo.delete(project.id)
    assert deleted is True
    assert repo.get_by_id(project.id) is None
    assert repo.delete(project.id) is False


def test_cascade_delete(session: Session):
    """Test that deleting a project cascades to its dependent scope rules and identities."""
    proj_repo = ProjectRepository(session)
    scope_repo = ScopeRuleRepository(session)
    identity_repo = IdentityRepository(session)

    project = proj_repo.create(name="Cascade Project")
    rule = scope_repo.create(project_id=project.id, hostname="api.example.com", is_excluded=False)
    ident = identity_repo.create(project_id=project.id, name="Auditor", role_type="admin")

    assert scope_repo.get_by_id(rule.id) is not None
    assert identity_repo.get_by_id(ident.id) is not None

    # Delete project
    assert proj_repo.delete(project.id) is True
    assert scope_repo.get_by_id(rule.id) is None
    assert identity_repo.get_by_id(ident.id) is None


def test_scope_rule_repository(session: Session):
    """Test ScopeRuleRepository CRUD operations."""
    proj_repo = ProjectRepository()
    scope_repo = ScopeRuleRepository()

    proj = proj_repo.create(session, name="Scope Proj")
    rule = scope_repo.create(
        session,
        project_id=proj.id,
        hostname="api.boundaryx.internal",
        port=8443,
        scheme="https",
        path_prefix="/v1",
        path_exclusions=["/v1/health", "/v1/metrics"],
        is_excluded=False,
    )
    assert rule.id is not None
    assert rule.port == 8443
    assert len(rule.path_exclusions) == 2

    # Query by project
    rules = scope_repo.list_by_project(session, proj.id)
    assert len(rules) == 1
    assert rules[0].hostname == "api.boundaryx.internal"

    # Update
    updated = scope_repo.update(session, rule.id, is_excluded=True, notes="Excluded temporarily")
    assert updated is not None
    assert updated.is_excluded is True

    # Delete
    assert scope_repo.delete(session, rule.id) is True
    assert scope_repo.get_by_id(session, rule.id) is None


def test_identity_and_auth_profile_repository(session: Session):
    """Test IdentityRepository and AuthProfileRepository operations."""
    proj_repo = ProjectRepository(session)
    ident_repo = IdentityRepository(session)
    auth_repo = AuthProfileRepository(session)

    proj = proj_repo.create(name="Identity Proj")

    # Identities
    alice = ident_repo.create(
        project_id=proj.id,
        name="Alice",
        role_type="tenant_admin",
        status="active",
        tags=["vip", "finance"],
    )
    bob = ident_repo.create(
        project_id=proj.id,
        name="Bob",
        role_type="standard_user",
        status="suspended",
    )
    assert bob.name == "Bob"
    assert bob.status == "suspended"

    assert ident_repo.get_by_id(alice.id).name == "Alice"
    active_users = ident_repo.list_by_project(proj.id, filters={"status": "active"})
    assert len(active_users) == 1
    assert active_users[0].name == "Alice"

    # Update identity
    updated_alice = ident_repo.update(alice.id, status="inactive")
    assert updated_alice.status == "inactive"

    # Auth profiles
    auth = auth_repo.create(
        project_id=proj.id,
        name="Bearer Auth",
        auth_method="jwt_bearer",
        header_name="Authorization",
        description="Main JWT token profile",
    )
    assert auth.id is not None
    assert auth.header_name == "Authorization"
    assert len(auth_repo.list_by_project(proj.id)) == 1

    # Delete auth profile
    assert auth_repo.delete(auth.id) is True
    assert auth_repo.get_by_id(auth.id) is None


def test_tenant_and_memberships(session: Session):
    """Test TenantRepository CRUD and membership management."""
    proj = ProjectRepository(session).create(name="Tenant Proj")
    ident_repo = IdentityRepository(session)
    tenant_repo = TenantRepository(session)

    user1 = ident_repo.create(project_id=proj.id, name="User1", role_type="user")
    user2 = ident_repo.create(project_id=proj.id, name="User2", role_type="user")

    # Create tenant
    tenant = tenant_repo.create_tenant(
        project_id=proj.id,
        name="Acme Corp",
        description="Primary enterprise client",
        owner_identity_id=user1.id,
        metadata_json={"tier": "enterprise"},
    )
    assert tenant.id is not None
    assert tenant.owner_identity_id == user1.id

    # Memberships
    m1 = tenant_repo.add_member(tenant.id, user1.id, role_in_tenant="admin")
    m2 = tenant_repo.add_member(tenant.id, user2.id, role_in_tenant="member")
    assert m1.role_in_tenant == "admin"
    assert m2.role_in_tenant == "member"

    members = tenant_repo.list_members(tenant.id)
    assert len(members) == 2

    # Lookup membership
    mem = tenant_repo.get_membership(tenant.id, user2.id)
    assert mem is not None
    assert mem.role_in_tenant == "member"

    # Update role
    updated_mem = tenant_repo.update_member_role(tenant.id, user2.id, role_in_tenant="reviewer")
    assert updated_mem is not None
    assert updated_mem.role_in_tenant == "reviewer"

    # Remove member
    assert tenant_repo.remove_member(tenant.id, user2.id) is True
    assert tenant_repo.get_membership(tenant.id, user2.id) is None
    assert len(tenant_repo.list_members(tenant.id)) == 1

    # Delete tenant
    assert tenant_repo.delete_tenant(tenant.id) is True
    assert tenant_repo.get_tenant_by_id(tenant.id) is None


def test_resource_hierarchy(session: Session):
    """Test ResourceRepository hierarchy, roots, and parent-child operations."""
    proj = ProjectRepository(session).create(name="Hierarchy Proj")
    res_repo = ResourceRepository(session)

    # Parent organization resource
    root_res = res_repo.create(
        project_id=proj.id,
        display_name="Organization 101",
        resource_type="organization",
    )

    # Child folder resource
    folder_res = res_repo.create(
        project_id=proj.id,
        display_name="Invoices Folder",
        resource_type="folder",
        parent_resource_id=root_res.id,
    )

    # Document child resource
    doc_res = res_repo.create(
        project_id=proj.id,
        display_name="Invoice_2026.pdf",
        resource_type="document",
        parent_resource_id=folder_res.id,
        sensitivity="high",
        external_id="DOC-9921",
        associated_endpoints=["/api/v1/invoices/9921"],
    )

    # Query roots
    roots = res_repo.get_root_resources(proj.id)
    assert len(roots) == 1
    assert roots[0].id == root_res.id

    # Query children
    children = res_repo.get_children(root_res.id)
    assert len(children) == 1
    assert children[0].id == folder_res.id

    sub_children = res_repo.get_children(folder_res.id)
    assert len(sub_children) == 1
    assert sub_children[0].id == doc_res.id
    assert sub_children[0].sensitivity == "high"


def test_policy_repository(session: Session):
    """Test PolicyRepository CRUD and filtering."""
    proj = ProjectRepository(session).create(name="Policy Proj")
    policy_repo = PolicyRepository(session)

    p1 = policy_repo.create(
        project_id=proj.id,
        name="Allow Admin Read Invoices",
        action="read",
        expected_decision="allow",
        subject_selector={"role": "admin"},
        resource_selector={"type": "invoice"},
    )
    p2 = policy_repo.create(
        project_id=proj.id,
        name="Deny Guest Delete Invoices",
        action="delete",
        expected_decision="deny",
        subject_selector={"role": "guest"},
        resource_selector={"type": "invoice"},
        enabled=False,
    )

    assert len(policy_repo.list_by_project(proj.id)) == 2
    enabled_only = policy_repo.list_by_project(proj.id, enabled_only=True)
    assert len(enabled_only) == 1
    assert enabled_only[0].id == p1.id

    delete_action = policy_repo.list_by_project(proj.id, action="delete")
    assert len(delete_action) == 1
    assert delete_action[0].id == p2.id


def test_traffic_record_repository(session: Session):
    """Test TrafficRecordRepository bulk creation, annotation, and links."""
    proj = ProjectRepository(session).create(name="Traffic Proj")
    ident = IdentityRepository(session).create(project_id=proj.id, name="Alice", role_type="user")
    res = ResourceRepository(session).create(project_id=proj.id, display_name="File", resource_type="file")
    traffic_repo = TrafficRecordRepository(session)

    # Bulk create
    records = [
        {
            "project_id": proj.id,
            "method": "GET",
            "url": "https://api.test.com/v1/users",
            "host": "api.test.com",
            "path": "/v1/users",
            "response_status": 200,
        },
        {
            "project_id": proj.id,
            "method": "POST",
            "url": "https://api.test.com/v1/users",
            "host": "api.test.com",
            "path": "/v1/users",
            "response_status": 201,
        },
    ]
    count = traffic_repo.bulk_create(records)
    assert count == 2

    # Query with host filter
    listed = traffic_repo.list_by_project(proj.id, host="api.test.com")
    assert len(listed) == 2
    first_id = listed[0].id

    # Annotate
    annotated = traffic_repo.annotate(first_id, {"auth_verified": True, "tag": "test"})
    assert annotated is not None
    assert annotated.annotations["auth_verified"] is True

    # Link identity and resource
    traffic_repo.link_identity(first_id, ident.id)
    traffic_repo.link_resource(first_id, res.id)

    rec = traffic_repo.get_by_id(first_id)
    assert rec.identity_id == ident.id
    assert rec.resource_id == res.id


def test_test_case_and_execution_lifecycle(session: Session):
    """Test TestCase and TestExecution workflow and outcome recording."""
    proj = ProjectRepository(session).create(name="Test Execution Proj")
    ident = IdentityRepository(session).create(project_id=proj.id, name="TestUser", role_type="user")
    case_repo = TestCaseRepository(session)
    exec_repo = TestExecutionRepository(session)

    case = case_repo.create(
        project_id=proj.id,
        name="TC-001 Read Other Tenant Doc",
        subject_identity_id=ident.id,
        action="read",
        expected_decision="deny",
    )
    assert case.result_status == "pending"

    # Start execution
    execution = exec_repo.create(
        test_case_id=case.id,
        project_id=proj.id,
        request_snapshot={"method": "GET", "url": "/docs/99"},
    )
    assert execution.status == "running"

    # Complete execution
    completed = exec_repo.complete(
        execution.id,
        status="passed",
        actual_status_code=403,
        actual_decision="deny",
        response_snapshot={"status": 403, "body": "Forbidden"},
    )
    assert completed is not None
    assert completed.status == "passed"
    assert completed.actual_decision == "deny"
    assert completed.completed_at is not None

    # Update case status
    case_repo.update(case.id, result_status="passed")
    assert case_repo.get_by_id(case.id).result_status == "passed"


def test_findings_repository(session: Session):
    """Test FindingRepository CRUD and status updates."""
    proj = ProjectRepository(session).create(name="Findings Proj")
    finding_repo = FindingRepository(session)

    finding = finding_repo.create(
        project_id=proj.id,
        title="BOLA Vulnerability in /api/v1/invoices",
        category="BOLA",
        affected_endpoint="/api/v1/invoices/{id}",
        expected_decision="deny",
        observed_decision="allow",
        severity="high",
        status="open",
    )
    assert finding.id is not None
    assert finding.severity == "high"

    # Filter
    high_findings = finding_repo.list_by_project(proj.id, severity="high")
    assert len(high_findings) == 1
    med_findings = finding_repo.list_by_project(proj.id, severity="medium")
    assert len(med_findings) == 0

    # Update status
    updated = finding_repo.update_status(finding.id, "verified", reviewer_notes="Confirmed by replay")
    assert updated is not None
    assert updated.status == "verified"
    assert updated.reviewer_notes == "Confirmed by replay"


def test_evidence_hash_and_tamper_detection(session: Session):
    """Test EvidenceRepository SHA-256 calculation and tamper verification."""
    proj = ProjectRepository(session).create(name="Evidence Proj")
    evidence_repo = EvidenceRepository(session)

    evidence = evidence_repo.create(
        project_id=proj.id,
        evidence_type="http_traffic",
        title="Unauthorized 200 OK Response",
        request_snapshot={"method": "GET", "url": "/api/secret"},
        response_snapshot={"status": 200, "body": "confidential_data"},
    )

    assert evidence.content_hash is not None
    assert len(evidence.content_hash) == 64

    # Verify original integrity
    assert evidence_repo.verify_hash(evidence.id) is True

    # Intentionally corrupt the stored content hash to simulate tampering
    evidence.content_hash = "0" * 64
    session.flush()

    assert evidence_repo.verify_hash(evidence.id) is False


def test_audit_event_repository(session: Session):
    """Test AuditEventRepository creation and date-range queries."""
    audit_repo = AuditEventRepository(session)

    now = datetime.now(UTC)
    t1 = now - timedelta(hours=2)
    t2 = now - timedelta(minutes=30)
    t3 = now

    audit_repo.create(event_type="LOGIN", description="User logged in", timestamp=t1)
    audit_repo.create(event_type="POLICY_EVAL", description="Evaluated policy", timestamp=t2)
    audit_repo.create(event_type="LOGOUT", description="User logged out", timestamp=t3)

    # Range query
    events_between = audit_repo.list_by_project(
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(minutes=1),
    )
    assert len(events_between) == 2
    types = [e.event_type for e in events_between]
    assert "POLICY_EVAL" in types
    assert "LOGOUT" in types


def test_settings_repository(session: Session):
    """Test SettingsRepository key-value management."""
    settings_repo = SettingsRepository(session)

    assert settings_repo.get("app.theme", default="dark") == "dark"

    # Set
    settings_repo.set("app.theme", "light")
    assert settings_repo.get("app.theme") == "light"

    settings_repo.set("proxy.port", "8080")
    all_settings = settings_repo.list_all()
    assert all_settings["app.theme"] == "light"
    assert all_settings["proxy.port"] == "8080"

    # Delete
    assert settings_repo.delete("app.theme") is True
    assert settings_repo.get("app.theme") is None
    assert settings_repo.delete("non_existent") is False
