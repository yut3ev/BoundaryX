"""Unit tests for ProjectService lifecycle, confirmations, backups, and statistics."""

from pathlib import Path
from uuid import uuid4

import pytest

from boundaryx.application.projects import (
    ConfirmationRequiredError,
    ProjectNotFoundError,
    ProjectService,
)
from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.infrastructure.database.models import FindingModel, IdentityModel
from boundaryx.security.audit import AuditLogger


@pytest.fixture
def test_db_manager(tmp_path: Path):
    db_file = tmp_path / "test_projects.db"
    manager = DatabaseManager(db_file)
    manager.create_tables()
    return manager


@pytest.fixture
def audit_logger(test_db_manager):
    return AuditLogger(session_factory=test_db_manager.session_factory)


@pytest.fixture
def project_service(test_db_manager, audit_logger):
    return ProjectService(db_manager=test_db_manager, audit_logger=audit_logger)


def test_project_create_and_open(project_service):
    proj = project_service.create_project(
        name="Banking API Security",
        description="Core banking endpoint test",
        settings={"env": "staging"},
    )
    assert proj["name"] == "Banking API Security"
    assert proj["description"] == "Core banking endpoint test"
    assert proj["settings"]["env"] == "staging"
    assert project_service.active_project_id == proj["id"]

    # Open project
    opened = project_service.open_project(proj["id"])
    assert opened["id"] == proj["id"]
    assert project_service.active_project_id == proj["id"]


def test_project_list_and_update(project_service):
    p1 = project_service.create_project(name="Project Alpha")
    p2 = project_service.create_project(name="Project Beta")

    projects = project_service.list_projects()
    assert len(projects) >= 2
    ids = [p["id"] for p in projects]
    assert p1["id"] in ids
    assert p2["id"] in ids

    # Update metadata
    updated = project_service.update_project(p1["id"], description="Updated alpha desc")
    assert updated["description"] == "Updated alpha desc"


def test_project_archive(project_service):
    p = project_service.create_project(name="Archived Target")
    project_service.archive_project(p["id"])

    active_projects = project_service.list_projects(include_archived=False)
    assert p["id"] not in [x["id"] for x in active_projects]

    all_projects = project_service.list_projects(include_archived=True)
    assert p["id"] in [x["id"] for x in all_projects]


def test_project_delete_confirmation_token_required(project_service):
    p = project_service.create_project(name="Doomed Project")
    pid = p["id"]

    # Deletion without token raises ConfirmationRequiredError
    with pytest.raises(ConfirmationRequiredError) as exc_info:
        project_service.delete_project(pid, confirmation_token="WRONG_TOKEN")
    assert "Expected confirmation_token=" in str(exc_info.value)

    # Deletion with correct token succeeds
    token = project_service.get_delete_confirmation_token(pid)
    deleted = project_service.delete_project(pid, confirmation_token=token)
    assert deleted is True

    # Subsequent open raises ProjectNotFoundError
    with pytest.raises(ProjectNotFoundError):
        project_service.open_project(pid)


def test_project_backup_and_restore(project_service, tmp_path: Path):
    p = project_service.create_project(name="Backup Candidate", description="Original")
    pid = p["id"]

    backup_dir = tmp_path / "backups"
    backup_file = project_service.backup_project(pid, backup_dir)
    assert backup_file.exists()

    # Restore from backup
    new_pid = project_service.restore_project(backup_file)
    assert new_pid is not None
    assert str(new_pid) != pid

    restored = project_service.open_project(new_pid)
    assert "Backup Candidate (Imported)" in restored["name"]


def test_project_stats(project_service, test_db_manager):
    p = project_service.create_project(name="Stats Project")
    pid = p["id"]

    with test_db_manager.get_session() as session:
        # Add 1 identity and 1 finding
        ident = IdentityModel(id=str(uuid4()), project_id=pid, name="Tester", role_type="EDITOR")
        session.add(ident)
        find = FindingModel(
            id=str(uuid4()),
            project_id=pid,
            title="Test finding",
            category="CUSTOM",
            affected_endpoint="/api/v1/test",
            expected_decision="DENY",
            observed_decision="ALLOW",
            severity="LOW",
        )
        session.add(find)

    stats = project_service.get_project_stats(pid)
    assert stats["project_name"] == "Stats Project"
    assert stats["identities_count"] == 1
    assert stats["findings_count"] == 1
    assert stats["policies_count"] == 0
