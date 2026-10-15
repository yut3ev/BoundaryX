"""Tests for AuditLogger security auditing, event queries, sanitization, and export."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from boundaryx.infrastructure.database.base import Base
from boundaryx.security.audit import (
    BACKUP_CREATED,
    BACKUP_RESTORED,
    CREDENTIAL_CHANGED,
    FINDING_STATUS_CHANGED,
    IDENTITY_MODIFIED,
    POLICY_CHANGED,
    PROJECT_CREATED,
    PROJECT_MODIFIED,
    REPORT_EXPORTED,
    SCOPE_CHANGED,
    SECURITY_ERROR,
    TEST_STARTED,
    TEST_STOPPED,
    AuditLogger,
)


@pytest.fixture
def db_session_factory():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    return session_factory


def test_constants_defined() -> None:
    constants = [
        PROJECT_CREATED,
        PROJECT_MODIFIED,
        SCOPE_CHANGED,
        IDENTITY_MODIFIED,
        CREDENTIAL_CHANGED,
        POLICY_CHANGED,
        TEST_STARTED,
        TEST_STOPPED,
        FINDING_STATUS_CHANGED,
        REPORT_EXPORTED,
        BACKUP_CREATED,
        BACKUP_RESTORED,
        SECURITY_ERROR,
    ]
    for c in constants:
        assert isinstance(c, str)
        assert getattr(AuditLogger, c) == c


def test_log_event_and_sanitize_details(db_session_factory) -> None:
    logger = AuditLogger(session_factory=db_session_factory)
    project_id = uuid.uuid4()

    details = {
        "user": "test_user",
        "password": "unmasked_password_123",
        "api_key": "secret_key_abc",
        "nested": {
            "token": "tok_xyz_789",
            "normal_field": "ok_value",
        },
    }

    event = logger.log(
        event_type=SCOPE_CHANGED,
        description="Updated project scope",
        project_id=project_id,
        details=details,
    )

    assert event.id is not None
    assert event.event_type == SCOPE_CHANGED
    assert event.project_id == str(project_id)

    # Verify secret fields were sanitized in the stored event
    assert event.details["password"] == "[REDACTED]"
    assert event.details["nested"]["token"] == "[REDACTED]"
    assert event.details["nested"]["normal_field"] == "ok_value"
    assert event.details["user"] == "test_user"


def test_get_events_with_filters(db_session_factory) -> None:
    logger = AuditLogger(session_factory=db_session_factory)
    p1 = uuid.uuid4()
    p2 = uuid.uuid4()

    logger.log(PROJECT_CREATED, "Project 1 created", project_id=p1)
    logger.log(SCOPE_CHANGED, "Project 1 scope changed", project_id=p1)
    logger.log(PROJECT_CREATED, "Project 2 created", project_id=p2)
    logger.log(SECURITY_ERROR, "Project 2 security error", project_id=p2)

    # Filter by project_id
    p1_events = logger.get_events(project_id=p1)
    assert len(p1_events) == 2
    assert all(e.project_id == str(p1) for e in p1_events)

    # Filter by event_type
    created_events = logger.get_events(event_type=PROJECT_CREATED)
    assert len(created_events) == 2

    # Filter by limit
    limited_events = logger.get_events(limit=1)
    assert len(limited_events) == 1

    # Filter by time boundaries
    now = datetime.now(UTC)
    recent_events = logger.get_events(since=now - timedelta(hours=1))
    assert len(recent_events) == 4

    past_events = logger.get_events(until=now - timedelta(days=1))
    assert len(past_events) == 0


def test_export_audit_log_json(db_session_factory, tmp_path: Path) -> None:
    logger = AuditLogger(session_factory=db_session_factory)
    project_id = uuid.uuid4()

    logger.log(PROJECT_CREATED, "Created project", project_id=project_id, details={"status": "init"})
    logger.log(TEST_STARTED, "Execution started", project_id=project_id, details={"mode": "active"})

    json_path = tmp_path / "audit_export.json"
    exported_file = logger.export_audit_log(project_id=project_id, output_path=json_path, format="json")

    assert exported_file.exists()
    with exported_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    assert len(data) == 2
    assert data[0]["event_type"] == PROJECT_CREATED
    assert data[1]["event_type"] == TEST_STARTED


def test_export_audit_log_csv(db_session_factory, tmp_path: Path) -> None:
    logger = AuditLogger(session_factory=db_session_factory)
    project_id = uuid.uuid4()

    logger.log(PROJECT_CREATED, "Created project", project_id=project_id)
    csv_path = tmp_path / "audit_export.csv"
    exported_file = logger.export_audit_log(project_id=project_id, output_path=csv_path, format="csv")

    assert exported_file.exists()
    content = exported_file.read_text(encoding="utf-8")
    assert "id,timestamp,event_type,project_id,description,details" in content
    assert PROJECT_CREATED in content
    assert str(project_id) in content
