"""Unit tests for ScopeService application logic and database persistence."""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from boundaryx.application.scope.service import ScopeService
from boundaryx.infrastructure.database.base import Base
from boundaryx.security.audit import SCOPE_CHANGED, AuditLogger
from boundaryx.security.scope import ScopeManager, ScopeRule


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


def test_scope_service_flow(db_session_factory) -> None:
    audit_logger = AuditLogger(session_factory=db_session_factory)
    scope_mgr = ScopeManager()
    service = ScopeService(scope_manager=scope_mgr, audit_logger=audit_logger)

    project_id = uuid.uuid4()

    with db_session_factory() as session:
        # 1. Add rules
        rule1 = ScopeRule(hostname="api.target.com", path_prefix="/v1")
        rule2 = ScopeRule(hostname="api.target.com", path_prefix="/v1/admin", is_exclusion=True)
        service.add_rule(session, project_id, rule1)
        service.add_rule(session, project_id, rule2)

    # Verify memory
    assert len(service.scope_manager.get_rules()) == 2

    # 2. Check URL validation via service
    allowed1, _ = service.check_url("https://api.target.com/v1/users")
    assert allowed1 is True

    allowed2, reason2 = service.check_url("https://api.target.com/v1/admin/keys")
    assert allowed2 is False
    assert "blocked by exclusion rule" in reason2

    # 3. Check redirect via service
    allowed_redir, _ = service.check_redirect("https://api.target.com/v1/users", "/v1/settings")
    assert allowed_redir is True

    # 4. Check preview via service
    prev = service.preview()
    assert prev["total_rules"] == 2
    assert prev["allow_rules_count"] == 1
    assert prev["exclusion_rules_count"] == 1

    # 5. Verify database persistence by loading in a fresh ScopeService
    fresh_mgr = ScopeManager()
    fresh_service = ScopeService(scope_manager=fresh_mgr, audit_logger=audit_logger)
    with db_session_factory() as session:
        loaded = fresh_service.load_rules_from_db(session, project_id)

    assert len(loaded) == 2
    assert loaded[0].hostname == "api.target.com"
    assert loaded[0].path_prefix == "/v1"
    assert loaded[1].is_exclusion is True

    # 6. Remove a rule
    with db_session_factory() as session:
        removed = fresh_service.remove_rule(session, project_id, 1)
        assert removed.is_exclusion is True

    assert len(fresh_service.scope_manager.get_rules()) == 1

    # Verify DB now only has 1 rule
    with db_session_factory() as session:
        reloaded = fresh_service.load_rules_from_db(session, project_id)
        assert len(reloaded) == 1

    # 7. Verify audit events were recorded
    events = audit_logger.get_events(project_id=project_id, event_type=SCOPE_CHANGED)
    assert len(events) >= 3  # added twice, removed once
