"""Unit tests for TestCaseService application service."""

from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from boundaryx.application.testing.models import (
    ExecutionMode,
    RequestTemplate,
    TestCaseDefinition,
    TestOutcome,
    TestResultStatus,
)
from boundaryx.application.testing.runner import TestRunner
from boundaryx.application.testing.service import TestCaseService
from boundaryx.domain.policies.engine import PolicyEngine
from boundaryx.infrastructure.database.base import Base
from boundaryx.infrastructure.database.models import (
    IdentityModel,
    PolicyModel,
    ProjectModel,
    ResourceModel,
)
from boundaryx.infrastructure.http.client import HttpClient, HttpResponse
from boundaryx.security.scope import ScopeManager, ScopeRule


@pytest.fixture
def db_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def test_case_service() -> TestCaseService:
    sm = ScopeManager()
    sm.add_rule(ScopeRule(hostname="api.test.local", scheme="https"))
    pe = PolicyEngine()
    mock_http = MagicMock(spec=HttpClient)
    mock_http.is_cancelled = False
    mock_http.send_request.return_value = HttpResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"external_id": "item_1", "status": "ok"}',
        content_type="application/json",
        url="https://api.test.local/items/item_1",
    )
    runner = TestRunner(http_client=mock_http, scope_manager=sm, policy_engine=pe)
    return TestCaseService(db_manager=None, test_runner=runner)


def test_create_and_get_test_case(db_session: Session, test_case_service: TestCaseService) -> None:
    proj_id = uuid4()
    ident_id = uuid4()

    # Create dummy project and identity in DB
    proj = ProjectModel(id=str(proj_id), name="Test Project")
    ident = IdentityModel(id=str(ident_id), project_id=str(proj_id), name="User A", role_type="AUTHENTICATED")
    db_session.add_all([proj, ident])
    db_session.commit()

    definition = TestCaseDefinition(
        project_id=proj_id,
        name="Test Read Item",
        subject_identity_id=ident_id,
        action="READ",
        expected_decision="ALLOW",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://api.test.local/items/1",
        ),
        preconditions=["token != null"],
        execution_mode=ExecutionMode.ACTIVE,
    )

    tc_id = test_case_service.create_test_case(db_session, proj_id, definition)
    assert tc_id == definition.id

    fetched = test_case_service.get_test_case(db_session, tc_id)
    assert fetched is not None
    assert fetched["name"] == "Test Read Item"
    assert fetched["action"] == "READ"
    assert fetched["expected_decision"] == "ALLOW"
    assert fetched["execution_mode"] == "ACTIVE"


def test_list_and_update_and_delete_test_case(db_session: Session, test_case_service: TestCaseService) -> None:
    proj_id = uuid4()
    ident_id = uuid4()

    proj = ProjectModel(id=str(proj_id), name="Project B")
    ident = IdentityModel(id=str(ident_id), project_id=str(proj_id), name="User B", role_type="ADMIN")
    db_session.add_all([proj, ident])
    db_session.commit()

    definition = TestCaseDefinition(
        project_id=proj_id,
        name="Test 1",
        subject_identity_id=ident_id,
        action="WRITE",
        expected_decision="ALLOW",
        request_template=RequestTemplate(method="POST", url_template="https://api.test.local/create"),
    )
    tc_id = test_case_service.create_test_case(db_session, proj_id, definition)

    # List
    cases = test_case_service.list_test_cases(db_session, proj_id)
    assert len(cases) == 1
    assert cases[0]["id"] == str(tc_id)

    # Update
    updated = test_case_service.update_test_case(db_session, tc_id, name="Updated Test 1", action="DELETE")
    assert updated["name"] == "Updated Test 1"
    assert updated["action"] == "DELETE"

    # Delete
    deleted = test_case_service.delete_test_case(db_session, tc_id)
    assert deleted is True
    assert test_case_service.get_test_case(db_session, tc_id) is None


def test_execute_test_and_finding_creation_on_violation(
    db_session: Session, test_case_service: TestCaseService
) -> None:
    proj_id = uuid4()
    ident_id = uuid4()
    res_id = uuid4()

    proj = ProjectModel(id=str(proj_id), name="Project C")
    ident = IdentityModel(id=str(ident_id), project_id=str(proj_id), name="Unauthorized User", role_type="GUEST")
    res = ResourceModel(
        id=str(res_id),
        project_id=str(proj_id),
        display_name="Private Order",
        resource_type="ORDER",
        external_id="item_1",
    )
    db_session.add_all([proj, ident, res])
    db_session.commit()

    # Define test case expecting DENY
    definition = TestCaseDefinition(
        project_id=proj_id,
        name="Verify Unauthorized Order Access Denied",
        subject_identity_id=ident_id,
        target_resource_id=res_id,
        action="READ",
        expected_decision="DENY",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://api.test.local/items/{resource_id}",
        ),
        execution_mode=ExecutionMode.ACTIVE,
    )
    tc_id = test_case_service.create_test_case(db_session, proj_id, definition)

    # Execute test (mock returns 200 with item_1 payload -> UNEXPECTED_ALLOW!)
    result = test_case_service.execute_test(db_session, tc_id, mode=ExecutionMode.ACTIVE)
    assert result.status == TestResultStatus.FAILED
    assert result.outcome == TestOutcome.UNEXPECTED_ALLOW

    # Verify execution history recorded
    history = test_case_service.get_execution_history(db_session, tc_id)
    assert len(history) == 1
    assert history[0]["actual_status_code"] == 200

    # Verify Finding was automatically created!
    findings = test_case_service.list_test_cases(db_session, proj_id)
    assert len(findings) == 1


def test_generate_test_cases_from_policies(db_session: Session, test_case_service: TestCaseService) -> None:
    proj_id = uuid4()
    ident_id = uuid4()
    res_id = uuid4()

    proj = ProjectModel(id=str(proj_id), name="Project D")
    ident = IdentityModel(id=str(ident_id), project_id=str(proj_id), name="Auditor", role_type="ADMIN")
    res = ResourceModel(
        id=str(res_id),
        project_id=str(proj_id),
        display_name="Invoice 100",
        resource_type="INVOICE",
        external_id="inv_100",
        associated_endpoints=["https://api.test.local/invoices/inv_100"],
    )
    policy = PolicyModel(
        id=str(uuid4()),
        project_id=str(proj_id),
        name="Admins Can Read Invoices",
        action="READ",
        expected_decision="ALLOW",
        subject_selector={"role_type": "ADMIN"},
        resource_selector={"resource_type": "INVOICE"},
        enabled=True,
    )
    db_session.add_all([proj, ident, res, policy])
    db_session.commit()

    generated_ids = test_case_service.generate_test_cases_from_policies(db_session, proj_id)
    assert len(generated_ids) >= 1

    cases = test_case_service.list_test_cases(db_session, proj_id)
    assert len(cases) == len(generated_ids)
    assert cases[0]["action"] == "READ"
    assert cases[0]["expected_decision"] == "ALLOW"
