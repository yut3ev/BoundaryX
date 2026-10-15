"""Unit tests for TestRunner execution engine."""

from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from boundaryx.application.testing.models import (
    ExecutionMode,
    RequestTemplate,
    TestCaseDefinition,
    TestExecutionResult,
    TestOutcome,
    TestResultStatus,
)
from boundaryx.application.testing.runner import TestRunner
from boundaryx.domain.identities.models import RoleType
from boundaryx.domain.policies.engine import PolicyEngine
from boundaryx.domain.policies.models import ExpectedDecision, Policy, PolicyAction, ResourceSelector, SubjectSelector
from boundaryx.domain.resources.models import ResourceType
from boundaryx.infrastructure.http.client import HttpClient, HttpResponse
from boundaryx.security.redaction import RedactionEngine
from boundaryx.security.scope import ScopeManager, ScopeRule


@pytest.fixture
def scope_manager() -> ScopeManager:
    sm = ScopeManager()
    sm.add_rule(ScopeRule(hostname="api.example.com", scheme="https"))
    return sm


@pytest.fixture
def mock_http_client() -> HttpClient:
    client = MagicMock(spec=HttpClient)
    client.is_cancelled = False
    return client


@pytest.fixture
def policy_engine() -> PolicyEngine:
    engine = PolicyEngine()
    policy = Policy(
        name="Allow Read for Editors",
        action=PolicyAction.READ,
        expected_decision=ExpectedDecision.ALLOW,
        subject_selector=SubjectSelector(role_type=RoleType.EDITOR),
        resource_selector=ResourceSelector(resource_type=ResourceType.DOCUMENT),
    )
    engine.add_policy(policy)
    return engine


@pytest.fixture
def test_runner(mock_http_client: HttpClient, scope_manager: ScopeManager, policy_engine: PolicyEngine) -> TestRunner:
    return TestRunner(
        http_client=mock_http_client,
        scope_manager=scope_manager,
        policy_engine=policy_engine,
        redaction_engine=RedactionEngine(),
    )


def test_preview_test(test_runner: TestRunner) -> None:
    project_id = uuid4()
    ident_id = uuid4()
    res_id = uuid4()

    tc = TestCaseDefinition(
        project_id=project_id,
        name="Preview Test Case",
        subject_identity_id=ident_id,
        target_resource_id=res_id,
        action="READ",
        expected_decision="ALLOW",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://api.example.com/docs/{resource_id}",
            headers={"Authorization": "Bearer secret-token-123"},
            query_params={"version": "2"},
        ),
    )

    identity = {"id": ident_id, "name": "Alice", "role_type": "EDITOR"}
    resource = {"id": res_id, "external_id": "doc_999", "display_name": "Quarterly Report"}

    preview = test_runner.preview_test(tc, identity, resource)

    assert "doc_999" in preview["raw_url"]
    assert "version=2" in preview["raw_url"]
    assert preview["scope_ok"] is True
    assert preview["identity_name"] == "Alice"
    assert preview["resource_name"] == "Quarterly Report"
    assert preview["headers"]["Authorization"] == "[REDACTED]"


def test_preview_test_out_of_scope(test_runner: TestRunner) -> None:
    tc = TestCaseDefinition(
        project_id=uuid4(),
        name="Out of scope test",
        subject_identity_id=uuid4(),
        action="READ",
        expected_decision="DENY",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://evil.external.com/api",
        ),
    )
    preview = test_runner.preview_test(tc, {"name": "Bob", "role_type": "AUTHENTICATED"})
    assert preview["scope_ok"] is False


def test_execute_offline_with_matching_evidence(test_runner: TestRunner, policy_engine: PolicyEngine) -> None:
    ident_id = uuid4()
    res_id = uuid4()

    tc = TestCaseDefinition(
        project_id=uuid4(),
        name="Offline Test",
        subject_identity_id=ident_id,
        target_resource_id=res_id,
        action="READ",
        expected_decision="ALLOW",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://api.example.com/docs/{resource_id}",
        ),
    )

    identity = {"id": ident_id, "name": "Alice", "role_type": "EDITOR"}
    resource = {"id": res_id, "external_id": "doc_123", "display_name": "Report", "resource_type": "DOCUMENT"}

    evidence = [
        {
            "id": str(uuid4()),
            "method": "GET",
            "url": "https://api.example.com/docs/doc_123",
            "response_status": 200,
            "response_body": '{"id": "doc_123", "title": "Report"}',
            "response_headers": {"content-type": "application/json"},
        }
    ]

    result = test_runner.execute_offline(tc, policy_engine, identity, resource, existing_evidence=evidence)
    assert result.status == TestResultStatus.PASSED
    assert result.outcome == TestOutcome.EXPECTED_ALLOW
    assert result.actual_status_code == 200


def test_execute_offline_insufficient_evidence(test_runner: TestRunner, policy_engine: PolicyEngine) -> None:
    tc = TestCaseDefinition(
        project_id=uuid4(),
        name="Offline Test No Evidence",
        subject_identity_id=uuid4(),
        action="READ",
        expected_decision="ALLOW",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://api.example.com/docs/absent",
        ),
    )
    result = test_runner.execute_offline(tc, policy_engine, {"name": "Alice"}, existing_evidence=[])
    assert result.status == TestResultStatus.INCONCLUSIVE
    assert result.outcome == TestOutcome.INSUFFICIENT_EVIDENCE


def test_execute_active_expected_allow_passed(test_runner: TestRunner, mock_http_client: MagicMock) -> None:
    res_id = uuid4()
    resource = {"id": res_id, "external_id": "res_100", "display_name": "Target Res"}

    tc = TestCaseDefinition(
        project_id=uuid4(),
        name="Active Allow Test",
        subject_identity_id=uuid4(),
        target_resource_id=res_id,
        action="READ",
        expected_decision="ALLOW",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://api.example.com/res/{resource_id}",
        ),
    )

    mock_http_client.send_request.return_value = HttpResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"external_id": "res_100", "data": "confidential"}',
        content_type="application/json",
        url="https://api.example.com/res/res_100",
    )

    result = test_runner.execute_active(tc, {"name": "Alice"}, {"Authorization": "Bearer token"}, resource)
    assert result.status == TestResultStatus.PASSED
    assert result.outcome == TestOutcome.EXPECTED_ALLOW
    assert result.actual_status_code == 200
    assert result.actual_decision == "ALLOW"


def test_execute_active_unexpected_allow_failed_defect(test_runner: TestRunner, mock_http_client: MagicMock) -> None:
    res_id = uuid4()
    resource = {"id": res_id, "external_id": "res_100", "display_name": "Target Res"}

    tc = TestCaseDefinition(
        project_id=uuid4(),
        name="Active Deny Expected",
        subject_identity_id=uuid4(),
        target_resource_id=res_id,
        action="READ",
        expected_decision="DENY",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://api.example.com/res/{resource_id}",
        ),
    )

    mock_http_client.send_request.return_value = HttpResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"external_id": "res_100", "data": "confidential"}',
        content_type="application/json",
        url="https://api.example.com/res/res_100",
    )

    result = test_runner.execute_active(tc, {"name": "Bob"}, {"Authorization": "Bearer bob-token"}, resource)
    assert result.status == TestResultStatus.FAILED
    assert result.outcome == TestOutcome.UNEXPECTED_ALLOW
    assert result.actual_decision == "ALLOW"


def test_execute_active_blocked_by_scope(test_runner: TestRunner) -> None:
    tc = TestCaseDefinition(
        project_id=uuid4(),
        name="Active Out of Scope",
        subject_identity_id=uuid4(),
        action="READ",
        expected_decision="ALLOW",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://unauthorized-domain.com/secret",
        ),
    )
    result = test_runner.execute_active(tc, {"name": "Alice"}, {})
    assert result.status == TestResultStatus.BLOCKED_BY_SCOPE
    assert result.scope_check_passed is False


def test_execute_active_cancellation(test_runner: TestRunner) -> None:
    test_runner.cancel()
    assert test_runner.is_cancelled is True

    tc = TestCaseDefinition(
        project_id=uuid4(),
        name="Active Cancelled",
        subject_identity_id=uuid4(),
        action="READ",
        expected_decision="ALLOW",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://api.example.com/test",
        ),
    )
    result = test_runner.execute_active(tc, {"name": "Alice"}, {})
    assert result.status == TestResultStatus.CANCELLED

    test_runner.reset()
    assert test_runner.is_cancelled is False


def test_execute_batch_preview(test_runner: TestRunner) -> None:
    tc1 = TestCaseDefinition(
        project_id=uuid4(),
        name="Batch TC 1",
        subject_identity_id=uuid4(),
        action="READ",
        expected_decision="ALLOW",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://api.example.com/items/1",
        ),
    )
    tc2 = TestCaseDefinition(
        project_id=uuid4(),
        name="Batch TC 2",
        subject_identity_id=uuid4(),
        action="READ",
        expected_decision="DENY",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://api.example.com/items/2",
        ),
    )

    progress_reports = []

    def on_progress(current: int, total: int, res: TestExecutionResult) -> None:
        progress_reports.append((current, total, res.status))

    results = test_runner.execute_batch(
        test_cases=[tc1, tc2],
        identities={},
        resources={},
        auth_profiles={},
        mode=ExecutionMode.PREVIEW,
        progress_callback=on_progress,
    )

    assert len(results) == 2
    assert len(progress_reports) == 2
    assert progress_reports[0][0] == 1
    assert progress_reports[1][0] == 2
