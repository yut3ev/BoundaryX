"""Unit tests for testing models, templates, and execution result structures."""

from uuid import uuid4

from boundaryx.application.testing.models import (
    ExecutionMode,
    RequestTemplate,
    TestCaseDefinition,
    TestExecutionResult,
    TestOutcome,
    TestResultStatus,
)


def test_execution_mode_coercion() -> None:
    assert ExecutionMode.from_str("active") == ExecutionMode.ACTIVE
    assert ExecutionMode.from_str("OFFLINE") == ExecutionMode.OFFLINE
    assert ExecutionMode.from_str("PREVIEW") == ExecutionMode.PREVIEW
    assert ExecutionMode.from_str("invalid_mode") == ExecutionMode.PREVIEW
    assert ExecutionMode.from_str(ExecutionMode.ACTIVE) == ExecutionMode.ACTIVE


def test_test_result_status_terminal() -> None:
    assert TestResultStatus.PASSED.is_terminal is True
    assert TestResultStatus.FAILED.is_terminal is True
    assert TestResultStatus.INCONCLUSIVE.is_terminal is True
    assert TestResultStatus.BLOCKED_BY_SCOPE.is_terminal is True
    assert TestResultStatus.CANCELLED.is_terminal is True
    assert TestResultStatus.ERROR.is_terminal is True
    assert TestResultStatus.NOT_RUN.is_terminal is False
    assert TestResultStatus.RUNNING.is_terminal is False
    assert TestResultStatus.QUEUED.is_terminal is False


def test_request_template_serialization() -> None:
    template = RequestTemplate(
        method="POST",
        url_template="https://api.example.com/items/{resource_id}",
        headers={"Content-Type": "application/json"},
        body_template='{"name": "test"}',
        query_params={"limit": 10},
    )
    dumped = template.to_dict()
    assert dumped["method"] == "POST"
    assert dumped["url_template"] == "https://api.example.com/items/{resource_id}"
    assert dumped["headers"]["Content-Type"] == "application/json"
    assert dumped["query_params"]["limit"] == 10


def test_test_case_definition_serialization() -> None:
    project_id = uuid4()
    ident_id = uuid4()
    res_id = uuid4()

    definition = TestCaseDefinition(
        project_id=project_id,
        name="Test IDOR On Order",
        subject_identity_id=ident_id,
        target_resource_id=res_id,
        action="READ",
        expected_decision="DENY",
        request_template=RequestTemplate(
            method="GET",
            url_template="https://api.example.com/orders/{resource_id}",
        ),
        preconditions=["resource.is_private == True"],
        execution_mode=ExecutionMode.ACTIVE,
    )

    dumped = definition.to_dict()
    assert dumped["name"] == "Test IDOR On Order"
    assert dumped["project_id"] == str(project_id)
    assert dumped["subject_identity_id"] == str(ident_id)
    assert dumped["target_resource_id"] == str(res_id)
    assert dumped["action"] == "READ"
    assert dumped["expected_decision"] == "DENY"
    assert dumped["execution_mode"] == "ACTIVE"


def test_test_execution_result_serialization() -> None:
    tc_id = uuid4()
    result = TestExecutionResult(
        test_case_id=tc_id,
        status=TestResultStatus.PASSED,
        outcome=TestOutcome.EXPECTED_DENIAL,
        actual_status_code=403,
        actual_decision="DENY",
        scope_check_passed=True,
        reasoning=["Access denied as expected"],
    )

    dumped = result.to_dict()
    assert dumped["test_case_id"] == str(tc_id)
    assert dumped["status"] == "PASSED"
    assert dumped["outcome"] == "EXPECTED_DENIAL"
    assert dumped["actual_status_code"] == 403
    assert dumped["actual_decision"] == "DENY"
    assert dumped["scope_check_passed"] is True
    assert "Access denied as expected" in dumped["reasoning"]
