"""Authorization testing domain models and data structures for BoundaryX.

Defines test case definitions, request templates, execution modes, test outcomes,
and execution result snapshots for security testing workflows.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(UTC)


class ExecutionMode(str, Enum):
    """Operational mode for authorization testing execution."""

    OFFLINE = "OFFLINE"
    PREVIEW = "PREVIEW"
    ACTIVE = "ACTIVE"

    @classmethod
    def from_str(cls, value: str | ExecutionMode) -> ExecutionMode:
        """Coerce a string or enum instance to ExecutionMode safely."""
        if isinstance(value, cls):
            return value
        val_upper = str(value).strip().upper()
        for member in cls:
            if member.value == val_upper:
                return member
        return cls.PREVIEW


class TestResultStatus(str, Enum):
    """Lifecycle and evaluation status of an authorization test execution."""

    __test__ = False

    NOT_RUN = "NOT_RUN"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED_BY_SCOPE = "BLOCKED_BY_SCOPE"
    CANCELLED = "CANCELLED"
    ERROR = "ERROR"

    @property
    def is_terminal(self) -> bool:
        """Return True if status represents a completed or aborted run."""
        return self in {
            TestResultStatus.PASSED,
            TestResultStatus.FAILED,
            TestResultStatus.INCONCLUSIVE,
            TestResultStatus.BLOCKED_BY_SCOPE,
            TestResultStatus.CANCELLED,
            TestResultStatus.ERROR,
        }


class TestOutcome(str, Enum):
    """Analytical verdict classifying the observed response against expectations."""

    __test__ = False

    EXPECTED_DENIAL = "EXPECTED_DENIAL"
    UNEXPECTED_ALLOW = "UNEXPECTED_ALLOW"
    UNEXPECTED_DENIAL = "UNEXPECTED_DENIAL"
    EXPECTED_ALLOW = "EXPECTED_ALLOW"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    HTTP_ERROR = "HTTP_ERROR"


class RequestTemplate(BaseModel):
    """Template describing the HTTP request structure for an authorization test."""

    model_config = ConfigDict(from_attributes=True)

    method: str = Field(default="GET", description="HTTP method (e.g. 'GET', 'POST', 'DELETE')")
    url_template: str = Field(
        description="URL pattern containing placeholder tokens (e.g. 'https://api.example.com/orders/{resource_id}')"
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Base headers to send (excluding runtime injected auth headers)",
    )
    body_template: str | None = Field(
        default=None,
        description="Optional payload template with placeholder support",
    )
    query_params: dict[str, Any] = Field(
        default_factory=dict,
        description="Query parameters to append to the URL",
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert RequestTemplate to a plain dictionary."""
        return self.model_dump(mode="json")


class TestCaseDefinition(BaseModel):
    """Complete specification of an authorization test case."""

    __test__ = False

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique test case identifier")
    project_id: UUID = Field(description="Parent project context ID")
    name: str = Field(description="Descriptive title of the test case")
    subject_identity_id: UUID = Field(description="ID of the identity executing the test")
    target_resource_id: UUID | None = Field(
        default=None,
        description="ID of the resource being targeted, if applicable",
    )
    action: str = Field(description="Action being performed (e.g. 'READ', 'WRITE', 'DELETE')")
    expected_decision: str = Field(description="Expected authorization decision ('ALLOW' or 'DENY')")
    request_template: RequestTemplate = Field(description="HTTP request construction template")
    preconditions: list[str] = Field(
        default_factory=list,
        description="List of prerequisites or invariant assertions",
    )
    auth_profile_id: UUID | None = Field(
        default=None,
        description="Optional linked authentication profile ID",
    )
    execution_mode: ExecutionMode = Field(
        default=ExecutionMode.PREVIEW,
        description="Designated execution mode for this test case",
    )
    created_at: datetime = Field(
        default_factory=_utc_now,
        description="Creation timestamp in UTC",
    )
    updated_at: datetime = Field(
        default_factory=_utc_now,
        description="Last update timestamp in UTC",
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert definition to dictionary format."""
        dumped = self.model_dump(mode="json")
        dumped["id"] = str(self.id)
        dumped["project_id"] = str(self.project_id)
        dumped["subject_identity_id"] = str(self.subject_identity_id)
        if self.target_resource_id:
            dumped["target_resource_id"] = str(self.target_resource_id)
        if self.auth_profile_id:
            dumped["auth_profile_id"] = str(self.auth_profile_id)
        return dumped


class TestExecutionResult(BaseModel):
    """Complete record of an executed authorization test case."""

    __test__ = False

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique test execution run ID")
    test_case_id: UUID = Field(description="ID of the test case executed")
    started_at: datetime = Field(
        default_factory=_utc_now,
        description="Timestamp when execution initiated (UTC)",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="Timestamp when execution finalized (UTC)",
    )
    status: TestResultStatus = Field(description="High-level test status outcome")
    outcome: TestOutcome | None = Field(
        default=None,
        description="Granular analytical authorization verdict",
    )
    request_snapshot: dict[str, Any] | None = Field(
        default=None,
        description="Snapshot of outgoing HTTP request with sensitive data sanitized",
    )
    response_snapshot: dict[str, Any] | None = Field(
        default=None,
        description="Snapshot of inbound HTTP response",
    )
    actual_status_code: int | None = Field(
        default=None,
        description="Received HTTP response status code (e.g. 200, 403)",
    )
    actual_decision: str | None = Field(
        default=None,
        description="Inferred access control decision ('ALLOW', 'DENY', or None)",
    )
    error_message: str | None = Field(
        default=None,
        description="Error description if test failed or errored",
    )
    evidence_id: UUID | None = Field(
        default=None,
        description="ID of created evidence record if persisted",
    )
    scope_check_passed: bool = Field(
        default=True,
        description="Whether target and redirect URLs complied with project scope",
    )
    reasoning: list[str] = Field(
        default_factory=list,
        description="Step-by-step analytical reasoning justifying the verdict",
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        dumped = self.model_dump(mode="json")
        dumped["id"] = str(self.id)
        dumped["test_case_id"] = str(self.test_case_id)
        if self.evidence_id:
            dumped["evidence_id"] = str(self.evidence_id)
        return dumped
