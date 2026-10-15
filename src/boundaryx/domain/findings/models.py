"""Security findings and authorization boundary defect models for BoundaryX.

Represents detected authorization vulnerabilities, IDOR issues, cross-tenant leaks,
confidence explanations, and reproduction details.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from boundaryx.domain.policies.models import ExpectedDecision  # noqa: TCH001


def _utc_now() -> datetime:
    """Return the current timestamp in UTC timezone."""
    return datetime.now(UTC)


class FindingSeverity(StrEnum):
    """Vulnerability severity rating following industry standards."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingStatus(StrEnum):
    """Operational triage and remediation lifecycle state."""

    NEW = "NEW"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FIXED = "FIXED"
    REOPENED = "REOPENED"


class FindingCategory(StrEnum):
    """Authorization defect classification."""

    CROSS_USER_ACCESS = "CROSS_USER_ACCESS"
    CROSS_TENANT_ACCESS = "CROSS_TENANT_ACCESS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    MISSING_AUTHORIZATION = "MISSING_AUTHORIZATION"
    INCONSISTENT_POLICY = "INCONSISTENT_POLICY"
    IDOR = "IDOR"
    BROKEN_BOUNDARY = "BROKEN_BOUNDARY"
    CUSTOM = "CUSTOM"


class ConfidenceLevel(StrEnum):
    """Analyst and automated test confidence level."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class ConfidenceExplanation(BaseModel):
    """Structured explanation justifying finding confidence rating."""

    model_config = ConfigDict(from_attributes=True)

    level: ConfidenceLevel = Field(description="Assigned confidence tier")
    factors: list[str] = Field(
        default_factory=list,
        description="Observed indicators supporting this finding (e.g. 'HTTP 200 with sensitive payload')",
    )
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Gaps or missing verification steps (e.g. 'State mutation not confirmed in second tenant')",
    )
    is_reproducible: bool | None = Field(
        default=None,
        description="Whether defect was consistently reproduced across multiple trials",
    )
    has_explicit_policy: bool = Field(
        default=False,
        description="Whether an explicit policy rule contradicted the observed response",
    )
    notes: str = Field(default="", description="Additional analyst notes on confidence assessment")


class Finding(BaseModel):
    """A detected authorization vulnerability or boundary defect."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique finding identifier")
    project_id: UUID = Field(default_factory=uuid4, description="Target project context ID")
    title: str = Field(description="Succinct finding title (e.g. 'BOLA on /api/orders/{id}')")
    category: FindingCategory = Field(description="Finding category classification")
    affected_endpoint: str = Field(description="HTTP endpoint or route affected (e.g. 'GET /api/v1/invoices/123')")
    affected_resource_id: UUID | None = Field(
        default=None,
        description="ID of target resource accessed across boundary (optional)",
    )
    subject_identity_id: UUID | None = Field(
        default=None,
        description="ID of identity used to reproduce unauthorized access (optional)",
    )
    expected_decision: ExpectedDecision = Field(
        description="Expected authorization decision (usually DENY for vulnerability findings)",
    )
    observed_decision: str | None = Field(
        default=None,
        description="Observed response behavior (e.g. 'HTTP 200 OK - ALLOW')",
    )
    severity: FindingSeverity = Field(description="Assigned vulnerability severity")
    confidence: ConfidenceExplanation = Field(description="Structured confidence justification")
    evidence_ids: list[UUID] = Field(
        default_factory=list,
        description="Linked Evidence records supporting this finding",
    )
    reproduction_steps: list[str] = Field(
        default_factory=list,
        description="Step-by-step procedure to reproduce this boundary defect",
    )
    status: FindingStatus = Field(
        default=FindingStatus.NEW,
        description="Current remediation/triage lifecycle status",
    )
    reviewer_notes: str = Field(default="", description="Analyst comments and verification notes")
    first_seen: datetime = Field(
        default_factory=_utc_now,
        description="Initial detection timestamp (UTC)",
    )
    last_verified: datetime | None = Field(
        default=None,
        description="Timestamp of most recent reproduction/verification (UTC)",
    )
    related_test_case_ids: list[UUID] = Field(
        default_factory=list,
        description="Linked test case definitions executing this check",
    )
    created_at: datetime = Field(
        default_factory=_utc_now,
        description="Finding creation timestamp (UTC)",
    )
    updated_at: datetime = Field(
        default_factory=_utc_now,
        description="Last update timestamp (UTC)",
    )

    @property
    def is_confirmed(self) -> bool:
        """Return True if finding has been verified and confirmed."""
        return self.status == FindingStatus.CONFIRMED

    @property
    def is_actionable(self) -> bool:
        """Return True if finding requires developer/analyst remediation."""
        return self.status in {
            FindingStatus.NEW,
            FindingStatus.NEEDS_REVIEW,
            FindingStatus.CONFIRMED,
            FindingStatus.REOPENED,
        }

    def mark_confirmed(self, notes: str = "") -> None:
        """Mark finding as confirmed by analyst."""
        self.status = FindingStatus.CONFIRMED
        if notes:
            self.reviewer_notes = f"{self.reviewer_notes}\n{notes}".strip()
        self.last_verified = _utc_now()
        self.updated_at = _utc_now()

    def mark_false_positive(self, notes: str = "") -> None:
        """Mark finding as a false positive."""
        self.status = FindingStatus.FALSE_POSITIVE
        if notes:
            self.reviewer_notes = f"{self.reviewer_notes}\n{notes}".strip()
        self.updated_at = _utc_now()


Finding.model_rebuild()
