"""Unit tests for Finding and vulnerability models."""

from uuid import UUID, uuid4

from boundaryx.domain.findings.models import (
    ConfidenceExplanation,
    ConfidenceLevel,
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
)
from boundaryx.domain.policies.models import ExpectedDecision


def test_finding_enums() -> None:
    """Verify Finding severity, status, category, and confidence level enums."""
    assert FindingSeverity.CRITICAL == "CRITICAL"
    assert FindingSeverity.HIGH == "HIGH"
    assert FindingSeverity.MEDIUM == "MEDIUM"
    assert FindingSeverity.LOW == "LOW"
    assert FindingSeverity.INFORMATIONAL == "INFORMATIONAL"

    assert FindingStatus.NEW == "NEW"
    assert FindingStatus.NEEDS_REVIEW == "NEEDS_REVIEW"
    assert FindingStatus.CONFIRMED == "CONFIRMED"
    assert FindingStatus.FALSE_POSITIVE == "FALSE_POSITIVE"
    assert FindingStatus.ACCEPTED_RISK == "ACCEPTED_RISK"
    assert FindingStatus.FIXED == "FIXED"
    assert FindingStatus.REOPENED == "REOPENED"

    assert FindingCategory.CROSS_USER_ACCESS == "CROSS_USER_ACCESS"
    assert FindingCategory.CROSS_TENANT_ACCESS == "CROSS_TENANT_ACCESS"
    assert FindingCategory.PRIVILEGE_ESCALATION == "PRIVILEGE_ESCALATION"
    assert FindingCategory.MISSING_AUTHORIZATION == "MISSING_AUTHORIZATION"
    assert FindingCategory.INCONSISTENT_POLICY == "INCONSISTENT_POLICY"
    assert FindingCategory.IDOR == "IDOR"
    assert FindingCategory.BROKEN_BOUNDARY == "BROKEN_BOUNDARY"
    assert FindingCategory.CUSTOM == "CUSTOM"

    assert ConfidenceLevel.HIGH == "HIGH"
    assert ConfidenceLevel.MEDIUM == "MEDIUM"
    assert ConfidenceLevel.LOW == "LOW"
    assert ConfidenceLevel.INSUFFICIENT_EVIDENCE == "INSUFFICIENT_EVIDENCE"


def test_confidence_explanation_model() -> None:
    """Test ConfidenceExplanation model."""
    explanation = ConfidenceExplanation(
        level=ConfidenceLevel.HIGH,
        factors=["HTTP 200 returned across distinct tenant accounts", "State persisted in target store"],
        missing_evidence=[],
        is_reproducible=True,
        has_explicit_policy=True,
        notes="High confidence IDOR",
    )
    assert explanation.level == ConfidenceLevel.HIGH
    assert len(explanation.factors) == 2
    assert explanation.is_reproducible is True
    assert explanation.has_explicit_policy is True


def test_finding_lifecycle_and_methods() -> None:
    """Test Finding lifecycle status transitions and properties."""
    project_id = uuid4()
    resource_id = uuid4()
    identity_id = uuid4()
    evidence_id = uuid4()

    finding = Finding(
        project_id=project_id,
        title="BOLA on /api/v1/invoices/{id}",
        category=FindingCategory.IDOR,
        affected_endpoint="GET /api/v1/invoices/991",
        affected_resource_id=resource_id,
        subject_identity_id=identity_id,
        expected_decision=ExpectedDecision.DENY,
        observed_decision="HTTP 200 OK with full invoice payload",
        severity=FindingSeverity.HIGH,
        confidence=ConfidenceExplanation(
            level=ConfidenceLevel.HIGH,
            factors=["Subject from Tenant A accessed invoice owned by Tenant B"],
        ),
        evidence_ids=[evidence_id],
        reproduction_steps=[
            "1. Authenticate as Tenant A member",
            "2. Issue GET /api/v1/invoices/991",
            "3. Observe HTTP 200 with sensitive financial records",
        ],
    )

    assert isinstance(finding.id, UUID)
    assert finding.status == FindingStatus.NEW
    assert finding.is_confirmed is False
    assert finding.is_actionable is True

    # Mark confirmed
    finding.mark_confirmed(notes="Verified manually with curl")
    assert finding.status == FindingStatus.CONFIRMED
    assert finding.is_confirmed is True
    assert finding.last_verified is not None
    assert "Verified manually with curl" in finding.reviewer_notes

    # Mark false positive
    finding.mark_false_positive(notes="Endpoint returns mocked demo data only")
    assert finding.status == FindingStatus.FALSE_POSITIVE
    assert finding.is_confirmed is False
    assert finding.is_actionable is False
