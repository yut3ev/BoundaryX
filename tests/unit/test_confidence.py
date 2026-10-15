"""Unit tests for deterministic ConfidenceEvaluator engine."""

from uuid import uuid4

from boundaryx.domain.evidence.models import Evidence, EvidenceType, HttpSnapshot
from boundaryx.domain.findings.confidence import (
    ConfidenceEvaluator,
    FindingEvaluationContext,
)
from boundaryx.domain.findings.models import (
    ConfidenceExplanation,
    ConfidenceLevel,
    Finding,
    FindingCategory,
    FindingSeverity,
)
from boundaryx.domain.policies.models import ExpectedDecision, Policy, PolicyAction
from boundaryx.domain.resources.models import Resource, ResourceType


def test_confidence_evaluator_high_confidence() -> None:
    """Test HIGH confidence when all 5 pillars are fully verified."""
    evaluator = ConfidenceEvaluator()

    ctx = FindingEvaluationContext(
        explicit_policy_present=True,
        policy_name="Strict Tenant Isolation Policy",
        policy_expected_decision=ExpectedDecision.DENY,
        reproduction_trials=3,
        successful_reproductions=3,
        is_reproducible=True,
        error_baseline_compared=True,
        differs_from_error_baseline=True,
        baseline_similarity_ratio=0.12,
        target_resource_data_verified=True,
        matched_resource_identifiers=["order_id:9999", "amount:500.00"],
        response_status_code=200,
        response_body='{"order_id": "9999", "amount": 500.00, "customer": "victim"}',
        response_content_type="application/json",
        cross_tenant_tested=True,
        cross_tenant_verified=True,
        source_tenant_id="tenant-alpha",
        target_tenant_id="tenant-beta",
    )

    explanation = evaluator.evaluate(ctx)

    assert explanation.level == ConfidenceLevel.HIGH
    assert explanation.has_explicit_policy is True
    assert explanation.is_reproducible is True
    assert len(explanation.factors) >= 4
    assert len(explanation.missing_evidence) == 0
    assert "Confidence Tier: HIGH" in explanation.notes


def test_confidence_evaluator_medium_confidence() -> None:
    """Test MEDIUM confidence when defect is observed with policy but lacks baseline diff."""
    evaluator = ConfidenceEvaluator()

    ctx = FindingEvaluationContext(
        explicit_policy_present=True,
        policy_expected_decision=ExpectedDecision.DENY,
        reproduction_trials=1,
        successful_reproductions=1,
        is_reproducible=True,
        error_baseline_compared=False,  # Gap: missing error baseline comparison
        differs_from_error_baseline=False,
        target_resource_data_verified=True,
        response_status_code=200,
        response_body='{"user_id": "123", "email": "victim@example.com"}',
    )

    explanation = evaluator.evaluate(ctx)

    assert explanation.level == ConfidenceLevel.MEDIUM
    assert explanation.has_explicit_policy is True
    assert len(explanation.missing_evidence) > 0
    assert any("error baseline" in m.lower() for m in explanation.missing_evidence)
    assert "Actionable Recommendations:" in explanation.notes


def test_confidence_evaluator_low_confidence() -> None:
    """Test LOW confidence when no explicit policy exists and no target data verified."""
    evaluator = ConfidenceEvaluator()

    ctx = FindingEvaluationContext(
        explicit_policy_present=False,  # Heuristic only
        reproduction_trials=0,
        is_reproducible=None,
        error_baseline_compared=False,
        target_resource_data_verified=False,
        response_status_code=200,
        response_body='{"status": "ok"}',
    )

    explanation = evaluator.evaluate(ctx)

    assert explanation.level == ConfidenceLevel.LOW
    assert explanation.has_explicit_policy is False
    assert len(explanation.missing_evidence) >= 3


def test_confidence_evaluator_insufficient_evidence_html_shell() -> None:
    """Test INSUFFICIENT_EVIDENCE when response returns an HTML SPA/login shell on status 200."""
    evaluator = ConfidenceEvaluator()

    ctx = FindingEvaluationContext(
        explicit_policy_present=True,
        is_reproducible=True,
        response_status_code=200,
        response_body="<!DOCTYPE html><html><head><title>Login Required</title></head><body>Redirecting to login...</body></html>",
        target_resource_data_verified=False,
    )

    explanation = evaluator.evaluate(ctx)

    assert explanation.level == ConfidenceLevel.INSUFFICIENT_EVIDENCE
    assert any("HTML document" in m for m in explanation.missing_evidence)


def test_confidence_evaluator_insufficient_evidence_server_error() -> None:
    """Test INSUFFICIENT_EVIDENCE when server returns 500 error."""
    evaluator = ConfidenceEvaluator()

    ctx = FindingEvaluationContext(
        explicit_policy_present=True,
        response_status_code=500,
        response_body='{"error": "Internal Server Error"}',
    )

    explanation = evaluator.evaluate(ctx)
    assert explanation.level == ConfidenceLevel.INSUFFICIENT_EVIDENCE
    assert any("500" in m for m in explanation.missing_evidence)


def test_confidence_evaluator_evaluate_finding_helper() -> None:
    """Test evaluating a complete Finding domain entity with Evidence objects."""
    evaluator = ConfidenceEvaluator()

    res_id = uuid4()
    resource = Resource(
        id=res_id,
        display_name="Confidential Report",
        resource_type=ResourceType.DOCUMENT,
        external_id="doc_9999",
    )

    policy = Policy(
        name="No Cross-Tenant Read",
        action=PolicyAction.READ,
        expected_decision=ExpectedDecision.DENY,
    )

    req_snap = HttpSnapshot(method="GET", url="https://api.example.com/docs/doc_9999")
    resp_snap = HttpSnapshot(
        status_code=200,
        body='{"id": "doc_9999", "title": "Confidential Report", "secret": "xyz"}',
        content_type="application/json",
    )
    evidence = Evidence(
        evidence_type=EvidenceType.REQUEST_RESPONSE,
        title="Unauthorized GET request",
        request_snapshot=req_snap,
        response_snapshot=resp_snap,
    )

    base_resp_snap = HttpSnapshot(
        status_code=404,
        body='{"error": "Document not found"}',
        content_type="application/json",
    )
    base_evidence = Evidence(
        evidence_type=EvidenceType.REQUEST_RESPONSE,
        title="Baseline 404 response",
        response_snapshot=base_resp_snap,
    )

    finding = Finding(
        title="Cross-Tenant Document Access",
        category=FindingCategory.CROSS_TENANT_ACCESS,
        affected_endpoint="GET /docs/doc_9999",
        affected_resource_id=res_id,
        expected_decision=ExpectedDecision.DENY,
        severity=FindingSeverity.HIGH,
        confidence=ConfidenceExplanation(
            level=ConfidenceLevel.LOW,
            factors=[],
            missing_evidence=[],
        ),
    )
    finding.mark_confirmed("Verified by analyst reproduction")

    computed_explanation = evaluator.evaluate_finding(
        finding=finding,
        evidence_records=[evidence],
        policy=policy,
        baseline_evidence=base_evidence,
        target_resource=resource,
    )

    assert computed_explanation.level == ConfidenceLevel.HIGH
    assert computed_explanation.has_explicit_policy is True
    assert computed_explanation.is_reproducible is True
    assert any("id:doc_9999" in f for f in computed_explanation.factors)
