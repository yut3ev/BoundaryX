import pytest

from boundaryx.ai.citation_validator import CitationValidator
from boundaryx.ai.consent_pipeline import ConsentPipeline
from boundaryx.ai.mock_provider import MockAIProvider
from boundaryx.ai.provider import AnalysisRequest
from boundaryx.ai.schemas import AnalysisOutput, FactItem
from boundaryx.domain.enums import AnalysisType


def test_mock_provider_success():
    provider = MockAIProvider()
    healthy, msg = provider.test_connection()
    assert healthy is True

    req = AnalysisRequest(
        analysis_type=AnalysisType.FINDING_EXPLANATION,
        target_summary="Vulnerable API endpoint /api/user/10",
        available_evidence_ids=["ev-1", "ev-2"],
    )
    result = provider.analyze(req)
    assert result.analysis_type == AnalysisType.FINDING_EXPLANATION
    assert len(result.facts) > 0
    assert "ev-1" in result.facts[0].evidence_ids


def test_citation_validator_strips_hallucinated_ids():
    output = AnalysisOutput(
        analysis_type=AnalysisType.TARGET_OVERVIEW,
        summary="Overview",
        facts=[
            FactItem(
                claim="Server leaked JWT token",
                evidence_ids=["ev-valid-1", "ev-hallucinated-999"],
            )
        ],
    )
    valid_ids = {"ev-valid-1"}
    validated = CitationValidator.validate_and_filter(output, valid_ids)

    # ev-hallucinated-999 should be stripped
    assert validated.facts[0].evidence_ids == ["ev-valid-1"]
    assert any("ev-hallucinated-999" in lim for lim in validated.limitations)


def test_consent_pipeline_requires_explicit_consent():
    pipeline = ConsentPipeline()
    preview = pipeline.generate_preview(
        analysis_type=AnalysisType.NEXT_TEST_PLAN,
        target_summary="Target test with Authorization: Bearer secret",
        evidence_snippets=[{"header": "Authorization: Bearer my_jwt_token"}],
        available_evidence_ids=["ev-1"],
    )

    # Secret was redacted in preview
    assert "[REDACTED_TOKEN]" in preview.target_summary
    assert "[REDACTED_TOKEN]" in str(preview.redacted_evidence_snippets)

    # Consent not granted yet
    with pytest.raises(PermissionError, match="Explicit user consent is required"):
        pipeline.build_authorized_request(preview)

    # Grant consent
    preview.user_consent_granted = True
    req = pipeline.build_authorized_request(preview)
    assert req.analysis_type == AnalysisType.NEXT_TEST_PLAN
    assert req.available_evidence_ids == ["ev-1"]


def test_mock_provider_error_simulation():
    provider_rate_limit = MockAIProvider(simulate_error="rate_limit")
    req = AnalysisRequest(
        analysis_type=AnalysisType.CORRELATION,
        target_summary="Target",
        available_evidence_ids=[],
    )
    with pytest.raises(RuntimeError, match="429 Resource exhausted"):
        provider_rate_limit.analyze(req)
