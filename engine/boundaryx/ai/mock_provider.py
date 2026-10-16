from typing import Any, Dict, List, Optional, Tuple

from boundaryx.ai.citation_validator import CitationValidator
from boundaryx.ai.provider import AIProvider, AnalysisRequest
from boundaryx.ai.schemas import AnalysisOutput, FactItem, HypothesisItem, NextStepItem
from boundaryx.domain.enums import AnalysisType


class MockAIProvider(AIProvider):
    """
    Mock AI Provider for automated tests and offline mode.
    Does not require network access or a real Gemini API key.
    """

    def __init__(self, simulate_error: Optional[str] = None, inject_hallucinated_citations: bool = False):
        self.simulate_error = simulate_error
        self.inject_hallucinated_citations = inject_hallucinated_citations

    def test_connection(self) -> Tuple[bool, str]:
        if self.simulate_error:
            return False, f"Simulated connection failure: {self.simulate_error}"
        return True, "Mock Gemini connection healthy (offline test mode)"

    def analyze(self, request: AnalysisRequest) -> AnalysisOutput:
        if self.simulate_error == "rate_limit":
            raise RuntimeError("429 Resource exhausted: Rate limit reached")
        elif self.simulate_error == "invalid_key":
            raise RuntimeError("400 API_KEY_INVALID: The provided Gemini API key is invalid")

        valid_ids = set(request.available_evidence_ids)
        cited_eids = list(valid_ids)[:2] if valid_ids else []

        if self.inject_hallucinated_citations:
            cited_eids.append("ev-fake-hallucination-999")

        output = AnalysisOutput(
            analysis_type=request.analysis_type,
            summary=f"Mock analysis completed for: {request.target_summary[:50]}",
            facts=[
                FactItem(
                    claim=f"Analyzed target {request.target_summary[:30]}",
                    evidence_ids=cited_eids,
                    confidence=0.95,
                )
            ],
            hypotheses=[
                HypothesisItem(
                    claim="Authorization boundary evaluated against imported evidence",
                    supporting_evidence_ids=cited_eids,
                    confidence="medium",
                    verification_needed=["Perform manual curl replay with user consent"],
                )
            ],
            suggested_next_steps=[
                NextStepItem(
                    title="Inspect endpoint headers",
                    purpose="Confirm authorization token validation",
                    active_or_passive="passive",
                    requires_user_confirmation=True,
                )
            ],
            limitations=["Analysis generated offline by Mock AI Provider."],
        )

        # Run through citation validator
        return CitationValidator.validate_and_filter(output, valid_ids)
