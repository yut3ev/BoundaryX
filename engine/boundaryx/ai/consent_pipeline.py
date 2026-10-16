from typing import Any, Dict, List

from pydantic import BaseModel

from boundaryx.ai.provider import AnalysisRequest
from boundaryx.domain.enums import AnalysisType
from boundaryx.security.redaction import RedactionEngine


class DataConsentPreview(BaseModel):
    analysis_type: AnalysisType
    target_summary: str
    redacted_evidence_snippets: List[Dict[str, Any]]
    available_evidence_ids: List[str]
    estimated_tokens: int
    user_consent_granted: bool = False


class ConsentPipeline:
    """
    Ensures minimum necessary data is sent to external AI providers.
    Generates preview of redacted evidence and enforces explicit consent.
    """

    def __init__(self, redactor: RedactionEngine = None):
        self.redactor = redactor or RedactionEngine()

    def generate_preview(
        self,
        analysis_type: AnalysisType,
        target_summary: str,
        evidence_snippets: List[Dict[str, Any]],
        available_evidence_ids: List[str],
        user_notes: str = None,
    ) -> DataConsentPreview:
        redacted_snippets = [self.redactor.redact_data(s) for s in evidence_snippets]
        safe_summary = self.redactor.redact_text(target_summary)

        # Rough token estimate: ~4 chars per token
        total_chars = len(safe_summary) + len(str(redacted_snippets)) + (len(user_notes) if user_notes else 0)
        estimated_tokens = max(10, total_chars // 4)

        return DataConsentPreview(
            analysis_type=analysis_type,
            target_summary=safe_summary,
            redacted_evidence_snippets=redacted_snippets,
            available_evidence_ids=available_evidence_ids,
            estimated_tokens=estimated_tokens,
            user_consent_granted=False,
        )

    def build_authorized_request(self, preview: DataConsentPreview, user_notes: str = None) -> AnalysisRequest:
        if not preview.user_consent_granted:
            raise PermissionError("Explicit user consent is required before sending data to Gemini provider.")

        return AnalysisRequest(
            analysis_type=preview.analysis_type,
            target_summary=preview.target_summary,
            evidence_snippets=preview.redacted_evidence_snippets,
            available_evidence_ids=preview.available_evidence_ids,
            user_notes=user_notes,
        )
