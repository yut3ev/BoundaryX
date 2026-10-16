from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from boundaryx.ai.schemas import AnalysisOutput
from boundaryx.domain.enums import AnalysisType


class AnalysisRequest(BaseModel):
    analysis_type: AnalysisType
    target_summary: str
    evidence_snippets: List[Dict[str, Any]] = Field(default_factory=list)
    available_evidence_ids: List[str] = Field(default_factory=list)
    user_notes: Optional[str] = None


class AIProvider(ABC):
    """Abstract interface isolating AI SDK implementations from domain logic."""

    @abstractmethod
    def test_connection(self) -> Tuple[bool, str]:
        pass

    @abstractmethod
    def analyze(self, request: AnalysisRequest) -> AnalysisOutput:
        pass
