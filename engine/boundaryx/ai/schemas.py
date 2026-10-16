from typing import List, Optional
from pydantic import BaseModel, Field

from boundaryx.domain.enums import AnalysisType


class FactItem(BaseModel):
    claim: str
    evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = 1.0


class HypothesisItem(BaseModel):
    claim: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    counter_evidence_ids: List[str] = Field(default_factory=list)
    confidence: str = "medium"  # low, medium, high
    verification_needed: List[str] = Field(default_factory=list)


class NextStepItem(BaseModel):
    title: str
    purpose: str
    active_or_passive: str = "passive"  # passive, active
    preconditions: List[str] = Field(default_factory=list)
    stop_conditions: List[str] = Field(default_factory=list)
    requires_user_confirmation: bool = True


class AnalysisOutput(BaseModel):
    analysis_type: AnalysisType
    summary: str
    facts: List[FactItem] = Field(default_factory=list)
    hypotheses: List[HypothesisItem] = Field(default_factory=list)
    suggested_next_steps: List[NextStepItem] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    report_draft: Optional[str] = None
