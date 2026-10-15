"""Analysis package for BoundaryX authorization and differential security analysis."""

from boundaryx.application.analysis.correlation import (
    CorrelatedTrafficRecord,
    IdentityMatch,
    PathParameter,
    PotentialIDORCandidate,
    ResourceMatch,
    TemplateMatchResult,
    TrafficCorrelationReport,
    TrafficCorrelator,
)
from boundaryx.application.analysis.normalization import NormalizationConfig, NormalizationEngine
from boundaryx.application.analysis.service import AnalysisService

__all__ = [
    "AnalysisService",
    "CorrelatedTrafficRecord",
    "IdentityMatch",
    "NormalizationConfig",
    "NormalizationEngine",
    "PathParameter",
    "PotentialIDORCandidate",
    "ResourceMatch",
    "TemplateMatchResult",
    "TrafficCorrelationReport",
    "TrafficCorrelator",
]
