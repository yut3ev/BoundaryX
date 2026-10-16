from difflib import SequenceMatcher
from typing import List

from pydantic import BaseModel

from boundaryx.domain.models import Finding


class DuplicateSuggestion(BaseModel):
    finding_id: str
    target_duplicate_id: str
    similarity_score: float
    reason: str


def compute_string_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower().strip(), b.lower().strip()).ratio()


class DuplicateDetector:
    """
    Identifies potential duplicate findings using similarity metrics.
    Requires human review before merging or linking duplicates.
    """

    def __init__(self, threshold: float = 0.75):
        self.threshold = threshold

    def find_duplicates(self, target: Finding, candidates: List[Finding]) -> List[DuplicateSuggestion]:
        suggestions = []
        for other in candidates:
            if other.id == target.id:
                continue

            # Must match category
            if other.category.lower() != target.category.lower():
                continue

            # Check title similarity
            title_sim = compute_string_similarity(target.title, other.title)

            # Check same asset
            same_asset = (target.asset_id is not None) and (target.asset_id == other.asset_id)

            score = title_sim
            if same_asset:
                score = min(1.0, score + 0.2)

            if score >= self.threshold:
                suggestions.append(
                    DuplicateSuggestion(
                        finding_id=target.id,
                        target_duplicate_id=other.id,
                        similarity_score=round(score, 3),
                        reason=f"High title similarity ({round(title_sim*100)}%)" + (" on same asset" if same_asset else ""),
                    )
                )

        return sorted(suggestions, key=lambda s: s.similarity_score, reverse=True)
