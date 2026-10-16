from typing import Dict, Set

from boundaryx.domain.enums import FindingStatus
from boundaryx.domain.models import Finding
from boundaryx.storage.repositories import FindingRepository


class FindingTransitionError(ValueError):
    pass


class FindingService:
    """
    Supervises finding lifecycle and deterministic state transitions.
    Enforces that 'verified' status requires explicit human review and evidence.
    """

    ALLOWED_TRANSITIONS: Dict[FindingStatus, Set[FindingStatus]] = {
        FindingStatus.CANDIDATE: {
            FindingStatus.NEEDS_REVIEW,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
        },
        FindingStatus.NEEDS_REVIEW: {
            FindingStatus.VERIFIED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
        },
        FindingStatus.VERIFIED: {
            FindingStatus.FIXED,
            FindingStatus.REOPENED,
            FindingStatus.ACCEPTED_RISK,
        },
        FindingStatus.FALSE_POSITIVE: {
            FindingStatus.NEEDS_REVIEW,
            FindingStatus.CANDIDATE,
        },
        FindingStatus.ACCEPTED_RISK: {
            FindingStatus.NEEDS_REVIEW,
            FindingStatus.REOPENED,
        },
        FindingStatus.FIXED: {
            FindingStatus.REOPENED,
        },
        FindingStatus.REOPENED: {
            FindingStatus.NEEDS_REVIEW,
            FindingStatus.VERIFIED,
            FindingStatus.FIXED,
        },
    }

    def __init__(self, finding_repo: FindingRepository):
        self.repo = finding_repo

    def transition_status(self, finding_id: str, new_status: FindingStatus, reason: str) -> Finding:
        finding = self.repo.get(finding_id)
        if not finding:
            raise FindingTransitionError(f"Finding not found: {finding_id}")

        allowed = self.ALLOWED_TRANSITIONS.get(finding.status, set())
        if new_status not in allowed:
            raise FindingTransitionError(
                f"Illegal finding state transition: cannot move from '{finding.status.value}' to '{new_status.value}'"
            )

        # Enforce that transition to VERIFIED requires human review reason and at least one evidence link
        if new_status == FindingStatus.VERIFIED:
            if not reason or len(reason.strip()) < 5:
                raise FindingTransitionError("Transition to 'verified' requires a documented verification reason.")
            if not finding.evidence_ids:
                raise FindingTransitionError("Transition to 'verified' requires at least one linked evidence ID.")

        self.repo.update_status(finding_id, new_status, reason)
        updated = self.repo.get(finding_id)
        return updated
