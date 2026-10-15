"""Policy models, selectors, and evaluation result domain entities for BoundaryX.

Defines authorization policies, subject and resource selector specifications,
expected decisions, evaluations, and conflict records.
"""

from __future__ import annotations

import fnmatch
import re
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from boundaryx.domain.identities.models import Identity, RoleType  # noqa: TCH001
from boundaryx.domain.resources.models import Resource, ResourceType  # noqa: TCH001


def _utc_now() -> datetime:
    """Return the current timestamp in UTC timezone."""
    return datetime.now(UTC)


class PolicyAction(StrEnum):
    """Actions performed on target resources."""

    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    ADMIN = "ADMIN"
    CUSTOM = "CUSTOM"


class ExpectedDecision(StrEnum):
    """Expected authorization evaluation decision."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class PolicyConfidenceSource(StrEnum):
    """Provenance/source of confidence for expected policy decision."""

    DOCUMENTATION = "DOCUMENTATION"
    OBSERVATION = "OBSERVATION"
    ASSUMPTION = "ASSUMPTION"
    USER_DEFINED = "USER_DEFINED"


class SubjectSelector(BaseModel):
    """Criteria matching subject identities."""

    model_config = ConfigDict(from_attributes=True)

    identity_id: UUID | None = Field(
        default=None,
        description="Explicit identity ID to match",
    )
    role_type: RoleType | None = Field(
        default=None,
        description="Role classification to match",
    )
    tenant_id: UUID | None = Field(
        default=None,
        description="Tenant boundary that the subject must belong to",
    )

    def is_empty(self) -> bool:
        """Return True if no specific subject criteria are set (wildcard)."""
        return self.identity_id is None and self.role_type is None and self.tenant_id is None

    def specificity(self) -> int:
        """Calculate specificity score (higher means more specific match criteria)."""
        score = 0
        if self.identity_id is not None:
            score += 10
        if self.tenant_id is not None:
            score += 5
        if self.role_type is not None:
            score += 3
        return score

    def matches(self, identity: Identity) -> bool:
        """Check whether the given identity satisfies this selector."""
        if self.identity_id is not None and identity.id != self.identity_id:
            return False
        if self.role_type is not None and identity.role_type != self.role_type:
            return False
        return not (self.tenant_id is not None and not identity.has_tenant(self.tenant_id))


class ResourceSelector(BaseModel):
    """Criteria matching target resources or endpoints."""

    model_config = ConfigDict(from_attributes=True)

    resource_id: UUID | None = Field(
        default=None,
        description="Explicit resource ID to match",
    )
    resource_type: ResourceType | None = Field(
        default=None,
        description="Resource type classification to match",
    )
    endpoint_pattern: str | None = Field(
        default=None,
        description="URL/route pattern (e.g. '/api/v1/orders/*', 'GET /api/docs')",
    )
    tenant_id: UUID | None = Field(
        default=None,
        description="Owning tenant partition boundary to match",
    )

    def is_empty(self) -> bool:
        """Return True if no specific resource criteria are set (wildcard)."""
        return (
            self.resource_id is None
            and self.resource_type is None
            and self.endpoint_pattern is None
            and self.tenant_id is None
        )

    def specificity(self) -> int:
        """Calculate specificity score (higher means more specific match criteria)."""
        score = 0
        if self.resource_id is not None:
            score += 10
        if self.tenant_id is not None:
            score += 5
        if self.resource_type is not None:
            score += 3
        if self.endpoint_pattern is not None:
            score += 2
        return score

    def matches(self, resource: Resource, endpoint: str | None = None) -> bool:
        """Check whether the given resource satisfies this selector."""
        if self.resource_id is not None and resource.id != self.resource_id:
            return False
        if self.resource_type is not None and resource.resource_type != self.resource_type:
            return False
        if self.tenant_id is not None and resource.owning_tenant_id != self.tenant_id:
            return False
        if self.endpoint_pattern is not None:
            pattern = self.endpoint_pattern.strip()
            # Check explicitly provided endpoint if given; otherwise check resource associated endpoints
            candidates = [endpoint] if endpoint is not None else list(resource.associated_endpoints)

            if not candidates:
                return False

            matched = False
            for cand in candidates:
                if cand and self._match_pattern(pattern, cand):
                    matched = True
                    break
            if not matched:
                return False

        return True

    @staticmethod
    def _match_pattern(pattern: str, candidate: str) -> bool:
        """Match pattern using wildcard globbing or regex."""
        if pattern == "*" or pattern == candidate:
            return True
        if fnmatch.fnmatch(candidate, pattern):
            return True
        try:
            if re.search(pattern, candidate):
                return True
        except re.error:
            pass
        return False


class Policy(BaseModel):
    """Authorization policy rule defining expected behavior."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique policy rule ID")
    project_id: UUID = Field(default_factory=uuid4, description="Project context ID")
    name: str = Field(description="Policy rule title or designation")
    description: str = Field(default="", description="Detailed business logic and rationale")
    subject_selector: SubjectSelector = Field(
        default_factory=SubjectSelector,
        description="Subject criteria for rule activation",
    )
    resource_selector: ResourceSelector = Field(
        default_factory=ResourceSelector,
        description="Resource criteria for rule activation",
    )
    action: PolicyAction = Field(description="Action covered by this rule")
    expected_decision: ExpectedDecision = Field(description="Expected authorization decision (ALLOW/DENY)")
    preconditions: list[str] = Field(
        default_factory=list,
        description="Required pre-conditions (e.g. 'resource.is_published == True')",
    )
    confidence_source: PolicyConfidenceSource = Field(
        default=PolicyConfidenceSource.USER_DEFINED,
        description="Source of truth for expected decision",
    )
    evidence_notes: str = Field(default="", description="Supporting notes or requirements documentation")
    enabled: bool = Field(default=True, description="Whether this policy rule is actively evaluated")
    created_at: datetime = Field(default_factory=_utc_now, description="Creation timestamp (UTC)")
    updated_at: datetime = Field(default_factory=_utc_now, description="Last update timestamp (UTC)")


class PolicyEvaluation(BaseModel):
    """Outcome of evaluating a subject, resource, and action against policy rules."""

    model_config = ConfigDict(from_attributes=True)

    policy_id: UUID | None = Field(
        default=None,
        description="ID of matched policy rule, or None if no match or conflict",
    )
    identity_id: UUID = Field(description="Subject identity evaluated")
    resource_id: UUID = Field(description="Target resource evaluated")
    action: PolicyAction = Field(description="Action evaluated")
    expected_decision: ExpectedDecision = Field(description="Evaluated expected decision")
    actual_decision: str | None = Field(
        default=None,
        description="Observed actual decision from runtime execution (if available)",
    )
    evidence_ids: list[UUID] = Field(
        default_factory=list,
        description="Linked evidence records supporting or verifying the evaluation",
    )
    reasoning: str = Field(
        default="",
        description="Deterministic explanation of how the decision was derived",
    )
    evaluated_at: datetime = Field(default_factory=_utc_now, description="Evaluation timestamp (UTC)")


class PolicyConflict(BaseModel):
    """Identified conflict between two overlapping policy rules."""

    model_config = ConfigDict(from_attributes=True)

    policy_a_id: UUID = Field(description="First conflicting policy ID")
    policy_b_id: UUID = Field(description="Second conflicting policy ID")
    description: str = Field(description="Description of overlap and contradiction")
    detected_at: datetime = Field(default_factory=_utc_now, description="Detection timestamp (UTC)")
