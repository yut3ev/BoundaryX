"""Deterministic PolicyEngine for authorization boundary evaluation.

Provides rule evaluation, selector matching, conflict detection,
and test matrix coverage analysis.
"""

from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING, Any

from boundaryx.domain.policies.models import (
    ExpectedDecision,
    Policy,
    PolicyAction,
    PolicyConflict,
    PolicyEvaluation,
    ResourceSelector,
    SubjectSelector,
)

if TYPE_CHECKING:
    from boundaryx.domain.identities.models import Identity
    from boundaryx.domain.resources.models import Resource


class PolicyEngine:
    """Deterministic authorization policy evaluation engine.

    Evaluates authorization requests against defined policy rules, resolves
    conflicts, detects overlapping contradictions, and calculates coverage statistics.
    """

    def __init__(self, policies: list[Policy] | None = None) -> None:
        """Initialize the PolicyEngine with an optional set of policies."""
        self._policies: list[Policy] = list(policies) if policies is not None else []

    @property
    def policies(self) -> list[Policy]:
        """Return the current list of registered policies."""
        return list(self._policies)

    def add_policy(self, policy: Policy) -> None:
        """Add a single policy rule to the engine."""
        self._policies.append(policy)

    def add_policies(self, policies: list[Policy]) -> None:
        """Add multiple policy rules to the engine."""
        self._policies.extend(policies)

    def clear(self) -> None:
        """Clear all registered policies from the engine."""
        self._policies.clear()

    def evaluate(
        self,
        identity: Identity,
        resource: Resource,
        action: PolicyAction,
        endpoint: str | None = None,
        policies: list[Policy] | None = None,
    ) -> PolicyEvaluation:
        """Evaluate an authorization request against matching policy rules.

        Args:
            identity: Subject identity performing the action.
            resource: Target resource being accessed.
            action: Action requested on the resource.
            endpoint: Optional specific endpoint URI for route pattern matching.
            policies: Optional explicit policy list to evaluate instead of registered ones.

        Returns:
            PolicyEvaluation instance containing the deterministic decision,
            matched policy ID, and detailed derivation reasoning.
        """
        pool = policies if policies is not None else self._policies

        # Filter enabled policies matching action
        active_policies = [p for p in pool if p.enabled and p.action == action]

        # Find all policies whose selectors match both subject and resource
        matching_policies: list[Policy] = []
        for policy in active_policies:
            if policy.subject_selector.matches(identity) and policy.resource_selector.matches(resource, endpoint):
                matching_policies.append(policy)

        # Case 1: No matching policy rule
        if not matching_policies:
            return PolicyEvaluation(
                policy_id=None,
                identity_id=identity.id,
                resource_id=resource.id,
                action=action,
                expected_decision=ExpectedDecision.UNKNOWN,
                actual_decision=None,
                evidence_ids=[],
                reasoning=(
                    f"No matching policy found for identity '{identity.name}' "
                    f"({identity.role_type.value}), resource '{resource.display_name}' "
                    f"({resource.resource_type.value}), and action '{action.value}'."
                ),
            )

        # Case 2: Check for conflicting decisions among matches
        decisions = {p.expected_decision for p in matching_policies}
        if len(decisions) > 1:
            conflict_descriptions = [f"'{p.name}' ({p.id}) -> {p.expected_decision.value}" for p in matching_policies]
            return PolicyEvaluation(
                policy_id=None,
                identity_id=identity.id,
                resource_id=resource.id,
                action=action,
                expected_decision=ExpectedDecision.UNKNOWN,
                actual_decision=None,
                evidence_ids=[],
                reasoning=(
                    f"Policy conflict detected: {len(matching_policies)} policies match with contradictory "
                    f"decisions: {', '.join(conflict_descriptions)}."
                ),
            )

        # Case 3: All matching policies agree on decision -> select most specific
        decision = next(iter(decisions))

        # Sort matching policies by combined specificity descending, tie-breaking by ID
        matching_policies.sort(
            key=lambda p: (
                p.subject_selector.specificity() + p.resource_selector.specificity(),
                str(p.id),
            ),
            reverse=True,
        )
        selected_policy = matching_policies[0]

        reasoning = (
            f"Matched policy '{selected_policy.name}' ({selected_policy.id}) "
            f"with expected decision '{decision.value}' (specificity: "
            f"{selected_policy.subject_selector.specificity() + selected_policy.resource_selector.specificity()})."
        )
        if len(matching_policies) > 1:
            reasoning += f" ({len(matching_policies) - 1} other matching policies agree on this decision)."

        return PolicyEvaluation(
            policy_id=selected_policy.id,
            identity_id=identity.id,
            resource_id=resource.id,
            action=action,
            expected_decision=decision,
            actual_decision=None,
            evidence_ids=[],
            reasoning=reasoning,
        )

    def detect_conflicts(self, policies: list[Policy] | None = None) -> list[PolicyConflict]:
        """Detect pairwise policy conflicts where rules overlap but mandate different decisions.

        Args:
            policies: Optional policy list to check; defaults to registered policies.

        Returns:
            A list of PolicyConflict records.
        """
        pool = policies if policies is not None else self._policies
        enabled_policies = [p for p in pool if p.enabled]
        conflicts: list[PolicyConflict] = []

        n = len(enabled_policies)
        for i in range(n):
            for j in range(i + 1, n):
                p_a = enabled_policies[i]
                p_b = enabled_policies[j]

                # Different actions do not conflict
                if p_a.action != p_b.action:
                    continue

                # Same expected decisions do not conflict
                if p_a.expected_decision == p_b.expected_decision:
                    continue

                # Check selector overlap
                if self._subjects_overlap(p_a.subject_selector, p_b.subject_selector) and self._resources_overlap(
                    p_a.resource_selector, p_b.resource_selector
                ):
                    desc = (
                        f"Conflict on action '{p_a.action.value}': policy '{p_a.name}' mandates "
                        f"'{p_a.expected_decision.value}' whereas policy '{p_b.name}' mandates "
                        f"'{p_b.expected_decision.value}' on overlapping subject and resource scopes."
                    )
                    conflicts.append(
                        PolicyConflict(
                            policy_a_id=p_a.id,
                            policy_b_id=p_b.id,
                            description=desc,
                        )
                    )

        return conflicts

    @staticmethod
    def _subjects_overlap(s_a: SubjectSelector, s_b: SubjectSelector) -> bool:
        """Return True if two subject selectors overlap in their matching domain."""
        if s_a.identity_id is not None and s_b.identity_id is not None and s_a.identity_id != s_b.identity_id:
            return False

        if s_a.role_type is not None and s_b.role_type is not None and s_a.role_type != s_b.role_type:
            return False

        return not (s_a.tenant_id is not None and s_b.tenant_id is not None and s_a.tenant_id != s_b.tenant_id)

    @staticmethod
    def _resources_overlap(r_a: ResourceSelector, r_b: ResourceSelector) -> bool:
        """Return True if two resource selectors overlap in their matching domain."""
        if r_a.resource_id is not None and r_b.resource_id is not None and r_a.resource_id != r_b.resource_id:
            return False

        if r_a.resource_type is not None and r_b.resource_type is not None and r_a.resource_type != r_b.resource_type:
            return False

        if r_a.tenant_id is not None and r_b.tenant_id is not None and r_a.tenant_id != r_b.tenant_id:
            return False

        if r_a.endpoint_pattern is not None and r_b.endpoint_pattern is not None:
            pat_a = r_a.endpoint_pattern.strip()
            pat_b = r_b.endpoint_pattern.strip()
            if (
                pat_a != pat_b
                and pat_a != "*"
                and pat_b != "*"
                and not (fnmatch.fnmatch(pat_a, pat_b) or fnmatch.fnmatch(pat_b, pat_a))
            ):
                return False

        return True

    def get_coverage_stats(
        self,
        policies: list[Policy] | None = None,
        resources: list[Resource] | None = None,
        identities: list[Identity] | None = None,
    ) -> dict[str, Any]:
        """Compute coverage statistics across defined policies, identities, and resources.

        Args:
            policies: Policies to measure. Defaults to engine's registered policies.
            resources: Target resources in test scope.
            identities: Subject identities in test scope.

        Returns:
            Dictionary containing metrics including total counts, covered combinations,
            coverage percentage, and conflict count.
        """
        pool = policies if policies is not None else self._policies
        res_list = list(resources) if resources is not None else []
        id_list = list(identities) if identities is not None else []

        total_policies = len(pool)
        enabled_policies = sum(1 for p in pool if p.enabled)
        disabled_policies = total_policies - enabled_policies

        actions_covered = sorted({p.action.value for p in pool if p.enabled})
        covered_resource_types = sorted(
            {p.resource_selector.resource_type.value for p in pool if p.enabled and p.resource_selector.resource_type}
        )
        covered_roles = sorted(
            {p.subject_selector.role_type.value for p in pool if p.enabled and p.subject_selector.role_type}
        )

        conflicts = self.detect_conflicts(pool)
        conflicts_count = len(conflicts)

        # Standard test action actions
        actions_to_test = (
            [PolicyAction(a) for a in actions_covered]
            if actions_covered
            else [PolicyAction.READ, PolicyAction.WRITE, PolicyAction.DELETE]
        )

        allowed_count = 0
        denied_count = 0
        unknown_count = 0
        matrix_conflicts_count = 0

        total_matrix_cells = len(id_list) * len(res_list) * len(actions_to_test)

        for identity in id_list:
            for resource in res_list:
                for act in actions_to_test:
                    evaluation = self.evaluate(identity, resource, act, policies=pool)
                    if evaluation.expected_decision == ExpectedDecision.ALLOW:
                        allowed_count += 1
                    elif evaluation.expected_decision == ExpectedDecision.DENY:
                        denied_count += 1
                    else:
                        unknown_count += 1
                        if "conflict" in evaluation.reasoning.lower():
                            matrix_conflicts_count += 1

        covered_cells = allowed_count + denied_count
        coverage_percentage = (
            round((covered_cells / total_matrix_cells) * 100.0, 2)
            if total_matrix_cells > 0
            else (100.0 if enabled_policies > 0 else 0.0)
        )

        return {
            "total_policies": total_policies,
            "enabled_policies": enabled_policies,
            "disabled_policies": disabled_policies,
            "total_identities": len(id_list),
            "total_resources": len(res_list),
            "actions_covered": actions_covered,
            "covered_resource_types": covered_resource_types,
            "covered_roles": covered_roles,
            "total_matrix_cells": total_matrix_cells,
            "covered_matrix_cells": covered_cells,
            "allowed_combinations": allowed_count,
            "denied_combinations": denied_count,
            "unknown_combinations": unknown_count,
            "matrix_conflicts": matrix_conflicts_count,
            "conflicts_count": conflicts_count,
            "coverage_percentage": coverage_percentage,
        }
