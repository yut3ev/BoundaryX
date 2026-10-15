"""Unit tests for deterministic PolicyEngine."""

from uuid import uuid4

from boundaryx.domain.identities.models import Identity, RoleType
from boundaryx.domain.policies.engine import PolicyEngine
from boundaryx.domain.policies.models import (
    ExpectedDecision,
    Policy,
    PolicyAction,
    ResourceSelector,
    SubjectSelector,
)
from boundaryx.domain.resources.models import Resource, ResourceType


def test_engine_single_policy_allow() -> None:
    """Test policy evaluation when matching an explicit ALLOW rule."""
    policy = Policy(
        name="Admins can delete any resource",
        subject_selector=SubjectSelector(role_type=RoleType.ADMIN),
        resource_selector=ResourceSelector(),
        action=PolicyAction.DELETE,
        expected_decision=ExpectedDecision.ALLOW,
    )
    engine = PolicyEngine([policy])

    admin = Identity(name="superadmin", role_type=RoleType.ADMIN)
    resource = Resource(display_name="Server Config", resource_type=ResourceType.API_RESOURCE, external_id="cfg-1")

    result = engine.evaluate(admin, resource, PolicyAction.DELETE)
    assert result.expected_decision == ExpectedDecision.ALLOW
    assert result.policy_id == policy.id
    assert "Matched policy" in result.reasoning


def test_engine_unmatched_policy_returns_unknown() -> None:
    """Test policy evaluation returns UNKNOWN when no policy matches."""
    policy = Policy(
        name="ReadOnly users can read",
        subject_selector=SubjectSelector(role_type=RoleType.READ_ONLY),
        resource_selector=ResourceSelector(),
        action=PolicyAction.READ,
        expected_decision=ExpectedDecision.ALLOW,
    )
    engine = PolicyEngine([policy])

    editor = Identity(name="editor1", role_type=RoleType.EDITOR)
    resource = Resource(display_name="Doc", resource_type=ResourceType.DOCUMENT, external_id="d1")

    # Action doesn't match or role doesn't match
    result = engine.evaluate(editor, resource, PolicyAction.WRITE)
    assert result.expected_decision == ExpectedDecision.UNKNOWN
    assert result.policy_id is None
    assert "No matching policy found" in result.reasoning


def test_engine_conflicting_matching_policies() -> None:
    """Test policy evaluation returns conflict notice when contradictory rules match."""
    p_allow = Policy(
        name="Allow authenticated to read user profiles",
        subject_selector=SubjectSelector(role_type=RoleType.AUTHENTICATED),
        resource_selector=ResourceSelector(resource_type=ResourceType.USER_PROFILE),
        action=PolicyAction.READ,
        expected_decision=ExpectedDecision.ALLOW,
    )
    p_deny = Policy(
        name="Deny reading user profiles",
        subject_selector=SubjectSelector(role_type=RoleType.AUTHENTICATED),
        resource_selector=ResourceSelector(resource_type=ResourceType.USER_PROFILE),
        action=PolicyAction.READ,
        expected_decision=ExpectedDecision.DENY,
    )
    engine = PolicyEngine([p_allow, p_deny])

    user = Identity(name="alice", role_type=RoleType.AUTHENTICATED)
    resource = Resource(display_name="Profile 10", resource_type=ResourceType.USER_PROFILE, external_id="usr-10")

    result = engine.evaluate(user, resource, PolicyAction.READ)
    assert result.expected_decision == ExpectedDecision.UNKNOWN
    assert result.policy_id is None
    assert "Policy conflict detected" in result.reasoning


def test_engine_specificity_precedence_on_agreement() -> None:
    """Test that engine picks the most specific policy when multiple rules agree."""
    res_id = uuid4()
    p_general = Policy(
        name="Allow authenticated read documents",
        subject_selector=SubjectSelector(role_type=RoleType.AUTHENTICATED),
        resource_selector=ResourceSelector(resource_type=ResourceType.DOCUMENT),
        action=PolicyAction.READ,
        expected_decision=ExpectedDecision.ALLOW,
    )
    p_specific = Policy(
        name="Allow specific user to read specific document",
        subject_selector=SubjectSelector(role_type=RoleType.AUTHENTICATED),
        resource_selector=ResourceSelector(resource_id=res_id, resource_type=ResourceType.DOCUMENT),
        action=PolicyAction.READ,
        expected_decision=ExpectedDecision.ALLOW,
    )
    engine = PolicyEngine([p_general, p_specific])

    user = Identity(name="alice", role_type=RoleType.AUTHENTICATED)
    resource = Resource(id=res_id, display_name="Special Doc", resource_type=ResourceType.DOCUMENT, external_id="sd1")

    result = engine.evaluate(user, resource, PolicyAction.READ)
    assert result.expected_decision == ExpectedDecision.ALLOW
    assert result.policy_id == p_specific.id  # More specific selector selected


def test_engine_detect_conflicts() -> None:
    """Test offline conflict detection for overlapping policies."""
    p1 = Policy(
        name="Rule 1 - Allow",
        subject_selector=SubjectSelector(role_type=RoleType.EDITOR),
        resource_selector=ResourceSelector(resource_type=ResourceType.PROJECT),
        action=PolicyAction.WRITE,
        expected_decision=ExpectedDecision.ALLOW,
    )
    p2 = Policy(
        name="Rule 2 - Deny",
        subject_selector=SubjectSelector(role_type=RoleType.EDITOR),
        resource_selector=ResourceSelector(resource_type=ResourceType.PROJECT),
        action=PolicyAction.WRITE,
        expected_decision=ExpectedDecision.DENY,
    )
    p_other_action = Policy(
        name="Rule 3 - Other action",
        subject_selector=SubjectSelector(role_type=RoleType.EDITOR),
        resource_selector=ResourceSelector(resource_type=ResourceType.PROJECT),
        action=PolicyAction.DELETE,
        expected_decision=ExpectedDecision.ALLOW,
    )

    engine = PolicyEngine([p1, p2, p_other_action])
    conflicts = engine.detect_conflicts()
    assert len(conflicts) == 1
    assert conflicts[0].policy_a_id == p1.id
    assert conflicts[0].policy_b_id == p2.id
    assert "Conflict on action 'WRITE'" in conflicts[0].description


def test_engine_get_coverage_stats() -> None:
    """Test policy coverage statistics calculation."""
    p = Policy(
        name="Allow read orders",
        subject_selector=SubjectSelector(role_type=RoleType.ADMIN),
        resource_selector=ResourceSelector(resource_type=ResourceType.ORDER),
        action=PolicyAction.READ,
        expected_decision=ExpectedDecision.ALLOW,
    )
    engine = PolicyEngine([p])

    admin = Identity(name="admin", role_type=RoleType.ADMIN)
    user = Identity(name="user", role_type=RoleType.AUTHENTICATED)
    order = Resource(display_name="Order 1", resource_type=ResourceType.ORDER, external_id="ord-1")

    stats = engine.get_coverage_stats(
        resources=[order],
        identities=[admin, user],
    )

    assert stats["total_policies"] == 1
    assert stats["enabled_policies"] == 1
    assert stats["total_identities"] == 2
    assert stats["total_resources"] == 1
    assert stats["actions_covered"] == ["READ"]
    assert stats["total_matrix_cells"] == 2  # 2 identities x 1 resource x 1 action
    assert stats["covered_matrix_cells"] == 1  # Admin was covered (ALLOW)
    assert stats["allowed_combinations"] == 1
    assert stats["unknown_combinations"] == 1
    assert stats["coverage_percentage"] == 50.0
    assert stats["conflicts_count"] == 0
