"""Unit tests for Policy models and selectors."""

from uuid import UUID, uuid4

from boundaryx.domain.identities.models import Identity, RoleType
from boundaryx.domain.policies.models import (
    ExpectedDecision,
    Policy,
    PolicyAction,
    PolicyConfidenceSource,
    PolicyConflict,
    PolicyEvaluation,
    ResourceSelector,
    SubjectSelector,
)
from boundaryx.domain.resources.models import Resource, ResourceType


def test_policy_enums() -> None:
    """Verify all policy-related enum values."""
    assert PolicyAction.READ == "READ"
    assert PolicyAction.WRITE == "WRITE"
    assert PolicyAction.DELETE == "DELETE"
    assert PolicyAction.EXECUTE == "EXECUTE"
    assert PolicyAction.ADMIN == "ADMIN"
    assert PolicyAction.CUSTOM == "CUSTOM"

    assert ExpectedDecision.ALLOW == "ALLOW"
    assert ExpectedDecision.DENY == "DENY"
    assert ExpectedDecision.UNKNOWN == "UNKNOWN"
    assert ExpectedDecision.NOT_APPLICABLE == "NOT_APPLICABLE"

    assert PolicyConfidenceSource.DOCUMENTATION == "DOCUMENTATION"
    assert PolicyConfidenceSource.OBSERVATION == "OBSERVATION"
    assert PolicyConfidenceSource.ASSUMPTION == "ASSUMPTION"
    assert PolicyConfidenceSource.USER_DEFINED == "USER_DEFINED"


def test_subject_selector_matching() -> None:
    """Test SubjectSelector specificity and matching conditions."""
    tenant_a = uuid4()
    tenant_b = uuid4()
    user_id = uuid4()

    # Empty selector matches everything
    empty_selector = SubjectSelector()
    assert empty_selector.is_empty() is True
    assert empty_selector.specificity() == 0

    id_matching = Identity(id=user_id, name="alice", role_type=RoleType.ADMIN, tenant_ids=[tenant_a])
    assert empty_selector.matches(id_matching) is True

    # Role matching
    role_selector = SubjectSelector(role_type=RoleType.ADMIN)
    assert role_selector.specificity() == 3
    assert role_selector.matches(id_matching) is True
    non_admin = Identity(name="charlie", role_type=RoleType.READ_ONLY)
    assert role_selector.matches(non_admin) is False

    # Tenant matching
    tenant_selector = SubjectSelector(tenant_id=tenant_a)
    assert tenant_selector.specificity() == 5
    assert tenant_selector.matches(id_matching) is True
    assert tenant_selector.matches(Identity(name="other", tenant_ids=[tenant_b])) is False

    # Exact identity ID matching
    exact_selector = SubjectSelector(identity_id=user_id)
    assert exact_selector.specificity() == 10
    assert exact_selector.matches(id_matching) is True
    assert exact_selector.matches(Identity(id=uuid4(), name="dave")) is False


def test_resource_selector_matching() -> None:
    """Test ResourceSelector specificity and matching conditions."""
    tenant_id = uuid4()
    res_id = uuid4()

    empty_selector = ResourceSelector()
    assert empty_selector.is_empty() is True
    assert empty_selector.specificity() == 0

    res = Resource(
        id=res_id,
        display_name="User Order 1",
        resource_type=ResourceType.ORDER,
        owning_tenant_id=tenant_id,
        associated_endpoints=["/api/v1/orders/1"],
        external_id="1",
    )
    assert empty_selector.matches(res) is True

    # Resource type selector
    type_selector = ResourceSelector(resource_type=ResourceType.ORDER)
    assert type_selector.specificity() == 3
    assert type_selector.matches(res) is True
    assert (
        type_selector.matches(Resource(display_name="Doc", resource_type=ResourceType.DOCUMENT, external_id="d1"))
        is False
    )

    # Endpoint pattern glob matching
    glob_selector = ResourceSelector(endpoint_pattern="/api/v1/orders/*")
    assert glob_selector.specificity() == 2
    assert glob_selector.matches(res) is True
    assert glob_selector.matches(res, endpoint="/api/v1/orders/1") is True
    assert glob_selector.matches(res, endpoint="/api/v1/invoices/99") is False


def test_policy_model_instantiation() -> None:
    """Test full Policy rule model instantiation."""
    pol = Policy(
        name="Allow read orders for authenticated users",
        description="Standard business rule",
        subject_selector=SubjectSelector(role_type=RoleType.AUTHENTICATED),
        resource_selector=ResourceSelector(resource_type=ResourceType.ORDER),
        action=PolicyAction.READ,
        expected_decision=ExpectedDecision.ALLOW,
        preconditions=["order.status != 'DRAFT'"],
        confidence_source=PolicyConfidenceSource.DOCUMENTATION,
        enabled=True,
    )
    assert isinstance(pol.id, UUID)
    assert isinstance(pol.project_id, UUID)
    assert pol.name == "Allow read orders for authenticated users"
    assert pol.action == PolicyAction.READ
    assert pol.expected_decision == ExpectedDecision.ALLOW
    assert len(pol.preconditions) == 1
    assert pol.enabled is True


def test_policy_conflict_and_evaluation_models() -> None:
    """Test PolicyConflict and PolicyEvaluation data models."""
    p1 = uuid4()
    p2 = uuid4()
    conflict = PolicyConflict(
        policy_a_id=p1,
        policy_b_id=p2,
        description="Direct ALLOW vs DENY on orders",
    )
    assert conflict.policy_a_id == p1
    assert conflict.policy_b_id == p2
    assert conflict.detected_at is not None

    evaluation = PolicyEvaluation(
        policy_id=p1,
        identity_id=uuid4(),
        resource_id=uuid4(),
        action=PolicyAction.WRITE,
        expected_decision=ExpectedDecision.DENY,
        reasoning="Matched explicit DENY rule",
    )
    assert evaluation.policy_id == p1
    assert evaluation.action == PolicyAction.WRITE
    assert evaluation.expected_decision == ExpectedDecision.DENY
    assert evaluation.evaluated_at is not None
