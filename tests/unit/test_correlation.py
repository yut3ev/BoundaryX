"""Unit tests for TrafficCorrelator and automated IDOR detection."""

from uuid import uuid4

from boundaryx.application.analysis.correlation import (
    TrafficCorrelator,
)
from boundaryx.domain.findings.models import FindingCategory, FindingSeverity
from boundaryx.domain.identities.models import Identity, RoleType
from boundaryx.domain.relationships.models import RelationshipConfidence, RelationshipType
from boundaryx.domain.resources.models import Resource, ResourceType


def test_template_extraction_dynamic_segments() -> None:
    """Test URL path template extraction with integers, UUIDs, and slugs."""
    correlator = TrafficCorrelator()

    # Numeric ID
    res1 = correlator.extract_template("/api/v1/users/42")
    assert res1.template == "/api/v1/users/{user_id}"
    assert res1.parameters == {"user_id": "42"}

    # Multiple hierarchical IDs
    res2 = correlator.extract_template("/api/v1/users/123/orders/987")
    assert res2.template == "/api/v1/users/{user_id}/orders/{order_id}"
    assert res2.parameters == {"user_id": "123", "order_id": "987"}

    # UUID parameter
    sample_uuid = "e7b0a324-4f01-447a-8bfe-98e37d5718df"
    res3 = correlator.extract_template(f"/api/v2/documents/{sample_uuid}")
    assert res3.template == "/api/v2/documents/{document_id}"
    assert res3.parameters == {"document_id": sample_uuid}

    # Static path without parameters
    res4 = correlator.extract_template("/api/v1/status")
    assert res4.template == "/api/v1/status"
    assert len(res4.parameters) == 0


def test_template_matching_against_known_templates() -> None:
    """Test path matching against predefined route templates."""
    known = [
        "/api/v1/projects/{proj_id}/tasks/{task_id}",
        "/api/v1/health",
    ]
    correlator = TrafficCorrelator(known_templates=known)

    res = correlator.extract_template("/api/v1/projects/alpha-99/tasks/t123")
    assert res.template == "/api/v1/projects/{proj_id}/tasks/{task_id}"
    assert res.parameters == {"proj_id": "alpha-99", "task_id": "t123"}


def test_identity_correlation_bearer_token_and_cookies() -> None:
    """Test identity correlation via Bearer token, session cookie, and explicit ID."""
    user_a_id = uuid4()
    user_a = Identity(id=user_a_id, name="Alice", role_type=RoleType.ADMIN)

    token_map = {"secret-token-alice": user_a_id}
    correlator = TrafficCorrelator(identities=[user_a], token_map=token_map)

    # 1. Bearer Token match
    m1 = correlator.correlate_identity(headers={"Authorization": "Bearer secret-token-alice"})
    assert m1.identity_id == user_a_id
    assert m1.identity_name == "Alice"
    assert m1.matched_credential_type == "BEARER_TOKEN"
    assert not m1.is_anonymous

    # 2. Cookie match
    m2 = correlator.correlate_identity(
        headers={},
        cookies={"sessionid": "secret-token-alice"},
    )
    assert m2.identity_id == user_a_id
    assert m2.matched_credential_type == "COOKIE"

    # 3. Anonymous / no credentials
    m3 = correlator.correlate_identity(headers={}, cookies={})
    assert m3.is_anonymous
    assert m3.identity_name == "anonymous"

    # 4. Unknown credentials (inferred user)
    m4 = correlator.correlate_identity(headers={"Authorization": "Bearer unknown-token-xyz"})
    assert m4.identity_id is None
    assert "inferred-user-" in m4.identity_name
    assert not m4.is_anonymous


def test_resource_correlation_from_path_and_query() -> None:
    """Test correlating target resource entities from path parameters and query strings."""
    res_id = uuid4()
    known_res = Resource(
        id=res_id,
        display_name="Order 1001",
        resource_type=ResourceType.ORDER,
        external_id="1001",
    )
    correlator = TrafficCorrelator(resources=[known_res])

    template_res = correlator.extract_template("/api/orders/1001")
    matches = correlator.correlate_resources(template_res, query_params={"tenant_id": "t1"})

    assert len(matches) == 2
    path_match = next(m for m in matches if m.source_location == "PATH")
    assert path_match.resource_id == res_id
    assert path_match.external_id == "1001"
    assert path_match.resource_type == ResourceType.ORDER.value


def test_idor_candidate_detection_and_test_generation() -> None:
    """Test multi-identity access detection leading to IDOR candidates and test suggestions."""
    user1_id = uuid4()
    user2_id = uuid4()
    user1 = Identity(id=user1_id, name="User1", role_type=RoleType.AUTHENTICATED)
    user2 = Identity(id=user2_id, name="User2", role_type=RoleType.AUTHENTICATED)

    target_res_id = uuid4()
    known_resource = Resource(
        id=target_res_id,
        display_name="User1 Private Document",
        resource_type=ResourceType.DOCUMENT,
        external_id="doc_555",
        owning_identity_id=user1_id,
    )

    token_map = {
        "tok-user-1": user1_id,
        "tok-user-2": user2_id,
    }
    correlator = TrafficCorrelator(
        identities=[user1, user2],
        resources=[known_resource],
        token_map=token_map,
    )

    # Traffic records: User 1 accesses doc_555 -> 200 OK
    rec1 = {
        "id": "rec-1",
        "method": "GET",
        "url": "https://api.example.com/api/documents/doc_555",
        "path": "/api/documents/doc_555",
        "request_headers": {"Authorization": "Bearer tok-user-1"},
        "response_status": 200,
    }

    # User 2 accesses SAME doc_555 -> 200 OK (IDOR breach!)
    rec2 = {
        "id": "rec-2",
        "method": "GET",
        "url": "https://api.example.com/api/documents/doc_555",
        "path": "/api/documents/doc_555",
        "request_headers": {"Authorization": "Bearer tok-user-2"},
        "response_status": 200,
    }

    report = correlator.analyze_traffic([rec1, rec2])

    assert report.total_records_analyzed == 2
    assert len(report.potential_idor_candidates) == 1

    candidate = report.potential_idor_candidates[0]
    assert candidate.category == FindingCategory.IDOR
    assert candidate.resource_external_id == "doc_555"
    assert candidate.resource_id == target_res_id
    assert "User1" in candidate.participating_identity_names
    assert "User2" in candidate.participating_identity_names

    # Verify suggested test cases
    assert len(report.test_case_suggestions) == 1
    sugg = report.test_case_suggestions[0]
    assert sugg.expected_decision == "DENY"
    assert sugg.action == "READ"
    assert sugg.request_template.method == "GET"

    # Verify inferred relationships
    violation_rels = [r for r in report.inferred_relationships if r.relationship_type == RelationshipType.VIOLATES]
    assert len(violation_rels) == 1
    assert violation_rels[0].source_id == user2_id
    assert violation_rels[0].target_id == target_res_id
    assert violation_rels[0].confidence == RelationshipConfidence.SUSPECTED_VIOLATION


def test_cross_tenant_idor_candidate() -> None:
    """Test detection of cross-tenant authorization leaks in traffic."""
    tenant1_id = uuid4()
    tenant2_id = uuid4()

    user_alpha = Identity(
        id=uuid4(),
        name="AlphaUser",
        role_type=RoleType.AUTHENTICATED,
        tenant_ids=[tenant1_id],
    )
    user_beta = Identity(
        id=uuid4(),
        name="BetaUser",
        role_type=RoleType.AUTHENTICATED,
        tenant_ids=[tenant2_id],
    )

    correlator = TrafficCorrelator(
        identities=[user_alpha, user_beta],
        token_map={"tok-alpha": user_alpha.id, "tok-beta": user_beta.id},
    )

    rec1 = {
        "id": "rec-a",
        "method": "GET",
        "path": "/api/v1/invoices/inv_999",
        "request_headers": {"Authorization": "Bearer tok-alpha"},
        "response_status": 200,
    }
    rec2 = {
        "id": "rec-b",
        "method": "GET",
        "path": "/api/v1/invoices/inv_999",
        "request_headers": {"Authorization": "Bearer tok-beta"},
        "response_status": 200,
    }

    report = correlator.analyze_traffic([rec1, rec2])
    assert len(report.potential_idor_candidates) == 1
    cand = report.potential_idor_candidates[0]
    assert cand.cross_tenant is True
    assert cand.category == FindingCategory.CROSS_TENANT_ACCESS
    assert cand.severity == FindingSeverity.CRITICAL
