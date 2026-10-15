"""Unit tests for AuthorizationGraph engine and visualization export."""

import os
import tempfile
from uuid import uuid4

from boundaryx.domain.findings.models import FindingSeverity
from boundaryx.domain.identities.models import RoleType
from boundaryx.domain.policies.models import ExpectedDecision, PolicyAction
from boundaryx.domain.relationships.graph import AuthorizationGraph, NodeType
from boundaryx.domain.relationships.models import RelationshipConfidence, RelationshipType
from boundaryx.domain.resources.models import ResourceType, SensitivityLevel


def test_authorization_graph_nodes_and_relationships() -> None:
    """Test adding all node types and relationships to the authorization graph."""
    g = AuthorizationGraph()

    t_id = g.add_tenant(uuid4(), "ACME Corp")
    i_id = g.add_identity(uuid4(), "alice@acme.com", RoleType.ADMIN, tenant_ids=[t_id])
    r_id = g.add_resource(
        uuid4(),
        "Invoice #1001",
        ResourceType.INVOICE,
        sensitivity=SensitivityLevel.CONFIDENTIAL,
        owning_tenant_id=t_id,
        owning_identity_id=i_id,
    )
    ep_id = g.add_endpoint("/api/v1/invoices/{id}", method="GET")
    p_id = g.add_policy(uuid4(), "Invoices Policy", PolicyAction.READ, ExpectedDecision.ALLOW)
    f_id = g.add_finding(uuid4(), "IDOR on Invoices", FindingSeverity.HIGH)

    # Edge from policy to resource
    g.add_relationship(
        source_id=p_id,
        target_id=r_id,
        rel_type=RelationshipType.HAS_ACCESS,
        confidence=RelationshipConfidence.CONFIRMED,
        description="Policy grants read access",
    )
    # Edge from endpoint to resource
    g.add_relationship(
        source_id=r_id,
        target_id=ep_id,
        rel_type=RelationshipType.PARENT_OF,
        confidence=RelationshipConfidence.CONFIRMED,
    )
    # Edge from finding to endpoint
    g.add_relationship(
        source_id=f_id,
        target_id=ep_id,
        rel_type=RelationshipType.TESTED_BY,
        confidence=RelationshipConfidence.CONFIRMED,
    )

    metrics = g.compute_metrics()
    assert metrics["total_nodes"] == 6
    assert metrics["node_counts_by_type"][NodeType.IDENTITY.value] == 1
    assert metrics["node_counts_by_type"][NodeType.TENANT.value] == 1
    assert metrics["node_counts_by_type"][NodeType.RESOURCE.value] == 1
    assert metrics["node_counts_by_type"][NodeType.ENDPOINT.value] == 1
    assert metrics["node_counts_by_type"][NodeType.POLICY.value] == 1
    assert metrics["node_counts_by_type"][NodeType.FINDING.value] == 1
    assert metrics["total_edges"] >= 5


def test_orphaned_resources() -> None:
    """Test identification of resources with no owner and no policies."""
    g = AuthorizationGraph()

    # Resource 1: orphaned (no owner, no policy)
    r1_id = g.add_resource(uuid4(), "Forgotten Doc", ResourceType.DOCUMENT)

    # Resource 2: has owner
    u_id = g.add_identity(uuid4(), "bob", RoleType.EDITOR)
    r2_id = g.add_resource(uuid4(), "Bob's Doc", ResourceType.DOCUMENT, owning_identity_id=u_id)

    # Resource 3: has attached policy
    r3_id = g.add_resource(uuid4(), "Policy Doc", ResourceType.DOCUMENT)
    p_id = g.add_policy(uuid4(), "Doc Policy", PolicyAction.READ, ExpectedDecision.ALLOW)
    g.add_relationship(p_id, r3_id, RelationshipType.HAS_ACCESS)

    orphans = g.get_orphaned_resources()
    orphan_ids = [o["resource_id"] for o in orphans]

    assert r1_id in orphan_ids
    assert r2_id not in orphan_ids
    assert r3_id not in orphan_ids


def test_cross_tenant_access_paths() -> None:
    """Test detection of paths between an identity in Tenant A and resource in Tenant B."""
    g = AuthorizationGraph()

    tenant_a = g.add_tenant(uuid4(), "Tenant Alpha")
    tenant_b = g.add_tenant(uuid4(), "Tenant Beta")

    user_a = g.add_identity(uuid4(), "attacker@alpha.com", RoleType.AUTHENTICATED, tenant_ids=[tenant_a])
    res_b = g.add_resource(
        uuid4(),
        "Secret Budget Beta",
        ResourceType.DOCUMENT,
        owning_tenant_id=tenant_b,
    )

    # Initially no cross-tenant path
    violations_before = g.get_cross_tenant_access_paths()
    assert len(violations_before) == 0

    # Unauthorized access edge added from User A to Resource B
    g.add_relationship(
        source_id=user_a,
        target_id=res_b,
        rel_type=RelationshipType.HAS_ACCESS,
        confidence=RelationshipConfidence.SUSPECTED_VIOLATION,
        description="Cross-tenant breach via IDOR",
    )

    violations_after = g.get_cross_tenant_access_paths()
    assert len(violations_after) == 1
    v = violations_after[0]
    assert v["source_identity_id"] == user_a
    assert v["target_resource_id"] == res_b
    assert v["target_tenant_id"] == tenant_b
    assert tenant_a in v["source_tenant_ids"]


def test_unprotected_endpoints() -> None:
    """Test detection of endpoints that have no governing policy."""
    g = AuthorizationGraph()

    # Endpoint without policy
    ep1 = g.add_endpoint("/api/v1/public/health", method="GET")

    # Endpoint with policy
    ep2 = g.add_endpoint("/api/v1/admin/users", method="GET")
    pol = g.add_policy(uuid4(), "Admin Users Policy", PolicyAction.READ, ExpectedDecision.DENY)
    g.add_relationship(pol, ep2, RelationshipType.HAS_ACCESS)

    unprotected = g.get_unprotected_endpoints()
    unprotected_ids = [u["endpoint_id"] for u in unprotected]

    assert ep1 in unprotected_ids
    assert ep2 not in unprotected_ids


def test_policy_conflicts() -> None:
    """Test detection of conflicting policies and contradictory edges."""
    g = AuthorizationGraph()

    u_id = g.add_identity(uuid4(), "charlie", RoleType.AUTHENTICATED)
    r_id = g.add_resource(uuid4(), "Sensitive File", ResourceType.DOCUMENT)

    # Edge contradiction: HAS_ACCESS and DENIED_ACCESS
    g.add_relationship(u_id, r_id, RelationshipType.HAS_ACCESS)
    g.add_relationship(u_id, r_id, RelationshipType.DENIED_ACCESS)

    # Policy decision contradiction on same resource
    p1 = g.add_policy(uuid4(), "Allow Rule", PolicyAction.READ, ExpectedDecision.ALLOW)
    p2 = g.add_policy(uuid4(), "Deny Rule", PolicyAction.READ, ExpectedDecision.DENY)
    g.add_relationship(p1, r_id, RelationshipType.HAS_ACCESS)
    g.add_relationship(p2, r_id, RelationshipType.DENIED_ACCESS)

    conflicts = g.get_policy_conflicts()
    assert len(conflicts) >= 2

    conflict_types = {c["type"] for c in conflicts}
    assert "EDGE_ACCESS_CONTRADICTION" in conflict_types
    assert "POLICY_DECISION_CONFLICT" in conflict_types


def test_filter_graph() -> None:
    """Test subgraph filtering by node types, edge types, and confidence."""
    g = AuthorizationGraph()

    i_id = g.add_identity(uuid4(), "david", RoleType.ADMIN)
    r_id = g.add_resource(uuid4(), "Data", ResourceType.DOCUMENT)
    ep_id = g.add_endpoint("/api/data", method="GET")

    g.add_relationship(i_id, r_id, RelationshipType.OWNS, confidence=RelationshipConfidence.CONFIRMED)
    g.add_relationship(
        r_id,
        ep_id,
        RelationshipType.TESTED_BY,
        confidence=RelationshipConfidence.INFERRED,
    )

    # Filter to only IDENTITY and RESOURCE nodes
    sub_nodes = g.filter_graph(node_types=[NodeType.IDENTITY, NodeType.RESOURCE])
    assert sub_nodes.raw_graph.number_of_nodes() == 2
    assert sub_nodes.raw_graph.has_node(i_id)
    assert sub_nodes.raw_graph.has_node(r_id)
    assert not sub_nodes.raw_graph.has_node(ep_id)

    # Filter by min_confidence CONFIRMED
    sub_conf = g.filter_graph(min_confidence=RelationshipConfidence.CONFIRMED)
    assert sub_conf.raw_graph.number_of_edges() == 1  # Only OWNS edge is CONFIRMED


def test_serialization_to_and_from_dict() -> None:
    """Test serialization to dict and reconstruction from dict."""
    g = AuthorizationGraph()
    u_id = g.add_identity(uuid4(), "eve", RoleType.AUTHENTICATED)
    r_id = g.add_resource(uuid4(), "Project Plan", ResourceType.PROJECT)
    g.add_relationship(
        u_id,
        r_id,
        RelationshipType.HAS_ACCESS,
        confidence=RelationshipConfidence.CONFIRMED,
        description="Eve has access",
    )

    data = g.to_dict()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1

    g_reconstructed = AuthorizationGraph.from_dict(data)
    assert g_reconstructed.raw_graph.number_of_nodes() == 2
    assert g_reconstructed.raw_graph.number_of_edges() == 1
    assert g_reconstructed.raw_graph.has_edge(u_id, r_id)


def test_export_svg_and_png() -> None:
    """Test visual SVG and PNG generation without external display servers."""
    g = AuthorizationGraph()
    t_id = g.add_tenant(uuid4(), "Tenant Export")
    u_id = g.add_identity(uuid4(), "frank", RoleType.ADMIN, tenant_ids=[t_id])
    r_id = g.add_resource(uuid4(), "Export Asset", ResourceType.API_RESOURCE, owning_tenant_id=t_id)
    g.add_relationship(u_id, r_id, RelationshipType.OWNS, confidence=RelationshipConfidence.CONFIRMED)

    with tempfile.TemporaryDirectory() as tmpdir:
        svg_path = os.path.join(tmpdir, "graph.svg")
        png_path = os.path.join(tmpdir, "graph.png")

        res_svg = g.export_svg(svg_path)
        assert os.path.exists(res_svg)
        assert os.path.getsize(res_svg) > 500

        with open(res_svg, encoding="utf-8") as f:
            content = f.read()
            assert "<svg" in content
            assert "BoundaryX Authorization Relationship Graph" in content
            assert "Export Asset" in content

        res_png = g.export_png(png_path)
        assert os.path.exists(res_png)
        assert os.path.getsize(res_png) > 1000
