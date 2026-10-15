"""Authorization and relationship graph engine for BoundaryX.

Builds and analyzes multidimensional authorization graphs representing
identities, roles, tenants, resources, endpoints, policies, and findings
using NetworkX. Provides graph queries for cross-tenant boundary leaks,
orphaned resources, unprotected endpoints, policy conflicts, filtering,
and visualization export.
"""

from __future__ import annotations

import html
import math
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

import networkx as nx

from boundaryx.domain.findings.models import FindingSeverity
from boundaryx.domain.identities.models import RoleType
from boundaryx.domain.policies.models import ExpectedDecision, PolicyAction
from boundaryx.domain.relationships.models import (
    RelationshipConfidence,
    RelationshipType,
)
from boundaryx.domain.resources.models import ResourceType, SensitivityLevel


class NodeType(str, Enum):
    """Categorization of nodes in the authorization graph."""

    IDENTITY = "IDENTITY"
    ROLE = "ROLE"
    TENANT = "TENANT"
    RESOURCE = "RESOURCE"
    ENDPOINT = "ENDPOINT"
    POLICY = "POLICY"
    FINDING = "FINDING"


_CONFIDENCE_RANKS: dict[str, int] = {
    RelationshipConfidence.UNKNOWN.value: 1,
    RelationshipConfidence.SUSPECTED_VIOLATION.value: 2,
    RelationshipConfidence.INFERRED.value: 3,
    RelationshipConfidence.USER_DEFINED.value: 4,
    RelationshipConfidence.CONFIRMED.value: 5,
}

_NODE_COLORS: dict[NodeType, str] = {
    NodeType.IDENTITY: "#2563EB",  # Blue
    NodeType.ROLE: "#7C3AED",  # Violet
    NodeType.TENANT: "#059669",  # Emerald
    NodeType.RESOURCE: "#D97706",  # Amber
    NodeType.ENDPOINT: "#0891B2",  # Cyan
    NodeType.POLICY: "#4F46E5",  # Indigo
    NodeType.FINDING: "#DC2626",  # Red
}

_EDGE_COLORS: dict[RelationshipType, str] = {
    RelationshipType.OWNS: "#2563EB",
    RelationshipType.MEMBER_OF: "#7C3AED",
    RelationshipType.HAS_ACCESS: "#059669",
    RelationshipType.DENIED_ACCESS: "#64748B",
    RelationshipType.MANAGES: "#4F46E5",
    RelationshipType.PARENT_OF: "#0891B2",
    RelationshipType.TESTED_BY: "#D97706",
    RelationshipType.VIOLATES: "#DC2626",
}


class AuthorizationGraph:
    """NetworkX-backed authorization relationship graph for security testing.

    Tracks relationships between subjects, permissions, tenants, protected assets,
    and security findings. Offers topological traversal, isolation boundary analysis,
    and diagram generation.
    """

    def __init__(self) -> None:
        """Initialize an empty authorization multi-directed graph."""
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()

    @property
    def raw_graph(self) -> nx.MultiDiGraph:
        """Access underlying NetworkX MultiDiGraph instance."""
        return self._graph

    # -------------------------------------------------------------------------
    # Node Addition Methods
    # -------------------------------------------------------------------------

    def add_identity(
        self,
        identity_id: UUID | str,
        name: str,
        role_type: RoleType | str,
        tenant_ids: list[UUID | str] | None = None,
        **kwargs: Any,
    ) -> str:
        """Add an identity node to the graph and attach tenant memberships.

        Args:
            identity_id: Unique identifier of identity.
            name: Display name or username.
            role_type: Role assigned to identity.
            tenant_ids: Optional list of tenant IDs identity belongs to.
            **kwargs: Extra custom attributes.

        Returns:
            String node identifier.
        """
        node_id = str(identity_id)
        role_str = role_type.value if isinstance(role_type, RoleType) else str(role_type)
        t_ids = [str(t) for t in (tenant_ids or [])]

        attrs: dict[str, Any] = {
            "display_name": name,
            "type": NodeType.IDENTITY.value,
            "confidence": RelationshipConfidence.CONFIRMED.value,
            "role_type": role_str,
            "tenant_ids": t_ids,
            "attributes": {
                "role_type": role_str,
                "tenant_ids": t_ids,
                **kwargs,
            },
        }
        self._graph.add_node(node_id, **attrs)

        # Connect identity to tenant nodes with MEMBER_OF relationship
        for t_id in t_ids:
            if not self._graph.has_node(t_id):
                self.add_tenant(t_id, f"Tenant {t_id[:8]}")
            self.add_relationship(
                source_id=node_id,
                target_id=t_id,
                rel_type=RelationshipType.MEMBER_OF,
                confidence=RelationshipConfidence.CONFIRMED,
                description=f"Identity '{name}' is member of tenant '{t_id}'",
            )

        return node_id

    def add_tenant(
        self,
        tenant_id: UUID | str,
        name: str,
        **kwargs: Any,
    ) -> str:
        """Add an organizational tenant boundary node.

        Args:
            tenant_id: Unique tenant identifier.
            name: Human-readable tenant name.
            **kwargs: Extra attributes.

        Returns:
            String node identifier.
        """
        node_id = str(tenant_id)
        attrs: dict[str, Any] = {
            "display_name": name,
            "type": NodeType.TENANT.value,
            "confidence": RelationshipConfidence.CONFIRMED.value,
            "attributes": kwargs,
        }
        self._graph.add_node(node_id, **attrs)
        return node_id

    def add_resource(
        self,
        resource_id: UUID | str,
        name: str,
        resource_type: ResourceType | str,
        sensitivity: SensitivityLevel | str | None = None,
        owning_tenant_id: UUID | str | None = None,
        owning_identity_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> str:
        """Add a target resource node to the graph.

        Args:
            resource_id: Unique resource identifier.
            name: Display name or label.
            resource_type: Type of resource (e.g. USER_PROFILE, DOCUMENT).
            sensitivity: Information classification level.
            owning_tenant_id: Optional parent tenant ID.
            owning_identity_id: Optional owner identity ID.
            **kwargs: Additional metadata.

        Returns:
            String node identifier.
        """
        node_id = str(resource_id)
        res_type_str = resource_type.value if isinstance(resource_type, ResourceType) else str(resource_type)
        sens_str = (
            sensitivity.value
            if isinstance(sensitivity, SensitivityLevel)
            else (str(sensitivity) if sensitivity is not None else None)
        )
        tenant_str = str(owning_tenant_id) if owning_tenant_id is not None else None
        owner_str = str(owning_identity_id) if owning_identity_id is not None else None

        attrs: dict[str, Any] = {
            "display_name": name,
            "type": NodeType.RESOURCE.value,
            "confidence": RelationshipConfidence.CONFIRMED.value,
            "resource_type": res_type_str,
            "sensitivity": sens_str,
            "owning_tenant_id": tenant_str,
            "owning_identity_id": owner_str,
            "attributes": {
                "resource_type": res_type_str,
                "sensitivity": sens_str,
                "owning_tenant_id": tenant_str,
                "owning_identity_id": owner_str,
                **kwargs,
            },
        }
        self._graph.add_node(node_id, **attrs)

        # Edge from owner identity if provided
        if owner_str:
            if not self._graph.has_node(owner_str):
                self._graph.add_node(
                    owner_str,
                    display_name=f"Identity {owner_str[:8]}",
                    type=NodeType.IDENTITY.value,
                    confidence=RelationshipConfidence.UNKNOWN.value,
                    attributes={},
                )
            self.add_relationship(
                source_id=owner_str,
                target_id=node_id,
                rel_type=RelationshipType.OWNS,
                confidence=RelationshipConfidence.CONFIRMED,
                description=f"Identity '{owner_str}' owns resource '{name}'",
            )

        # Edge from owning tenant if provided
        if tenant_str:
            if not self._graph.has_node(tenant_str):
                self.add_tenant(tenant_str, f"Tenant {tenant_str[:8]}")
            self.add_relationship(
                source_id=tenant_str,
                target_id=node_id,
                rel_type=RelationshipType.OWNS,
                confidence=RelationshipConfidence.CONFIRMED,
                description=f"Tenant '{tenant_str}' owns resource '{name}'",
            )

        return node_id

    def add_endpoint(
        self,
        endpoint_url: str,
        method: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Add an HTTP endpoint node to the graph.

        Args:
            endpoint_url: URL path or pattern.
            method: Optional HTTP method (GET, POST, etc.).
            **kwargs: Extra endpoint parameters or schema info.

        Returns:
            String node identifier.
        """
        method_str = method.upper().strip() if method else None
        node_id = f"{method_str} {endpoint_url.strip()}" if method_str else endpoint_url.strip()

        attrs: dict[str, Any] = {
            "display_name": node_id,
            "type": NodeType.ENDPOINT.value,
            "confidence": RelationshipConfidence.CONFIRMED.value,
            "endpoint_url": endpoint_url,
            "method": method_str,
            "attributes": {
                "endpoint_url": endpoint_url,
                "method": method_str,
                **kwargs,
            },
        }
        self._graph.add_node(node_id, **attrs)
        return node_id

    def add_policy(
        self,
        policy_id: UUID | str,
        name: str,
        action: PolicyAction | str,
        expected_decision: ExpectedDecision | str,
        **kwargs: Any,
    ) -> str:
        """Add an authorization policy rule node.

        Args:
            policy_id: Unique policy identifier.
            name: Policy name or title.
            action: Action governed by the policy (e.g. READ, WRITE).
            expected_decision: Expected evaluation result (ALLOW, DENY).
            **kwargs: Extra policy metadata.

        Returns:
            String node identifier.
        """
        node_id = str(policy_id)
        action_str = action.value if isinstance(action, PolicyAction) else str(action)
        decision_str = (
            expected_decision.value if isinstance(expected_decision, ExpectedDecision) else str(expected_decision)
        )

        attrs: dict[str, Any] = {
            "display_name": name,
            "type": NodeType.POLICY.value,
            "confidence": RelationshipConfidence.CONFIRMED.value,
            "action": action_str,
            "expected_decision": decision_str,
            "attributes": {
                "action": action_str,
                "expected_decision": decision_str,
                **kwargs,
            },
        }
        self._graph.add_node(node_id, **attrs)
        return node_id

    def add_finding(
        self,
        finding_id: UUID | str,
        title: str,
        severity: FindingSeverity | str,
        **kwargs: Any,
    ) -> str:
        """Add a security finding or boundary defect node.

        Args:
            finding_id: Unique finding identifier.
            title: Finding title or vulnerability headline.
            severity: Finding severity level.
            **kwargs: Extra metadata.

        Returns:
            String node identifier.
        """
        node_id = str(finding_id)
        sev_str = severity.value if isinstance(severity, FindingSeverity) else str(severity)

        attrs: dict[str, Any] = {
            "display_name": title,
            "type": NodeType.FINDING.value,
            "confidence": RelationshipConfidence.CONFIRMED.value,
            "severity": sev_str,
            "attributes": {
                "severity": sev_str,
                **kwargs,
            },
        }
        self._graph.add_node(node_id, **attrs)
        return node_id

    # -------------------------------------------------------------------------
    # Relationship / Edge Addition
    # -------------------------------------------------------------------------

    def add_relationship(
        self,
        source_id: UUID | str,
        target_id: UUID | str,
        rel_type: RelationshipType | str,
        confidence: RelationshipConfidence | str = RelationshipConfidence.USER_DEFINED,
        description: str = "",
        evidence_ids: list[UUID | str] | None = None,
        **kwargs: Any,
    ) -> str:
        """Add a directional relationship edge linking two nodes in the graph.

        Args:
            source_id: Source node identifier.
            target_id: Target node identifier.
            rel_type: Type of relationship (e.g. HAS_ACCESS, OWNS, VIOLATES).
            confidence: Confidence level in the relationship.
            description: Explanatory notes.
            evidence_ids: List of linked evidence UUIDs.
            **kwargs: Extra custom edge attributes.

        Returns:
            Edge key string.
        """
        src = str(source_id)
        dst = str(target_id)
        type_str = rel_type.value if isinstance(rel_type, RelationshipType) else str(rel_type)
        conf_str = confidence.value if isinstance(confidence, RelationshipConfidence) else str(confidence)
        ev_ids = [str(e) for e in (evidence_ids or [])]

        if not self._graph.has_node(src):
            self._graph.add_node(
                src,
                display_name=src[:8],
                type="UNKNOWN",
                confidence=RelationshipConfidence.UNKNOWN.value,
                attributes={},
            )
        if not self._graph.has_node(dst):
            self._graph.add_node(
                dst,
                display_name=dst[:8],
                type="UNKNOWN",
                confidence=RelationshipConfidence.UNKNOWN.value,
                attributes={},
            )

        edge_attrs: dict[str, Any] = {
            "rel_type": type_str,
            "type": type_str,
            "confidence": conf_str,
            "description": description,
            "evidence_ids": ev_ids,
            "attributes": kwargs,
        }
        key = f"{type_str}:{src}->{dst}"
        self._graph.add_edge(src, dst, key=key, **edge_attrs)
        return key

    # -------------------------------------------------------------------------
    # Graph Analysis & Authorization Boundary Queries
    # -------------------------------------------------------------------------

    def get_orphaned_resources(self) -> list[dict[str, Any]]:
        """Identify resources with no assigned identity/tenant owner and no attached policies.

        Returns:
            List of resource node dictionaries that lack governance.
        """
        orphans: list[dict[str, Any]] = []

        for node_id, data in self._graph.nodes(data=True):
            if data.get("type") != NodeType.RESOURCE.value:
                continue

            has_attr_owner = bool(data.get("owning_identity_id") or data.get("owning_tenant_id"))

            # Check incoming OWNS or MANAGES edges
            has_edge_owner = False
            for src, _, edge_data in self._graph.in_edges(node_id, data=True):
                r_type = edge_data.get("rel_type")
                if r_type in {RelationshipType.OWNS.value, RelationshipType.MANAGES.value}:
                    has_edge_owner = True
                    break

            # Check attached policies (incident edges to POLICY nodes)
            has_policy = False
            for neighbor in self._graph.neighbors(node_id):
                if self._graph.nodes[neighbor].get("type") == NodeType.POLICY.value:
                    has_policy = True
                    break
            if not has_policy:
                for predecessor in self._graph.predecessors(node_id):
                    if self._graph.nodes[predecessor].get("type") == NodeType.POLICY.value:
                        has_policy = True
                        break

            if not has_attr_owner and not has_edge_owner and not has_policy:
                orphans.append(
                    {
                        "resource_id": node_id,
                        "display_name": data.get("display_name", node_id),
                        "resource_type": data.get("resource_type", "UNKNOWN"),
                        "sensitivity": data.get("sensitivity"),
                        "attributes": data.get("attributes", {}),
                    }
                )

        return orphans

    def get_cross_tenant_access_paths(self) -> list[dict[str, Any]]:
        """Detect access paths connecting an identity in one tenant to a resource in another tenant.

        Returns:
            List of detailed cross-tenant exposure path records.
        """
        cross_tenant_violations: list[dict[str, Any]] = []

        # Access-granting edge types
        active_access_types = {
            RelationshipType.HAS_ACCESS.value,
            RelationshipType.OWNS.value,
            RelationshipType.MANAGES.value,
            RelationshipType.VIOLATES.value,
        }

        # Build map of identities and their tenant IDs
        identity_tenants: dict[str, set[str]] = {}
        for node_id, data in self._graph.nodes(data=True):
            if data.get("type") == NodeType.IDENTITY.value:
                t_set: set[str] = set(data.get("tenant_ids") or [])
                # Check outgoing MEMBER_OF edges
                for _, dst, edge_data in self._graph.out_edges(node_id, data=True):
                    if (
                        edge_data.get("rel_type") == RelationshipType.MEMBER_OF.value
                        and self._graph.nodes[dst].get("type") == NodeType.TENANT.value
                    ):
                        t_set.add(dst)
                if t_set:
                    identity_tenants[node_id] = t_set

        # Build map of resources and their owning tenant ID
        resource_tenants: dict[str, str] = {}
        for node_id, data in self._graph.nodes(data=True):
            if data.get("type") == NodeType.RESOURCE.value:
                owning_tenant = data.get("owning_tenant_id")
                if owning_tenant:
                    resource_tenants[node_id] = owning_tenant
                else:
                    for src, _, edge_data in self._graph.in_edges(node_id, data=True):
                        if (
                            edge_data.get("rel_type") in {RelationshipType.OWNS.value, RelationshipType.PARENT_OF.value}
                            and self._graph.nodes[src].get("type") == NodeType.TENANT.value
                        ):
                            resource_tenants[node_id] = src
                            break

        # Check access paths between cross-tenant identities and resources
        for id_node, id_t_set in identity_tenants.items():
            for res_node, res_t_id in resource_tenants.items():
                if res_t_id in id_t_set:
                    continue  # Same tenant boundary, legitimate intra-tenant access

                # Search paths between id_node and res_node
                if nx.has_path(self._graph, id_node, res_node):
                    try:
                        all_paths = list(nx.all_simple_paths(self._graph, id_node, res_node, cutoff=4))
                    except (nx.NetworkXNoPath, nx.NetworkXError):
                        all_paths = []

                    for path in all_paths:
                        # Verify path contains valid access edges
                        path_valid = True
                        edge_details: list[dict[str, Any]] = []

                        for i in range(len(path) - 1):
                            u = path[i]
                            v = path[i + 1]
                            edge_dict = self._graph.get_edge_data(u, v)
                            matched_edge = None
                            for _, e_data in edge_dict.items():
                                if e_data.get("rel_type") in active_access_types:
                                    matched_edge = e_data
                                    break
                            if not matched_edge:
                                path_valid = False
                                break
                            edge_details.append(
                                {
                                    "source": u,
                                    "target": v,
                                    "rel_type": matched_edge.get("rel_type"),
                                    "confidence": matched_edge.get("confidence"),
                                    "description": matched_edge.get("description", ""),
                                }
                            )

                        if path_valid and edge_details:
                            id_name = self._graph.nodes[id_node].get("display_name", id_node)
                            res_name = self._graph.nodes[res_node].get("display_name", res_node)
                            source_tenant_name = list(id_t_set)[0]

                            cross_tenant_violations.append(
                                {
                                    "source_identity_id": id_node,
                                    "source_identity_name": id_name,
                                    "source_tenant_ids": list(id_t_set),
                                    "source_tenant_id": source_tenant_name,
                                    "target_resource_id": res_node,
                                    "target_resource_name": res_name,
                                    "target_tenant_id": res_t_id,
                                    "path": path,
                                    "edges": edge_details,
                                    "description": (
                                        f"Cross-tenant access path discovered: Identity '{id_name}' "
                                        f"(Tenant {source_tenant_name}) reaches Resource '{res_name}' "
                                        f"(Tenant {res_t_id}) across {len(path) - 1} edge(s)."
                                    ),
                                }
                            )

        return cross_tenant_violations

    def get_unprotected_endpoints(self) -> list[dict[str, Any]]:
        """Identify endpoint nodes that are not governed by any policy rule.

        Returns:
            List of unprotected endpoint node descriptions.
        """
        unprotected: list[dict[str, Any]] = []

        for node_id, data in self._graph.nodes(data=True):
            if data.get("type") != NodeType.ENDPOINT.value:
                continue

            has_policy = False
            # Check direct connections to policy nodes
            for neighbor in self._graph.neighbors(node_id):
                if self._graph.nodes[neighbor].get("type") == NodeType.POLICY.value:
                    has_policy = True
                    break
            if not has_policy:
                for predecessor in self._graph.predecessors(node_id):
                    if self._graph.nodes[predecessor].get("type") == NodeType.POLICY.value:
                        has_policy = True
                        break

            # If not directly protected, check if endpoint is connected to a protected resource
            if not has_policy:
                for neighbor in self._graph.neighbors(node_id):
                    if self._graph.nodes[neighbor].get("type") == NodeType.RESOURCE.value:
                        for r_neighbor in self._graph.neighbors(neighbor):
                            if self._graph.nodes[r_neighbor].get("type") == NodeType.POLICY.value:
                                has_policy = True
                                break
                        if has_policy:
                            break

            if not has_policy:
                unprotected.append(
                    {
                        "endpoint_id": node_id,
                        "display_name": data.get("display_name", node_id),
                        "endpoint_url": data.get("endpoint_url", node_id),
                        "method": data.get("method"),
                        "attributes": data.get("attributes", {}),
                    }
                )

        return unprotected

    def get_policy_conflicts(self) -> list[dict[str, Any]]:
        """Identify conflicting policies and contradictory relationship access edges.

        Returns:
            List of conflict descriptions detailing contradictory rules or states.
        """
        conflicts: list[dict[str, Any]] = []

        # 1. Contradictory relationship edges between the same nodes
        for u, v in self._graph.edges():
            edge_dict = self._graph.get_edge_data(u, v)
            rel_types = {e_data.get("rel_type") for e_data in edge_dict.values()}

            if RelationshipType.HAS_ACCESS.value in rel_types and RelationshipType.DENIED_ACCESS.value in rel_types:
                u_name = self._graph.nodes[u].get("display_name", u)
                v_name = self._graph.nodes[v].get("display_name", v)
                conflicts.append(
                    {
                        "type": "EDGE_ACCESS_CONTRADICTION",
                        "source_id": u,
                        "target_id": v,
                        "description": (
                            f"Contradictory access edges between '{u_name}' and '{v_name}': "
                            "both HAS_ACCESS and DENIED_ACCESS relationships exist simultaneously."
                        ),
                    }
                )

            if RelationshipType.HAS_ACCESS.value in rel_types and RelationshipType.VIOLATES.value in rel_types:
                u_name = self._graph.nodes[u].get("display_name", u)
                v_name = self._graph.nodes[v].get("display_name", v)
                conflicts.append(
                    {
                        "type": "EDGE_VIOLATION_CONFLICT",
                        "source_id": u,
                        "target_id": v,
                        "description": (
                            f"Active access contradicts reported violation between '{u_name}' and '{v_name}'."
                        ),
                    }
                )

        # 2. Conflicting Policy nodes targeting overlapping resources/endpoints with opposing decisions
        policies: list[tuple[str, dict[str, Any]]] = [
            (n, d) for n, d in self._graph.nodes(data=True) if d.get("type") == NodeType.POLICY.value
        ]

        for i in range(len(policies)):
            p1_id, p1_data = policies[i]
            p1_targets = set(self._graph.neighbors(p1_id)) | set(self._graph.predecessors(p1_id))
            p1_action = p1_data.get("action")
            p1_decision = p1_data.get("expected_decision")

            for j in range(i + 1, len(policies)):
                p2_id, p2_data = policies[j]
                p2_targets = set(self._graph.neighbors(p2_id)) | set(self._graph.predecessors(p2_id))
                p2_action = p2_data.get("action")
                p2_decision = p2_data.get("expected_decision")

                shared_targets = p1_targets & p2_targets
                if shared_targets and p1_action == p2_action and p1_decision != p2_decision:
                    target_names = [self._graph.nodes[t].get("display_name", t) for t in shared_targets]
                    conflicts.append(
                        {
                            "type": "POLICY_DECISION_CONFLICT",
                            "policy_a_id": p1_id,
                            "policy_a_name": p1_data.get("display_name", p1_id),
                            "policy_b_id": p2_id,
                            "policy_b_name": p2_data.get("display_name", p2_id),
                            "shared_targets": list(shared_targets),
                            "target_names": target_names,
                            "action": p1_action,
                            "decision_a": p1_decision,
                            "decision_b": p2_decision,
                            "description": (
                                f"Contradictory policy decisions on target(s) {target_names} for action '{p1_action}': "
                                f"Policy '{p1_data.get('display_name')}' specifies {p1_decision} whereas "
                                f"Policy '{p2_data.get('display_name')}' specifies {p2_decision}."
                            ),
                        }
                    )

        return conflicts

    # -------------------------------------------------------------------------
    # Filtering & Subgraph Generation
    # -------------------------------------------------------------------------

    def filter_graph(
        self,
        node_types: list[NodeType | str] | None = None,
        edge_types: list[RelationshipType | str] | None = None,
        min_confidence: RelationshipConfidence | str | None = None,
    ) -> AuthorizationGraph:
        """Create a filtered subgraph based on node types, edge types, and confidence threshold.

        Args:
            node_types: Optional subset of node types to retain.
            edge_types: Optional subset of relationship edge types to retain.
            min_confidence: Minimum confidence tier required for edges.

        Returns:
            New AuthorizationGraph instance containing only filtered elements.
        """
        filtered = AuthorizationGraph()

        allowed_node_types: set[str] | None = (
            {n.value if isinstance(n, NodeType) else str(n) for n in node_types} if node_types is not None else None
        )
        allowed_edge_types: set[str] | None = (
            {e.value if isinstance(e, RelationshipType) else str(e) for e in edge_types}
            if edge_types is not None
            else None
        )

        min_conf_val = (
            min_confidence.value
            if isinstance(min_confidence, RelationshipConfidence)
            else (str(min_confidence) if min_confidence is not None else None)
        )
        min_rank = _CONFIDENCE_RANKS.get(min_conf_val, 0) if min_conf_val else 0

        # Copy matching nodes
        for node_id, data in self._graph.nodes(data=True):
            n_type = data.get("type")
            if allowed_node_types is not None and n_type not in allowed_node_types:
                continue
            filtered._graph.add_node(node_id, **data)

        # Copy matching edges between retained nodes
        for u, v, key, data in self._graph.edges(data=True, keys=True):
            if not filtered._graph.has_node(u) or not filtered._graph.has_node(v):
                continue

            r_type = data.get("rel_type")
            if allowed_edge_types is not None and r_type not in allowed_edge_types:
                continue

            edge_conf = data.get("confidence", RelationshipConfidence.UNKNOWN.value)
            if _CONFIDENCE_RANKS.get(edge_conf, 0) < min_rank:
                continue

            filtered._graph.add_edge(u, v, key=key, **data)

        return filtered

    # -------------------------------------------------------------------------
    # Metrics Computation
    # -------------------------------------------------------------------------

    def compute_metrics(self) -> dict[str, Any]:
        """Compute structural, topological, and inventory metrics for the authorization graph.

        Returns:
            Dictionary containing node/edge counts, density, connectivity, and degree stats.
        """
        total_nodes = self._graph.number_of_nodes()
        total_edges = self._graph.number_of_edges()

        # Node breakdown
        node_counts_by_type: dict[str, int] = {}
        for _, data in self._graph.nodes(data=True):
            n_type = data.get("type", "UNKNOWN")
            node_counts_by_type[n_type] = node_counts_by_type.get(n_type, 0) + 1

        # Edge breakdown
        edge_counts_by_type: dict[str, int] = {}
        edge_counts_by_confidence: dict[str, int] = {}
        for _, _, data in self._graph.edges(data=True):
            r_type = data.get("rel_type", "UNKNOWN")
            conf = data.get("confidence", "UNKNOWN")
            edge_counts_by_type[r_type] = edge_counts_by_type.get(r_type, 0) + 1
            edge_counts_by_confidence[conf] = edge_counts_by_confidence.get(conf, 0) + 1

        # Connectivity stats
        density = nx.density(self._graph) if total_nodes > 1 else 0.0
        is_weakly_conn = nx.is_weakly_connected(self._graph) if total_nodes > 0 else False
        num_components = nx.number_weakly_connected_components(self._graph) if total_nodes > 0 else 0
        isolated_nodes = list(nx.isolates(self._graph))
        isolated_count = len(isolated_nodes)

        degrees = [d for _, d in self._graph.degree()]
        avg_degree = sum(degrees) / total_nodes if total_nodes > 0 else 0.0

        return {
            "total_nodes": total_nodes,
            "node_counts_by_type": node_counts_by_type,
            "total_edges": total_edges,
            "edge_counts_by_type": edge_counts_by_type,
            "edge_counts_by_confidence": edge_counts_by_confidence,
            "density": round(density, 4),
            "is_weakly_connected": is_weakly_conn,
            "number_weakly_connected_components": num_components,
            "isolated_nodes_count": isolated_count,
            "average_degree": round(avg_degree, 2),
        }

    # -------------------------------------------------------------------------
    # Serialization (to_dict / from_dict)
    # -------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize authorization graph to a clean JSON-serializable dictionary.

        Returns:
            Dictionary containing schema version, nodes list, and edges list.
        """
        nodes_list: list[dict[str, Any]] = []
        for node_id, data in self._graph.nodes(data=True):
            nodes_list.append(
                {
                    "id": str(node_id),
                    "display_name": data.get("display_name", str(node_id)),
                    "type": data.get("type", "UNKNOWN"),
                    "confidence": data.get("confidence", RelationshipConfidence.CONFIRMED.value),
                    "attributes": data.get("attributes", {}),
                }
            )

        edges_list: list[dict[str, Any]] = []
        for u, v, key, data in self._graph.edges(data=True, keys=True):
            edges_list.append(
                {
                    "source": str(u),
                    "target": str(v),
                    "key": str(key),
                    "rel_type": data.get("rel_type", RelationshipType.HAS_ACCESS.value),
                    "confidence": data.get("confidence", RelationshipConfidence.USER_DEFINED.value),
                    "description": data.get("description", ""),
                    "evidence_ids": data.get("evidence_ids", []),
                    "attributes": data.get("attributes", {}),
                }
            )

        return {
            "version": "1.0",
            "nodes": nodes_list,
            "edges": edges_list,
            "metrics": self.compute_metrics(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthorizationGraph:
        """Reconstruct an AuthorizationGraph from a serialized dictionary.

        Args:
            data: Serialized graph dictionary.

        Returns:
            Rehydrated AuthorizationGraph instance.
        """
        graph = cls()

        for node in data.get("nodes", []):
            node_id = str(node["id"])
            attrs = {
                "display_name": node.get("display_name", node_id),
                "type": node.get("type", "UNKNOWN"),
                "confidence": node.get("confidence", RelationshipConfidence.CONFIRMED.value),
                "attributes": node.get("attributes", {}),
            }
            # Unpack attributes into top-level for convenience
            for k, val in node.get("attributes", {}).items():
                if k not in attrs:
                    attrs[k] = val
            graph._graph.add_node(node_id, **attrs)

        for edge in data.get("edges", []):
            src = str(edge["source"])
            dst = str(edge["target"])
            key = edge.get("key", f"{src}->{dst}")
            edge_attrs = {
                "rel_type": edge.get("rel_type", RelationshipType.HAS_ACCESS.value),
                "type": edge.get("rel_type", RelationshipType.HAS_ACCESS.value),
                "confidence": edge.get("confidence", RelationshipConfidence.USER_DEFINED.value),
                "description": edge.get("description", ""),
                "evidence_ids": edge.get("evidence_ids", []),
                "attributes": edge.get("attributes", {}),
            }
            graph._graph.add_edge(src, dst, key=key, **edge_attrs)

        return graph

    # -------------------------------------------------------------------------
    # Visual Export (SVG and PNG without external GUI/Display)
    # -------------------------------------------------------------------------

    def export_svg(self, output_path: str | Path) -> str:
        """Export the graph as an SVG vector image without requiring display servers.

        Args:
            output_path: Destination file path for the SVG.

        Returns:
            Absolute path string to written SVG file.
        """
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)

        width = 1400
        height = 900
        padding = 100

        nodes = list(self._graph.nodes(data=True))
        if not nodes:
            svg_content = (
                f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
                f'viewBox="0 0 {width} {height}"><rect width="100%" height="100%" fill="#F8FAFC"/>'
                '<text x="50%" y="50%" text-anchor="middle" font-family="sans-serif" font-size="20" '
                'fill="#64748B">Empty Authorization Graph</text></svg>'
            )
            out_p.write_text(svg_content, encoding="utf-8")
            return str(out_p)

        # Compute positions using NetworkX spring layout
        layout_k = 2.5 / math.sqrt(len(nodes)) if len(nodes) > 1 else 1.0
        pos = nx.spring_layout(self._graph, seed=42, k=layout_k, iterations=60)

        # Map positions to canvas bounds
        xs = [coord[0] for coord in pos.values()]
        ys = [coord[1] for coord in pos.values()]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        x_range = max_x - min_x if max_x != min_x else 1.0
        y_range = max_y - min_y if max_y != min_y else 1.0

        coords: dict[str, tuple[float, float]] = {}
        for n_id, (x, y) in pos.items():
            cx = padding + ((x - min_x) / x_range) * (width - 2 * padding)
            cy = padding + ((y - min_y) / y_range) * (height - 2 * padding)
            coords[str(n_id)] = (cx, cy)

        # Build SVG tags
        svg_parts: list[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
            "<defs>",
            '  <filter id="shadow" x="-10%" y="-10%" width="120%" height="130%">',
            '    <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.12"/>',
            "  </filter>",
        ]

        # Arrow markers for each edge color
        all_colors = set(_EDGE_COLORS.values()) | {"#64748B"}
        for col in sorted(all_colors):
            m_id = f"arrow-{col.replace('#', '')}"
            svg_parts.append(
                f'  <marker id="{m_id}" viewBox="0 0 10 10" refX="28" refY="5" '
                f'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
                f'<path d="M 0 1 L 10 5 L 0 9 z" fill="{col}"/>'
                "</marker>"
            )
        svg_parts.append("</defs>")

        # Background
        svg_parts.append('<rect width="100%" height="100%" fill="#0F172A"/>')

        # Header Title
        svg_parts.append(
            '<text x="40" y="45" font-family="Segoe UI, Roboto, Helvetica, Arial, sans-serif" '
            'font-size="22" font-weight="700" fill="#F8FAFC">BoundaryX Authorization Relationship Graph</text>'
        )
        svg_parts.append(
            f'<text x="40" y="70" font-family="Segoe UI, Roboto, Helvetica, Arial, sans-serif" '
            f'font-size="13" fill="#94A3B8">Entities: {len(nodes)} | Edges: {self._graph.number_of_edges()}</text>'
        )

        # Render Edges
        svg_parts.append('<g id="edges">')
        for u, v, data in self._graph.edges(data=True):
            u_str, v_str = str(u), str(v)
            if u_str not in coords or v_str not in coords:
                continue
            x1, y1 = coords[u_str]
            x2, y2 = coords[v_str]

            r_type = data.get("rel_type", RelationshipType.HAS_ACCESS.value)
            rel_enum = (
                RelationshipType(r_type) if r_type in RelationshipType.__members__ else RelationshipType.HAS_ACCESS
            )
            color = _EDGE_COLORS.get(rel_enum, "#64748B")
            m_id = f"arrow-{color.replace('#', '')}"

            dash_style = (
                'stroke-dasharray="4,4"'
                if data.get("confidence") == RelationshipConfidence.SUSPECTED_VIOLATION.value
                else ""
            )

            svg_parts.append(
                f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                f'stroke="{color}" stroke-width="2" {dash_style} marker-end="url(#{m_id})"/>'
            )

            # Edge label at midpoint
            mx = (x1 + x2) / 2
            my = (y1 + y2) / 2
            svg_parts.append(
                f'<text x="{mx:.1f}" y="{my - 6:.1f}" font-family="sans-serif" font-size="10" '
                f'fill="{color}" text-anchor="middle" font-weight="600">{html.escape(r_type)}</text>'
            )
        svg_parts.append("</g>")

        # Render Nodes
        svg_parts.append('<g id="nodes">')
        box_w = 160
        box_h = 48
        half_w = box_w / 2
        half_h = box_h / 2

        for node_id, data in nodes:
            n_str = str(node_id)
            if n_str not in coords:
                continue
            cx, cy = coords[n_str]
            rx = cx - half_w
            ry = cy - half_h

            n_type = data.get("type", "UNKNOWN")
            type_enum = NodeType(n_type) if n_type in NodeType.__members__ else NodeType.RESOURCE
            fill_col = _NODE_COLORS.get(type_enum, "#475569")
            disp_name = data.get("display_name", n_str)
            disp_short = disp_name if len(disp_name) <= 20 else disp_name[:18] + "..."

            svg_parts.append(
                f'<rect x="{rx:.1f}" y="{ry:.1f}" width="{box_w}" height="{box_h}" rx="8" '
                f'fill="{fill_col}" stroke="#FFFFFF" stroke-width="1.5" filter="url(#shadow)"/>'
            )
            svg_parts.append(
                f'<text x="{cx:.1f}" y="{ry + 20:.1f}" text-anchor="middle" font-family="sans-serif" '
                f'font-size="12" font-weight="700" fill="#FFFFFF">{html.escape(disp_short)}</text>'
            )
            svg_parts.append(
                f'<text x="{cx:.1f}" y="{ry + 36:.1f}" text-anchor="middle" font-family="sans-serif" '
                f'font-size="10" font-weight="400" fill="#E2E8F0">[{html.escape(n_type)}]</text>'
            )
        svg_parts.append("</g>")

        # Legend Box in bottom right
        leg_x = width - 260
        leg_y = height - 220
        svg_parts.append(
            f'<g id="legend" transform="translate({leg_x}, {leg_y})">'
            '<rect width="230" height="190" rx="8" fill="#1E293B" stroke="#334155" stroke-width="1"/>'
            '<text x="15" y="22" font-family="sans-serif" font-size="12" font-weight="700" fill="#F8FAFC">Node Legend</text>'
        )
        curr_y = 42
        for n_enum, col in _NODE_COLORS.items():
            svg_parts.append(
                f'<circle cx="22" cy="{curr_y}" r="6" fill="{col}"/>'
                f'<text x="36" y="{curr_y + 4}" font-family="sans-serif" font-size="11" fill="#CBD5E1">{n_enum.value}</text>'
            )
            curr_y += 20
        svg_parts.append("</g>")

        svg_parts.append("</svg>")

        out_p.write_text("\n".join(svg_parts), encoding="utf-8")
        return str(out_p)

    def export_png(self, output_path: str | Path) -> str:
        """Export the authorization graph to a raster PNG file using PIL.

        Args:
            output_path: Target PNG file location.

        Returns:
            Absolute path string to written PNG file.
        """
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)

        from PIL import Image, ImageDraw

        width = 1600
        height = 1000
        padding = 120

        img = Image.new("RGBA", (width, height), (15, 23, 42, 255))  # Dark slate
        draw = ImageDraw.Draw(img)

        nodes = list(self._graph.nodes(data=True))
        if not nodes:
            draw.text((width // 2 - 120, height // 2), "Empty Authorization Graph", fill=(148, 163, 184))
            img.convert("RGB").save(str(out_p), "PNG")
            return str(out_p)

        # Coordinates
        layout_k = 2.5 / math.sqrt(len(nodes)) if len(nodes) > 1 else 1.0
        pos = nx.spring_layout(self._graph, seed=42, k=layout_k, iterations=60)
        xs = [coord[0] for coord in pos.values()]
        ys = [coord[1] for coord in pos.values()]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        x_range = max_x - min_x if max_x != min_x else 1.0
        y_range = max_y - min_y if max_y != min_y else 1.0

        coords: dict[str, tuple[float, float]] = {}
        for n_id, (x, y) in pos.items():
            cx = padding + ((x - min_x) / x_range) * (width - 2 * padding)
            cy = padding + ((y - min_y) / y_range) * (height - 2 * padding)
            coords[str(n_id)] = (cx, cy)

        # Draw header
        draw.text((40, 30), "BoundaryX Authorization Relationship Graph", fill=(248, 250, 252))
        draw.text((40, 55), f"Entities: {len(nodes)} | Edges: {self._graph.number_of_edges()}", fill=(148, 163, 184))

        def _hex_to_rgb(hex_code: str) -> tuple[int, int, int]:
            h = hex_code.lstrip("#")
            return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))  # type: ignore

        # Draw Edges
        for u, v, data in self._graph.edges(data=True):
            u_str, v_str = str(u), str(v)
            if u_str not in coords or v_str not in coords:
                continue
            x1, y1 = coords[u_str]
            x2, y2 = coords[v_str]

            r_type = data.get("rel_type", RelationshipType.HAS_ACCESS.value)
            rel_enum = (
                RelationshipType(r_type) if r_type in RelationshipType.__members__ else RelationshipType.HAS_ACCESS
            )
            col_hex = _EDGE_COLORS.get(rel_enum, "#64748B")
            rgb = _hex_to_rgb(col_hex)

            draw.line([(x1, y1), (x2, y2)], fill=rgb, width=2)
            # Label
            mx = (x1 + x2) / 2
            my = (y1 + y2) / 2
            draw.text((mx - 20, my - 12), r_type, fill=rgb)

        # Draw Nodes
        box_w = 150
        box_h = 44
        half_w = box_w / 2
        half_h = box_h / 2

        for node_id, data in nodes:
            n_str = str(node_id)
            if n_str not in coords:
                continue
            cx, cy = coords[n_str]
            x0 = cx - half_w
            y0 = cy - half_h
            x1 = cx + half_w
            y1 = cy + half_h

            n_type = data.get("type", "UNKNOWN")
            type_enum = NodeType(n_type) if n_type in NodeType.__members__ else NodeType.RESOURCE
            fill_hex = _NODE_COLORS.get(type_enum, "#475569")
            node_rgb = _hex_to_rgb(fill_hex)

            draw.rounded_rectangle([x0, y0, x1, y1], radius=6, fill=node_rgb, outline=(255, 255, 255), width=2)

            disp_name = data.get("display_name", n_str)
            disp_short = disp_name if len(disp_name) <= 18 else disp_name[:16] + ".."
            draw.text((x0 + 10, y0 + 6), disp_short, fill=(255, 255, 255))
            draw.text((x0 + 10, y0 + 24), f"[{n_type}]", fill=(226, 232, 240))

        img.convert("RGB").save(str(out_p), "PNG")
        return str(out_p)
