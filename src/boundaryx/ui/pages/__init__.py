"""BoundaryX User Interface Pages Package.

Provides responsive PySide6 views for overview dashboard, project workspaces,
target scope management, identities, resources, authorization policy matrices,
HTTP traffic analysis, interactive relationship graph, test lab execution,
findings triage, cryptographic evidence vault, report export, audit log, and settings.
"""

from __future__ import annotations

from boundaryx.ui.pages.audit_log_page import AuditLogPage
from boundaryx.ui.pages.evidence_vault_page import EvidenceVaultPage
from boundaryx.ui.pages.findings_page import FindingsPage
from boundaryx.ui.pages.graph_page import GraphPage
from boundaryx.ui.pages.identities_page import IdentitiesPage
from boundaryx.ui.pages.overview_page import OverviewPage
from boundaryx.ui.pages.policies_page import PoliciesPage
from boundaryx.ui.pages.projects_page import ProjectsPage
from boundaryx.ui.pages.reports_page import ReportsPage
from boundaryx.ui.pages.resources_page import ResourcesPage
from boundaryx.ui.pages.scope_page import ScopePage
from boundaryx.ui.pages.settings_page import SettingsPage
from boundaryx.ui.pages.test_lab_page import TestLabPage
from boundaryx.ui.pages.traffic_page import TrafficPage

__all__ = [
    "AuditLogPage",
    "EvidenceVaultPage",
    "FindingsPage",
    "GraphPage",
    "IdentitiesPage",
    "OverviewPage",
    "PoliciesPage",
    "ProjectsPage",
    "ReportsPage",
    "ResourcesPage",
    "ScopePage",
    "SettingsPage",
    "TestLabPage",
    "TrafficPage",
]
