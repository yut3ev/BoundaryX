"""Widget and interaction tests for BoundaryX core UI pages."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication

from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.infrastructure.database.models import Base
from boundaryx.security.scope import ScopeManager, ScopeRule
from boundaryx.ui.pages import (
    IdentitiesPage,
    OverviewPage,
    PoliciesPage,
    ProjectsPage,
    ResourcesPage,
    ScopePage,
)


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Fixture providing QApplication for offscreen testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(["-platform", "offscreen"])
    return app


@pytest.fixture
def memory_db() -> DatabaseManager:
    """Fixture providing an in-memory SQLite database initialized with all tables."""
    db = DatabaseManager(":memory:")
    Base.metadata.create_all(db.engine)
    return db


# ============================================================================
# OverviewPage Tests
# ============================================================================


def test_overview_page_empty_and_populated_states(qapp: QApplication) -> None:
    page = OverviewPage()
    assert not page._empty_state.isHidden()
    assert page._scroll_area.isHidden()

    page.set_metrics(
        identities=4,
        tenants=2,
        resources=15,
        policies=12,
        tests=50,
        findings=2,
        scope_rules_count=3,
        coverage_pct=80,
    )

    assert page._empty_state.isHidden()
    assert not page._scroll_area.isHidden()
    assert page._card_identities.get_value() == "4"
    assert page._card_tenants.get_value() == "2"
    assert page._card_resources.get_value() == "15"
    assert page._card_policies.get_value() == "12"
    assert page._card_tests.get_value() == "50"
    assert page._card_findings.get_value() == "2"
    assert page._coverage_bar.value() == 80


# ============================================================================
# ProjectsPage Tests
# ============================================================================


def test_projects_page_table_and_filtering(qapp: QApplication, memory_db: DatabaseManager) -> None:
    page = ProjectsPage(db_manager=memory_db)

    # Insert sample projects via page._projects_cache
    page._projects_cache = [
        {
            "id": "p-1",
            "name": "Payment Gateway",
            "description": "Core checkout",
            "archived": False,
            "settings": {"target_host": "pay.example.com"},
        },
        {
            "id": "p-2",
            "name": "Customer Portal",
            "description": "Self-service web app",
            "archived": False,
            "settings": {"target_host": "portal.example.com"},
        },
        {"id": "p-3", "name": "Legacy Auth", "description": "Archived system", "archived": True, "settings": {}},
    ]
    page._apply_filters()

    # Active Only by default
    assert len(page._filtered_projects) == 2
    assert page._table.rowCount() == 2

    # Filter search text
    page._search_bar._search_input.setText("Payment")
    page._apply_filters()
    assert len(page._filtered_projects) == 1
    assert page._filtered_projects[0]["name"] == "Payment Gateway"

    # Reset search, filter archived only
    page._search_bar._search_input.clear()
    page._search_bar.set_filter_value("status", "Archived Only")
    page._apply_filters()
    assert len(page._filtered_projects) == 1
    assert page._filtered_projects[0]["name"] == "Legacy Auth"


# ============================================================================
# ScopePage Tests
# ============================================================================


def test_scope_page_rules_and_checker(qapp: QApplication) -> None:
    scope = ScopeManager()
    scope.add_rule(ScopeRule(hostname="api.target.local", scheme="https", port=443, path_prefix="/api"))
    scope.add_rule(ScopeRule(hostname="api.target.local", path_prefix="/api/admin/danger", is_exclusion=True))

    page = ScopePage(scope_manager=scope)
    assert page._table.rowCount() == 2

    # Test allowed URL
    page._url_input.setText("https://api.target.local:443/api/v1/orders")
    page._on_check_scope()
    assert page._result_badge.text() == "IN-SCOPE"
    assert "Permitted" in page._result_text.text()

    # Test excluded URL
    page._url_input.setText("https://api.target.local:443/api/admin/danger/reset")
    page._on_check_scope()
    assert page._result_badge.text() == "OUT-OF-SCOPE"
    assert "Blocked" in page._result_text.text()

    # Test out of scope domain
    page._url_input.setText("https://evil.external.com/leak")
    page._on_check_scope()
    assert page._result_badge.text() == "OUT-OF-SCOPE"


# ============================================================================
# IdentitiesPage Tests
# ============================================================================


def test_identities_page_filtering_and_tabs(qapp: QApplication) -> None:
    page = IdentitiesPage()
    page._identities = [
        {"id": "i-1", "name": "alice_admin", "role_type": "ADMIN", "status": "active", "tags": ["prod", "tier1"]},
        {"id": "i-2", "name": "bob_auditor", "role_type": "READ_ONLY", "status": "active", "tags": ["audit"]},
        {"id": "i-3", "name": "service_bot", "role_type": "AUTHENTICATED", "status": "inactive", "tags": []},
    ]
    page._tenants = [{"id": "t-1", "name": "Acme Org", "description": "Main tenant", "owner_identity_id": "i-1"}]
    page._auth_profiles = [
        {"id": "ap-1", "name": "JWT Auth", "auth_method": "BEARER_TOKEN", "header_name": "Authorization"}
    ]

    page._filter_identities()
    page._populate_tenants()
    page._populate_auth_profiles()

    assert page._ident_table.rowCount() == 3
    assert page._tenant_table.rowCount() == 1
    assert page._auth_table.rowCount() == 1

    # Filter by role
    page._ident_search_bar.set_filter_value("role", "ADMIN")
    page._filter_identities()
    assert page._ident_table.rowCount() == 1

    # Filter by search query
    page._ident_search_bar.set_filter_value("role", "All Roles")
    page._ident_search_bar._search_input.setText("audit")
    page._filter_identities()
    assert page._ident_table.rowCount() == 1
    assert page._ident_table.item(0, 0).text() == "bob_auditor"


# ============================================================================
# ResourcesPage Tests
# ============================================================================


def test_resources_page_filtering(qapp: QApplication) -> None:
    page = ResourcesPage()
    page._resources = [
        {
            "id": "r-1",
            "display_name": "Order 1001",
            "resource_type": "ORDER",
            "external_id": "1001",
            "sensitivity": "restricted",
            "associated_endpoints": ["/api/orders/1001"],
        },
        {
            "id": "r-2",
            "display_name": "Doc Guidelines",
            "resource_type": "DOCUMENT",
            "external_id": "doc-55",
            "sensitivity": "public",
            "associated_endpoints": ["/api/docs/55"],
        },
    ]
    page._apply_filters()
    assert page._table.rowCount() == 2

    # Filter by resource type
    page._search_bar.set_filter_value("type", "ORDER")
    page._apply_filters()
    assert page._table.rowCount() == 1
    assert page._table.item(0, 0).text() == "Order 1001"

    # Filter by sensitivity
    page._search_bar.set_filter_value("type", "All Types")
    page._search_bar.set_filter_value("sensitivity", "PUBLIC")
    page._apply_filters()
    assert page._table.rowCount() == 1
    assert page._table.item(0, 0).text() == "Doc Guidelines"


# ============================================================================
# PoliciesPage Tests
# ============================================================================


def test_policies_page_matrix_and_conflict_detection(qapp: QApplication) -> None:
    page = PoliciesPage()
    page._policies = [
        {
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "Allow Admins Delete Orders",
            "action": "DELETE",
            "expected_decision": "ALLOW",
            "subject_selector": {"role_type": "ADMIN"},
            "resource_selector": {"resource_type": "ORDER"},
            "enabled": True,
        },
        {
            "id": "00000000-0000-0000-0000-000000000002",
            "name": "Deny Admins Delete Orders Contradiction",
            "action": "DELETE",
            "expected_decision": "DENY",
            "subject_selector": {"role_type": "ADMIN"},
            "resource_selector": {"resource_type": "ORDER"},
            "enabled": True,
        },
    ]
    page._apply_filters()
    assert page._table.rowCount() == 2

    # Run conflict detection
    page._on_check_conflicts()
    assert not page._conflict_panel.isHidden()
    assert page._conflict_list.count() == 1
    assert "Conflict 1" in page._conflict_list.item(0).text()
