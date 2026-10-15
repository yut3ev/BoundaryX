"""Widget tests for BoundaryX modal dialogs."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication

from boundaryx.domain.identities.models import RoleType
from boundaryx.domain.policies.models import ExpectedDecision, PolicyAction
from boundaryx.domain.resources.models import ResourceType
from boundaryx.security.scope import ScopeManager, ScopeRule
from boundaryx.ui.dialogs import (
    IdentityDialog,
    PolicyDialog,
    ProjectDialog,
    ResourceDialog,
    TestPreviewDialog,
)


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Fixture providing QApplication for offscreen testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(["-platform", "offscreen"])
    return app


# ============================================================================
# ProjectDialog Tests
# ============================================================================


def test_project_dialog_create_mode(qapp: QApplication) -> None:
    dialog = ProjectDialog()
    assert dialog.windowTitle() == "Create New Project"

    # Initially empty name
    data = dialog.get_data()
    assert data["name"] == ""
    assert data["description"] is None

    # Set name & description
    dialog._name_input.setText("FinTech API Boundary")
    dialog._desc_input.setPlainText("Audit scope for payment microservices")
    dialog._target_host_input.setText("api.fintech.local")

    data = dialog.get_data()
    assert data["name"] == "FinTech API Boundary"
    assert data["description"] == "Audit scope for payment microservices"
    assert data["settings"]["target_host"] == "api.fintech.local"


def test_project_dialog_edit_mode(qapp: QApplication) -> None:
    existing = {
        "id": "proj-123",
        "name": "Existing Target",
        "description": "Pre-existing description",
        "settings": {"target_host": "test.target.local", "rate_limit": 25},
    }
    dialog = ProjectDialog(project_data=existing)
    assert dialog.windowTitle() == "Edit Project"
    assert dialog._name_input.text() == "Existing Target"
    assert dialog._desc_input.toPlainText() == "Pre-existing description"
    assert dialog._rate_limit_spin.value() == 25


def test_project_dialog_validation_prevents_empty_name(qapp: QApplication) -> None:
    dialog = ProjectDialog()
    dialog._name_input.setText("   ")
    dialog._validate_and_accept()
    assert not dialog._error_label.isHidden()
    assert "required" in dialog._error_label.text().lower()


# ============================================================================
# IdentityDialog Tests
# ============================================================================


def test_identity_dialog_creation(qapp: QApplication) -> None:
    tenants = [{"id": "t-1", "name": "Tenant Alpha"}]
    auth_profiles = [{"id": "ap-1", "name": "Bearer Admin", "auth_method": "BEARER_TOKEN"}]

    dialog = IdentityDialog(tenants=tenants, auth_profiles=auth_profiles)
    assert dialog.windowTitle() == "Add Subject Identity"

    dialog._name_input.setText("bob_auditor")
    dialog._role_combo.setCurrentText(RoleType.ADMIN.value)
    dialog._tags_input.setText("finance, audit, tier1")
    dialog._notes_input.setPlainText("Testing user with elevated credentials")

    data = dialog.get_data()
    assert data["name"] == "bob_auditor"
    assert data["role_type"] == RoleType.ADMIN.value
    assert data["tags"] == ["finance", "audit", "tier1"]
    assert data["notes"] == "Testing user with elevated credentials"


def test_identity_dialog_custom_role(qapp: QApplication) -> None:
    dialog = IdentityDialog()
    dialog._role_combo.setCurrentText(RoleType.CUSTOM.value)
    assert dialog._custom_role_input.isEnabled()

    dialog._name_input.setText("custom_user")
    dialog._custom_role_input.setText("COMPLIANCE_OFFICER")

    data = dialog.get_data()
    assert data["role_type"] == RoleType.CUSTOM.value
    assert data["custom_role_name"] == "COMPLIANCE_OFFICER"


# ============================================================================
# ResourceDialog Tests
# ============================================================================


def test_resource_dialog_create(qapp: QApplication) -> None:
    dialog = ResourceDialog()
    assert dialog.windowTitle() == "Add Target Resource"

    dialog._name_input.setText("Invoice Entity #992")
    dialog._type_combo.setCurrentText(ResourceType.INVOICE.value)
    dialog._external_id_input.setText("inv_992")
    dialog._endpoints_input.setPlainText("/api/v1/invoices/992\n/api/v1/invoices/992/pdf")
    dialog._tags_input.setText("billing, confidential")

    data = dialog.get_data()
    assert data["display_name"] == "Invoice Entity #992"
    assert data["resource_type"] == ResourceType.INVOICE.value
    assert data["external_id"] == "inv_992"
    assert data["associated_endpoints"] == ["/api/v1/invoices/992", "/api/v1/invoices/992/pdf"]
    assert data["tags"] == ["billing", "confidential"]


def test_resource_dialog_validation(qapp: QApplication) -> None:
    dialog = ResourceDialog()
    dialog._name_input.setText("Resource Without External ID")
    dialog._external_id_input.setText("")
    dialog._validate_and_accept()

    assert not dialog._error_label.isHidden()
    assert "external id" in dialog._error_label.text().lower()


# ============================================================================
# PolicyDialog Tests
# ============================================================================


def test_policy_dialog_create(qapp: QApplication) -> None:
    dialog = PolicyDialog()
    assert dialog.windowTitle() == "New Authorization Policy"

    dialog._name_input.setText("Editors Cannot Delete Invoices")
    dialog._desc_input.setText("Prevents non-admin accounts from deleting invoices")
    dialog._subj_role_combo.setCurrentText(RoleType.EDITOR.value)
    dialog._res_type_combo.setCurrentText(ResourceType.INVOICE.value)
    dialog._endpoint_pattern_input.setText("/api/v1/invoices/*")
    dialog._action_combo.setCurrentText(PolicyAction.DELETE.value)
    dialog._decision_combo.setCurrentText(ExpectedDecision.DENY.value)
    dialog._preconditions_input.setText("user.tier < 3")

    data = dialog.get_data()
    assert data["name"] == "Editors Cannot Delete Invoices"
    assert data["action"] == PolicyAction.DELETE.value
    assert data["expected_decision"] == ExpectedDecision.DENY.value
    assert data["subject_selector"]["role_type"] == RoleType.EDITOR.value
    assert data["resource_selector"]["resource_type"] == ResourceType.INVOICE.value
    assert data["resource_selector"]["endpoint_pattern"] == "/api/v1/invoices/*"
    assert data["preconditions"]["expression"] == "user.tier < 3"
    assert data["enabled"] is True


# ============================================================================
# TestPreviewDialog Tests
# ============================================================================


def test_test_preview_dialog_with_scope_manager(qapp: QApplication) -> None:
    scope = ScopeManager(
        [
            ScopeRule(hostname="api.example.com", scheme="https", port=443),
        ]
    )

    test_cases = [
        {"name": "Get User Profile", "url": "https://api.example.com/users/1", "method": "GET"},
        {"name": "Delete User", "url": "https://api.example.com/users/1", "method": "DELETE"},
        {"name": "Post Payment", "url": "https://api.example.com/pay", "method": "POST"},
        {"name": "Evil Ext Target", "url": "https://evil.external.com/leak", "method": "GET"},
    ]

    dialog = TestPreviewDialog(test_cases=test_cases, scope_manager=scope)

    assert dialog._in_scope_count == 3
    assert dialog._out_of_scope_count == 1
    assert dialog._unsafe_method_count == 2  # DELETE, POST

    executable = dialog.get_executable_test_cases()
    assert len(executable) == 3
    assert all(tc["in_scope"] is True for tc in executable)
