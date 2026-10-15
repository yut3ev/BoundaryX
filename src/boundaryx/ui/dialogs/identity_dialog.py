"""Identity management dialog for BoundaryX.

Provides an interface for provisioning, updating, and categorizing test subjects,
roles, tenant memberships, and authentication configurations.
"""

from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QLabel,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from boundaryx.domain.identities.models import AuthMethod, IdentityStatus, RoleType
from boundaryx.ui.resources.styles import apply_button_class, apply_label_class
from boundaryx.ui.resources.themes import get_current_palette

logger = logging.getLogger(__name__)


class IdentityDialog(QDialog):
    """Dialog for creating or editing an authorization testing subject identity."""

    identity_saved = Signal(dict)

    def __init__(
        self,
        identity_data: dict[str, Any] | None = None,
        tenants: list[Any] | None = None,
        auth_profiles: list[Any] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the IdentityDialog.

        Args:
            identity_data: Optional dictionary or entity attributes of identity to edit.
            tenants: Optional list of available TenantModel or dict objects.
            auth_profiles: Optional list of available AuthenticationProfileModel or dict objects.
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._is_edit_mode = identity_data is not None
        self._identity_data = identity_data or {}
        self._tenants = tenants or []
        self._auth_profiles = auth_profiles or []

        self.setWindowTitle("Edit Identity" if self._is_edit_mode else "Add Subject Identity")
        self.setMinimumWidth(560)
        self.setModal(True)

        self._init_ui()
        self._load_data()

    def _init_ui(self) -> None:
        """Build form layout and controls."""
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)

        self._header_title = QLabel("Identity Profile" if self._is_edit_mode else "New Subject Identity")
        apply_label_class(self._header_title, "title")
        self._header_title.setStyleSheet("font-size: 18px; font-weight: 700;")

        self._header_sub = QLabel("Configure subject identity attributes, role assignment, and tenant scoping.")
        apply_label_class(self._header_sub, "subtitle")

        header_layout.addWidget(self._header_title)
        header_layout.addWidget(self._header_sub)
        layout.addLayout(header_layout)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background-color: {palette.border}; max-height: 1px;")
        layout.addWidget(sep)

        # Form
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_layout.setSpacing(12)

        # Name
        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("e.g. alice@example.com, auditor_user, svc-billing")
        form_layout.addRow("Identity Name *:", self._name_input)

        # Role Type
        self._role_combo = QComboBox()
        for role in RoleType:
            self._role_combo.addItem(role.value, role.value)
        self._role_combo.currentIndexChanged.connect(self._on_role_changed)
        form_layout.addRow("Role Type:", self._role_combo)

        # Custom Role Name (only enabled if CUSTOM)
        self._custom_role_input = QLineEdit()
        self._custom_role_input.setPlaceholderText("Specify custom role name...")
        self._custom_role_input.setEnabled(False)
        form_layout.addRow("Custom Role:", self._custom_role_input)

        # Operational Status
        self._status_combo = QComboBox()
        for status in IdentityStatus:
            self._status_combo.addItem(status.value, status.value)
        form_layout.addRow("Status:", self._status_combo)

        # Tenant Selection
        self._tenant_combo = QComboBox()
        self._tenant_combo.addItem("(None / Global Tenant)", None)
        for t in self._tenants:
            t_id = getattr(t, "id", None) or t.get("id") if isinstance(t, dict) else str(t)
            t_name = getattr(t, "name", None) or (t.get("name") if isinstance(t, dict) else str(t))
            self._tenant_combo.addItem(
                f"{t_name} ({str(t_id)[:8]})" if t_id else str(t_name), str(t_id) if t_id else None
            )
        form_layout.addRow("Tenant Scope:", self._tenant_combo)

        # Auth Profile / Auth Method
        self._auth_combo = QComboBox()
        self._auth_combo.addItem("(Default / Inherit)", None)
        if self._auth_profiles:
            for ap in self._auth_profiles:
                ap_id = getattr(ap, "id", None) or (ap.get("id") if isinstance(ap, dict) else str(ap))
                ap_name = getattr(ap, "name", None) or (ap.get("name") if isinstance(ap, dict) else str(ap))
                ap_method = getattr(ap, "auth_method", None) or (ap.get("auth_method") if isinstance(ap, dict) else "")
                label = f"{ap_name} [{ap_method}]" if ap_method else str(ap_name)
                self._auth_combo.addItem(label, str(ap_id) if ap_id else None)
        else:
            for method in AuthMethod:
                self._auth_combo.addItem(f"Standard {method.value}", method.value)
        form_layout.addRow("Auth Profile / Method:", self._auth_combo)

        # Tags
        self._tags_input = QLineEdit()
        self._tags_input.setPlaceholderText("Comma-separated tags (e.g. tier1, qa, unprivileged)")
        form_layout.addRow("Tags:", self._tags_input)

        # Notes
        self._notes_input = QTextEdit()
        self._notes_input.setPlaceholderText("Subject credentials reference, test notes, or persona description...")
        self._notes_input.setMaximumHeight(80)
        form_layout.addRow("Notes:", self._notes_input)

        layout.addLayout(form_layout)

        # Error display label
        self._error_label = QLabel()
        self._error_label.setStyleSheet(f"color: {palette.danger}; font-size: 12px; font-weight: 600;")
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        # Buttons
        button_box = QDialogButtonBox()
        self._save_button = button_box.addButton(
            "Save Identity" if self._is_edit_mode else "Add Identity",
            QDialogButtonBox.ButtonRole.AcceptRole,
        )
        self._cancel_button = button_box.addButton(
            "Cancel",
            QDialogButtonBox.ButtonRole.RejectRole,
        )
        apply_button_class(self._save_button, "primary")
        apply_button_class(self._cancel_button, "secondary")

        button_box.accepted.connect(self._validate_and_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _on_role_changed(self, index: int) -> None:
        """Enable or disable custom role field based on role selection."""
        is_custom = self._role_combo.currentText() == RoleType.CUSTOM.value
        self._custom_role_input.setEnabled(is_custom)
        if not is_custom:
            self._custom_role_input.clear()

    def _load_data(self) -> None:
        """Populate form with existing identity attributes if editing."""
        if not self._is_edit_mode:
            return

        name = self._identity_data.get("name", "")
        role_type = self._identity_data.get("role_type", "AUTHENTICATED")
        custom_role = self._identity_data.get("custom_role_name", "") or ""
        status = self._identity_data.get("status", "ACTIVE")
        tenant_id = self._identity_data.get("tenant_id") or (
            self._identity_data.get("tenant_ids", [None])[0] if self._identity_data.get("tenant_ids") else None
        )
        auth_profile_id = self._identity_data.get("auth_profile_id")
        tags = self._identity_data.get("tags", [])
        notes = self._identity_data.get("notes", "") or ""

        self._name_input.setText(str(name))

        # Select role
        idx = self._role_combo.findText(str(role_type).upper())
        if idx >= 0:
            self._role_combo.setCurrentIndex(idx)
        self._custom_role_input.setText(custom_role)
        self._custom_role_input.setEnabled(self._role_combo.currentText() == RoleType.CUSTOM.value)

        # Select status
        idx = self._status_combo.findText(str(status).upper())
        if idx >= 0:
            self._status_combo.setCurrentIndex(idx)

        # Select tenant
        if tenant_id:
            for i in range(self._tenant_combo.count()):
                if self._tenant_combo.itemData(i) == str(tenant_id):
                    self._tenant_combo.setCurrentIndex(i)
                    break

        # Select auth profile
        if auth_profile_id:
            for i in range(self._auth_combo.count()):
                if self._auth_combo.itemData(i) == str(auth_profile_id):
                    self._auth_combo.setCurrentIndex(i)
                    break

        if isinstance(tags, list):
            self._tags_input.setText(", ".join(str(t) for t in tags))
        elif isinstance(tags, str):
            self._tags_input.setText(tags)

        self._notes_input.setPlainText(notes)

    def _validate_and_accept(self) -> None:
        """Validate form inputs."""
        name = self._name_input.text().strip()
        if not name:
            self._error_label.setText("Identity name is required.")
            self._error_label.setVisible(True)
            self._name_input.setFocus()
            return

        if self._role_combo.currentText() == RoleType.CUSTOM.value and not self._custom_role_input.text().strip():
            self._error_label.setText("Custom role name is required when Role Type is CUSTOM.")
            self._error_label.setVisible(True)
            self._custom_role_input.setFocus()
            return

        self._error_label.setVisible(False)
        self.identity_saved.emit(self.get_data())
        self.accept()

    def get_data(self) -> dict[str, Any]:
        """Extract identity data dictionary."""
        raw_tags = self._tags_input.text().strip()
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []

        selected_tenant = self._tenant_combo.currentData()
        tenant_ids = [selected_tenant] if selected_tenant else []

        return {
            "name": self._name_input.text().strip(),
            "role_type": self._role_combo.currentText(),
            "custom_role_name": self._custom_role_input.text().strip() or None,
            "status": self._status_combo.currentText().lower(),
            "tenant_id": selected_tenant,
            "tenant_ids": tenant_ids,
            "auth_profile_id": self._auth_combo.currentData(),
            "tags": tags,
            "notes": self._notes_input.toPlainText().strip() or None,
        }
