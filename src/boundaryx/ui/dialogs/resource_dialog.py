"""Resource creation and management dialog for BoundaryX.

Provides an interface for configuring target resources, sensitivity classifications,
tenant boundaries, identity ownership, and associated route endpoints.
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

from boundaryx.domain.resources.models import ResourceType, SensitivityLevel
from boundaryx.ui.resources.styles import apply_button_class, apply_label_class
from boundaryx.ui.resources.themes import get_current_palette

logger = logging.getLogger(__name__)


class ResourceDialog(QDialog):
    """Dialog for creating or updating an authorization target resource."""

    resource_saved = Signal(dict)

    def __init__(
        self,
        resource_data: dict[str, Any] | None = None,
        identities: list[Any] | None = None,
        tenants: list[Any] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ResourceDialog.

        Args:
            resource_data: Optional existing resource entity attributes to edit.
            identities: List of available IdentityModel or dict objects for ownership selection.
            tenants: List of available TenantModel or dict objects for tenancy selection.
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._is_edit_mode = resource_data is not None
        self._resource_data = resource_data or {}
        self._identities = identities or []
        self._tenants = tenants or []

        self.setWindowTitle("Edit Resource" if self._is_edit_mode else "Add Target Resource")
        self.setMinimumWidth(580)
        self.setModal(True)

        self._init_ui()
        self._load_data()

    def _init_ui(self) -> None:
        """Construct dialog controls and form layout."""
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)

        self._header_title = QLabel("Resource Definition" if self._is_edit_mode else "New Target Resource")
        apply_label_class(self._header_title, "title")
        self._header_title.setStyleSheet("font-size: 18px; font-weight: 700;")

        self._header_sub = QLabel("Define target objects, entities, and route boundaries subject to authorization.")
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

        # Display Name
        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("e.g. User Profile 402, Q3 Financial Report")
        form_layout.addRow("Display Name *:", self._name_input)

        # Resource Type
        self._type_combo = QComboBox()
        for r_type in ResourceType:
            self._type_combo.addItem(r_type.value, r_type.value)
        self._type_combo.currentIndexChanged.connect(self._on_type_changed)
        form_layout.addRow("Resource Type:", self._type_combo)

        # Custom Type Name
        self._custom_type_input = QLineEdit()
        self._custom_type_input.setPlaceholderText("Custom type name (e.g. INVENTORY_ITEM)")
        self._custom_type_input.setEnabled(False)
        form_layout.addRow("Custom Type:", self._custom_type_input)

        # External ID
        self._external_id_input = QLineEdit()
        self._external_id_input.setPlaceholderText("e.g. 1001, doc-98312, inv_55a9")
        form_layout.addRow("External ID *:", self._external_id_input)

        # Owner Identity Dropdown
        self._owner_identity_combo = QComboBox()
        self._owner_identity_combo.addItem("(None / System-Owned)", None)
        for ident in self._identities:
            i_id = getattr(ident, "id", None) or (ident.get("id") if isinstance(ident, dict) else str(ident))
            i_name = getattr(ident, "name", None) or (ident.get("name") if isinstance(ident, dict) else str(ident))
            i_role = getattr(ident, "role_type", "") or (ident.get("role_type", "") if isinstance(ident, dict) else "")
            label = f"{i_name} [{i_role}]" if i_role else str(i_name)
            self._owner_identity_combo.addItem(label, str(i_id) if i_id else None)
        form_layout.addRow("Owner Identity:", self._owner_identity_combo)

        # Owner Tenant Dropdown
        self._owner_tenant_combo = QComboBox()
        self._owner_tenant_combo.addItem("(None / Global Tenant)", None)
        for t in self._tenants:
            t_id = getattr(t, "id", None) or (t.get("id") if isinstance(t, dict) else str(t))
            t_name = getattr(t, "name", None) or (t.get("name") if isinstance(t, dict) else str(t))
            self._owner_tenant_combo.addItem(str(t_name), str(t_id) if t_id else None)
        form_layout.addRow("Owner Tenant:", self._owner_tenant_combo)

        # Sensitivity Classification
        self._sensitivity_combo = QComboBox()
        for sens in SensitivityLevel:
            self._sensitivity_combo.addItem(sens.value, sens.value)
        self._sensitivity_combo.setCurrentText(SensitivityLevel.INTERNAL.value)
        form_layout.addRow("Sensitivity:", self._sensitivity_combo)

        # Associated Endpoints
        self._endpoints_input = QTextEdit()
        self._endpoints_input.setPlaceholderText(
            "Associated endpoints (one route per line, e.g.):\n/api/v1/orders/{id}\n/api/v1/orders/{id}/invoice"
        )
        self._endpoints_input.setMaximumHeight(85)
        form_layout.addRow("Associated Routes:", self._endpoints_input)

        # Tags
        self._tags_input = QLineEdit()
        self._tags_input.setPlaceholderText("Comma-separated tags (e.g. pii, financial, billing)")
        form_layout.addRow("Tags:", self._tags_input)

        # Notes
        self._notes_input = QTextEdit()
        self._notes_input.setPlaceholderText("Resource schema details, parameter names, or testing observations...")
        self._notes_input.setMaximumHeight(70)
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
            "Save Resource" if self._is_edit_mode else "Add Resource",
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

    def _on_type_changed(self, index: int) -> None:
        """Handle resource type selection changes."""
        is_custom = self._type_combo.currentText() == ResourceType.CUSTOM.value
        self._custom_type_input.setEnabled(is_custom)
        if not is_custom:
            self._custom_type_input.clear()

    def _load_data(self) -> None:
        """Populate form with existing resource attributes."""
        if not self._is_edit_mode:
            return

        name = self._resource_data.get("display_name", "")
        r_type = self._resource_data.get("resource_type", "USER_PROFILE")
        custom_type = self._resource_data.get("custom_type_name", "") or ""
        ext_id = self._resource_data.get("external_id", "") or ""
        owner_id = self._resource_data.get("owning_identity_id")
        tenant_id = self._resource_data.get("owning_tenant_id")
        sensitivity = self._resource_data.get("sensitivity", "INTERNAL")
        endpoints = self._resource_data.get("associated_endpoints", [])
        tags = self._resource_data.get("tags", [])
        notes = self._resource_data.get("notes", "") or ""

        self._name_input.setText(str(name))

        # Select type
        idx = self._type_combo.findText(str(r_type).upper())
        if idx >= 0:
            self._type_combo.setCurrentIndex(idx)
        self._custom_type_input.setText(custom_type)
        self._custom_type_input.setEnabled(self._type_combo.currentText() == ResourceType.CUSTOM.value)

        self._external_id_input.setText(str(ext_id))

        # Select owner identity
        if owner_id:
            for i in range(self._owner_identity_combo.count()):
                if self._owner_identity_combo.itemData(i) == str(owner_id):
                    self._owner_identity_combo.setCurrentIndex(i)
                    break

        # Select owner tenant
        if tenant_id:
            for i in range(self._owner_tenant_combo.count()):
                if self._owner_tenant_combo.itemData(i) == str(tenant_id):
                    self._owner_tenant_combo.setCurrentIndex(i)
                    break

        # Select sensitivity
        idx = self._sensitivity_combo.findText(str(sensitivity).upper())
        if idx >= 0:
            self._sensitivity_combo.setCurrentIndex(idx)

        # Endpoints
        if isinstance(endpoints, list):
            self._endpoints_input.setPlainText("\n".join(str(ep) for ep in endpoints))
        elif isinstance(endpoints, str):
            self._endpoints_input.setPlainText(endpoints)

        # Tags
        if isinstance(tags, list):
            self._tags_input.setText(", ".join(str(t) for t in tags))
        elif isinstance(tags, str):
            self._tags_input.setText(tags)

        self._notes_input.setPlainText(notes)

    def _validate_and_accept(self) -> None:
        """Validate required fields before accepting."""
        name = self._name_input.text().strip()
        if not name:
            self._error_label.setText("Display name is required.")
            self._error_label.setVisible(True)
            self._name_input.setFocus()
            return

        ext_id = self._external_id_input.text().strip()
        if not ext_id:
            self._error_label.setText("External ID is required (e.g. resource primary key in HTTP requests).")
            self._error_label.setVisible(True)
            self._external_id_input.setFocus()
            return

        if self._type_combo.currentText() == ResourceType.CUSTOM.value and not self._custom_type_input.text().strip():
            self._error_label.setText("Custom resource type name is required when type is CUSTOM.")
            self._error_label.setVisible(True)
            self._custom_type_input.setFocus()
            return

        self._error_label.setVisible(False)
        self.resource_saved.emit(self.get_data())
        self.accept()

    def get_data(self) -> dict[str, Any]:
        """Extract resource data dictionary."""
        raw_endpoints = self._endpoints_input.toPlainText().strip()
        endpoints = [line.strip() for line in raw_endpoints.splitlines() if line.strip()]

        raw_tags = self._tags_input.text().strip()
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []

        return {
            "display_name": self._name_input.text().strip(),
            "resource_type": self._type_combo.currentText(),
            "custom_type_name": self._custom_type_input.text().strip() or None,
            "external_id": self._external_id_input.text().strip(),
            "owning_identity_id": self._owner_identity_combo.currentData(),
            "owning_tenant_id": self._owner_tenant_combo.currentData(),
            "sensitivity": self._sensitivity_combo.currentText().lower(),
            "associated_endpoints": endpoints,
            "tags": tags,
            "notes": self._notes_input.toPlainText().strip() or None,
        }
