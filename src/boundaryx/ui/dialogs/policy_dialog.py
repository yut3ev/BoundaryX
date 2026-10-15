"""Policy authoring and editing dialog for BoundaryX.

Provides an interface for specifying authorization boundary rules, subject selectors,
resource selectors, route patterns, expected decisions, and preconditions.
"""

from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from boundaryx.domain.identities.models import RoleType
from boundaryx.domain.policies.models import (
    ExpectedDecision,
    PolicyAction,
    PolicyConfidenceSource,
)
from boundaryx.domain.resources.models import ResourceType
from boundaryx.ui.components.status_badge import StatusBadge
from boundaryx.ui.resources.styles import apply_button_class, apply_label_class
from boundaryx.ui.resources.themes import get_current_palette

logger = logging.getLogger(__name__)


class PolicyDialog(QDialog):
    """Dialog for creating or updating an authorization policy invariant."""

    policy_saved = Signal(dict)

    def __init__(
        self,
        policy_data: dict[str, Any] | None = None,
        identities: list[Any] | None = None,
        tenants: list[Any] | None = None,
        resources: list[Any] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the PolicyDialog.

        Args:
            policy_data: Optional existing policy dictionary or model attributes to edit.
            identities: List of available IdentityModel or dict instances.
            tenants: List of available TenantModel or dict instances.
            resources: List of available ResourceModel or dict instances.
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._is_edit_mode = policy_data is not None
        self._policy_data = policy_data or {}
        self._identities = identities or []
        self._tenants = tenants or []
        self._resources = resources or []

        self.setWindowTitle("Edit Policy Rule" if self._is_edit_mode else "New Authorization Policy")
        self.setMinimumWidth(640)
        self.setModal(True)

        self._init_ui()
        self._load_data()

    def _init_ui(self) -> None:
        """Construct dialog controls and layout."""
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        # Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)

        self._header_title = QLabel("Authorization Policy Rule" if self._is_edit_mode else "New Authorization Policy")
        apply_label_class(self._header_title, "title")
        self._header_title.setStyleSheet("font-size: 18px; font-weight: 700;")

        self._header_sub = QLabel("Define expected access control boundaries between subjects, resources, and actions.")
        apply_label_class(self._header_sub, "subtitle")

        header_layout.addWidget(self._header_title)
        header_layout.addWidget(self._header_sub)
        layout.addLayout(header_layout)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background-color: {palette.border}; max-height: 1px;")
        layout.addWidget(sep)

        # Policy Info
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_layout.setSpacing(10)

        # Name
        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("e.g. Standard Users Cannot Delete Invoices")
        form_layout.addRow("Policy Name *:", self._name_input)

        # Description
        self._desc_input = QLineEdit()
        self._desc_input.setPlaceholderText("Business logic rule or compliance requirement...")
        form_layout.addRow("Description:", self._desc_input)

        layout.addLayout(form_layout)

        # Subject Selector Group
        subj_group = QGroupBox("Subject Selector (Who does this rule apply to?)")
        subj_layout = QFormLayout(subj_group)
        subj_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        subj_layout.setSpacing(10)

        # Subject Role
        self._subj_role_combo = QComboBox()
        self._subj_role_combo.addItem("(Any Role / Wildcard)", None)
        for r in RoleType:
            self._subj_role_combo.addItem(r.value, r.value)
        subj_layout.addRow("By Role:", self._subj_role_combo)

        # Subject Identity
        self._subj_ident_combo = QComboBox()
        self._subj_ident_combo.addItem("(Any Identity / Wildcard)", None)
        for ident in self._identities:
            i_id = getattr(ident, "id", None) or (ident.get("id") if isinstance(ident, dict) else str(ident))
            i_name = getattr(ident, "name", None) or (ident.get("name") if isinstance(ident, dict) else str(ident))
            self._subj_ident_combo.addItem(str(i_name), str(i_id) if i_id else None)
        subj_layout.addRow("By Identity:", self._subj_ident_combo)

        # Subject Tenant
        self._subj_tenant_combo = QComboBox()
        self._subj_tenant_combo.addItem("(Any Tenant / Wildcard)", None)
        for t in self._tenants:
            t_id = getattr(t, "id", None) or (t.get("id") if isinstance(t, dict) else str(t))
            t_name = getattr(t, "name", None) or (t.get("name") if isinstance(t, dict) else str(t))
            self._subj_tenant_combo.addItem(str(t_name), str(t_id) if t_id else None)
        subj_layout.addRow("By Tenant:", self._subj_tenant_combo)

        layout.addWidget(subj_group)

        # Resource Selector Group
        res_group = QGroupBox("Resource Selector (What asset is being targeted?)")
        res_layout = QFormLayout(res_group)
        res_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        res_layout.setSpacing(10)

        # Resource Type
        self._res_type_combo = QComboBox()
        self._res_type_combo.addItem("(Any Resource Type / Wildcard)", None)
        for rt in ResourceType:
            self._res_type_combo.addItem(rt.value, rt.value)
        res_layout.addRow("Resource Type:", self._res_type_combo)

        # Specific Resource
        self._res_item_combo = QComboBox()
        self._res_item_combo.addItem("(Any Resource Object / Wildcard)", None)
        for res in self._resources:
            r_id = getattr(res, "id", None) or (res.get("id") if isinstance(res, dict) else str(res))
            r_name = getattr(res, "display_name", None) or (
                res.get("display_name") if isinstance(res, dict) else str(res)
            )
            self._res_item_combo.addItem(str(r_name), str(r_id) if r_id else None)
        res_layout.addRow("Specific Resource:", self._res_item_combo)

        # Endpoint Pattern
        self._endpoint_pattern_input = QLineEdit()
        self._endpoint_pattern_input.setPlaceholderText("e.g. /api/v1/orders/*, /admin/*, or *")
        res_layout.addRow("Route Pattern:", self._endpoint_pattern_input)

        layout.addWidget(res_group)

        # Action & Expected Decision Group
        decision_group = QGroupBox("Authorization Expectation & Action")
        dec_layout = QFormLayout(decision_group)
        dec_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        dec_layout.setSpacing(10)

        # Action
        self._action_combo = QComboBox()
        for action in PolicyAction:
            self._action_combo.addItem(action.value, action.value)
        dec_layout.addRow("Action *:", self._action_combo)

        # Expected Decision
        dec_row_layout = QHBoxLayout()
        self._decision_combo = QComboBox()
        self._decision_combo.addItem(ExpectedDecision.ALLOW.value, ExpectedDecision.ALLOW.value)
        self._decision_combo.addItem(ExpectedDecision.DENY.value, ExpectedDecision.DENY.value)
        self._decision_badge = StatusBadge("ALLOW", variant="ALLOW")
        self._decision_combo.currentTextChanged.connect(self._on_decision_changed)

        dec_row_layout.addWidget(self._decision_combo, 1)
        dec_row_layout.addWidget(self._decision_badge)
        dec_layout.addRow("Expected Decision *:", dec_row_layout)

        # Preconditions
        self._preconditions_input = QLineEdit()
        self._preconditions_input.setPlaceholderText("e.g. resource.owner == identity.id")
        dec_layout.addRow("Preconditions:", self._preconditions_input)

        # Confidence Source
        self._source_combo = QComboBox()
        for src in PolicyConfidenceSource:
            self._source_combo.addItem(src.value, src.value)
        self._source_combo.setCurrentText(PolicyConfidenceSource.USER_DEFINED.value)
        dec_layout.addRow("Confidence Source:", self._source_combo)

        layout.addWidget(decision_group)

        # Evidence Notes & Enabled
        meta_layout = QFormLayout()
        meta_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        meta_layout.setSpacing(10)

        self._notes_input = QTextEdit()
        self._notes_input.setPlaceholderText("Evidence justification, specification docs reference, test comments...")
        self._notes_input.setMaximumHeight(60)
        meta_layout.addRow("Evidence Notes:", self._notes_input)

        self._enabled_check = QCheckBox("Enable this policy for authorization matrix evaluation")
        self._enabled_check.setChecked(True)
        meta_layout.addRow("", self._enabled_check)

        layout.addLayout(meta_layout)

        # Error display label
        self._error_label = QLabel()
        self._error_label.setStyleSheet(f"color: {palette.danger}; font-size: 12px; font-weight: 600;")
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        # Buttons
        button_box = QDialogButtonBox()
        self._save_button = button_box.addButton(
            "Save Policy" if self._is_edit_mode else "Add Policy",
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

    def _on_decision_changed(self, text: str) -> None:
        """Update decision badge styling."""
        self._decision_badge.setText(text)
        self._decision_badge._variant = text
        self._decision_badge._apply_style()

    def _load_data(self) -> None:
        """Populate form with existing policy attributes."""
        if not self._is_edit_mode:
            return

        name = self._policy_data.get("name", "")
        desc = self._policy_data.get("description", "") or ""
        action = self._policy_data.get("action", "READ")
        decision = self._policy_data.get("expected_decision", "ALLOW")
        source = self._policy_data.get("confidence_source", "USER_DEFINED")
        notes = self._policy_data.get("evidence_notes", "") or ""
        enabled = self._policy_data.get("enabled", True)

        subj = self._policy_data.get("subject_selector", {}) or {}
        res = self._policy_data.get("resource_selector", {}) or {}
        preconds = self._policy_data.get("preconditions", {}) or {}

        self._name_input.setText(str(name))
        self._desc_input.setText(str(desc))

        # Select action
        idx = self._action_combo.findText(str(action).upper())
        if idx >= 0:
            self._action_combo.setCurrentIndex(idx)

        # Select decision
        idx = self._decision_combo.findText(str(decision).upper())
        if idx >= 0:
            self._decision_combo.setCurrentIndex(idx)
        self._on_decision_changed(self._decision_combo.currentText())

        # Select source
        idx = self._source_combo.findText(str(source).upper())
        if idx >= 0:
            self._source_combo.setCurrentIndex(idx)

        # Subject role
        s_role = subj.get("role_type")
        if s_role:
            idx = self._subj_role_combo.findText(str(s_role).upper())
            if idx >= 0:
                self._subj_role_combo.setCurrentIndex(idx)

        # Subject identity
        s_ident = subj.get("identity_id")
        if s_ident:
            for i in range(self._subj_ident_combo.count()):
                if self._subj_ident_combo.itemData(i) == str(s_ident):
                    self._subj_ident_combo.setCurrentIndex(i)
                    break

        # Subject tenant
        s_tenant = subj.get("tenant_id")
        if s_tenant:
            for i in range(self._subj_tenant_combo.count()):
                if self._subj_tenant_combo.itemData(i) == str(s_tenant):
                    self._subj_tenant_combo.setCurrentIndex(i)
                    break

        # Resource type
        r_type = res.get("resource_type")
        if r_type:
            idx = self._res_type_combo.findText(str(r_type).upper())
            if idx >= 0:
                self._res_type_combo.setCurrentIndex(idx)

        # Resource ID
        r_id = res.get("resource_id")
        if r_id:
            for i in range(self._res_item_combo.count()):
                if self._res_item_combo.itemData(i) == str(r_id):
                    self._res_item_combo.setCurrentIndex(i)
                    break

        # Endpoint pattern
        ep_pat = res.get("endpoint_pattern", "")
        self._endpoint_pattern_input.setText(str(ep_pat) if ep_pat else "")

        # Preconditions
        if isinstance(preconds, dict):
            # Formulate text representation
            exprs = [f"{k} == {v}" for k, v in preconds.items()]
            self._preconditions_input.setText("; ".join(exprs))
        elif isinstance(preconds, list):
            self._preconditions_input.setText("; ".join(str(p) for p in preconds))
        elif isinstance(preconds, str):
            self._preconditions_input.setText(preconds)

        self._notes_input.setPlainText(str(notes))
        self._enabled_check.setChecked(bool(enabled))

    def _validate_and_accept(self) -> None:
        """Validate required fields before accepting."""
        name = self._name_input.text().strip()
        if not name:
            self._error_label.setText("Policy name is required.")
            self._error_label.setVisible(True)
            self._name_input.setFocus()
            return

        self._error_label.setVisible(False)
        self.policy_saved.emit(self.get_data())
        self.accept()

    def get_data(self) -> dict[str, Any]:
        """Extract structured policy dictionary."""
        subject_selector: dict[str, Any] = {}
        if self._subj_role_combo.currentData():
            subject_selector["role_type"] = self._subj_role_combo.currentData()
        if self._subj_ident_combo.currentData():
            subject_selector["identity_id"] = self._subj_ident_combo.currentData()
        if self._subj_tenant_combo.currentData():
            subject_selector["tenant_id"] = self._subj_tenant_combo.currentData()

        resource_selector: dict[str, Any] = {}
        if self._res_type_combo.currentData():
            resource_selector["resource_type"] = self._res_type_combo.currentData()
        if self._res_item_combo.currentData():
            resource_selector["resource_id"] = self._res_item_combo.currentData()
        if self._endpoint_pattern_input.text().strip():
            resource_selector["endpoint_pattern"] = self._endpoint_pattern_input.text().strip()

        preconditions_text = self._preconditions_input.text().strip()
        preconditions: dict[str, Any] = {}
        if preconditions_text:
            preconditions["expression"] = preconditions_text

        return {
            "name": self._name_input.text().strip(),
            "description": self._desc_input.text().strip() or None,
            "action": self._action_combo.currentText(),
            "expected_decision": self._decision_combo.currentText(),
            "subject_selector": subject_selector,
            "resource_selector": resource_selector,
            "preconditions": preconditions,
            "confidence_source": self._source_combo.currentText(),
            "evidence_notes": self._notes_input.toPlainText().strip() or None,
            "enabled": self._enabled_check.isChecked(),
        }
