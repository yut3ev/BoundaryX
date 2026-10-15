"""Project creation and configuration dialog for BoundaryX.

Provides a guided interface for defining project metadata, assessment boundaries,
scope presets, and target execution parameters.
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
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from boundaryx.ui.resources.styles import apply_button_class, apply_label_class
from boundaryx.ui.resources.themes import get_current_palette

logger = logging.getLogger(__name__)

SCOPE_PRESETS: list[dict[str, Any]] = [
    {
        "name": "Custom / Manual Configuration",
        "description": "Configure all target hosts, ports, and exclusions manually in Scope Manager.",
        "default_host": "",
        "scheme": "https",
        "port": 443,
    },
    {
        "name": "Standard REST API (HTTPS/443)",
        "description": "Single API gateway or backend service with standard TLS.",
        "default_host": "api.example.com",
        "scheme": "https",
        "port": 443,
    },
    {
        "name": "Multi-Tenant Cloud Platform (*.target.com)",
        "description": "Wildcard tenant subdomains on shared platform domain.",
        "default_host": "*.example.com",
        "scheme": "https",
        "port": 443,
    },
    {
        "name": "Local Development / QA Environment",
        "description": "Local test servers on non-standard ports (e.g. 8080, 8443, 3000).",
        "default_host": "localhost",
        "scheme": "http",
        "port": 8080,
    },
]


class ProjectDialog(QDialog):
    """Dialog for creating a new project or updating existing project settings."""

    project_saved = Signal(dict)

    def __init__(
        self,
        project_data: dict[str, Any] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the project dialog.

        Args:
            project_data: Optional existing project data to edit. If None, create mode is assumed.
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._is_edit_mode = project_data is not None
        self._project_data = project_data or {}

        self.setWindowTitle("Edit Project" if self._is_edit_mode else "Create New Project")
        self.setMinimumWidth(560)
        self.setModal(True)

        self._init_ui()
        self._load_data()

    def _init_ui(self) -> None:
        """Set up the layout and form components."""
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)

        self._header_title = QLabel("Project Settings" if self._is_edit_mode else "New Assessment Project")
        apply_label_class(self._header_title, "title")
        self._header_title.setStyleSheet("font-size: 18px; font-weight: 700;")

        self._header_sub = QLabel("Configure application security testing boundaries and operational defaults.")
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

        # Project Name (Required)
        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("e.g. Acme Corp Core Banking API")
        form_layout.addRow("Project Name *:", self._name_input)

        # Description
        self._desc_input = QTextEdit()
        self._desc_input.setPlaceholderText("Assessment scope, business context, or tester notes...")
        self._desc_input.setMaximumHeight(80)
        form_layout.addRow("Description:", self._desc_input)

        # Target Scope Preset
        self._preset_combo = QComboBox()
        for preset in SCOPE_PRESETS:
            self._preset_combo.addItem(preset["name"], preset)
        self._preset_combo.currentIndexChanged.connect(self._on_preset_changed)
        form_layout.addRow("Scope Preset:", self._preset_combo)

        # Primary Target Host
        self._target_host_input = QLineEdit()
        self._target_host_input.setPlaceholderText("e.g. api.target.local or *.target.com")
        form_layout.addRow("Primary Target Host:", self._target_host_input)

        # Preset info description label
        self._preset_desc_label = QLabel()
        self._preset_desc_label.setWordWrap(True)
        self._preset_desc_label.setStyleSheet(f"color: {palette.text_muted}; font-size: 11px;")
        form_layout.addRow("", self._preset_desc_label)

        # Rate Limit SpinBox
        self._rate_limit_spin = QSpinBox()
        self._rate_limit_spin.setRange(1, 1000)
        self._rate_limit_spin.setValue(10)
        self._rate_limit_spin.setSuffix(" req/s")
        form_layout.addRow("Rate Limit:", self._rate_limit_spin)

        # Request Timeout SpinBox
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 120)
        self._timeout_spin.setValue(15)
        self._timeout_spin.setSuffix(" seconds")
        form_layout.addRow("Request Timeout:", self._timeout_spin)

        layout.addLayout(form_layout)

        # Error display label
        self._error_label = QLabel()
        self._error_label.setStyleSheet(f"color: {palette.danger}; font-size: 12px; font-weight: 600;")
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        # Buttons
        button_box = QDialogButtonBox()
        self._save_button = button_box.addButton(
            "Save Changes" if self._is_edit_mode else "Create Project",
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

        self._on_preset_changed(0)

    def _on_preset_changed(self, index: int) -> None:
        """Update preset description and default target host when preset changes."""
        preset = self._preset_combo.currentData()
        if preset:
            self._preset_desc_label.setText(preset.get("description", ""))
            if not self._is_edit_mode and not self._target_host_input.text():
                self._target_host_input.setText(preset.get("default_host", ""))

    def _load_data(self) -> None:
        """Pre-populate fields if editing an existing project."""
        if not self._is_edit_mode:
            return

        name = self._project_data.get("name", "")
        desc = self._project_data.get("description", "") or ""
        settings = self._project_data.get("settings", {}) or {}

        self._name_input.setText(name)
        self._desc_input.setPlainText(desc)

        preset_name = settings.get("scope_preset", "")
        for idx in range(self._preset_combo.count()):
            if self._preset_combo.itemText(idx) == preset_name:
                self._preset_combo.setCurrentIndex(idx)
                break

        self._target_host_input.setText(settings.get("target_host", ""))
        self._rate_limit_spin.setValue(int(settings.get("rate_limit", 10)))
        self._timeout_spin.setValue(int(settings.get("timeout_seconds", 15)))

    def _validate_and_accept(self) -> None:
        """Validate required fields before accepting the dialog."""
        name = self._name_input.text().strip()
        if not name:
            self._error_label.setText("Project name is required.")
            self._error_label.setVisible(True)
            self._name_input.setFocus()
            return

        self._error_label.setVisible(False)
        self.project_saved.emit(self.get_data())
        self.accept()

    def get_data(self) -> dict[str, Any]:
        """Extract structured project parameters from dialog controls.

        Returns:
            Dictionary containing name, description, and nested settings.
        """
        preset = self._preset_combo.currentData() or {}
        settings = dict(self._project_data.get("settings", {}))
        settings.update(
            {
                "scope_preset": self._preset_combo.currentText(),
                "target_host": self._target_host_input.text().strip(),
                "rate_limit": self._rate_limit_spin.value(),
                "timeout_seconds": self._timeout_spin.value(),
                "preset_scheme": preset.get("scheme", "https"),
                "preset_port": preset.get("port", 443),
            }
        )

        return {
            "name": self._name_input.text().strip(),
            "description": self._desc_input.toPlainText().strip() or None,
            "settings": settings,
        }
