"""Scope Management and Boundary Validation page for BoundaryX.

Provides interactive rule authoring, exclusion definitions, and real-time
URL scope validation using ScopeManager.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from sqlalchemy.orm import Session

from boundaryx.infrastructure.database.repositories import ScopeRuleRepository
from boundaryx.security.scope import ScopeManager, ScopeRule
from boundaryx.ui.components.empty_state import EmptyStateWidget
from boundaryx.ui.components.status_badge import StatusBadge
from boundaryx.ui.resources.styles import apply_button_class, apply_label_class
from boundaryx.ui.resources.themes import get_current_palette

if TYPE_CHECKING:
    from boundaryx.infrastructure.database.manager import DatabaseManager

logger = logging.getLogger(__name__)


class AddScopeRuleDialog(QDialog):
    """Dialog for creating a new authorization scope boundary rule."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the AddScopeRuleDialog."""
        super().__init__(parent)
        self.setWindowTitle("Add Scope Boundary Rule")
        self.setMinimumWidth(500)
        self.setModal(True)
        self._init_ui()

    def _init_ui(self) -> None:
        """Construct rule input controls."""
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header
        header = QLabel("New Scope Boundary Rule")
        apply_label_class(header, "title")
        header.setStyleSheet("font-size: 16px; font-weight: 700;")
        layout.addWidget(header)

        sub = QLabel("Define target hosts, schemes, ports, and excluded paths.")
        apply_label_class(sub, "subtitle")
        layout.addWidget(sub)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setSpacing(10)

        # Rule Action (Inclusion vs Exclusion)
        self._is_exclusion_check = QCheckBox("Mark as Exclusion Rule (Deny-list)")
        self._is_exclusion_check.setToolTip(
            "Exclusion rules take precedence over inclusion rules and strictly block matching targets."
        )
        form.addRow("", self._is_exclusion_check)

        # Hostname (Required)
        self._host_input = QLineEdit()
        self._host_input.setPlaceholderText("e.g. api.target.local, *.target.com, 10.0.0.1")
        form.addRow("Hostname *:", self._host_input)

        # Scheme
        self._scheme_combo = QComboBox()
        self._scheme_combo.addItem("https", "https")
        self._scheme_combo.addItem("http", "http")
        self._scheme_combo.addItem("(Any Scheme)", "")
        form.addRow("Scheme:", self._scheme_combo)

        # Port
        self._port_spin = QSpinBox()
        self._port_spin.setRange(0, 65535)
        self._port_spin.setValue(443)
        self._port_spin.setSpecialValueText("(Default Port)")
        form.addRow("Port:", self._port_spin)

        # Path Prefix
        self._path_prefix_input = QLineEdit()
        self._path_prefix_input.setPlaceholderText("e.g. /api/v1 (leave empty for all paths)")
        form.addRow("Path Prefix:", self._path_prefix_input)

        # Excluded Paths
        self._excluded_paths_input = QLineEdit()
        self._excluded_paths_input.setPlaceholderText("Comma-separated (e.g. /logout, /auth/reset)")
        form.addRow("Excluded Paths:", self._excluded_paths_input)

        # Notes
        self._notes_input = QLineEdit()
        self._notes_input.setPlaceholderText("e.g. Main production gateway, Staging auth server")
        form.addRow("Notes:", self._notes_input)

        layout.addLayout(form)

        # Error label
        self._error_label = QLabel()
        self._error_label.setStyleSheet(f"color: {palette.danger}; font-size: 12px; font-weight: 600;")
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        # Buttons
        button_box = QDialogButtonBox()
        save_btn = button_box.addButton("Add Rule", QDialogButtonBox.ButtonRole.AcceptRole)
        cancel_btn = button_box.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        apply_button_class(save_btn, "primary")
        apply_button_class(cancel_btn, "secondary")

        button_box.accepted.connect(self._validate_and_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _validate_and_accept(self) -> None:
        """Validate hostname is provided."""
        host = self._host_input.text().strip()
        if not host:
            self._error_label.setText("Hostname is required.")
            self._error_label.setVisible(True)
            self._host_input.setFocus()
            return
        self._error_label.setVisible(False)
        self.accept()

    def get_rule_data(self) -> dict[str, Any]:
        """Extract entered ScopeRule attributes."""
        port_val = self._port_spin.value()
        port = port_val if port_val > 0 else None
        scheme = self._scheme_combo.currentData() or None

        raw_excl = self._excluded_paths_input.text().strip()
        excluded_paths = [p.strip() for p in raw_excl.split(",") if p.strip()] if raw_excl else []

        prefix = self._path_prefix_input.text().strip() or None

        return {
            "hostname": self._host_input.text().strip(),
            "port": port,
            "scheme": scheme,
            "path_prefix": prefix,
            "excluded_paths": excluded_paths,
            "is_exclusion": self._is_exclusion_check.isChecked(),
            "notes": self._notes_input.text().strip(),
        }


class ScopePage(QWidget):
    """Target scope configuration and interactive testing page."""

    rules_updated = Signal()

    def __init__(
        self,
        scope_manager: ScopeManager | None = None,
        db_manager: DatabaseManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ScopePage.

        Args:
            scope_manager: Optional ScopeManager instance.
            db_manager: Optional DatabaseManager for database persistence.
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._scope_manager = scope_manager or ScopeManager()
        self._db_manager = db_manager
        self._repo = ScopeRuleRepository()
        self._active_project_id: str | None = None

        self._init_ui()
        self._refresh_rules_table()

    def set_scope_manager(self, scope_manager: ScopeManager) -> None:
        """Attach a new ScopeManager."""
        self._scope_manager = scope_manager
        self._refresh_rules_table()

    def set_project(self, project_id: str | None, session: Session | None = None) -> None:
        """Set active project and load scope rules from database."""
        self._active_project_id = project_id
        if project_id and self._db_manager:
            try:
                with Session(self._db_manager.engine) as s:
                    models = self._repo.list_by_project(session=s, project_id=str(project_id))
                    rules = [
                        ScopeRule(
                            hostname=m.hostname,
                            port=m.port,
                            scheme=m.scheme,
                            path_prefix=m.path_prefix,
                            excluded_paths=list(m.path_exclusions or []),
                            is_exclusion=m.is_excluded,
                            notes=m.notes or "",
                        )
                        for m in models
                    ]
                    self._scope_manager.set_rules(rules)
            except Exception as exc:
                logger.error("Failed to load scope rules for project %s: %s", project_id, exc)

        self._refresh_rules_table()

    def _init_ui(self) -> None:
        """Build scope rules manager and interactive scope verification panel."""
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Header
        header_layout = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        title = QLabel("Target Scope Boundaries")
        apply_label_class(title, "title")
        title.setStyleSheet("font-size: 20px; font-weight: 700;")

        subtitle = QLabel(
            "Enforce strict target network boundaries. All traffic outside these rules is dropped automatically."
        )
        apply_label_class(subtitle, "subtitle")

        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        header_layout.addLayout(title_col, 1)

        # Header Action: Add Rule
        self._btn_add_rule = QPushButton("+ Add Scope Rule")
        apply_button_class(self._btn_add_rule, "primary")
        self._btn_add_rule.clicked.connect(self._on_add_rule)
        header_layout.addWidget(self._btn_add_rule)

        layout.addLayout(header_layout)

        # Rules Manager Card
        rules_frame = QFrame()
        rules_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {palette.surface};
                border: 1px solid {palette.border};
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        rf_layout = QVBoxLayout(rules_frame)
        rf_layout.setContentsMargins(10, 10, 10, 10)
        rf_layout.setSpacing(10)

        # Action bar above table
        tbl_actions = QHBoxLayout()
        self._rules_count_lbl = QLabel("Active Rules: 0")
        self._rules_count_lbl.setStyleSheet(f"font-size: 13px; font-weight: 700; color: {palette.text_primary};")
        tbl_actions.addWidget(self._rules_count_lbl)
        tbl_actions.addStretch()

        self._btn_remove_rule = QPushButton("Remove Rule")
        apply_button_class(self._btn_remove_rule, "danger")
        self._btn_remove_rule.setEnabled(False)
        self._btn_remove_rule.clicked.connect(self._on_remove_rule)
        tbl_actions.addWidget(self._btn_remove_rule)

        self._btn_clear_rules = QPushButton("Clear All")
        apply_button_class(self._btn_clear_rules, "secondary")
        self._btn_clear_rules.clicked.connect(self._on_clear_all)
        tbl_actions.addWidget(self._btn_clear_rules)

        rf_layout.addLayout(tbl_actions)

        # Scope Rules Table
        self._table = QTableWidget()
        self._table.setColumnCount(7)
        self._table.setHorizontalHeaderLabels(
            [
                "Rule Type",
                "Hostname",
                "Port",
                "Scheme",
                "Path Prefix",
                "Excluded Paths",
                "Notes",
            ]
        )
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)

        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)

        rf_layout.addWidget(self._table, 1)

        # Empty State
        self._empty_state = EmptyStateWidget(
            title="No Scope Rules Defined",
            description="Add at least one allowed target hostname to enable security testing requests.",
            icon="🛡️",
            primary_button_text="Add Scope Rule",
            secondary_button_text="",
            parent=self,
        )
        self._empty_state.primary_action_clicked.connect(self._on_add_rule)
        self._empty_state.setVisible(False)
        rf_layout.addWidget(self._empty_state)

        layout.addWidget(rules_frame, 1)

        # Interactive Scope Tester Card
        tester_card = self._build_scope_tester(palette)
        layout.addWidget(tester_card)

    def _build_scope_tester(self, palette: Any) -> QFrame:
        """Construct the interactive 'Test URL Scope' checker card."""
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {palette.surface};
                border: 1px solid {palette.border};
                border-radius: 8px;
                padding: 14px;
            }}
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Title
        title_box = QHBoxLayout()
        title = QLabel("Interactive URL Scope Validator")
        title.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {palette.text_primary};")
        subtitle = QLabel("Verify whether a target URL passes authorization boundary checks.")
        subtitle.setStyleSheet(f"font-size: 12px; color: {palette.text_secondary};")

        title_box.addWidget(title)
        title_box.addSpacing(10)
        title_box.addWidget(subtitle)
        title_box.addStretch()
        layout.addLayout(title_box)

        # Input row
        input_row = QHBoxLayout()
        input_row.setSpacing(10)

        self._url_input = QLineEdit()
        self._url_input.setPlaceholderText("Enter full URL e.g. https://api.target.local:443/api/v1/orders/101")
        self._url_input.returnPressed.connect(self._on_check_scope)
        input_row.addWidget(self._url_input, 1)

        self._btn_check_scope = QPushButton("Check Scope")
        apply_button_class(self._btn_check_scope, "primary")
        self._btn_check_scope.clicked.connect(self._on_check_scope)
        input_row.addWidget(self._btn_check_scope)

        layout.addLayout(input_row)

        # Result display container
        self._result_frame = QFrame()
        self._result_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {palette.card};
                border: 1px solid {palette.border};
                border-radius: 6px;
                padding: 10px;
            }}
        """)
        res_layout = QHBoxLayout(self._result_frame)
        res_layout.setContentsMargins(8, 6, 8, 6)
        res_layout.setSpacing(12)

        self._result_badge = StatusBadge("READY", variant="neutral")
        self._result_text = QLabel("Enter a URL and click 'Check Scope' to test boundary enforcement.")
        self._result_text.setStyleSheet(f"font-size: 12px; color: {palette.text_secondary};")
        self._result_text.setWordWrap(True)

        res_layout.addWidget(self._result_badge)
        res_layout.addWidget(self._result_text, 1)

        layout.addWidget(self._result_frame)
        return frame

    def _refresh_rules_table(self) -> None:
        """Render active scope rules in table."""
        rules = self._scope_manager.get_rules()
        count = len(rules)
        self._rules_count_lbl.setText(f"Active Rules: {count}")

        has_rules = count > 0
        self._table.setVisible(has_rules)
        self._empty_state.setVisible(not has_rules)
        self._btn_clear_rules.setEnabled(has_rules)

        self._table.setRowCount(count)

        for row, rule in enumerate(rules):
            # Rule Type badge
            type_badge = StatusBadge(
                "EXCLUDE" if rule.is_exclusion else "ALLOW",
                variant="DENY" if rule.is_exclusion else "ALLOW",
            )
            cell_widget = QWidget()
            cw_layout = QHBoxLayout(cell_widget)
            cw_layout.setContentsMargins(4, 2, 4, 2)
            cw_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cw_layout.addWidget(type_badge)
            self._table.setCellWidget(row, 0, cell_widget)

            # Hostname
            host_item = QTableWidgetItem(rule.hostname)
            self._table.setItem(row, 1, host_item)

            # Port
            port_str = str(rule.port) if rule.port is not None else "(Any)"
            port_item = QTableWidgetItem(port_str)
            port_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 2, port_item)

            # Scheme
            scheme_str = rule.scheme or "(Any)"
            scheme_item = QTableWidgetItem(scheme_str)
            scheme_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 3, scheme_item)

            # Path prefix
            prefix_str = rule.path_prefix or "/"
            prefix_item = QTableWidgetItem(prefix_str)
            self._table.setItem(row, 4, prefix_item)

            # Excluded paths
            excl_str = ", ".join(rule.excluded_paths) if rule.excluded_paths else "(None)"
            excl_item = QTableWidgetItem(excl_str)
            self._table.setItem(row, 5, excl_item)

            # Notes
            notes_item = QTableWidgetItem(rule.notes or "")
            self._table.setItem(row, 6, notes_item)

        self._on_selection_changed()

    def _on_selection_changed(self) -> None:
        """Update state of Remove Rule button."""
        has_sel = len(self._table.selectionModel().selectedRows()) > 0
        self._btn_remove_rule.setEnabled(has_sel)

    def _on_add_rule(self) -> None:
        """Display Add Scope Rule dialog and persist."""
        dialog = AddScopeRuleDialog(self)
        if dialog.exec() == AddScopeRuleDialog.DialogCode.Accepted:
            data = dialog.get_rule_data()
            rule = ScopeRule(
                hostname=data["hostname"],
                port=data["port"],
                scheme=data["scheme"],
                path_prefix=data["path_prefix"],
                excluded_paths=data["excluded_paths"],
                is_exclusion=data["is_exclusion"],
                notes=data["notes"],
            )
            self._scope_manager.add_rule(rule)

            # Persist if project active
            if self._active_project_id and self._db_manager:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._repo.create(
                            session=session,
                            project_id=str(self._active_project_id),
                            hostname=rule.hostname,
                            port=rule.port,
                            scheme=rule.scheme,
                            path_prefix=rule.path_prefix,
                            path_exclusions=rule.excluded_paths,
                            is_excluded=rule.is_exclusion,
                            notes=rule.notes,
                        )
                        session.commit()
                except Exception as exc:
                    logger.error("Failed to persist scope rule: %s", exc)

            self._refresh_rules_table()
            self.rules_updated.emit()

    def _on_remove_rule(self) -> None:
        """Remove selected scope rule."""
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return

        index = rows[0].row()
        try:
            self._scope_manager.remove_rule(index)

            if self._active_project_id and self._db_manager:
                try:
                    with Session(self._db_manager.engine) as session:
                        # Find matching model and delete
                        models = self._repo.list_by_project(session=session, project_id=str(self._active_project_id))
                        if 0 <= index < len(models):
                            self._repo.delete(session=session, rule_id=str(models[index].id))
                            session.commit()
                except Exception as exc:
                    logger.error("Failed to delete scope rule from database: %s", exc)

            self._refresh_rules_table()
            self.rules_updated.emit()
        except IndexError:
            pass

    def _on_clear_all(self) -> None:
        """Clear all active rules after confirmation."""
        reply = QMessageBox.question(
            self,
            "Clear Scope Rules",
            "Are you sure you want to remove all defined scope boundary rules?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._scope_manager.clear_rules()

        if self._active_project_id and self._db_manager:
            try:
                with Session(self._db_manager.engine) as session:
                    models = self._repo.list_by_project(session=session, project_id=str(self._active_project_id))
                    for m in models:
                        self._repo.delete(session=session, rule_id=str(m.id))
                    session.commit()
            except Exception as exc:
                logger.error("Failed to clear scope rules from database: %s", exc)

        self._refresh_rules_table()
        self.rules_updated.emit()

    def _on_check_scope(self) -> None:
        """Evaluate the entered URL against the active ScopeManager and render exact reasoning."""
        url = self._url_input.text().strip()
        if not url:
            self._result_badge.setText("ERROR")
            self._result_badge._variant = "DANGER"
            self._result_badge._apply_style()
            self._result_text.setText("Please enter a valid URL to validate.")
            return

        is_allowed, reason = self._scope_manager.is_in_scope(url)

        if is_allowed:
            self._result_badge.setText("IN-SCOPE")
            self._result_badge._variant = "ALLOW"
            self._result_badge._apply_style()
            self._result_text.setText(f"<b>Permitted:</b> {reason}")
        else:
            self._result_badge.setText("OUT-OF-SCOPE")
            self._result_badge._variant = "DENY"
            self._result_badge._apply_style()
            self._result_text.setText(f"<b>Blocked:</b> {reason}")
