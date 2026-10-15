"""Authorization Policy Matrix and Conflict Detection page for BoundaryX.

Provides authoring of expected access control invariants, subject/resource selector mapping,
pairwise conflict analysis via PolicyEngine, and rule lifecycle toggling.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from sqlalchemy.orm import Session

from boundaryx.domain.identities.models import RoleType
from boundaryx.domain.policies.engine import PolicyEngine
from boundaryx.domain.policies.models import (
    ExpectedDecision,
    Policy,
    PolicyAction,
    ResourceSelector,
    SubjectSelector,
)
from boundaryx.infrastructure.database.repositories import (
    IdentityRepository,
    PolicyRepository,
    ResourceRepository,
    TenantRepository,
)
from boundaryx.ui.components.empty_state import EmptyStateWidget
from boundaryx.ui.components.search_bar import SearchFilterBar
from boundaryx.ui.components.status_badge import StatusBadge
from boundaryx.ui.dialogs.policy_dialog import PolicyDialog
from boundaryx.ui.resources.styles import apply_button_class, apply_label_class
from boundaryx.ui.resources.themes import get_current_palette

if TYPE_CHECKING:
    from boundaryx.infrastructure.database.manager import DatabaseManager

logger = logging.getLogger(__name__)


class PoliciesPage(QWidget):
    """Authorization policy matrix management and conflict detection page."""

    policy_selected = Signal(str)
    data_changed = Signal()

    def __init__(
        self,
        db_manager: DatabaseManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize PoliciesPage.

        Args:
            db_manager: Optional DatabaseManager instance.
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._db_manager = db_manager
        self._policy_repo = PolicyRepository()
        self._ident_repo = IdentityRepository()
        self._res_repo = ResourceRepository()
        self._tenant_repo = TenantRepository()

        self._active_project_id: str | None = None
        self._policies: list[dict[str, Any]] = []
        self._identities: list[dict[str, Any]] = []
        self._tenants: list[dict[str, Any]] = []
        self._resources: list[dict[str, Any]] = []
        self._filtered_policies: list[dict[str, Any]] = []

        self._engine = PolicyEngine()

        self._init_ui()
        self.refresh_data()

    def set_project(self, project_id: str | None) -> None:
        """Set active project context and reload policies."""
        self._active_project_id = project_id
        self.refresh_data()

    def _init_ui(self) -> None:
        """Build policy matrix layout, search/filters, action bar, table, and conflict drawer."""
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header
        header_layout = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        title = QLabel("Authorization Policy Matrix")
        apply_label_class(title, "title")
        title.setStyleSheet("font-size: 20px; font-weight: 700;")

        subtitle = QLabel(
            "Define expected authorization decisions (ALLOW/DENY) across subjects, resources, and actions."
        )
        apply_label_class(subtitle, "subtitle")

        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        header_layout.addLayout(title_col, 1)

        self._btn_add_top = QPushButton("+ New Policy Rule")
        apply_button_class(self._btn_add_top, "primary")
        self._btn_add_top.clicked.connect(self._on_add_policy)
        header_layout.addWidget(self._btn_add_top)

        layout.addLayout(header_layout)

        # Search & Filter Bar
        self._search_bar = SearchFilterBar(
            placeholder="Search policies by name, subject, resource, pattern...",
            parent=self,
        )
        self._search_bar.add_filter(
            "decision",
            ["All Decisions", "ALLOW", "DENY"],
            "All Decisions",
            min_width=130,
        )
        action_options = ["All Actions"] + [a.value for a in PolicyAction]
        self._search_bar.add_filter(
            "action",
            action_options,
            "All Actions",
            min_width=130,
        )

        self._search_bar.search_changed.connect(self._apply_filters)
        self._search_bar.filter_changed.connect(lambda k, v: self._apply_filters())
        layout.addWidget(self._search_bar)

        # Actions Toolbar
        toolbar = QHBoxLayout()
        self._btn_add = QPushButton("Add Policy")
        apply_button_class(self._btn_add, "primary")
        self._btn_add.clicked.connect(self._on_add_policy)
        toolbar.addWidget(self._btn_add)

        self._btn_edit = QPushButton("Edit")
        apply_button_class(self._btn_edit, "secondary")
        self._btn_edit.setEnabled(False)
        self._btn_edit.clicked.connect(self._on_edit_policy)
        toolbar.addWidget(self._btn_edit)

        self._btn_toggle = QPushButton("Toggle Enabled")
        apply_button_class(self._btn_toggle, "secondary")
        self._btn_toggle.setEnabled(False)
        self._btn_toggle.clicked.connect(self._on_toggle_policy)
        toolbar.addWidget(self._btn_toggle)

        self._btn_delete = QPushButton("Delete")
        apply_button_class(self._btn_delete, "danger")
        self._btn_delete.setEnabled(False)
        self._btn_delete.clicked.connect(self._on_delete_policy)
        toolbar.addWidget(self._btn_delete)

        toolbar.addSpacing(12)

        # Conflict Detection Button
        self._btn_check_conflicts = QPushButton("⚡ Check Policy Conflicts")
        apply_button_class(self._btn_check_conflicts, "secondary")
        self._btn_check_conflicts.clicked.connect(self._on_check_conflicts)
        toolbar.addWidget(self._btn_check_conflicts)

        toolbar.addStretch()
        self._count_lbl = QLabel("0 policies")
        self._count_lbl.setStyleSheet(f"color: {palette.text_muted}; font-size: 12px;")
        toolbar.addWidget(self._count_lbl)

        layout.addLayout(toolbar)

        # Splitter between Table and Conflict Detection Drawer
        self._splitter = QSplitter(Qt.Orientation.Vertical)

        # Table Container
        table_container = QWidget()
        tc_layout = QVBoxLayout(table_container)
        tc_layout.setContentsMargins(0, 0, 0, 0)

        self._table = QTableWidget()
        self._table.setColumnCount(7)
        self._table.setHorizontalHeaderLabels(
            [
                "Policy Rule Name",
                "Subject Selector",
                "Resource Selector",
                "Action",
                "Expected Decision",
                "Confidence Source",
                "Status",
            ]
        )
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)

        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._table.doubleClicked.connect(self._on_edit_policy)

        tc_layout.addWidget(self._table, 1)

        # Empty State
        self._empty_state = EmptyStateWidget(
            title="No Authorization Policies",
            description="Create authorization policy rules defining expected ALLOW and DENY access invariants.",
            icon="📜",
            primary_button_text="Create Policy Rule",
            parent=table_container,
        )
        self._empty_state.primary_action_clicked.connect(self._on_add_policy)
        self._empty_state.setVisible(False)
        tc_layout.addWidget(self._empty_state)

        self._splitter.addWidget(table_container)

        # Conflict Detection Panel
        self._conflict_panel = self._build_conflict_panel(palette)
        self._conflict_panel.setVisible(False)
        self._splitter.addWidget(self._conflict_panel)

        self._splitter.setStretchFactor(0, 3)
        self._splitter.setStretchFactor(1, 1)

        layout.addWidget(self._splitter, 1)

    def _build_conflict_panel(self, palette: Any) -> QFrame:
        """Construct the collapsible conflict inspection drawer."""
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {palette.surface};
                border: 1px solid {palette.border};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(8)

        # Title line
        header = QHBoxLayout()
        title = QLabel("Policy Contradictions & Conflict Analysis")
        title.setStyleSheet(f"font-size: 13px; font-weight: 700; color: {palette.text_primary};")
        header.addWidget(title)
        header.addStretch()

        self._conflict_status_badge = StatusBadge("0 Conflicts", variant="ALLOW")
        header.addWidget(self._conflict_status_badge)

        close_btn = QPushButton("✕ Close")
        apply_button_class(close_btn, "ghost")
        close_btn.setStyleSheet("font-size: 11px; padding: 2px 6px;")
        close_btn.clicked.connect(lambda: self._conflict_panel.setVisible(False))
        header.addWidget(close_btn)

        layout.addLayout(header)

        # Conflict message or list
        self._conflict_list = QListWidget()
        self._conflict_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        self._conflict_list.setMinimumHeight(100)
        layout.addWidget(self._conflict_list, 1)

        return frame

    def refresh_data(self) -> None:
        """Fetch all policies and metadata from DB or cache."""
        if self._db_manager and self._active_project_id:
            try:
                with Session(self._db_manager.engine) as session:
                    # Identities for lookup
                    i_models = self._ident_repo.list_by_project(session, self._active_project_id)
                    self._identities = [{"id": str(i.id), "name": i.name, "role_type": i.role_type} for i in i_models]

                    # Tenants for lookup
                    t_models = self._tenant_repo.list_by_project(session, self._active_project_id)
                    self._tenants = [{"id": str(t.id), "name": t.name} for t in t_models]

                    # Resources for lookup
                    r_models = self._res_repo.list_by_project(session, self._active_project_id)
                    self._resources = [
                        {"id": str(r.id), "display_name": r.display_name, "resource_type": r.resource_type}
                        for r in r_models
                    ]

                    # Policies
                    p_models = self._policy_repo.list_by_project(session, self._active_project_id)
                    self._policies = [
                        {
                            "id": str(p.id),
                            "name": p.name,
                            "description": p.description,
                            "action": p.action,
                            "expected_decision": p.expected_decision,
                            "subject_selector": p.subject_selector or {},
                            "resource_selector": p.resource_selector or {},
                            "preconditions": p.preconditions or {},
                            "confidence_source": p.confidence_source or "USER_DEFINED",
                            "evidence_notes": p.evidence_notes,
                            "enabled": p.enabled,
                        }
                        for p in p_models
                    ]
            except Exception as exc:
                logger.error("Failed to query policies from database: %s", exc)

        self._apply_filters()

    def _apply_filters(self) -> None:
        """Filter policies based on search query, decision, and action."""
        query = self._search_bar.get_search_text().lower().strip()
        decision_filter = self._search_bar.get_filter_value("decision")
        action_filter = self._search_bar.get_filter_value("action")

        filtered = []
        for p in self._policies:
            dec = str(p.get("expected_decision", "ALLOW")).upper()
            act = str(p.get("action", "READ")).upper()

            if decision_filter != "All Decisions" and dec != decision_filter.upper():
                continue
            if action_filter != "All Actions" and act != action_filter.upper():
                continue

            name = str(p.get("name", "")).lower()
            desc = str(p.get("description", "") or "").lower()
            subj_str = str(p.get("subject_selector", {})).lower()
            res_str = str(p.get("resource_selector", {})).lower()

            if query and query not in name and query not in desc and query not in subj_str and query not in res_str:
                continue

            filtered.append(p)

        self._filtered_policies = filtered
        self._populate_table()

    def _format_subject_selector(self, s: dict[str, Any]) -> str:
        """Format human-readable subject selector string."""
        if not s:
            return "(Any Subject / Wildcard)"
        parts = []
        if s.get("role_type"):
            parts.append(f"Role: {s['role_type']}")
        if s.get("identity_id"):
            ident_name = s["identity_id"]
            for i in self._identities:
                if i["id"] == str(s["identity_id"]):
                    ident_name = i["name"]
                    break
            parts.append(f"Identity: {ident_name}")
        if s.get("tenant_id"):
            tenant_name = s["tenant_id"]
            for t in self._tenants:
                if t["id"] == str(s["tenant_id"]):
                    tenant_name = t["name"]
                    break
            parts.append(f"Tenant: {tenant_name}")
        return ", ".join(parts) if parts else "(Any)"

    def _format_resource_selector(self, r: dict[str, Any]) -> str:
        """Format human-readable resource selector string."""
        if not r:
            return "(Any Resource / Wildcard)"
        parts = []
        if r.get("resource_type"):
            parts.append(f"Type: {r['resource_type']}")
        if r.get("resource_id"):
            res_name = r["resource_id"]
            for res in self._resources:
                if res["id"] == str(r["resource_id"]):
                    res_name = res["display_name"]
                    break
            parts.append(f"Resource: {res_name}")
        if r.get("endpoint_pattern"):
            parts.append(f"Route: {r['endpoint_pattern']}")
        return ", ".join(parts) if parts else "(Any)"

    def _populate_table(self) -> None:
        """Render filtered policies into table."""
        count = len(self._filtered_policies)
        self._count_lbl.setText(f"{count} policies")

        has_items = count > 0
        self._table.setVisible(has_items)
        self._empty_state.setVisible(not has_items)

        self._table.setRowCount(count)

        for row, p in enumerate(self._filtered_policies):
            # Name
            name_item = QTableWidgetItem(str(p.get("name", "")))
            name_item.setData(Qt.ItemDataRole.UserRole, p.get("id"))
            self._table.setItem(row, 0, name_item)

            # Subject
            subj_item = QTableWidgetItem(self._format_subject_selector(p.get("subject_selector", {})))
            self._table.setItem(row, 1, subj_item)

            # Resource
            res_item = QTableWidgetItem(self._format_resource_selector(p.get("resource_selector", {})))
            self._table.setItem(row, 2, res_item)

            # Action
            act_item = QTableWidgetItem(str(p.get("action", "")))
            act_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 3, act_item)

            # Expected Decision Badge
            dec = str(p.get("expected_decision", "ALLOW")).upper()
            dec_badge = StatusBadge(dec, variant=dec)
            cell_widget = QWidget()
            cw_layout = QHBoxLayout(cell_widget)
            cw_layout.setContentsMargins(4, 2, 4, 2)
            cw_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cw_layout.addWidget(dec_badge)
            self._table.setCellWidget(row, 4, cell_widget)

            # Confidence Source
            src_item = QTableWidgetItem(str(p.get("confidence_source", "USER_DEFINED")))
            src_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 5, src_item)

            # Status (Enabled/Disabled)
            is_enabled = bool(p.get("enabled", True))
            status_badge = StatusBadge(
                "ENABLED" if is_enabled else "DISABLED",
                variant="ALLOW" if is_enabled else "neutral",
            )
            st_cell = QWidget()
            st_layout = QHBoxLayout(st_cell)
            st_layout.setContentsMargins(4, 2, 4, 2)
            st_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            st_layout.addWidget(status_badge)
            self._table.setCellWidget(row, 6, st_cell)

        self._on_selection_changed()

    def _on_selection_changed(self) -> None:
        """Update toolbar actions based on selection."""
        item = self._get_selected_policy()
        has_sel = item is not None
        self._btn_edit.setEnabled(has_sel)
        self._btn_toggle.setEnabled(has_sel)
        self._btn_delete.setEnabled(has_sel)

        if item:
            enabled = item.get("enabled", True)
            self._btn_toggle.setText("Disable" if enabled else "Enable")
        else:
            self._btn_toggle.setText("Toggle Enabled")

    def _get_selected_policy(self) -> dict[str, Any] | None:
        """Return the dictionary of selected policy."""
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        p_id = self._table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole)
        for p in self._policies:
            if p.get("id") == p_id:
                return p
        return None

    def _on_add_policy(self) -> None:
        """Open PolicyDialog and create policy rule."""
        dialog = PolicyDialog(
            identities=self._identities,
            tenants=self._tenants,
            resources=self._resources,
            parent=self,
        )
        if dialog.exec() == PolicyDialog.DialogCode.Accepted:
            data = dialog.get_data()
            if self._db_manager and self._active_project_id:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._policy_repo.create(
                            session=session,
                            project_id=str(self._active_project_id),
                            name=data["name"],
                            description=data["description"],
                            action=data["action"],
                            expected_decision=data["expected_decision"],
                            subject_selector=data["subject_selector"],
                            resource_selector=data["resource_selector"],
                            preconditions=data["preconditions"],
                            confidence_source=data["confidence_source"],
                            evidence_notes=data["evidence_notes"],
                            enabled=data["enabled"],
                        )
                        session.commit()
                except Exception as exc:
                    QMessageBox.critical(self, "Database Error", f"Failed to create policy: {exc}")
                    return
            else:
                import uuid

                data["id"] = str(uuid.uuid4())
                self._policies.append(data)

            self.refresh_data()
            self.data_changed.emit()

    def _on_edit_policy(self) -> None:
        """Open PolicyDialog to edit selected policy."""
        policy = self._get_selected_policy()
        if not policy:
            return

        dialog = PolicyDialog(
            policy_data=policy,
            identities=self._identities,
            tenants=self._tenants,
            resources=self._resources,
            parent=self,
        )
        if dialog.exec() == PolicyDialog.DialogCode.Accepted:
            data = dialog.get_data()
            p_id = policy["id"]
            if self._db_manager and self._active_project_id:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._policy_repo.update(
                            session=session,
                            policy_id=str(p_id),
                            name=data["name"],
                            description=data["description"],
                            action=data["action"],
                            expected_decision=data["expected_decision"],
                            subject_selector=data["subject_selector"],
                            resource_selector=data["resource_selector"],
                            preconditions=data["preconditions"],
                            confidence_source=data["confidence_source"],
                            evidence_notes=data["evidence_notes"],
                            enabled=data["enabled"],
                        )
                        session.commit()
                except Exception as exc:
                    QMessageBox.critical(self, "Update Error", f"Failed to update policy: {exc}")
                    return
            else:
                policy.update(data)

            self.refresh_data()
            self.data_changed.emit()

    def _on_toggle_policy(self) -> None:
        """Toggle enabled status of selected policy."""
        policy = self._get_selected_policy()
        if not policy:
            return

        p_id = policy["id"]
        new_state = not policy.get("enabled", True)

        if self._db_manager and self._active_project_id:
            try:
                with Session(self._db_manager.engine) as session:
                    self._policy_repo.update(session=session, policy_id=str(p_id), enabled=new_state)
                    session.commit()
            except Exception as exc:
                QMessageBox.critical(self, "Update Error", f"Failed to toggle policy: {exc}")
                return
        else:
            policy["enabled"] = new_state

        self.refresh_data()
        self.data_changed.emit()

    def _on_delete_policy(self) -> None:
        """Delete selected policy rule after confirmation."""
        policy = self._get_selected_policy()
        if not policy:
            return

        name = policy.get("name", "Unknown")
        reply = QMessageBox.question(
            self,
            "Confirm Policy Deletion",
            f"Are you sure you want to delete policy rule '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        p_id = policy["id"]
        if self._db_manager and self._active_project_id:
            try:
                with Session(self._db_manager.engine) as session:
                    self._policy_repo.delete(session=session, policy_id=str(p_id))
                    session.commit()
            except Exception as exc:
                QMessageBox.critical(self, "Delete Error", f"Failed to delete policy: {exc}")
                return
        else:
            self._policies = [p for p in self._policies if p.get("id") != p_id]

        self.refresh_data()
        self.data_changed.emit()

    def _on_check_conflicts(self) -> None:
        """Run PolicyEngine.detect_conflicts across enabled policies and display in panel."""
        domain_policies: list[Policy] = []
        for p in self._policies:
            try:
                subj = SubjectSelector(
                    identity_id=UUID(str(p["subject_selector"]["identity_id"]))
                    if p.get("subject_selector", {}).get("identity_id")
                    else None,
                    role_type=RoleType(str(p["subject_selector"]["role_type"]).upper())
                    if p.get("subject_selector", {}).get("role_type")
                    else None,
                    tenant_id=UUID(str(p["subject_selector"]["tenant_id"]))
                    if p.get("subject_selector", {}).get("tenant_id")
                    else None,
                )
                res = ResourceSelector(
                    resource_id=UUID(str(p["resource_selector"]["resource_id"]))
                    if p.get("resource_selector", {}).get("resource_id")
                    else None,
                    resource_type=p.get("resource_selector", {}).get("resource_type") or None,
                    endpoint_pattern=p.get("resource_selector", {}).get("endpoint_pattern") or None,
                )
                domain_p = Policy(
                    id=UUID(str(p["id"])) if "id" in p else UUID(int=0),
                    project_id=UUID(str(self._active_project_id)) if self._active_project_id else UUID(int=0),
                    name=p.get("name", ""),
                    action=PolicyAction(str(p.get("action", "READ")).upper()),
                    expected_decision=ExpectedDecision(str(p.get("expected_decision", "ALLOW")).upper()),
                    subject_selector=subj,
                    resource_selector=res,
                    enabled=bool(p.get("enabled", True)),
                )
                domain_policies.append(domain_p)
            except Exception as exc:
                logger.warning("Could not convert policy '%s' to domain model: %s", p.get("name"), exc)

        conflicts = self._engine.detect_conflicts(domain_policies)

        self._conflict_panel.setVisible(True)
        self._conflict_list.clear()

        if not conflicts:
            self._conflict_status_badge.setText("0 Conflicts (Clean)")
            self._conflict_status_badge._variant = "ALLOW"
            self._conflict_status_badge._apply_style()

            item = QListWidgetItem("✅ No contradictory policy rules detected across active policy definitions.")
            self._conflict_list.addItem(item)
        else:
            self._conflict_status_badge.setText(f"{len(conflicts)} Conflicts Detected")
            self._conflict_status_badge._variant = "DENY"
            self._conflict_status_badge._apply_style()

            for idx, c in enumerate(conflicts):
                item_text = f"⚠️ [Conflict {idx + 1}] {c.description}"
                item = QListWidgetItem(item_text)
                self._conflict_list.addItem(item)
