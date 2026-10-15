"""Target Resources management page for BoundaryX.

Provides inventory modeling for sensitive assets, objects, data entities,
and route endpoints evaluated against authorization boundaries.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from sqlalchemy.orm import Session

from boundaryx.domain.resources.models import ResourceType, SensitivityLevel
from boundaryx.infrastructure.database.repositories import (
    IdentityRepository,
    ResourceRepository,
    TenantRepository,
)
from boundaryx.ui.components.empty_state import EmptyStateWidget
from boundaryx.ui.components.search_bar import SearchFilterBar
from boundaryx.ui.components.status_badge import StatusBadge
from boundaryx.ui.dialogs.resource_dialog import ResourceDialog
from boundaryx.ui.resources.styles import apply_button_class, apply_label_class
from boundaryx.ui.resources.themes import get_current_palette

if TYPE_CHECKING:
    from boundaryx.infrastructure.database.manager import DatabaseManager

logger = logging.getLogger(__name__)


class ResourcesPage(QWidget):
    """Target resources and endpoint boundaries inventory page."""

    resource_selected = Signal(str)
    data_changed = Signal()

    def __init__(
        self,
        db_manager: DatabaseManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize ResourcesPage.

        Args:
            db_manager: Optional DatabaseManager instance.
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._db_manager = db_manager
        self._res_repo = ResourceRepository()
        self._ident_repo = IdentityRepository()
        self._tenant_repo = TenantRepository()

        self._active_project_id: str | None = None
        self._resources: list[dict[str, Any]] = []
        self._identities: list[dict[str, Any]] = []
        self._tenants: list[dict[str, Any]] = []
        self._filtered_resources: list[dict[str, Any]] = []

        self._init_ui()
        self.refresh_data()

    def set_project(self, project_id: str | None) -> None:
        """Set active project context and reload resources."""
        self._active_project_id = project_id
        self.refresh_data()

    def _init_ui(self) -> None:
        """Build page layout, search/filters, action bar, and table."""
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header
        header_layout = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        title = QLabel("Target Resources & Entities")
        apply_label_class(title, "title")
        title.setStyleSheet("font-size: 20px; font-weight: 700;")

        subtitle = QLabel(
            "Catalog objects, database entities, and API route templates tested under authorization rules."
        )
        apply_label_class(subtitle, "subtitle")

        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        header_layout.addLayout(title_col, 1)

        self._btn_add_top = QPushButton("+ Add Resource")
        apply_button_class(self._btn_add_top, "primary")
        self._btn_add_top.clicked.connect(self._on_add_resource)
        header_layout.addWidget(self._btn_add_top)

        layout.addLayout(header_layout)

        # Search & Filter Bar
        self._search_bar = SearchFilterBar(
            placeholder="Search resources by name, external ID, endpoint...",
            parent=self,
        )
        type_options = ["All Types"] + [t.value for t in ResourceType]
        self._search_bar.add_filter("type", type_options, "All Types", min_width=140)

        sens_options = ["All Sensitivities"] + [s.value for s in SensitivityLevel]
        self._search_bar.add_filter("sensitivity", sens_options, "All Sensitivities", min_width=140)

        self._search_bar.search_changed.connect(self._apply_filters)
        self._search_bar.filter_changed.connect(lambda k, v: self._apply_filters())
        layout.addWidget(self._search_bar)

        # Actions Toolbar
        toolbar = QHBoxLayout()
        self._btn_add = QPushButton("Add Resource")
        apply_button_class(self._btn_add, "primary")
        self._btn_add.clicked.connect(self._on_add_resource)
        toolbar.addWidget(self._btn_add)

        self._btn_edit = QPushButton("Edit")
        apply_button_class(self._btn_edit, "secondary")
        self._btn_edit.setEnabled(False)
        self._btn_edit.clicked.connect(self._on_edit_resource)
        toolbar.addWidget(self._btn_edit)

        self._btn_delete = QPushButton("Delete")
        apply_button_class(self._btn_delete, "danger")
        self._btn_delete.setEnabled(False)
        self._btn_delete.clicked.connect(self._on_delete_resource)
        toolbar.addWidget(self._btn_delete)

        toolbar.addStretch()
        self._count_lbl = QLabel("0 resources")
        self._count_lbl.setStyleSheet(f"color: {palette.text_muted}; font-size: 12px;")
        toolbar.addWidget(self._count_lbl)

        layout.addLayout(toolbar)

        # Resources Table
        self._table = QTableWidget()
        self._table.setColumnCount(7)
        self._table.setHorizontalHeaderLabels(
            [
                "Display Name",
                "Type",
                "External ID",
                "Owning Tenant",
                "Owning Identity",
                "Sensitivity",
                "Associated Endpoints",
            ]
        )
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._table.doubleClicked.connect(self._on_edit_resource)

        layout.addWidget(self._table, 1)

        # Empty State
        self._empty_state = EmptyStateWidget(
            title="No Resources Defined",
            description="Add application entities (e.g. Orders, Documents, User Profiles) and their HTTP endpoints to construct authorization test matrices.",
            icon="📦",
            primary_button_text="Add Resource",
            parent=self,
        )
        self._empty_state.primary_action_clicked.connect(self._on_add_resource)
        self._empty_state.setVisible(False)
        layout.addWidget(self._empty_state)

    def refresh_data(self) -> None:
        """Fetch all resources, identities, and tenants from DB or cache."""
        if self._db_manager and self._active_project_id:
            try:
                with Session(self._db_manager.engine) as session:
                    # Identities for lookup
                    i_models = self._ident_repo.list_by_project(session, self._active_project_id)
                    self._identities = [{"id": str(i.id), "name": i.name, "role_type": i.role_type} for i in i_models]

                    # Tenants for lookup
                    t_models = self._tenant_repo.list_by_project(session, self._active_project_id)
                    self._tenants = [{"id": str(t.id), "name": t.name} for t in t_models]

                    # Resources
                    r_models = self._res_repo.list_by_project(session, self._active_project_id)
                    self._resources = [
                        {
                            "id": str(r.id),
                            "display_name": r.display_name,
                            "resource_type": r.resource_type,
                            "custom_type_name": r.custom_type_name,
                            "external_id": r.external_id,
                            "owning_identity_id": r.owning_identity_id,
                            "owning_tenant_id": r.owning_tenant_id,
                            "sensitivity": r.sensitivity,
                            "associated_endpoints": list(r.associated_endpoints or []),
                            "tags": list(r.tags or []),
                            "notes": r.notes,
                        }
                        for r in r_models
                    ]
            except Exception as exc:
                logger.error("Failed to query resources from database: %s", exc)

        self._apply_filters()

    def _apply_filters(self) -> None:
        """Filter resources based on search query and type/sensitivity dropdowns."""
        query = self._search_bar.get_search_text().lower().strip()
        type_filter = self._search_bar.get_filter_value("type")
        sens_filter = self._search_bar.get_filter_value("sensitivity")

        filtered = []
        for res in self._resources:
            r_type = res.get("resource_type", "USER_PROFILE")
            sens = res.get("sensitivity", "INTERNAL")

            if type_filter != "All Types" and r_type.upper() != type_filter.upper():
                continue
            if sens_filter != "All Sensitivities" and sens.upper() != sens_filter.upper():
                continue

            name = str(res.get("display_name", "")).lower()
            ext_id = str(res.get("external_id", "") or "").lower()
            endpoints = " ".join(res.get("associated_endpoints", [])).lower()

            if query and query not in name and query not in ext_id and query not in endpoints:
                continue

            filtered.append(res)

        self._filtered_resources = filtered
        self._populate_table()

    def _populate_table(self) -> None:
        """Render filtered resources into table."""
        count = len(self._filtered_resources)
        self._count_lbl.setText(f"{count} resources")

        has_items = count > 0
        self._table.setVisible(has_items)
        self._empty_state.setVisible(not has_items)

        self._table.setRowCount(count)

        ident_map = {i["id"]: i["name"] for i in self._identities}
        tenant_map = {t["id"]: t["name"] for t in self._tenants}

        for row, res in enumerate(self._filtered_resources):
            # Display Name
            name_item = QTableWidgetItem(str(res.get("display_name", "")))
            name_item.setData(Qt.ItemDataRole.UserRole, res.get("id"))
            self._table.setItem(row, 0, name_item)

            # Type
            t_str = res.get("custom_type_name") or res.get("resource_type", "")
            type_item = QTableWidgetItem(str(t_str))
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 1, type_item)

            # External ID
            ext_item = QTableWidgetItem(str(res.get("external_id", "") or ""))
            self._table.setItem(row, 2, ext_item)

            # Owning Tenant
            t_id = res.get("owning_tenant_id")
            tenant_name = tenant_map.get(t_id, "(Global)") if t_id else "(Global)"
            tenant_item = QTableWidgetItem(tenant_name)
            self._table.setItem(row, 3, tenant_item)

            # Owning Identity
            o_id = res.get("owning_identity_id")
            owner_name = ident_map.get(o_id, "(System)") if o_id else "(System)"
            owner_item = QTableWidgetItem(owner_name)
            self._table.setItem(row, 4, owner_item)

            # Sensitivity Badge
            sens = str(res.get("sensitivity", "INTERNAL")).upper()
            sens_badge = StatusBadge(sens, variant=sens)
            cell_widget = QWidget()
            cw_layout = QHBoxLayout(cell_widget)
            cw_layout.setContentsMargins(4, 2, 4, 2)
            cw_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cw_layout.addWidget(sens_badge)
            self._table.setCellWidget(row, 5, cell_widget)

            # Associated Endpoints
            eps = res.get("associated_endpoints", [])
            ep_str = ", ".join(eps) if eps else "(None)"
            ep_item = QTableWidgetItem(ep_str)
            self._table.setItem(row, 6, ep_item)

        self._on_selection_changed()

    def _on_selection_changed(self) -> None:
        """Update toolbar button states."""
        has_sel = len(self._table.selectionModel().selectedRows()) > 0
        self._btn_edit.setEnabled(has_sel)
        self._btn_delete.setEnabled(has_sel)

    def _get_selected_resource(self) -> dict[str, Any] | None:
        """Return the dictionary of selected resource."""
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        r_id = self._table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole)
        for r in self._resources:
            if r.get("id") == r_id:
                return r
        return None

    def _on_add_resource(self) -> None:
        """Open ResourceDialog and create resource."""
        dialog = ResourceDialog(
            identities=self._identities,
            tenants=self._tenants,
            parent=self,
        )
        if dialog.exec() == ResourceDialog.DialogCode.Accepted:
            data = dialog.get_data()
            if self._db_manager and self._active_project_id:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._res_repo.create(
                            session=session,
                            project_id=str(self._active_project_id),
                            display_name=data["display_name"],
                            resource_type=data["resource_type"],
                            custom_type_name=data["custom_type_name"],
                            external_id=data["external_id"],
                            owning_identity_id=data["owning_identity_id"],
                            owning_tenant_id=data["owning_tenant_id"],
                            sensitivity=data["sensitivity"],
                            associated_endpoints=data["associated_endpoints"],
                            tags=data["tags"],
                            notes=data["notes"],
                        )
                        session.commit()
                except Exception as exc:
                    QMessageBox.critical(self, "Database Error", f"Failed to create resource: {exc}")
                    return
            else:
                import uuid

                data["id"] = str(uuid.uuid4())
                self._resources.append(data)

            self.refresh_data()
            self.data_changed.emit()

    def _on_edit_resource(self) -> None:
        """Open ResourceDialog to edit selected resource."""
        res = self._get_selected_resource()
        if not res:
            return

        dialog = ResourceDialog(
            resource_data=res,
            identities=self._identities,
            tenants=self._tenants,
            parent=self,
        )
        if dialog.exec() == ResourceDialog.DialogCode.Accepted:
            data = dialog.get_data()
            r_id = res["id"]
            if self._db_manager and self._active_project_id:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._res_repo.update(
                            session=session,
                            resource_id=str(r_id),
                            display_name=data["display_name"],
                            resource_type=data["resource_type"],
                            custom_type_name=data["custom_type_name"],
                            external_id=data["external_id"],
                            owning_identity_id=data["owning_identity_id"],
                            owning_tenant_id=data["owning_tenant_id"],
                            sensitivity=data["sensitivity"],
                            associated_endpoints=data["associated_endpoints"],
                            tags=data["tags"],
                            notes=data["notes"],
                        )
                        session.commit()
                except Exception as exc:
                    QMessageBox.critical(self, "Update Error", f"Failed to update resource: {exc}")
                    return
            else:
                res.update(data)

            self.refresh_data()
            self.data_changed.emit()

    def _on_delete_resource(self) -> None:
        """Delete selected resource after confirmation."""
        res = self._get_selected_resource()
        if not res:
            return

        name = res.get("display_name", "Unknown")
        reply = QMessageBox.question(
            self,
            "Confirm Resource Deletion",
            f"Are you sure you want to delete target resource '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        r_id = res["id"]
        if self._db_manager and self._active_project_id:
            try:
                with Session(self._db_manager.engine) as session:
                    self._res_repo.delete(session=session, resource_id=str(r_id))
                    session.commit()
            except Exception as exc:
                QMessageBox.critical(self, "Delete Error", f"Failed to delete resource: {exc}")
                return
        else:
            self._resources = [r for r in self._resources if r.get("id") != r_id]

        self.refresh_data()
        self.data_changed.emit()
