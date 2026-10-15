"""Identities, Tenants, and Authentication Profiles management page for BoundaryX.

Provides subject modeling, role assignments, multi-tenant isolation configuration,
and credentials/token profile management.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from sqlalchemy.orm import Session

from boundaryx.domain.identities.models import AuthMethod, IdentityStatus, RoleType
from boundaryx.infrastructure.database.repositories import (
    AuthProfileRepository,
    IdentityRepository,
    TenantRepository,
)
from boundaryx.ui.components.empty_state import EmptyStateWidget
from boundaryx.ui.components.search_bar import SearchFilterBar
from boundaryx.ui.components.status_badge import StatusBadge
from boundaryx.ui.dialogs.identity_dialog import IdentityDialog
from boundaryx.ui.resources.styles import apply_button_class, apply_label_class
from boundaryx.ui.resources.themes import get_current_palette

if TYPE_CHECKING:
    from boundaryx.infrastructure.database.manager import DatabaseManager

logger = logging.getLogger(__name__)


class TenantDialog(QDialog):
    """Dialog for creating or editing an organizational tenant boundary."""

    def __init__(
        self,
        tenant_data: dict[str, Any] | None = None,
        identities: list[Any] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize TenantDialog."""
        super().__init__(parent)
        self._is_edit = tenant_data is not None
        self._tenant_data = tenant_data or {}
        self._identities = identities or []

        self.setWindowTitle("Edit Tenant" if self._is_edit else "Create Tenant Boundary")
        self.setMinimumWidth(480)
        self.setModal(True)
        self._init_ui()
        self._load_data()

    def _init_ui(self) -> None:
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title = QLabel("Tenant Configuration" if self._is_edit else "New Tenant Partition")
        apply_label_class(title, "title")
        title.setStyleSheet("font-size: 16px; font-weight: 700;")
        layout.addWidget(title)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setSpacing(10)

        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("e.g. Org Alpha, Enterprise Tenant 42")
        form.addRow("Tenant Name *:", self._name_input)

        self._desc_input = QTextEdit()
        self._desc_input.setPlaceholderText("Tenant business context, isolation requirements...")
        self._desc_input.setMaximumHeight(70)
        form.addRow("Description:", self._desc_input)

        self._owner_combo = QComboBox()
        self._owner_combo.addItem("(None / System Admin)", None)
        for ident in self._identities:
            i_id = getattr(ident, "id", None) or (ident.get("id") if isinstance(ident, dict) else str(ident))
            i_name = getattr(ident, "name", None) or (ident.get("name") if isinstance(ident, dict) else str(ident))
            self._owner_combo.addItem(str(i_name), str(i_id) if i_id else None)
        form.addRow("Owner Identity:", self._owner_combo)

        layout.addLayout(form)

        self._error_label = QLabel()
        self._error_label.setStyleSheet(f"color: {palette.danger}; font-size: 12px; font-weight: 600;")
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        button_box = QDialogButtonBox()
        save_btn = button_box.addButton(
            "Save Tenant" if self._is_edit else "Create Tenant", QDialogButtonBox.ButtonRole.AcceptRole
        )
        cancel_btn = button_box.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        apply_button_class(save_btn, "primary")
        apply_button_class(cancel_btn, "secondary")

        button_box.accepted.connect(self._validate_and_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _load_data(self) -> None:
        if not self._is_edit:
            return
        self._name_input.setText(str(self._tenant_data.get("name", "")))
        self._desc_input.setPlainText(str(self._tenant_data.get("description", "") or ""))
        owner_id = self._tenant_data.get("owner_identity_id")
        if owner_id:
            for idx in range(self._owner_combo.count()):
                if self._owner_combo.itemData(idx) == str(owner_id):
                    self._owner_combo.setCurrentIndex(idx)
                    break

    def _validate_and_accept(self) -> None:
        if not self._name_input.text().strip():
            self._error_label.setText("Tenant name is required.")
            self._error_label.setVisible(True)
            self._name_input.setFocus()
            return
        self._error_label.setVisible(False)
        self.accept()

    def get_data(self) -> dict[str, Any]:
        return {
            "name": self._name_input.text().strip(),
            "description": self._desc_input.toPlainText().strip() or None,
            "owner_identity_id": self._owner_combo.currentData(),
        }


class AuthProfileDialog(QDialog):
    """Dialog for creating or editing an authentication profile."""

    def __init__(
        self,
        profile_data: dict[str, Any] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize AuthProfileDialog."""
        super().__init__(parent)
        self._is_edit = profile_data is not None
        self._profile_data = profile_data or {}

        self.setWindowTitle("Edit Auth Profile" if self._is_edit else "New Authentication Profile")
        self.setMinimumWidth(480)
        self.setModal(True)
        self._init_ui()
        self._load_data()

    def _init_ui(self) -> None:
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title = QLabel("Authentication Profile" if self._is_edit else "New Authentication Profile")
        apply_label_class(title, "title")
        title.setStyleSheet("font-size: 16px; font-weight: 700;")
        layout.addWidget(title)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setSpacing(10)

        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("e.g. Admin Bearer Token, API Key Header")
        form.addRow("Profile Name *:", self._name_input)

        self._method_combo = QComboBox()
        for method in AuthMethod:
            self._method_combo.addItem(method.value, method.value)
        self._method_combo.currentIndexChanged.connect(self._on_method_changed)
        form.addRow("Auth Method:", self._method_combo)

        self._header_name_input = QLineEdit()
        self._header_name_input.setPlaceholderText("e.g. X-API-Key, Authorization")
        self._header_name_input.setText("Authorization")
        form.addRow("Header Name:", self._header_name_input)

        self._desc_input = QTextEdit()
        self._desc_input.setPlaceholderText("Token lifecycle notes, source service...")
        self._desc_input.setMaximumHeight(70)
        form.addRow("Description:", self._desc_input)

        layout.addLayout(form)

        self._error_label = QLabel()
        self._error_label.setStyleSheet(f"color: {palette.danger}; font-size: 12px; font-weight: 600;")
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        button_box = QDialogButtonBox()
        save_btn = button_box.addButton(
            "Save Profile" if self._is_edit else "Add Profile", QDialogButtonBox.ButtonRole.AcceptRole
        )
        cancel_btn = button_box.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        apply_button_class(save_btn, "primary")
        apply_button_class(cancel_btn, "secondary")

        button_box.accepted.connect(self._validate_and_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _on_method_changed(self, index: int) -> None:
        method = self._method_combo.currentText()
        if method == AuthMethod.BEARER_TOKEN.value:
            self._header_name_input.setText("Authorization")
        elif method == AuthMethod.COOKIE.value:
            self._header_name_input.setText("Cookie")
        elif method == AuthMethod.CUSTOM_HEADER.value:
            self._header_name_input.setText("X-API-Key")

    def _load_data(self) -> None:
        if not self._is_edit:
            return
        self._name_input.setText(str(self._profile_data.get("name", "")))
        method = self._profile_data.get("auth_method", "BEARER_TOKEN")
        idx = self._method_combo.findText(str(method).upper())
        if idx >= 0:
            self._method_combo.setCurrentIndex(idx)
        self._header_name_input.setText(str(self._profile_data.get("header_name", "Authorization") or ""))
        self._desc_input.setPlainText(str(self._profile_data.get("description", "") or ""))

    def _validate_and_accept(self) -> None:
        if not self._name_input.text().strip():
            self._error_label.setText("Profile name is required.")
            self._error_label.setVisible(True)
            self._name_input.setFocus()
            return
        self._error_label.setVisible(False)
        self.accept()

    def get_data(self) -> dict[str, Any]:
        return {
            "name": self._name_input.text().strip(),
            "auth_method": self._method_combo.currentText(),
            "header_name": self._header_name_input.text().strip() or None,
            "description": self._desc_input.toPlainText().strip() or None,
        }


class IdentitiesPage(QWidget):
    """Identities, Tenants, and Authentication Profiles management workspace."""

    identity_selected = Signal(str)
    tenant_selected = Signal(str)
    data_changed = Signal()

    def __init__(
        self,
        db_manager: DatabaseManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize IdentitiesPage."""
        super().__init__(parent)

        self._db_manager = db_manager
        self._ident_repo = IdentityRepository()
        self._tenant_repo = TenantRepository()
        self._auth_repo = AuthProfileRepository()

        self._active_project_id: str | None = None
        self._identities: list[dict[str, Any]] = []
        self._tenants: list[dict[str, Any]] = []
        self._auth_profiles: list[dict[str, Any]] = []

        self._init_ui()
        self.refresh_data()

    def set_project(self, project_id: str | None) -> None:
        """Set active project context and reload identities and tenants."""
        self._active_project_id = project_id
        self.refresh_data()

    def _init_ui(self) -> None:
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header
        header_layout = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        title = QLabel("Subjects & Identity Boundaries")
        apply_label_class(title, "title")
        title.setStyleSheet("font-size: 20px; font-weight: 700;")

        subtitle = QLabel("Provision test user personas, tenant partitions, and authentication credentials.")
        apply_label_class(subtitle, "subtitle")

        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        header_layout.addLayout(title_col, 1)

        self._btn_add_identity_top = QPushButton("+ Add Identity")
        apply_button_class(self._btn_add_identity_top, "primary")
        self._btn_add_identity_top.clicked.connect(self._on_add_identity)
        header_layout.addWidget(self._btn_add_identity_top)

        layout.addLayout(header_layout)

        # Tabs: Identities | Tenants | Auth Profiles
        self._tabs = QTabWidget()

        # Tab 1: Identities Tab
        self._identities_tab = self._build_identities_tab(palette)
        self._tabs.addTab(self._identities_tab, "Identities & Roles")

        # Tab 2: Tenants Tab
        self._tenants_tab = self._build_tenants_tab(palette)
        self._tabs.addTab(self._tenants_tab, "Tenants & Organizations")

        # Tab 3: Auth Profiles Tab
        self._auth_tab = self._build_auth_profiles_tab(palette)
        self._tabs.addTab(self._auth_tab, "Authentication Profiles")

        layout.addWidget(self._tabs, 1)

    def _build_identities_tab(self, palette: Any) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(10)

        # Search bar
        self._ident_search_bar = SearchFilterBar(
            placeholder="Search identities by name, role, tags...",
            parent=widget,
        )
        role_options = ["All Roles"] + [r.value for r in RoleType]
        self._ident_search_bar.add_filter("role", role_options, "All Roles", min_width=140)
        status_options = ["All Statuses"] + [s.value for s in IdentityStatus]
        self._ident_search_bar.add_filter("status", status_options, "All Statuses", min_width=120)

        self._ident_search_bar.search_changed.connect(self._filter_identities)
        self._ident_search_bar.filter_changed.connect(lambda k, v: self._filter_identities())
        layout.addWidget(self._ident_search_bar)

        # Toolbar
        toolbar = QHBoxLayout()
        self._btn_ident_add = QPushButton("Add Identity")
        apply_button_class(self._btn_ident_add, "primary")
        self._btn_ident_add.clicked.connect(self._on_add_identity)
        toolbar.addWidget(self._btn_ident_add)

        self._btn_ident_edit = QPushButton("Edit")
        apply_button_class(self._btn_ident_edit, "secondary")
        self._btn_ident_edit.setEnabled(False)
        self._btn_ident_edit.clicked.connect(self._on_edit_identity)
        toolbar.addWidget(self._btn_ident_edit)

        self._btn_ident_delete = QPushButton("Delete")
        apply_button_class(self._btn_ident_delete, "danger")
        self._btn_ident_delete.setEnabled(False)
        self._btn_ident_delete.clicked.connect(self._on_delete_identity)
        toolbar.addWidget(self._btn_ident_delete)

        toolbar.addStretch()
        self._ident_count_lbl = QLabel("0 identities")
        self._ident_count_lbl.setStyleSheet(f"color: {palette.text_muted}; font-size: 12px;")
        toolbar.addWidget(self._ident_count_lbl)

        layout.addLayout(toolbar)

        # Table
        self._ident_table = QTableWidget()
        self._ident_table.setColumnCount(6)
        self._ident_table.setHorizontalHeaderLabels(
            [
                "Identity Name",
                "Role",
                "Tenant Scope",
                "Status",
                "Auth Profile",
                "Tags",
            ]
        )
        self._ident_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self._ident_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._ident_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self._ident_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._ident_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self._ident_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)

        self._ident_table.setAlternatingRowColors(True)
        self._ident_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._ident_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._ident_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._ident_table.itemSelectionChanged.connect(self._on_ident_selection_changed)

        layout.addWidget(self._ident_table, 1)

        self._ident_empty = EmptyStateWidget(
            title="No Identities Found",
            description="Add subject identities with roles and authentication tokens to execute authorization tests.",
            icon="👤",
            primary_button_text="Add Identity",
            parent=widget,
        )
        self._ident_empty.primary_action_clicked.connect(self._on_add_identity)
        self._ident_empty.setVisible(False)
        layout.addWidget(self._ident_empty)

        return widget

    def _build_tenants_tab(self, palette: Any) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(10)

        # Toolbar
        toolbar = QHBoxLayout()
        btn_add_t = QPushButton("+ Add Tenant")
        apply_button_class(btn_add_t, "primary")
        btn_add_t.clicked.connect(self._on_add_tenant)
        toolbar.addWidget(btn_add_t)

        self._btn_edit_tenant = QPushButton("Edit Tenant")
        apply_button_class(self._btn_edit_tenant, "secondary")
        self._btn_edit_tenant.setEnabled(False)
        self._btn_edit_tenant.clicked.connect(self._on_edit_tenant)
        toolbar.addWidget(self._btn_edit_tenant)

        self._btn_del_tenant = QPushButton("Delete Tenant")
        apply_button_class(self._btn_del_tenant, "danger")
        self._btn_del_tenant.setEnabled(False)
        self._btn_del_tenant.clicked.connect(self._on_delete_tenant)
        toolbar.addWidget(self._btn_del_tenant)

        toolbar.addStretch()
        self._tenant_count_lbl = QLabel("0 tenants")
        self._tenant_count_lbl.setStyleSheet(f"color: {palette.text_muted}; font-size: 12px;")
        toolbar.addWidget(self._tenant_count_lbl)
        layout.addLayout(toolbar)

        # Tenants Table
        self._tenant_table = QTableWidget()
        self._tenant_table.setColumnCount(4)
        self._tenant_table.setHorizontalHeaderLabels(
            [
                "Tenant Name",
                "Description",
                "Owner Identity",
                "Tenant ID",
            ]
        )
        self._tenant_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self._tenant_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._tenant_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self._tenant_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        self._tenant_table.setAlternatingRowColors(True)
        self._tenant_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tenant_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._tenant_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._tenant_table.itemSelectionChanged.connect(self._on_tenant_selection_changed)

        layout.addWidget(self._tenant_table, 1)

        self._tenant_empty = EmptyStateWidget(
            title="No Tenants Configured",
            description="Create tenant boundaries to simulate multi-tenant workspaces and detect cross-tenant access leaks.",
            icon="🏢",
            primary_button_text="Add Tenant",
            parent=widget,
        )
        self._tenant_empty.primary_action_clicked.connect(self._on_add_tenant)
        self._tenant_empty.setVisible(False)
        layout.addWidget(self._tenant_empty)

        return widget

    def _build_auth_profiles_tab(self, palette: Any) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(10)

        toolbar = QHBoxLayout()
        btn_add_ap = QPushButton("+ Add Auth Profile")
        apply_button_class(btn_add_ap, "primary")
        btn_add_ap.clicked.connect(self._on_add_auth_profile)
        toolbar.addWidget(btn_add_ap)

        self._btn_edit_ap = QPushButton("Edit Profile")
        apply_button_class(self._btn_edit_ap, "secondary")
        self._btn_edit_ap.setEnabled(False)
        self._btn_edit_ap.clicked.connect(self._on_edit_auth_profile)
        toolbar.addWidget(self._btn_edit_ap)

        self._btn_del_ap = QPushButton("Delete Profile")
        apply_button_class(self._btn_del_ap, "danger")
        self._btn_del_ap.setEnabled(False)
        self._btn_del_ap.clicked.connect(self._on_delete_auth_profile)
        toolbar.addWidget(self._btn_del_ap)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        self._auth_table = QTableWidget()
        self._auth_table.setColumnCount(4)
        self._auth_table.setHorizontalHeaderLabels(
            [
                "Profile Name",
                "Auth Method",
                "Header Name",
                "Description",
            ]
        )
        self._auth_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self._auth_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._auth_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._auth_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

        self._auth_table.setAlternatingRowColors(True)
        self._auth_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._auth_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._auth_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._auth_table.itemSelectionChanged.connect(self._on_auth_selection_changed)

        layout.addWidget(self._auth_table, 1)

        self._auth_empty = EmptyStateWidget(
            title="No Authentication Profiles",
            description="Create authentication profiles to manage headers, tokens, and cookies for test execution.",
            icon="🔑",
            primary_button_text="Add Profile",
            parent=widget,
        )
        self._auth_empty.primary_action_clicked.connect(self._on_add_auth_profile)
        self._auth_empty.setVisible(False)
        layout.addWidget(self._auth_empty)

        return widget

    def refresh_data(self) -> None:
        """Fetch all records from database or cache."""
        if self._db_manager and self._active_project_id:
            try:
                with Session(self._db_manager.engine) as session:
                    # Load tenants
                    t_models = self._tenant_repo.list_by_project(session, self._active_project_id)
                    self._tenants = [
                        {
                            "id": str(t.id),
                            "name": t.name,
                            "description": t.description,
                            "owner_identity_id": t.owner_identity_id,
                        }
                        for t in t_models
                    ]

                    # Load auth profiles
                    ap_models = self._auth_repo.list_by_project(session, self._active_project_id)
                    self._auth_profiles = [
                        {
                            "id": str(ap.id),
                            "name": ap.name,
                            "auth_method": ap.auth_method,
                            "header_name": ap.header_name,
                            "description": ap.description,
                        }
                        for ap in ap_models
                    ]

                    # Load identities
                    i_models = self._ident_repo.list_by_project(session, self._active_project_id)
                    self._identities = [
                        {
                            "id": str(i.id),
                            "name": i.name,
                            "role_type": i.role_type,
                            "custom_role_name": i.custom_role_name,
                            "status": i.status,
                            "tags": list(i.tags or []),
                            "notes": i.notes,
                            "tenant_id": i.tenant_memberships[0].tenant_id if i.tenant_memberships else None,
                        }
                        for i in i_models
                    ]
            except Exception as exc:
                logger.error("Failed to load identities data from DB: %s", exc)

        self._filter_identities()
        self._populate_tenants()
        self._populate_auth_profiles()

    def _filter_identities(self) -> None:
        query = self._ident_search_bar.get_search_text().lower().strip()
        role_filter = self._ident_search_bar.get_filter_value("role")
        status_filter = self._ident_search_bar.get_filter_value("status")

        filtered = []
        for ident in self._identities:
            r = ident.get("role_type", "AUTHENTICATED")
            s = ident.get("status", "ACTIVE")

            if role_filter != "All Roles" and r.upper() != role_filter.upper():
                continue
            if status_filter != "All Statuses" and s.upper() != status_filter.upper():
                continue

            name = str(ident.get("name", "")).lower()
            tags = " ".join(ident.get("tags", [])).lower()
            if query and query not in name and query not in tags:
                continue

            filtered.append(ident)

        self._populate_identities(filtered)

    def _populate_identities(self, items: list[dict[str, Any]]) -> None:
        count = len(items)
        self._ident_count_lbl.setText(f"{count} identities")

        has_items = count > 0
        self._ident_table.setVisible(has_items)
        self._ident_empty.setVisible(not has_items)

        self._ident_table.setRowCount(count)

        # Tenant name lookup map
        tenant_map = {t["id"]: t["name"] for t in self._tenants}

        for row, ident in enumerate(items):
            # Name
            name_item = QTableWidgetItem(str(ident.get("name", "")))
            name_item.setData(Qt.ItemDataRole.UserRole, ident.get("id"))
            self._ident_table.setItem(row, 0, name_item)

            # Role
            r_str = ident.get("custom_role_name") or ident.get("role_type", "AUTHENTICATED")
            r_item = QTableWidgetItem(str(r_str))
            r_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._ident_table.setItem(row, 1, r_item)

            # Tenant Scope
            t_id = ident.get("tenant_id")
            t_name = tenant_map.get(t_id, "(Global)") if t_id else "(Global)"
            t_item = QTableWidgetItem(t_name)
            self._ident_table.setItem(row, 2, t_item)

            # Status Badge
            st = ident.get("status", "active").upper()
            st_badge = StatusBadge(st, variant=st)
            cell_widget = QWidget()
            cw_layout = QHBoxLayout(cell_widget)
            cw_layout.setContentsMargins(4, 2, 4, 2)
            cw_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cw_layout.addWidget(st_badge)
            self._ident_table.setCellWidget(row, 3, cell_widget)

            # Auth Profile
            ap_id = ident.get("auth_profile_id")
            ap_name = "Default"
            for ap in self._auth_profiles:
                if ap.get("id") == ap_id:
                    ap_name = ap.get("name", "Default")
                    break
            ap_item = QTableWidgetItem(ap_name)
            self._ident_table.setItem(row, 4, ap_item)

            # Tags
            tags_str = ", ".join(ident.get("tags", [])) if ident.get("tags") else ""
            tags_item = QTableWidgetItem(tags_str)
            self._ident_table.setItem(row, 5, tags_item)

        self._on_ident_selection_changed()

    def _populate_tenants(self) -> None:
        count = len(self._tenants)
        self._tenant_count_lbl.setText(f"{count} tenants")

        has_items = count > 0
        self._tenant_table.setVisible(has_items)
        self._tenant_empty.setVisible(not has_items)

        self._tenant_table.setRowCount(count)

        ident_map = {i["id"]: i["name"] for i in self._identities}

        for row, t in enumerate(self._tenants):
            name_item = QTableWidgetItem(str(t.get("name", "")))
            name_item.setData(Qt.ItemDataRole.UserRole, t.get("id"))
            self._tenant_table.setItem(row, 0, name_item)

            desc_item = QTableWidgetItem(str(t.get("description") or ""))
            self._tenant_table.setItem(row, 1, desc_item)

            owner_id = t.get("owner_identity_id")
            owner_name = ident_map.get(owner_id, "(None)") if owner_id else "(None)"
            owner_item = QTableWidgetItem(owner_name)
            self._tenant_table.setItem(row, 2, owner_item)

            id_str = str(t.get("id", ""))[:8]
            id_item = QTableWidgetItem(id_str)
            id_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._tenant_table.setItem(row, 3, id_item)

        self._on_tenant_selection_changed()

    def _populate_auth_profiles(self) -> None:
        count = len(self._auth_profiles)
        has_items = count > 0
        self._auth_table.setVisible(has_items)
        self._auth_empty.setVisible(not has_items)

        self._auth_table.setRowCount(count)

        for row, ap in enumerate(self._auth_profiles):
            name_item = QTableWidgetItem(str(ap.get("name", "")))
            name_item.setData(Qt.ItemDataRole.UserRole, ap.get("id"))
            self._auth_table.setItem(row, 0, name_item)

            method_item = QTableWidgetItem(str(ap.get("auth_method", "")))
            method_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._auth_table.setItem(row, 1, method_item)

            hdr_item = QTableWidgetItem(str(ap.get("header_name") or ""))
            hdr_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._auth_table.setItem(row, 2, hdr_item)

            desc_item = QTableWidgetItem(str(ap.get("description") or ""))
            self._auth_table.setItem(row, 3, desc_item)

        self._on_auth_selection_changed()

    def _on_ident_selection_changed(self) -> None:
        selected = len(self._ident_table.selectionModel().selectedRows()) > 0
        self._btn_ident_edit.setEnabled(selected)
        self._btn_ident_delete.setEnabled(selected)

    def _on_tenant_selection_changed(self) -> None:
        selected = len(self._tenant_table.selectionModel().selectedRows()) > 0
        self._btn_edit_tenant.setEnabled(selected)
        self._btn_del_tenant.setEnabled(selected)

    def _on_auth_selection_changed(self) -> None:
        selected = len(self._auth_table.selectionModel().selectedRows()) > 0
        self._btn_edit_ap.setEnabled(selected)
        self._btn_del_ap.setEnabled(selected)

    def _get_selected_identity(self) -> dict[str, Any] | None:
        rows = self._ident_table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._ident_table.item(rows[0].row(), 0)
        ident_id = item.data(Qt.ItemDataRole.UserRole)
        for i in self._identities:
            if i.get("id") == ident_id:
                return i
        return None

    def _get_selected_tenant(self) -> dict[str, Any] | None:
        rows = self._tenant_table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._tenant_table.item(rows[0].row(), 0)
        t_id = item.data(Qt.ItemDataRole.UserRole)
        for t in self._tenants:
            if t.get("id") == t_id:
                return t
        return None

    def _get_selected_auth_profile(self) -> dict[str, Any] | None:
        rows = self._auth_table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._auth_table.item(rows[0].row(), 0)
        ap_id = item.data(Qt.ItemDataRole.UserRole)
        for ap in self._auth_profiles:
            if ap.get("id") == ap_id:
                return ap
        return None

    def _on_add_identity(self) -> None:
        dialog = IdentityDialog(
            tenants=self._tenants,
            auth_profiles=self._auth_profiles,
            parent=self,
        )
        if dialog.exec() == IdentityDialog.DialogCode.Accepted:
            data = dialog.get_data()
            if self._db_manager and self._active_project_id:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._ident_repo.create(
                            session=session,
                            project_id=str(self._active_project_id),
                            name=data["name"],
                            role_type=data["role_type"],
                            custom_role_name=data["custom_role_name"],
                            status=data["status"],
                            tags=data["tags"],
                            notes=data["notes"],
                        )
                        session.commit()
                except Exception as exc:
                    QMessageBox.critical(self, "Database Error", f"Failed to create identity: {exc}")
                    return
            else:
                import uuid

                data["id"] = str(uuid.uuid4())
                self._identities.append(data)

            self.refresh_data()
            self.data_changed.emit()

    def _on_edit_identity(self) -> None:
        ident = self._get_selected_identity()
        if not ident:
            return

        dialog = IdentityDialog(
            identity_data=ident,
            tenants=self._tenants,
            auth_profiles=self._auth_profiles,
            parent=self,
        )
        if dialog.exec() == IdentityDialog.DialogCode.Accepted:
            data = dialog.get_data()
            i_id = ident["id"]
            if self._db_manager and self._active_project_id:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._ident_repo.update(
                            session=session,
                            identity_id=str(i_id),
                            name=data["name"],
                            role_type=data["role_type"],
                            custom_role_name=data["custom_role_name"],
                            status=data["status"],
                            tags=data["tags"],
                            notes=data["notes"],
                        )
                        session.commit()
                except Exception as exc:
                    QMessageBox.critical(self, "Update Error", f"Failed to update identity: {exc}")
                    return
            else:
                ident.update(data)

            self.refresh_data()
            self.data_changed.emit()

    def _on_delete_identity(self) -> None:
        ident = self._get_selected_identity()
        if not ident:
            return

        name = ident.get("name", "Unknown")
        reply = QMessageBox.question(
            self,
            "Confirm Identity Deletion",
            f"Are you sure you want to delete identity '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        i_id = ident["id"]
        if self._db_manager and self._active_project_id:
            try:
                with Session(self._db_manager.engine) as session:
                    self._ident_repo.delete(session=session, identity_id=str(i_id))
                    session.commit()
            except Exception as exc:
                QMessageBox.critical(self, "Delete Error", f"Failed to delete identity: {exc}")
                return
        else:
            self._identities = [i for i in self._identities if i.get("id") != i_id]

        self.refresh_data()
        self.data_changed.emit()

    def _on_add_tenant(self) -> None:
        dialog = TenantDialog(identities=self._identities, parent=self)
        if dialog.exec() == TenantDialog.DialogCode.Accepted:
            data = dialog.get_data()
            if self._db_manager and self._active_project_id:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._tenant_repo.create(
                            session=session,
                            project_id=str(self._active_project_id),
                            name=data["name"],
                            description=data["description"],
                            owner_identity_id=data["owner_identity_id"],
                        )
                        session.commit()
                except Exception as exc:
                    QMessageBox.critical(self, "Database Error", f"Failed to create tenant: {exc}")
                    return
            else:
                import uuid

                data["id"] = str(uuid.uuid4())
                self._tenants.append(data)

            self.refresh_data()
            self.data_changed.emit()

    def _on_edit_tenant(self) -> None:
        tenant = self._get_selected_tenant()
        if not tenant:
            return

        dialog = TenantDialog(tenant_data=tenant, identities=self._identities, parent=self)
        if dialog.exec() == TenantDialog.DialogCode.Accepted:
            data = dialog.get_data()
            t_id = tenant["id"]
            if self._db_manager and self._active_project_id:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._tenant_repo.update_tenant(
                            session=session,
                            tenant_id=str(t_id),
                            name=data["name"],
                            description=data["description"],
                            owner_identity_id=data["owner_identity_id"],
                        )
                        session.commit()
                except Exception as exc:
                    QMessageBox.critical(self, "Update Error", f"Failed to update tenant: {exc}")
                    return
            else:
                tenant.update(data)

            self.refresh_data()
            self.data_changed.emit()

    def _on_delete_tenant(self) -> None:
        tenant = self._get_selected_tenant()
        if not tenant:
            return

        name = tenant.get("name", "Unknown")
        reply = QMessageBox.question(
            self,
            "Confirm Tenant Deletion",
            f"Are you sure you want to delete tenant '{name}' and remove all memberships?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        t_id = tenant["id"]
        if self._db_manager and self._active_project_id:
            try:
                with Session(self._db_manager.engine) as session:
                    self._tenant_repo.delete_tenant(session=session, tenant_id=str(t_id))
                    session.commit()
            except Exception as exc:
                QMessageBox.critical(self, "Delete Error", f"Failed to delete tenant: {exc}")
                return
        else:
            self._tenants = [t for t in self._tenants if t.get("id") != t_id]

        self.refresh_data()
        self.data_changed.emit()

    def _on_add_auth_profile(self) -> None:
        dialog = AuthProfileDialog(parent=self)
        if dialog.exec() == AuthProfileDialog.DialogCode.Accepted:
            data = dialog.get_data()
            if self._db_manager and self._active_project_id:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._auth_repo.create(
                            session=session,
                            project_id=str(self._active_project_id),
                            name=data["name"],
                            auth_method=data["auth_method"],
                            header_name=data["header_name"],
                            description=data["description"],
                        )
                        session.commit()
                except Exception as exc:
                    QMessageBox.critical(self, "Database Error", f"Failed to create auth profile: {exc}")
                    return
            else:
                import uuid

                data["id"] = str(uuid.uuid4())
                self._auth_profiles.append(data)

            self.refresh_data()
            self.data_changed.emit()

    def _on_edit_auth_profile(self) -> None:
        ap = self._get_selected_auth_profile()
        if not ap:
            return

        dialog = AuthProfileDialog(profile_data=ap, parent=self)
        if dialog.exec() == AuthProfileDialog.DialogCode.Accepted:
            data = dialog.get_data()
            ap_id = ap["id"]
            if self._db_manager and self._active_project_id:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._auth_repo.update(
                            session=session,
                            profile_id=str(ap_id),
                            name=data["name"],
                            auth_method=data["auth_method"],
                            header_name=data["header_name"],
                            description=data["description"],
                        )
                        session.commit()
                except Exception as exc:
                    QMessageBox.critical(self, "Update Error", f"Failed to update auth profile: {exc}")
                    return
            else:
                ap.update(data)

            self.refresh_data()
            self.data_changed.emit()

    def _on_delete_auth_profile(self) -> None:
        ap = self._get_selected_auth_profile()
        if not ap:
            return

        name = ap.get("name", "Unknown")
        reply = QMessageBox.question(
            self,
            "Confirm Auth Profile Deletion",
            f"Are you sure you want to delete profile '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        ap_id = ap["id"]
        if self._db_manager and self._active_project_id:
            try:
                with Session(self._db_manager.engine) as session:
                    self._auth_repo.delete(session=session, profile_id=str(ap_id))
                    session.commit()
            except Exception as exc:
                QMessageBox.critical(self, "Delete Error", f"Failed to delete auth profile: {exc}")
                return
        else:
            self._auth_profiles = [p for p in self._auth_profiles if p.get("id") != ap_id]

        self.refresh_data()
        self.data_changed.emit()
