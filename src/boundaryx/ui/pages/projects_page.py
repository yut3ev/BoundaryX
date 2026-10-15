"""Projects workspace page for BoundaryX.

Provides management of security assessment projects, creation wizards, archiving,
database snapshot backup/restore, JSON export, and project selection switching.
"""

from __future__ import annotations

import contextlib
import json
import logging
from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from sqlalchemy.orm import Session

from boundaryx.infrastructure.database.repositories import ProjectRepository
from boundaryx.ui.components.empty_state import EmptyStateWidget
from boundaryx.ui.components.search_bar import SearchFilterBar
from boundaryx.ui.components.status_badge import StatusBadge
from boundaryx.ui.dialogs.project_dialog import ProjectDialog
from boundaryx.ui.resources.styles import apply_button_class, apply_label_class
from boundaryx.ui.resources.themes import get_current_palette

if TYPE_CHECKING:
    from boundaryx.infrastructure.database.manager import DatabaseManager

logger = logging.getLogger(__name__)


class ProjectsPage(QWidget):
    """Projects workspace page allowing testers to organize, switch, and back up projects."""

    project_selected = Signal(UUID)
    project_selected_str = Signal(str)
    project_changed = Signal()

    def __init__(
        self,
        db_manager: DatabaseManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ProjectsPage.

        Args:
            db_manager: Optional DatabaseManager instance.
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._db_manager = db_manager
        self._repo = ProjectRepository()
        self._projects_cache: list[dict[str, Any]] = []
        self._filtered_projects: list[dict[str, Any]] = []

        self._init_ui()
        self.refresh_projects()

    def set_db_manager(self, db_manager: DatabaseManager) -> None:
        """Update the database manager and reload data."""
        self._db_manager = db_manager
        self.refresh_projects()

    def _init_ui(self) -> None:
        """Build the page layout, search bar, table, and actions bar."""
        get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header Title and Stats
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        self._title_label = QLabel("Assessment Projects")
        apply_label_class(self._title_label, "title")
        self._title_label.setStyleSheet("font-size: 20px; font-weight: 700;")

        self._subtitle_label = QLabel(
            "Manage target environments, assessment parameters, and authorization boundaries."
        )
        apply_label_class(self._subtitle_label, "subtitle")

        title_col.addWidget(self._title_label)
        title_col.addWidget(self._subtitle_label)
        header_layout.addLayout(title_col, 1)

        # Quick New Project Button in header
        self._top_new_btn = QPushButton("+ New Project")
        apply_button_class(self._top_new_btn, "primary")
        self._top_new_btn.clicked.connect(self._on_new_project)
        header_layout.addWidget(self._top_new_btn)

        layout.addLayout(header_layout)

        # Search & Filter Bar
        self._search_bar = SearchFilterBar(
            placeholder="Search projects by name, description, target...",
            parent=self,
        )
        self._search_bar.add_filter(
            key="status",
            options=["Active Only", "All Projects", "Archived Only"],
            default="Active Only",
            min_width=130,
        )
        self._search_bar.search_changed.connect(self._on_filter_changed)
        self._search_bar.filter_changed.connect(lambda k, v: self._on_filter_changed())
        layout.addWidget(self._search_bar)

        # Action Toolbar Bar
        self._toolbar = self._build_toolbar()
        layout.addWidget(self._toolbar)

        # Projects Table
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(
            [
                "Project Name",
                "Description",
                "Target Scope",
                "Created (UTC)",
                "Status",
            ]
        )
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)

        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._table.doubleClicked.connect(self._on_row_double_clicked)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)

        layout.addWidget(self._table, 1)

        # Empty State Widget
        self._empty_state = EmptyStateWidget(
            title="No Projects Available",
            description="Create your first security testing project to begin modeling authorization boundaries.",
            icon="📁",
            primary_button_text="Create Project",
            secondary_button_text="",
            parent=self,
        )
        self._empty_state.primary_action_clicked.connect(self._on_new_project)
        self._empty_state.setVisible(False)
        layout.addWidget(self._empty_state)

        self._update_action_states()

    def _build_toolbar(self) -> QWidget:
        """Construct the contextual actions bar."""
        toolbar = QWidget()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Open Project
        self._btn_open = QPushButton("Open Project")
        apply_button_class(self._btn_open, "primary")
        self._btn_open.clicked.connect(self._on_open_project)
        layout.addWidget(self._btn_open)

        # Edit Project
        self._btn_edit = QPushButton("Edit")
        apply_button_class(self._btn_edit, "secondary")
        self._btn_edit.clicked.connect(self._on_edit_project)
        layout.addWidget(self._btn_edit)

        # Archive Project
        self._btn_archive = QPushButton("Archive")
        apply_button_class(self._btn_archive, "secondary")
        self._btn_archive.clicked.connect(self._on_archive_project)
        layout.addWidget(self._btn_archive)

        # Backup Project Database
        self._btn_backup = QPushButton("Backup...")
        apply_button_class(self._btn_backup, "secondary")
        self._btn_backup.setToolTip("Export a consistent SQLite snapshot backup of this project database")
        self._btn_backup.clicked.connect(self._on_backup_project)
        layout.addWidget(self._btn_backup)

        # Restore Project Database
        self._btn_restore = QPushButton("Restore...")
        apply_button_class(self._btn_restore, "secondary")
        self._btn_restore.setToolTip("Restore project state from a previous snapshot backup")
        self._btn_restore.clicked.connect(self._on_restore_project)
        layout.addWidget(self._btn_restore)

        # Export Project JSON
        self._btn_export = QPushButton("Export JSON")
        apply_button_class(self._btn_export, "secondary")
        self._btn_export.clicked.connect(self._on_export_project)
        layout.addWidget(self._btn_export)

        layout.addStretch()

        # Delete Project
        self._btn_delete = QPushButton("Delete")
        apply_button_class(self._btn_delete, "danger")
        self._btn_delete.clicked.connect(self._on_delete_project)
        layout.addWidget(self._btn_delete)

        return toolbar

    def _get_selected_project(self) -> dict[str, Any] | None:
        """Return the dictionary of the currently selected project row."""
        selected_rows = self._table.selectionModel().selectedRows()
        if not selected_rows:
            return None
        row = selected_rows[0].row()
        if 0 <= row < len(self._filtered_projects):
            return self._filtered_projects[row]
        return None

    def _on_selection_changed(self) -> None:
        """Update enabled states of contextual toolbar actions."""
        self._update_action_states()

    def _update_action_states(self) -> None:
        """Enable or disable toolbar buttons based on selection."""
        item = self._get_selected_project()
        has_sel = item is not None
        self._btn_open.setEnabled(has_sel)
        self._btn_edit.setEnabled(has_sel)
        self._btn_archive.setEnabled(has_sel)
        self._btn_export.setEnabled(has_sel)
        self._btn_delete.setEnabled(has_sel)

        if item:
            is_archived = item.get("archived", False)
            self._btn_archive.setText("Unarchive" if is_archived else "Archive")
        else:
            self._btn_archive.setText("Archive")

    def _on_row_double_clicked(self) -> None:
        """Double clicking a project row activates and opens the project."""
        self._on_open_project()

    def _on_context_menu(self, pos: Any) -> None:
        """Show right-click context menu on table."""
        project = self._get_selected_project()
        if not project:
            return

        menu = QMenu(self)
        open_action = menu.addAction("Open Project")
        edit_action = menu.addAction("Edit Settings")
        menu.addSeparator()

        is_archived = project.get("archived", False)
        archive_action = menu.addAction("Unarchive Project" if is_archived else "Archive Project")
        backup_action = menu.addAction("Backup Database...")
        export_action = menu.addAction("Export Project JSON...")
        menu.addSeparator()
        delete_action = menu.addAction("Delete Project")

        action = menu.exec(self._table.viewport().mapToGlobal(pos))
        if action == open_action:
            self._on_open_project()
        elif action == edit_action:
            self._on_edit_project()
        elif action == archive_action:
            self._on_archive_project()
        elif action == backup_action:
            self._on_backup_project()
        elif action == export_action:
            self._on_export_project()
        elif action == delete_action:
            self._on_delete_project()

    def refresh_projects(self) -> None:
        """Fetch all projects from database or cache and refresh display."""
        if self._db_manager is not None:
            try:
                with Session(self._db_manager.engine) as session:
                    models = self._repo.list_all(session=session, include_archived=True)
                    self._projects_cache = [
                        {
                            "id": m.id,
                            "name": m.name,
                            "description": m.description,
                            "created_at": m.created_at,
                            "updated_at": m.updated_at,
                            "archived": m.archived,
                            "settings": m.settings or {},
                        }
                        for m in models
                    ]
            except Exception as exc:
                logger.error("Failed to query projects from database: %s", exc)
        self._apply_filters()

    def _apply_filters(self) -> None:
        """Filter cached projects by query and status dropdown."""
        query = self._search_bar.get_search_text().lower().strip()
        status_filter = self._search_bar.get_filter_value("status")

        filtered = []
        for p in self._projects_cache:
            is_archived = p.get("archived", False)
            if status_filter == "Active Only" and is_archived:
                continue
            if status_filter == "Archived Only" and not is_archived:
                continue

            name = str(p.get("name", "")).lower()
            desc = str(p.get("description", "") or "").lower()
            host = str(p.get("settings", {}).get("target_host", "")).lower()

            if query and query not in name and query not in desc and query not in host:
                continue

            filtered.append(p)

        self._filtered_projects = filtered
        self._populate_table()

    def _populate_table(self) -> None:
        """Render filtered projects into the table."""
        has_items = len(self._filtered_projects) > 0
        self._table.setVisible(has_items)
        self._empty_state.setVisible(not has_items)

        self._table.setRowCount(len(self._filtered_projects))

        for row, p in enumerate(self._filtered_projects):
            # Name
            name_item = QTableWidgetItem(str(p.get("name", "")))
            name_item.setData(Qt.ItemDataRole.UserRole, p.get("id"))
            self._table.setItem(row, 0, name_item)

            # Description
            desc_item = QTableWidgetItem(str(p.get("description") or ""))
            self._table.setItem(row, 1, desc_item)

            # Target Scope Preset / Host
            settings = p.get("settings", {}) or {}
            preset = settings.get("scope_preset") or settings.get("target_host") or "Standard"
            scope_item = QTableWidgetItem(str(preset))
            self._table.setItem(row, 2, scope_item)

            # Created
            c_at = p.get("created_at")
            c_str = c_at.strftime("%Y-%m-%d %H:%M") if hasattr(c_at, "strftime") else str(c_at or "")
            created_item = QTableWidgetItem(c_str)
            created_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 3, created_item)

            # Status Badge
            is_archived = p.get("archived", False)
            badge = StatusBadge(
                "ARCHIVED" if is_archived else "ACTIVE",
                variant="neutral" if is_archived else "ALLOW",
            )
            cell_widget = QWidget()
            cw_layout = QHBoxLayout(cell_widget)
            cw_layout.setContentsMargins(4, 2, 4, 2)
            cw_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cw_layout.addWidget(badge)
            self._table.setCellWidget(row, 4, cell_widget)

        self._update_action_states()

    def _on_filter_changed(self, *args: Any) -> None:
        """Trigger filter re-evaluation."""
        self._apply_filters()

    def _on_new_project(self) -> None:
        """Open the New Project dialog and persist."""
        dialog = ProjectDialog(parent=self)
        if dialog.exec() == ProjectDialog.DialogCode.Accepted:
            data = dialog.get_data()
            if self._db_manager:
                try:
                    with Session(self._db_manager.engine) as session:
                        model = self._repo.create(
                            session=session,
                            name=data["name"],
                            description=data["description"],
                            settings=data["settings"],
                        )
                        session.commit()
                        logger.info("Created new project: %s (%s)", model.name, model.id)
                except Exception as exc:
                    QMessageBox.critical(self, "Database Error", f"Failed to create project: {exc}")
                    return
            else:
                # Standalone mock fallback
                import uuid
                from datetime import datetime

                new_item = {
                    "id": str(uuid.uuid4()),
                    "name": data["name"],
                    "description": data["description"],
                    "created_at": datetime.now(UTC),
                    "updated_at": datetime.now(UTC),
                    "archived": False,
                    "settings": data["settings"],
                }
                self._projects_cache.insert(0, new_item)

            self.refresh_projects()
            self.project_changed.emit()

    def _on_open_project(self) -> None:
        """Activate the selected project."""
        project = self._get_selected_project()
        if not project:
            return

        p_id_str = str(project["id"])
        self.project_selected_str.emit(p_id_str)
        with contextlib.suppress(Exception):
            self.project_selected.emit(UUID(p_id_str))

    def _on_edit_project(self) -> None:
        """Open edit dialog for selected project."""
        project = self._get_selected_project()
        if not project:
            return

        dialog = ProjectDialog(project_data=project, parent=self)
        if dialog.exec() == ProjectDialog.DialogCode.Accepted:
            data = dialog.get_data()
            p_id = project["id"]
            if self._db_manager:
                try:
                    with Session(self._db_manager.engine) as session:
                        self._repo.update(
                            session=session,
                            project_id=str(p_id),
                            name=data["name"],
                            description=data["description"],
                            settings=data["settings"],
                        )
                        session.commit()
                except Exception as exc:
                    QMessageBox.critical(self, "Update Error", f"Failed to update project: {exc}")
                    return
            else:
                project["name"] = data["name"]
                project["description"] = data["description"]
                project["settings"] = data["settings"]

            self.refresh_projects()
            self.project_changed.emit()

    def _on_archive_project(self) -> None:
        """Toggle archived status of selected project."""
        project = self._get_selected_project()
        if not project:
            return

        p_id = project["id"]
        new_archived_state = not project.get("archived", False)

        if self._db_manager:
            try:
                with Session(self._db_manager.engine) as session:
                    self._repo.update(
                        session=session,
                        project_id=str(p_id),
                        archived=new_archived_state,
                    )
                    session.commit()
            except Exception as exc:
                QMessageBox.critical(self, "Archive Error", f"Failed to update archive status: {exc}")
                return
        else:
            project["archived"] = new_archived_state

        self.refresh_projects()
        self.project_changed.emit()

    def _on_backup_project(self) -> None:
        """Create an online SQLite snapshot backup."""
        if not self._db_manager:
            QMessageBox.information(self, "Backup", "Database manager is operating in in-memory mode.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Database Backup",
            str(Path.home() / "boundaryx_backup.db"),
            "BoundaryX Database Backups (*.db *.sqlite)",
        )
        if not file_path:
            return

        try:
            target = self._db_manager.backup(file_path)
            QMessageBox.information(
                self,
                "Backup Successful",
                f"Project database snapshot was successfully saved to:\n{target}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Backup Failed", f"Failed to create backup: {exc}")

    def _on_restore_project(self) -> None:
        """Restore database from snapshot backup file."""
        if not self._db_manager:
            QMessageBox.warning(self, "Restore", "Database manager is operating in in-memory mode.")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Database Backup to Restore",
            str(Path.home()),
            "BoundaryX Database Backups (*.db *.sqlite)",
        )
        if not file_path:
            return

        reply = QMessageBox.warning(
            self,
            "Confirm Database Restore",
            "Restoring will overwrite current project state with data from the backup file.\n\nAre you sure you want to proceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            self._db_manager.restore(file_path)
            self.refresh_projects()
            self.project_changed.emit()
            QMessageBox.information(self, "Restore Complete", "Database state restored successfully.")
        except Exception as exc:
            QMessageBox.critical(self, "Restore Failed", f"Failed to restore database: {exc}")

    def _on_export_project(self) -> None:
        """Export project metadata and settings to a JSON file."""
        project = self._get_selected_project()
        if not project:
            return

        default_name = f"{project.get('name', 'project').replace(' ', '_').lower()}_export.json"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Project JSON",
            str(Path.home() / default_name),
            "JSON Files (*.json)",
        )
        if not file_path:
            return

        try:
            # Serialize project info
            export_payload = {
                "id": str(project.get("id")),
                "name": project.get("name"),
                "description": project.get("description"),
                "settings": project.get("settings", {}),
                "created_at": str(project.get("created_at")),
                "updated_at": str(project.get("updated_at")),
            }
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(export_payload, f, indent=2)

            QMessageBox.information(
                self,
                "Export Complete",
                f"Project exported successfully to:\n{file_path}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", f"Failed to export project: {exc}")

    def _on_delete_project(self) -> None:
        """Hard delete selected project after confirmation."""
        project = self._get_selected_project()
        if not project:
            return

        name = project.get("name", "Unknown")
        reply = QMessageBox.question(
            self,
            "Confirm Project Deletion",
            f"Are you sure you want to permanently delete project '{name}'?\n\n"
            "This will cascade delete all associated scope rules, identities, resources, "
            "authorization policies, and findings. This action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        p_id = project["id"]
        if self._db_manager:
            try:
                with Session(self._db_manager.engine) as session:
                    self._repo.delete(session=session, project_id=str(p_id))
                    session.commit()
            except Exception as exc:
                QMessageBox.critical(self, "Delete Failed", f"Failed to delete project: {exc}")
                return
        else:
            self._projects_cache = [p for p in self._projects_cache if p.get("id") != p_id]

        self.refresh_projects()
        self.project_changed.emit()
