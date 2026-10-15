"""Audit Logging and Operational History page for BoundaryX.

Provides immutable timeline tracking of security events, configuration modifications,
test executions, triage status transitions, and audit export capabilities.
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import UTC, datetime
from typing import Any

from PySide6.QtCore import QDate, Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDateEdit,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.infrastructure.database.repositories import AuditEventRepository
from boundaryx.ui.components.badges import create_badge
from boundaryx.ui.resources.styles import apply_button_class

logger = logging.getLogger(__name__)


class AuditLogPage(QWidget):
    """Audit events log viewer and forensics interface."""

    status_message = Signal(str)

    EVENT_TYPES = [
        "All",
        "PROJECT_CREATED",
        "PROJECT_MODIFIED",
        "SCOPE_CHANGED",
        "IDENTITY_MODIFIED",
        "CREDENTIAL_CHANGED",
        "POLICY_CHANGED",
        "TEST_STARTED",
        "TEST_STOPPED",
        "FINDING_STATUS_CHANGED",
        "REPORT_EXPORTED",
        "BACKUP_CREATED",
        "BACKUP_RESTORED",
        "SECURITY_ERROR",
    ]

    def __init__(
        self,
        db_manager: DatabaseManager,
        project_id: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.db_manager = db_manager
        self.project_id = project_id
        self._audit_records: list[dict[str, Any]] = []

        self._init_ui()

    def set_project(self, project_id: str | None) -> None:
        """Switch current active project context and reload events."""
        self.project_id = project_id
        self.load_audit_logs()

    def _init_ui(self) -> None:
        """Construct UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header bar
        header_layout = QHBoxLayout()
        title_label = QLabel("Security Audit Log")
        title_label.setStyleSheet("font-size: 18px; font-weight: 700;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        self.export_btn = QPushButton("Export Audit Log")
        apply_button_class(self.export_btn, "primary")
        self.export_btn.clicked.connect(self._export_logs)
        header_layout.addWidget(self.export_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.load_audit_logs)
        header_layout.addWidget(self.refresh_btn)

        layout.addLayout(header_layout)

        # Filter bar
        filter_frame = QFrame()
        filter_frame.setStyleSheet(
            "background-color: #1a1f2c; border: 1px solid #2d354d; border-radius: 6px; padding: 6px;"
        )
        filter_layout = QHBoxLayout(filter_frame)
        filter_layout.setContentsMargins(8, 4, 8, 4)
        filter_layout.setSpacing(12)

        filter_layout.addWidget(QLabel("Event Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(self.EVENT_TYPES)
        self.type_combo.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.type_combo)

        filter_layout.addWidget(QLabel("From:"))
        self.start_date_edit = QDateEdit()
        self.start_date_edit.setCalendarPopup(True)
        self.start_date_edit.setDate(QDate.currentDate().addDays(-30))
        self.start_date_edit.dateChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.start_date_edit)

        filter_layout.addWidget(QLabel("To:"))
        self.end_date_edit = QDateEdit()
        self.end_date_edit.setCalendarPopup(True)
        self.end_date_edit.setDate(QDate.currentDate().addDays(1))
        self.end_date_edit.dateChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.end_date_edit)

        filter_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search description or details...")
        self.search_input.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.search_input, stretch=2)

        self.count_label = QLabel("0 events")
        self.count_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        filter_layout.addWidget(self.count_label)

        layout.addWidget(filter_frame)

        # Splitter: Table above, JSON Details below
        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter, stretch=1)

        # Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Timestamp (UTC)", "Event Type", "Description", "Details"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self.table)

        # Detail pane
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 4, 0, 0)
        detail_layout.setSpacing(4)

        detail_label = QLabel("Event Payload & Forensic Details")
        detail_label.setStyleSheet("font-weight: 600; color: #f8fafc;")
        detail_layout.addWidget(detail_label)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFontFamily("Cascadia Code, Consolas, monospace")
        self.detail_text.setStyleSheet(
            "background-color: #0f172a; color: #38bdf8; border: 1px solid #1e293b; border-radius: 4px;"
        )
        detail_layout.addWidget(self.detail_text)

        splitter.addWidget(detail_widget)
        splitter.setSizes([450, 200])

    def load_audit_logs(self) -> None:
        """Fetch audit log events from database."""
        try:
            with self.db_manager.get_session() as session:
                repo = AuditEventRepository(session)
                # If project_id is None, fetch all system events; else fetch project events
                records = repo.list_by_project(session, project_id=self.project_id, limit=2000)

                self._audit_records = []
                for ev in records:
                    self._audit_records.append(
                        {
                            "id": ev.id,
                            "timestamp": ev.timestamp,
                            "timestamp_str": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                            "event_type": ev.event_type,
                            "description": ev.description,
                            "details": ev.details or {},
                        }
                    )

            self._apply_filters()
        except Exception as exc:
            logger.error("Failed to load audit events: %s", exc)

    def _apply_filters(self) -> None:
        """Filter audit events based on event type, date range, and text search."""
        selected_type = self.type_combo.currentText()
        query = self.search_input.text().strip().lower()

        # Date range conversion
        q_start = self.start_date_edit.date()
        q_end = self.end_date_edit.date()
        dt_start = datetime(q_start.year(), q_start.month(), q_start.day(), 0, 0, 0, tzinfo=UTC)
        dt_end = datetime(q_end.year(), q_end.month(), q_end.day(), 23, 59, 59, tzinfo=UTC)

        filtered: list[dict[str, Any]] = []
        for rec in self._audit_records:
            if selected_type != "All" and rec["event_type"] != selected_type:
                continue

            rec_dt = rec["timestamp"]
            if rec_dt.tzinfo is None:
                rec_dt = rec_dt.replace(tzinfo=UTC)

            if not (dt_start <= rec_dt <= dt_end):
                continue

            if query:
                combined = f"{rec['description']} {rec['event_type']} {json.dumps(rec['details'])}".lower()
                if query not in combined:
                    continue

            filtered.append(rec)

        self._render_table(filtered)

    def _render_table(self, records: list[dict[str, Any]]) -> None:
        """Populate audit events table widget."""
        self.table.setRowCount(len(records))
        self.count_label.setText(f"{len(records)} of {len(self._audit_records)} events")

        for row, ev in enumerate(records):
            # Timestamp
            ts_item = QTableWidgetItem(ev["timestamp_str"])
            ts_item.setData(Qt.ItemDataRole.UserRole, ev)
            ts_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 0, ts_item)

            # Type badge
            type_color = "#38bdf8"
            if "ERROR" in ev["event_type"]:
                type_color = "#f87171"
            elif "CHANGED" in ev["event_type"] or "MODIFIED" in ev["event_type"]:
                type_color = "#fbbf24"
            badge = create_badge(ev["event_type"], "#1e293b", type_color, "#475569")
            self.table.setCellWidget(row, 1, badge)

            # Description
            self.table.setItem(row, 2, QTableWidgetItem(ev["description"]))

            # Details preview
            det_str = json.dumps(ev["details"])
            det_item = QTableWidgetItem(det_str if len(det_str) <= 80 else det_str[:77] + "...")
            self.table.setItem(row, 3, det_item)

    def _on_selection_changed(self) -> None:
        """Display payload details for selected event."""
        items = self.table.selectedItems()
        if not items:
            self.detail_text.clear()
            return

        row = items[0].row()
        item = self.table.item(row, 0)
        if not item:
            return

        ev = item.data(Qt.ItemDataRole.UserRole)
        formatted = json.dumps(
            {
                "id": ev["id"],
                "event_type": ev["event_type"],
                "timestamp": ev["timestamp_str"],
                "description": ev["description"],
                "details": ev["details"],
            },
            indent=2,
        )
        self.detail_text.setPlainText(formatted)

    def _export_logs(self) -> None:
        """Export current filtered audit events to CSV or JSON."""
        if not self._audit_records:
            QMessageBox.information(self, "No Records", "No audit log records available to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Audit Log",
            "boundaryx_audit_log.csv",
            "CSV File (*.csv);;JSON File (*.json)",
        )
        if not file_path:
            return

        try:
            if file_path.lower().endswith(".json"):
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(self._audit_records, f, indent=2, default=str)
            else:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Timestamp", "EventType", "Description", "Details"])
                    for rec in self._audit_records:
                        writer.writerow(
                            [
                                rec["timestamp_str"],
                                rec["event_type"],
                                rec["description"],
                                json.dumps(rec["details"]),
                            ]
                        )

            QMessageBox.information(self, "Export Successful", f"Audit logs exported to:\n{file_path}")
            self.status_message.emit("Audit logs exported")
        except Exception as exc:
            logger.error("Failed to export audit logs: %s", exc)
            QMessageBox.critical(self, "Export Failed", f"Could not export audit logs: {exc}")
