"""Findings triage and security defect management page for BoundaryX.

Provides finding triage, severity badges, confidence breakdowns, reproduction details,
evidence snapshot links, reviewer notes editing, and lifecycle status transitions.
"""

from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGroupBox,
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

from boundaryx.domain.findings.models import FindingStatus
from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.infrastructure.database.models import FindingModel
from boundaryx.infrastructure.database.repositories import EvidenceRepository, FindingRepository
from boundaryx.security.audit import FINDING_STATUS_CHANGED, AuditLogger
from boundaryx.ui.components.badges import SeverityBadge, StatusBadge
from boundaryx.ui.resources.styles import apply_button_class

logger = logging.getLogger(__name__)


class FindingsPage(QWidget):
    """Authorization findings and defect review interface."""

    status_message = Signal(str)

    def __init__(
        self,
        db_manager: DatabaseManager,
        project_id: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.db_manager = db_manager
        self.project_id = project_id
        self._findings: list[dict[str, Any]] = []
        self._current_finding: dict[str, Any] | None = None

        self._init_ui()

    def set_project(self, project_id: str | None) -> None:
        """Switch current active project context and reload findings."""
        self.project_id = project_id
        self.load_findings()

    def _init_ui(self) -> None:
        """Initialize UI layout and subpanels."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header bar
        header_layout = QHBoxLayout()
        title_label = QLabel("Security Defect Findings")
        title_label.setStyleSheet("font-size: 18px; font-weight: 700;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.load_findings)
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

        filter_layout.addWidget(QLabel("Filter:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search title, endpoint, or category...")
        self.search_input.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.search_input, stretch=2)

        filter_layout.addWidget(QLabel("Severity:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])
        self.severity_combo.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.severity_combo)

        filter_layout.addWidget(QLabel("Status:"))
        self.status_combo = QComboBox()
        self.status_combo.addItems(["All", "NEW", "CONFIRMED", "NEEDS_REVIEW", "FALSE_POSITIVE", "FIXED", "REOPENED"])
        self.status_combo.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.status_combo)

        self.count_label = QLabel("0 findings")
        self.count_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        filter_layout.addWidget(self.count_label)

        layout.addWidget(filter_frame)

        # Splitter: Findings Table (top) and Detail View (bottom)
        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter, stretch=1)

        # Findings Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Severity", "Title", "Category", "Affected Endpoint", "Identity", "Expected vs Observed", "Status"]
        )
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self.table)

        # Detail View
        detail_container = QWidget()
        detail_layout = QVBoxLayout(detail_container)
        detail_layout.setContentsMargins(0, 6, 0, 0)
        detail_layout.setSpacing(8)

        # Detail action buttons
        actions_bar = QHBoxLayout()
        self.detail_title = QLabel("Finding Details")
        self.detail_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #f8fafc;")
        actions_bar.addWidget(self.detail_title)
        actions_bar.addStretch()

        self.btn_confirm = QPushButton("Mark Confirmed")
        apply_button_class(self.btn_confirm, "danger")
        self.btn_confirm.clicked.connect(lambda: self._update_status(FindingStatus.CONFIRMED.value))
        actions_bar.addWidget(self.btn_confirm)

        self.btn_fp = QPushButton("Mark False Positive")
        self.btn_fp.clicked.connect(lambda: self._update_status(FindingStatus.FALSE_POSITIVE.value))
        actions_bar.addWidget(self.btn_fp)

        self.btn_fixed = QPushButton("Mark Fixed")
        apply_button_class(self.btn_fixed, "primary")
        self.btn_fixed.clicked.connect(lambda: self._update_status(FindingStatus.FIXED.value))
        actions_bar.addWidget(self.btn_fixed)

        self.btn_reopen = QPushButton("Reopen")
        self.btn_reopen.clicked.connect(lambda: self._update_status(FindingStatus.REOPENED.value))
        actions_bar.addWidget(self.btn_reopen)

        detail_layout.addLayout(actions_bar)

        # Horizontal Splitter in Detail: Left = Reproduction & Confidence, Right = Evidence & Notes
        detail_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Detail Panel
        left_panel = QWidget()
        lp_layout = QVBoxLayout(left_panel)
        lp_layout.setContentsMargins(0, 0, 0, 0)
        lp_layout.setSpacing(8)

        repro_box = QGroupBox("Reproduction Steps")
        rb_layout = QVBoxLayout(repro_box)
        self.repro_text = QTextEdit()
        self.repro_text.setReadOnly(True)
        self.repro_text.setFontFamily("Consolas, monospace")
        rb_layout.addWidget(self.repro_text)
        lp_layout.addWidget(repro_box, stretch=1)

        conf_box = QGroupBox("Confidence Breakdown & Risk Indicators")
        cb_layout = QVBoxLayout(conf_box)
        self.conf_text = QTextEdit()
        self.conf_text.setReadOnly(True)
        cb_layout.addWidget(self.conf_text)
        lp_layout.addWidget(conf_box, stretch=1)

        detail_splitter.addWidget(left_panel)

        # Right Detail Panel
        right_panel = QWidget()
        rp_layout = QVBoxLayout(right_panel)
        rp_layout.setContentsMargins(0, 0, 0, 0)
        rp_layout.setSpacing(8)

        ev_box = QGroupBox("Linked Evidence Snapshots")
        ev_layout = QVBoxLayout(ev_box)
        self.evidence_list_text = QTextEdit()
        self.evidence_list_text.setReadOnly(True)
        self.evidence_list_text.setFontFamily("Consolas, monospace")
        ev_layout.addWidget(self.evidence_list_text)
        rp_layout.addWidget(ev_box, stretch=1)

        notes_box = QGroupBox("Reviewer Notes & Remediation Guidance")
        nb_layout = QVBoxLayout(notes_box)
        self.notes_edit = QTextEdit()
        nb_layout.addWidget(self.notes_edit)

        save_notes_btn = QPushButton("Save Notes")
        save_notes_btn.clicked.connect(self._save_notes)
        nb_layout.addWidget(save_notes_btn)
        rp_layout.addWidget(notes_box, stretch=1)

        detail_splitter.addWidget(right_panel)
        detail_splitter.setSizes([450, 450])

        detail_layout.addWidget(detail_splitter)
        splitter.addWidget(detail_container)
        splitter.setSizes([400, 350])

    def load_findings(self) -> None:
        """Load all findings from database for active project."""
        if not self.project_id:
            self._findings = []
            self.table.setRowCount(0)
            self.count_label.setText("No active project")
            return

        try:
            with self.db_manager.get_session() as session:
                repo = FindingRepository(session)
                models: list[FindingModel] = repo.list_by_project(session, self.project_id)

                self._findings = []
                for f in models:
                    self._findings.append(
                        {
                            "id": f.id,
                            "title": f.title,
                            "category": f.category,
                            "endpoint": f.affected_endpoint,
                            "identity_name": f.subject_identity.display_name if f.subject_identity else "Unassigned",
                            "expected": f.expected_decision,
                            "observed": f.observed_decision,
                            "severity": f.severity.upper(),
                            "status": f.status.upper(),
                            "reproduction_steps": f.reproduction_steps or [],
                            "confidence_data": f.confidence_data or {},
                            "evidence_ids": f.evidence_ids or [],
                            "reviewer_notes": f.reviewer_notes or "",
                        }
                    )

            self._apply_filters()
        except Exception as exc:
            logger.error("Failed to load findings: %s", exc)

    def _apply_filters(self) -> None:
        """Filter table by search query, severity, and status."""
        query = self.search_input.text().strip().lower()
        selected_sev = self.severity_combo.currentText().upper()
        selected_stat = self.status_combo.currentText().upper()

        filtered: list[dict[str, Any]] = []
        for f in self._findings:
            if selected_sev != "ALL" and f["severity"] != selected_sev:
                continue
            if selected_stat != "ALL" and f["status"] != selected_stat:
                continue
            if query:
                combined = f"{f['title']} {f['endpoint']} {f['category']}".lower()
                if query not in combined:
                    continue
            filtered.append(f)

        self._render_table(filtered)

    def _render_table(self, findings: list[dict[str, Any]]) -> None:
        """Populate findings table widget."""
        self.table.setRowCount(len(findings))
        self.count_label.setText(f"{len(findings)} of {len(self._findings)} findings")

        for row, f in enumerate(findings):
            # Severity
            sev_badge = SeverityBadge(f["severity"])
            self.table.setCellWidget(row, 0, sev_badge)

            # Title
            title_item = QTableWidgetItem(f["title"])
            title_item.setData(Qt.ItemDataRole.UserRole, f)
            self.table.setItem(row, 1, title_item)

            # Category
            self.table.setItem(row, 2, QTableWidgetItem(f["category"]))

            # Endpoint
            self.table.setItem(row, 3, QTableWidgetItem(f["endpoint"]))

            # Identity
            self.table.setItem(row, 4, QTableWidgetItem(f["identity_name"]))

            # Expected vs Observed
            exp_obs = f"{f['expected']} -> {f['observed']}"
            eo_item = QTableWidgetItem(exp_obs)
            eo_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 5, eo_item)

            # Status
            stat_badge = StatusBadge(f["status"])
            self.table.setCellWidget(row, 6, stat_badge)

    def _on_selection_changed(self) -> None:
        """Update detail panel upon selection change."""
        items = self.table.selectedItems()
        if not items:
            self._current_finding = None
            self.repro_text.clear()
            self.conf_text.clear()
            self.evidence_list_text.clear()
            self.notes_edit.clear()
            return

        row = items[0].row()
        item = self.table.item(row, 1)
        if not item:
            return

        f = item.data(Qt.ItemDataRole.UserRole)
        self._current_finding = f
        self.detail_title.setText(f"Finding: {f['title']}")

        # Reproduction steps
        repro = f.get("reproduction_steps", [])
        if isinstance(repro, list):
            self.repro_text.setPlainText("\n".join(f"{i + 1}. {step}" for i, step in enumerate(repro)))
        else:
            self.repro_text.setPlainText(str(repro))

        # Confidence breakdown
        conf = f.get("confidence_data", {})
        level = conf.get("level", "HIGH")
        factors = conf.get("factors", ["Deterministic policy denial expected", "Observed HTTP 200 OK bypass"])
        missing = conf.get("missing_evidence", ["State mutation confirmed"])

        conf_lines = [
            f"Confidence Level: {level}",
            "",
            "Observed Indicators & Factors:",
        ]
        for fact in factors:
            conf_lines.append(f"  • {fact}")
        conf_lines.append("")
        conf_lines.append("Missing or Inconclusive Verifications:")
        for mis in missing:
            conf_lines.append(f"  - {mis}")

        self.conf_text.setPlainText("\n".join(conf_lines))

        # Evidence
        ev_ids = f.get("evidence_ids", [])
        if ev_ids:
            with self.db_manager.get_session() as session:
                ev_repo = EvidenceRepository(session)
                ev_lines = []
                for eid in ev_ids:
                    rec = ev_repo.get_by_id(session, str(eid))
                    if rec:
                        ev_lines.append(f"[{rec.evidence_type}] {rec.title} (SHA-256: {rec.content_hash[:16]}...)")
                self.evidence_list_text.setPlainText("\n".join(ev_lines))
        else:
            self.evidence_list_text.setPlainText("No linked evidence snapshots.")

        # Notes
        self.notes_edit.setPlainText(f.get("reviewer_notes", ""))

    def _update_status(self, new_status: str) -> None:
        """Update lifecycle status of active finding."""
        if not self._current_finding or not self.project_id:
            return

        fid = self._current_finding["id"]
        old_status = self._current_finding["status"]

        try:
            with self.db_manager.get_session() as session:
                repo = FindingRepository(session)
                repo.update_status(session, fid, new_status)

                # Log audit event
                audit = AuditLogger(session)
                audit.log(
                    project_id=self.project_id,
                    event_type=FINDING_STATUS_CHANGED,
                    action=f"Changed finding status from {old_status} to {new_status}",
                    entity_type="FINDING",
                    entity_id=fid,
                    details={"old_status": old_status, "new_status": new_status},
                )

            self.status_message.emit(f"Finding updated to {new_status}")
            self.load_findings()
        except Exception as exc:
            logger.error("Failed updating finding status: %s", exc)
            QMessageBox.critical(self, "Error", f"Could not update status: {exc}")

    def _save_notes(self) -> None:
        """Save reviewer notes to database."""
        if not self._current_finding:
            return

        fid = self._current_finding["id"]
        notes = self.notes_edit.toPlainText().strip()

        try:
            with self.db_manager.get_session() as session:
                repo = FindingRepository(session)
                finding = repo.get_by_id(session, fid)
                if finding:
                    finding.reviewer_notes = notes

            self.status_message.emit("Notes saved successfully")
            QMessageBox.information(self, "Notes Saved", "Reviewer notes have been updated.")
        except Exception as exc:
            logger.error("Failed to save notes: %s", exc)
            QMessageBox.critical(self, "Error", f"Failed saving notes: {exc}")
