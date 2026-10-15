"""Evidence Vault and Cryptographic Integrity Inspection page for BoundaryX.

Provides immutable evidence management, cryptographic SHA-256 hash verification,
request/response snapshot inspection with raw/redacted views, and tampering detection.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
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
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.infrastructure.database.models import EvidenceModel
from boundaryx.infrastructure.database.repositories import EvidenceRepository
from boundaryx.security.redaction import RedactionEngine
from boundaryx.ui.components.badges import create_badge
from boundaryx.ui.resources.styles import apply_button_class

logger = logging.getLogger(__name__)


class EvidenceVaultPage(QWidget):
    """Cryptographic evidence vault and audit proof inspector."""

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
        self.redaction_engine = RedactionEngine()
        self.is_redacted = False

        self._evidence_records: list[dict[str, Any]] = []
        self._current_evidence: dict[str, Any] | None = None

        self._init_ui()

    def set_project(self, project_id: str | None) -> None:
        """Switch current active project and reload evidence records."""
        self.project_id = project_id
        self.load_evidence()

    def _init_ui(self) -> None:
        """Construct UI layout and inspection widgets."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header bar
        header_layout = QHBoxLayout()
        title_label = QLabel("Evidence Vault & Cryptographic Proofs")
        title_label.setStyleSheet("font-size: 18px; font-weight: 700;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        self.verify_all_btn = QPushButton("Verify Integrity")
        apply_button_class(self.verify_all_btn, "primary")
        self.verify_all_btn.clicked.connect(self._verify_selected_or_all)
        header_layout.addWidget(self.verify_all_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.load_evidence)
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

        filter_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search evidence title, SHA-256 hash, or snapshot text...")
        self.search_input.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.search_input, stretch=2)

        filter_layout.addWidget(QLabel("Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["All", "REQUEST_RESPONSE", "POLICY_EVALUATION", "LOG_ENTRY", "IMPORTED_TRAFFIC"])
        self.type_combo.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.type_combo)

        self.count_label = QLabel("0 records")
        self.count_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        filter_layout.addWidget(self.count_label)

        layout.addWidget(filter_frame)

        # Splitter: Table above, Snapshot Inspector below
        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter, stretch=1)

        # Evidence Table
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Evidence Type", "Title", "Timestamp (UTC)", "SHA-256 Hash", "Integrity State"]
        )
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self.table)

        # Detail Inspector
        inspector_container = QWidget()
        ins_layout = QVBoxLayout(inspector_container)
        ins_layout.setContentsMargins(0, 8, 0, 0)
        ins_layout.setSpacing(8)

        ins_header = QHBoxLayout()
        self.ins_title = QLabel("Snapshot Inspector")
        self.ins_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #f8fafc;")
        ins_header.addWidget(self.ins_title)
        ins_header.addStretch()

        self.redact_btn = QPushButton("Redact View: OFF")
        self.redact_btn.setCheckable(True)
        self.redact_btn.clicked.connect(self._toggle_redaction)
        ins_header.addWidget(self.redact_btn)

        ins_layout.addLayout(ins_header)

        # Tab Widget for Snapshot / Metadata
        self.tabs = QTabWidget()

        # Request Snapshot Tab
        req_widget = QWidget()
        rw_layout = QVBoxLayout(req_widget)
        self.req_text = QTextEdit()
        self.req_text.setReadOnly(True)
        self.req_text.setFontFamily("Cascadia Code, Consolas, monospace")
        rw_layout.addWidget(self.req_text)
        self.tabs.addTab(req_widget, "Request Snapshot")

        # Response Snapshot Tab
        res_widget = QWidget()
        res_layout = QVBoxLayout(res_widget)
        self.res_text = QTextEdit()
        self.res_text.setReadOnly(True)
        self.res_text.setFontFamily("Cascadia Code, Consolas, monospace")
        res_layout.addWidget(self.res_text)
        self.tabs.addTab(res_widget, "Response Snapshot")

        # Policy & Context Tab
        ctx_widget = QWidget()
        ctx_layout = QVBoxLayout(ctx_widget)
        self.ctx_text = QTextEdit()
        self.ctx_text.setReadOnly(True)
        self.ctx_text.setFontFamily("Cascadia Code, Consolas, monospace")
        ctx_layout.addWidget(self.ctx_text)
        self.tabs.addTab(ctx_widget, "Evaluation Context")

        ins_layout.addWidget(self.tabs)
        splitter.addWidget(inspector_container)
        splitter.setSizes([380, 360])

    def load_evidence(self) -> None:
        """Fetch all evidence records for the active project."""
        if not self.project_id:
            self._evidence_records = []
            self.table.setRowCount(0)
            self.count_label.setText("No active project")
            return

        try:
            with self.db_manager.get_session() as session:
                repo = EvidenceRepository(session)
                records: list[EvidenceModel] = repo.list_by_project(session, self.project_id)

                self._evidence_records = []
                for ev in records:
                    self._evidence_records.append(
                        {
                            "id": ev.id,
                            "type": ev.evidence_type,
                            "title": ev.title,
                            "description": ev.description or "",
                            "timestamp": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                            "hash": ev.content_hash,
                            "request_snapshot": ev.request_snapshot or {},
                            "response_snapshot": ev.response_snapshot or {},
                            "policy_snapshot": ev.policy_eval_snapshot or {},
                            "identity_context": ev.identity_context or {},
                            "verified": None,  # None = not verified yet in this session
                        }
                    )

            self._apply_filters()
        except Exception as exc:
            logger.error("Failed to load evidence: %s", exc)

    def _apply_filters(self) -> None:
        """Filter evidence by search query and type."""
        query = self.search_input.text().strip().lower()
        selected_type = self.type_combo.currentText()

        filtered: list[dict[str, Any]] = []
        for ev in self._evidence_records:
            if selected_type != "All" and ev["type"] != selected_type:
                continue
            if query:
                combined = f"{ev['title']} {ev['hash']} {json.dumps(ev['request_snapshot'])}".lower()
                if query not in combined:
                    continue
            filtered.append(ev)

        self._render_table(filtered)

    def _render_table(self, records: list[dict[str, Any]]) -> None:
        """Render evidence rows."""
        self.table.setRowCount(len(records))
        self.count_label.setText(f"{len(records)} of {len(self._evidence_records)} records")

        for row, ev in enumerate(records):
            # Type
            type_item = QTableWidgetItem(ev["type"])
            type_item.setData(Qt.ItemDataRole.UserRole, ev)
            self.table.setItem(row, 0, type_item)

            # Title
            self.table.setItem(row, 1, QTableWidgetItem(ev["title"]))

            # Timestamp
            ts_item = QTableWidgetItem(ev["timestamp"])
            ts_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 2, ts_item)

            # SHA-256 Hash
            hash_preview = f"{ev['hash'][:16]}..." if len(ev["hash"]) > 16 else ev["hash"]
            hash_item = QTableWidgetItem(hash_preview)
            hash_item.setToolTip(ev["hash"])
            hash_item.setFont(self.font())
            self.table.setItem(row, 3, hash_item)

            # Integrity State
            ver_status = ev["verified"]
            if ver_status is True:
                badge = create_badge("VERIFIED", "#064e3b", "#34d399", "#059669")
            elif ver_status is False:
                badge = create_badge("TAMPERED", "#7f1d1d", "#f87171", "#dc2626")
            else:
                badge = create_badge("STORED", "#1e293b", "#94a3b8", "#475569")
            self.table.setCellWidget(row, 4, badge)

    def _on_selection_changed(self) -> None:
        """Update snapshot view upon item selection."""
        items = self.table.selectedItems()
        if not items:
            self._current_evidence = None
            self.req_text.clear()
            self.res_text.clear()
            self.ctx_text.clear()
            return

        row = items[0].row()
        item = self.table.item(row, 0)
        if not item:
            return

        ev = item.data(Qt.ItemDataRole.UserRole)
        self._current_evidence = ev
        self.ins_title.setText(f"Snapshot: {ev['title']} (SHA-256: {ev['hash']})")
        self._render_snapshots()

    def _render_snapshots(self) -> None:
        """Render request, response, and context JSON."""
        if not self._current_evidence:
            return

        ev = self._current_evidence
        req_str = json.dumps(ev.get("request_snapshot", {}), indent=2)
        res_str = json.dumps(ev.get("response_snapshot", {}), indent=2)
        ctx_data = {
            "policy_snapshot": ev.get("policy_snapshot", {}),
            "identity_context": ev.get("identity_context", {}),
            "description": ev.get("description", ""),
        }
        ctx_str = json.dumps(ctx_data, indent=2)

        if self.is_redacted:
            req_str = self.redaction_engine.redact_text(req_str)
            res_str = self.redaction_engine.redact_text(res_str)
            ctx_str = self.redaction_engine.redact_text(ctx_str)

        self.req_text.setPlainText(req_str)
        self.res_text.setPlainText(res_str)
        self.ctx_text.setPlainText(ctx_str)

    def _toggle_redaction(self) -> None:
        """Toggle secret redaction for snapshot displays."""
        self.is_redacted = self.redact_btn.isChecked()
        self.redact_btn.setText("Redact View: ON" if self.is_redacted else "Redact View: OFF")
        self._render_snapshots()

    def _verify_selected_or_all(self) -> None:
        """Recompute cryptographic SHA-256 digests and verify integrity."""
        if not self._evidence_records:
            QMessageBox.information(self, "No Evidence", "No evidence records available to verify.")
            return

        verified_count = 0
        tampered_count = 0

        with self.db_manager.get_session() as session:
            repo = EvidenceRepository(session)
            for ev in self._evidence_records:
                is_valid = repo.verify_hash(session, ev["id"])
                ev["verified"] = is_valid
                if is_valid:
                    verified_count += 1
                else:
                    tampered_count += 1

        self._apply_filters()

        if tampered_count > 0:
            QMessageBox.warning(
                self,
                "Integrity Warning",
                f"Verification Completed:\n{verified_count} records VERIFIED.\n{tampered_count} records MISMATCHED / TAMPERED!",
            )
        else:
            QMessageBox.information(
                self,
                "Integrity Verified",
                f"All {verified_count} evidence records have valid cryptographic SHA-256 integrity digests.",
            )
