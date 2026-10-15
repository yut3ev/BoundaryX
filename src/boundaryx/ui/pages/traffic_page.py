"""Traffic analysis and HTTP capture inspection page for BoundaryX.

Provides HAR 1.2, Raw HTTP, and JSON traffic ingestion, interactive request/response
split inspection, search/filtering, secret redaction toggles, and automated endpoint/identity correlation.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from uuid import UUID

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
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
from boundaryx.infrastructure.database.models import TrafficRecordModel
from boundaryx.infrastructure.database.repositories import (
    ResourceRepository,
    TrafficRecordRepository,
)
from boundaryx.infrastructure.imports.boundaryx_importer import BoundaryXImporter
from boundaryx.infrastructure.imports.har_importer import HarImporter
from boundaryx.infrastructure.imports.raw_http_importer import RawHttpImporter
from boundaryx.security.redaction import RedactionEngine
from boundaryx.ui.components.badges import MethodBadge, StatusCodeBadge
from boundaryx.ui.resources.styles import apply_button_class
from boundaryx.workers.async_worker import run_in_background

logger = logging.getLogger(__name__)


class TrafficPage(QWidget):
    """Traffic inspection, parsing, and correlation page."""

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

        self._traffic_records: list[dict[str, Any]] = []
        self._current_selected_record: dict[str, Any] | None = None

        self._init_ui()

    def set_project(self, project_id: str | None) -> None:
        """Switch current active project context and reload traffic records."""
        self.project_id = project_id
        self.load_traffic()

    def _init_ui(self) -> None:
        """Initialize layout and components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header bar
        header_layout = QHBoxLayout()
        title_label = QLabel("HTTP Traffic Analysis")
        title_label.setStyleSheet("font-size: 18px; font-weight: 700;")
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        self.import_btn = QPushButton("Import Traffic")
        apply_button_class(self.import_btn, "primary")
        self.import_btn.clicked.connect(self._on_import_clicked)
        header_layout.addWidget(self.import_btn)

        self.correlate_btn = QPushButton("Correlate Traffic")
        apply_button_class(self.correlate_btn, "secondary")
        self.correlate_btn.clicked.connect(self._on_correlate_clicked)
        header_layout.addWidget(self.correlate_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.load_traffic)
        header_layout.addWidget(self.refresh_btn)

        layout.addLayout(header_layout)

        # Progress bar (hidden by default)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setTextVisible(False)
        layout.addWidget(self.progress_bar)

        # Filter bar
        filter_frame = QFrame()
        filter_frame.setObjectName("filterBar")
        filter_frame.setStyleSheet(
            "QFrame#filterBar { background-color: #1a1f2c; border: 1px solid #2d354d; border-radius: 6px; padding: 6px; }"
        )
        filter_layout = QHBoxLayout(filter_frame)
        filter_layout.setContentsMargins(8, 6, 8, 6)
        filter_layout.setSpacing(10)

        filter_layout.addWidget(QLabel("Filter:"))

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search URL host or path (regex supported)...")
        self.search_input.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.search_input, stretch=2)

        filter_layout.addWidget(QLabel("Method:"))
        self.method_filter = QComboBox()
        self.method_filter.addItems(["All", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
        self.method_filter.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.method_filter)

        filter_layout.addWidget(QLabel("Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "2xx Success", "3xx Redirect", "4xx Client Error", "5xx Server Error"])
        self.status_filter.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.status_filter)

        self.record_count_label = QLabel("0 records")
        self.record_count_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        filter_layout.addWidget(self.record_count_label)

        layout.addWidget(filter_frame)

        # Splitter: Table on top/left, Details below/right
        self.splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(self.splitter, stretch=1)

        # Traffic table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["#", "Method", "URL", "Status", "Length", "Timing (ms)", "Matched Entity"]
        )
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._on_table_selection_changed)
        self.splitter.addWidget(self.table)

        # Detail pane
        self.detail_widget = QWidget()
        detail_layout = QVBoxLayout(self.detail_widget)
        detail_layout.setContentsMargins(0, 8, 0, 0)
        detail_layout.setSpacing(8)

        detail_header = QHBoxLayout()
        self.detail_title = QLabel("Request & Response Inspector")
        self.detail_title.setStyleSheet("font-weight: 600; color: #f8fafc;")
        detail_header.addWidget(self.detail_title)
        detail_header.addStretch()

        self.redact_btn = QPushButton("Redact Secrets: OFF")
        self.redact_btn.setCheckable(True)
        self.redact_btn.clicked.connect(self._toggle_redaction)
        detail_header.addWidget(self.redact_btn)

        self.copy_curl_btn = QPushButton("Copy cURL")
        self.copy_curl_btn.clicked.connect(self._copy_as_curl)
        detail_header.addWidget(self.copy_curl_btn)

        detail_layout.addLayout(detail_header)

        # Tab widget for split Request / Response
        self.detail_tabs = QTabWidget()

        # Request tab
        request_container = QWidget()
        req_layout = QVBoxLayout(request_container)
        req_layout.setContentsMargins(4, 4, 4, 4)
        req_splitter = QSplitter(Qt.Orientation.Horizontal)

        req_headers_box = QGroupBox("Request Headers")
        req_h_layout = QVBoxLayout(req_headers_box)
        self.req_headers_edit = QTextEdit()
        self.req_headers_edit.setReadOnly(True)
        self.req_headers_edit.setFontFamily("Cascadia Code, Consolas, monospace")
        req_h_layout.addWidget(self.req_headers_edit)
        req_splitter.addWidget(req_headers_box)

        req_body_box = QGroupBox("Request Body")
        req_b_layout = QVBoxLayout(req_body_box)
        self.req_body_edit = QTextEdit()
        self.req_body_edit.setReadOnly(True)
        self.req_body_edit.setFontFamily("Cascadia Code, Consolas, monospace")
        req_b_layout.addWidget(self.req_body_edit)
        req_splitter.addWidget(req_body_box)

        req_splitter.setSizes([300, 500])
        req_layout.addWidget(req_splitter)
        self.detail_tabs.addTab(request_container, "Request")

        # Response tab
        response_container = QWidget()
        res_layout = QVBoxLayout(response_container)
        res_layout.setContentsMargins(4, 4, 4, 4)
        res_splitter = QSplitter(Qt.Orientation.Horizontal)

        res_headers_box = QGroupBox("Response Headers")
        res_h_layout = QVBoxLayout(res_headers_box)
        self.res_headers_edit = QTextEdit()
        self.res_headers_edit.setReadOnly(True)
        self.res_headers_edit.setFontFamily("Cascadia Code, Consolas, monospace")
        res_h_layout.addWidget(self.res_headers_edit)
        res_splitter.addWidget(res_headers_box)

        res_body_box = QGroupBox("Response Body")
        res_b_layout = QVBoxLayout(res_body_box)
        self.res_body_edit = QTextEdit()
        self.res_body_edit.setReadOnly(True)
        self.res_body_edit.setFontFamily("Cascadia Code, Consolas, monospace")
        res_b_layout.addWidget(self.res_body_edit)
        res_splitter.addWidget(res_body_box)

        res_splitter.setSizes([300, 500])
        res_layout.addWidget(res_splitter)
        self.detail_tabs.addTab(response_container, "Response")

        detail_layout.addWidget(self.detail_tabs)
        self.splitter.addWidget(self.detail_widget)
        self.splitter.setSizes([400, 350])

    def load_traffic(self) -> None:
        """Fetch traffic records from SQLite database for active project."""
        if not self.project_id:
            self._traffic_records = []
            self.table.setRowCount(0)
            self.record_count_label.setText("No active project")
            return

        try:
            with self.db_manager.get_session() as session:
                repo = TrafficRecordRepository(session)
                records: list[TrafficRecordModel] = repo.list_by_project(session, self.project_id, limit=2000)

                self._traffic_records = []
                for r in records:
                    self._traffic_records.append(
                        {
                            "id": r.id,
                            "method": r.method,
                            "url": r.url,
                            "status": r.response_status or 0,
                            "request_headers": r.request_headers or {},
                            "request_body": r.request_body or "",
                            "response_headers": r.response_headers or {},
                            "response_body": r.response_body or "",
                            "timing_ms": r.timing_ms or 0.0,
                            "identity_id": r.identity_id,
                            "resource_id": r.resource_id,
                            "identity_name": r.identity.display_name if r.identity else None,
                            "resource_name": r.resource.display_name if r.resource else None,
                        }
                    )

            self._apply_filters()
            self.status_message.emit(f"Loaded {len(self._traffic_records)} traffic records")
        except Exception as exc:
            logger.error("Failed to load traffic records: %s", exc)
            self.status_message.emit(f"Error loading traffic: {exc}")

    def _apply_filters(self) -> None:
        """Filter traffic table based on method, status code, and URL search query."""
        search_query = self.search_input.text().strip()
        selected_method = self.method_filter.currentText()
        selected_status = self.status_filter.currentText()

        pattern = None
        if search_query:
            try:
                pattern = re.compile(search_query, re.IGNORECASE)
            except re.error:
                pattern = None

        filtered: list[dict[str, Any]] = []
        for rec in self._traffic_records:
            # Method filter
            if selected_method != "All" and rec["method"].upper() != selected_method.upper():
                continue

            # Status filter
            code = rec["status"]
            if selected_status == "2xx Success" and not (200 <= code < 300):
                continue
            if selected_status == "3xx Redirect" and not (300 <= code < 400):
                continue
            if selected_status == "4xx Client Error" and not (400 <= code < 500):
                continue
            if selected_status == "5xx Server Error" and not (code >= 500):
                continue

            # Text filter
            if search_query:
                if pattern:
                    if not pattern.search(rec["url"]):
                        continue
                elif search_query.lower() not in rec["url"].lower():
                    continue

            filtered.append(rec)

        self._populate_table(filtered)

    def _populate_table(self, records: list[dict[str, Any]]) -> None:
        """Populate table widget rows."""
        self.table.setRowCount(0)
        self.table.setRowCount(len(records))
        self.record_count_label.setText(f"{len(records)} of {len(self._traffic_records)} records")

        for row, rec in enumerate(records):
            # Index
            idx_item = QTableWidgetItem(str(row + 1))
            idx_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            idx_item.setData(Qt.ItemDataRole.UserRole, rec)
            self.table.setItem(row, 0, idx_item)

            # Method badge
            method_badge = MethodBadge(rec["method"])
            self.table.setCellWidget(row, 1, method_badge)

            # URL
            url_item = QTableWidgetItem(rec["url"])
            self.table.setItem(row, 2, url_item)

            # Status badge
            status_badge = StatusCodeBadge(rec["status"] if rec["status"] > 0 else "-")
            self.table.setCellWidget(row, 3, status_badge)

            # Length
            res_len = len(rec["response_body"].encode("utf-8")) if rec["response_body"] else 0
            len_str = f"{res_len:,} B" if res_len < 1024 else f"{res_len / 1024:.1f} KB"
            len_item = QTableWidgetItem(len_str)
            len_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(row, 4, len_item)

            # Timing
            timing_val = rec["timing_ms"]
            timing_item = QTableWidgetItem(f"{timing_val:.1f}" if timing_val else "-")
            timing_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(row, 5, timing_item)

            # Matched Entity
            matched = rec.get("identity_name") or rec.get("resource_name") or "-"
            match_item = QTableWidgetItem(str(matched))
            self.table.setItem(row, 6, match_item)

    def _on_table_selection_changed(self) -> None:
        """Update inspection pane when selected table row changes."""
        selected_rows = self.table.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        item = self.table.item(row, 0)
        if not item:
            return

        rec = item.data(Qt.ItemDataRole.UserRole)
        self._current_selected_record = rec
        self._render_details(rec)

    def _render_details(self, rec: dict[str, Any] | None) -> None:
        """Render request and response details with redaction applied if enabled."""
        if not rec:
            self.req_headers_edit.clear()
            self.req_body_edit.clear()
            self.res_headers_edit.clear()
            self.res_body_edit.clear()
            return

        # Request Headers
        req_headers = rec.get("request_headers", {})
        req_h_str = "\n".join(f"{k}: {v}" for k, v in req_headers.items())
        if self.is_redacted:
            req_h_str = self.redaction_engine.redact_text(req_h_str)
        self.req_headers_edit.setPlainText(req_h_str)

        # Request Body
        req_b_str = rec.get("request_body", "") or ""
        req_b_str = self._format_body(req_b_str)
        if self.is_redacted:
            req_b_str = self.redaction_engine.redact_text(req_b_str)
        self.req_body_edit.setPlainText(req_b_str)

        # Response Headers
        res_headers = rec.get("response_headers", {})
        res_h_str = "\n".join(f"{k}: {v}" for k, v in res_headers.items())
        if self.is_redacted:
            res_h_str = self.redaction_engine.redact_text(res_h_str)
        self.res_headers_edit.setPlainText(res_h_str)

        # Response Body
        res_b_str = rec.get("response_body", "") or ""
        res_b_str = self._format_body(res_b_str)
        if self.is_redacted:
            res_b_str = self.redaction_engine.redact_text(res_b_str)
        self.res_body_edit.setPlainText(res_b_str)

    def _format_body(self, text: str) -> str:
        """Try pretty-printing JSON if applicable."""
        stripped = text.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            try:
                parsed = json.loads(stripped)
                return json.dumps(parsed, indent=2)
            except Exception:
                pass
        return text

    def _toggle_redaction(self) -> None:
        """Toggle secret redaction mode."""
        self.is_redacted = self.redact_btn.isChecked()
        self.redact_btn.setText("Redact Secrets: ON" if self.is_redacted else "Redact Secrets: OFF")
        self._render_details(self._current_selected_record)

    def _copy_as_curl(self) -> None:
        """Generate and copy cURL command for current request."""
        if not self._current_selected_record:
            return
        rec = self._current_selected_record
        method = rec.get("method", "GET")
        url = rec.get("url", "")
        headers = rec.get("request_headers", {})
        body = rec.get("request_body", "")

        cmd = [f"curl -X {method} '{url}'"]
        for k, v in headers.items():
            cmd.append(f"-H '{k}: {v}'")
        if body and method in {"POST", "PUT", "PATCH"}:
            sanitized_body = body.replace("'", "'\\''")
            cmd.append(f"--data '{sanitized_body}'")

        from PySide6.QtGui import QGuiApplication

        cb = QGuiApplication.clipboard()
        cb.setText(" \\\n  ".join(cmd))
        self.status_message.emit("cURL command copied to clipboard")

    def _on_import_clicked(self) -> None:
        """Open file picker to import traffic archive."""
        if not self.project_id:
            QMessageBox.warning(
                self, "No Active Project", "Please select or create an active project before importing traffic."
            )
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import HTTP Traffic",
            "",
            "All Traffic Files (*.har *.json *.txt *.raw);;HAR Archive (*.har);;JSON File (*.json);;Raw HTTP (*.txt *.raw);;All Files (*.*)",
        )
        if not file_path:
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_message.emit(f"Importing {file_path}...")

        def _worker_task() -> int:
            project_uuid = UUID(self.project_id)
            lower_name = file_path.lower()
            with self.db_manager.get_session() as session:
                if lower_name.endswith(".har"):
                    importer = HarImporter(session=session)
                    result = importer.import_file(file_path, project_uuid)
                elif lower_name.endswith(".json"):
                    importer = BoundaryXImporter(session=session)
                    result = importer.import_file(file_path, project_uuid)
                else:
                    importer = RawHttpImporter(session=session)
                    result = importer.import_file(file_path, project_uuid)
                return result.records_imported

        worker = run_in_background(_worker_task)
        worker.signals.result.connect(self._on_import_success)
        worker.signals.error.connect(self._on_import_error)
        worker.signals.finished.connect(lambda: self.progress_bar.setVisible(False))

    def _on_import_success(self, count: int) -> None:
        """Handle successful traffic import."""
        self.load_traffic()
        QMessageBox.information(
            self,
            "Import Successful",
            f"Successfully imported {count} traffic records into the project.",
        )

    def _on_import_error(self, err_title: str, err_details: str) -> None:
        """Handle traffic import error."""
        logger.error("Import error: %s\n%s", err_title, err_details)
        QMessageBox.critical(
            self,
            "Import Failed",
            f"Failed to import traffic file:\n{err_title}",
        )

    def _on_correlate_clicked(self) -> None:
        """Analyze loaded traffic to correlate candidate identities and resources."""
        if not self._traffic_records:
            QMessageBox.information(self, "No Traffic", "No traffic records available to correlate.")
            return

        endpoints: dict[str, set[str]] = {}
        auth_tokens: dict[str, str] = {}

        for rec in self._traffic_records:
            url = rec.get("url", "")
            method = rec.get("method", "GET").upper()
            # Path extraction
            from urllib.parse import urlparse

            parsed = urlparse(url)
            path = parsed.path or "/"

            # Normalize path variables like /orders/123 -> /orders/{id}
            norm_path = re.sub(r"/\d+", "/{id}", path)
            norm_path = re.sub(r"/[a-f0-9\-]{36}", "/{uuid}", norm_path)

            if norm_path not in endpoints:
                endpoints[norm_path] = set()
            endpoints[norm_path].add(method)

            # Inspect headers for auth tokens
            headers = rec.get("request_headers", {})
            for h_name, h_val in headers.items():
                lower_h = h_name.lower()
                if lower_h == "authorization":
                    token_preview = h_val[:20] + "..." if len(h_val) > 20 else h_val
                    auth_tokens[token_preview] = h_val
                elif lower_h == "cookie" and "session" in h_val.lower():
                    token_preview = h_val[:25] + "..."
                    auth_tokens[token_preview] = h_val

        msg = (
            f"Traffic Correlation Analysis:\n\n"
            f"Discovered Endpoints: {len(endpoints)}\n"
            f"Candidate Auth Identities: {len(auth_tokens)}\n\n"
            f"Would you like to register these candidate endpoints as Resources in your project?"
        )

        reply = QMessageBox.question(
            self,
            "Correlate Traffic Results",
            msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes and self.project_id:
            try:
                with self.db_manager.get_session() as session:
                    res_repo = ResourceRepository(session)
                    created_count = 0
                    for path, methods in endpoints.items():
                        for m in methods:
                            name = f"{m} {path}"
                            res_repo.create(
                                session=session,
                                project_id=self.project_id,
                                display_name=name,
                                resource_type="API_ENDPOINT",
                                path=path,
                                method=m,
                            )
                            created_count += 1
                QMessageBox.information(
                    self,
                    "Resources Registered",
                    f"Registered {created_count} candidate resources from traffic.",
                )
            except Exception as exc:
                QMessageBox.warning(self, "Correlation Error", f"Failed to persist resources: {exc}")
