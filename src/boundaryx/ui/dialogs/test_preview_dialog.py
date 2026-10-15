"""Pre-execution test plan preview dialog for BoundaryX.

Presents a pre-flight execution summary, validating in-scope versus out-of-scope targets,
flagging mutating HTTP methods, and enforcing safety controls before test dispatch.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from boundaryx.ui.components.status_badge import StatusBadge
from boundaryx.ui.resources.styles import apply_button_class, apply_label_class
from boundaryx.ui.resources.themes import get_current_palette

if TYPE_CHECKING:
    from boundaryx.security.scope import ScopeManager

logger = logging.getLogger(__name__)

UNSAFE_HTTP_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


class TestPreviewDialog(QDialog):
    """Modal pre-flight review dialog displaying planned test cases before execution."""

    __test__ = False

    run_confirmed = Signal(list)

    def __init__(
        self,
        test_cases: list[dict[str, Any]],
        scope_manager: ScopeManager | None = None,
        default_rate_limit: int = 10,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the TestPreviewDialog.

        Args:
            test_cases: List of test case definition dictionaries.
            scope_manager: Optional ScopeManager instance to validate URLs against boundaries.
            default_rate_limit: Configured rate limit in requests/sec.
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._raw_test_cases = test_cases
        self._scope_manager = scope_manager
        self._default_rate_limit = default_rate_limit

        self._evaluated_cases: list[dict[str, Any]] = []
        self._in_scope_count = 0
        self._out_of_scope_count = 0
        self._unsafe_method_count = 0

        self.setWindowTitle("Pre-Flight Test Execution Plan")
        self.setMinimumSize(880, 560)
        self.setModal(True)

        self._evaluate_test_cases()
        self._init_ui()
        self._populate_table()

    def _evaluate_test_cases(self) -> None:
        """Inspect all test cases for scope conformance and method safety."""
        self._evaluated_cases.clear()
        self._in_scope_count = 0
        self._out_of_scope_count = 0
        self._unsafe_method_count = 0

        for tc in self._raw_test_cases:
            item = dict(tc)
            url = item.get("url") or item.get("target_url") or ""
            method = str(item.get("http_method") or item.get("method") or "GET").upper()
            rate_limit = item.get("rate_limit", self._default_rate_limit)

            # Determine scope status
            if "is_in_scope" in item:
                in_scope = bool(item["is_in_scope"])
                scope_reason = item.get("scope_reason", "Pre-validated")
            elif self._scope_manager and url:
                in_scope, scope_reason = self._scope_manager.is_in_scope(url)
            else:
                in_scope = True
                scope_reason = "No scope manager provided"

            if in_scope:
                self._in_scope_count += 1
            else:
                self._out_of_scope_count += 1

            if method in UNSAFE_HTTP_METHODS:
                self._unsafe_method_count += 1

            item["method"] = method
            item["url"] = url
            item["in_scope"] = in_scope
            item["scope_reason"] = scope_reason
            item["rate_limit"] = rate_limit

            self._evaluated_cases.append(item)

    def _init_ui(self) -> None:
        """Construct preview layout, metric summaries, warnings, and table."""
        palette = get_current_palette()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        # Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)

        title_label = QLabel("Test Execution Plan & Boundary Pre-Flight Check")
        apply_label_class(title_label, "title")
        title_label.setStyleSheet("font-size: 18px; font-weight: 700;")

        subtitle_label = QLabel(
            "Review target endpoints, HTTP methods, authorization assumptions, and rate limits before firing requests."
        )
        apply_label_class(subtitle_label, "subtitle")

        header_layout.addWidget(title_label)
        header_layout.addWidget(subtitle_label)
        layout.addLayout(header_layout)

        # Summary Metrics Bar
        metrics_frame = QFrame()
        metrics_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {palette.surface};
                border: 1px solid {palette.border};
                border-radius: 8px;
                padding: 10px 14px;
            }}
        """)
        metrics_layout = QHBoxLayout(metrics_frame)
        metrics_layout.setContentsMargins(8, 6, 8, 6)

        total_cases = len(self._evaluated_cases)
        metrics_layout.addWidget(self._make_stat_pill("Total Tests", str(total_cases), palette.accent))
        metrics_layout.addWidget(self._make_stat_pill("In-Scope", str(self._in_scope_count), palette.success))

        out_color = palette.danger if self._out_of_scope_count > 0 else palette.text_muted
        metrics_layout.addWidget(self._make_stat_pill("Out-of-Scope", str(self._out_of_scope_count), out_color))

        unsafe_color = palette.warning if self._unsafe_method_count > 0 else palette.text_muted
        metrics_layout.addWidget(self._make_stat_pill("Mutating Methods", str(self._unsafe_method_count), unsafe_color))

        metrics_layout.addStretch()
        layout.addWidget(metrics_frame)

        # Unsafe Method Alert Banner (if mutating methods exist)
        if self._unsafe_method_count > 0:
            warning_banner = QFrame()
            warning_banner.setStyleSheet(f"""
                QFrame {{
                    background-color: rgba(245, 158, 11, 0.12);
                    border: 1px solid {palette.warning};
                    border-radius: 6px;
                    padding: 8px 12px;
                }}
            """)
            w_layout = QHBoxLayout(warning_banner)
            w_layout.setContentsMargins(6, 4, 6, 4)

            w_icon = QLabel("⚠️")
            w_icon.setStyleSheet("font-size: 16px;")
            w_text = QLabel(
                f"<b>Warning:</b> Plan includes <b>{self._unsafe_method_count}</b> unsafe mutating requests "
                "(POST, PUT, DELETE, PATCH). Executing these requests may alter or remove remote server state."
            )
            w_text.setWordWrap(True)
            w_text.setStyleSheet(f"color: {palette.text_primary}; font-size: 12px;")

            w_layout.addWidget(w_icon)
            w_layout.addWidget(w_text, 1)
            layout.addWidget(warning_banner)

        # Out of Scope Alert Banner (if out of scope items exist)
        if self._out_of_scope_count > 0:
            scope_banner = QFrame()
            scope_banner.setStyleSheet(f"""
                QFrame {{
                    background-color: rgba(239, 68, 68, 0.12);
                    border: 1px solid {palette.danger};
                    border-radius: 6px;
                    padding: 8px 12px;
                }}
            """)
            s_layout = QHBoxLayout(scope_banner)
            s_layout.setContentsMargins(6, 4, 6, 4)

            s_icon = QLabel("🛡️")
            s_icon.setStyleSheet("font-size: 16px;")
            s_text = QLabel(
                f"<b>Boundary Notice:</b> <b>{self._out_of_scope_count}</b> test cases target out-of-scope "
                "endpoints and will be safely skipped during execution."
            )
            s_text.setWordWrap(True)
            s_text.setStyleSheet(f"color: {palette.text_primary}; font-size: 12px;")

            s_layout.addWidget(s_icon)
            s_layout.addWidget(s_text, 1)
            layout.addWidget(scope_banner)

        # Table of Test Cases
        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels(
            [
                "#",
                "Test Case Name",
                "Method",
                "Target URL",
                "Scope Status",
                "Rate Limit",
            ]
        )
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout.addWidget(self._table, 1)

        # Buttons
        button_box = QDialogButtonBox()
        self._run_button = button_box.addButton(
            "Execute Tests",
            QDialogButtonBox.ButtonRole.AcceptRole,
        )
        self._cancel_button = button_box.addButton(
            "Cancel",
            QDialogButtonBox.ButtonRole.RejectRole,
        )
        apply_button_class(self._run_button, "primary")
        apply_button_class(self._cancel_button, "secondary")

        button_box.accepted.connect(self._on_confirm_run)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _make_stat_pill(self, label: str, value: str, color: str) -> QWidget:
        """Construct a lightweight metric pill widget."""
        w = QWidget()
        pill_layout = QHBoxLayout(w)
        pill_layout.setContentsMargins(6, 2, 6, 2)
        pill_layout.setSpacing(6)

        lbl = QLabel(f"{label}:")
        lbl.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: 500;")

        val = QLabel(value)
        val.setStyleSheet(f"color: {color}; font-size: 13px; font-weight: 700;")

        pill_layout.addWidget(lbl)
        pill_layout.addWidget(val)
        return w

    def _populate_table(self) -> None:
        """Populate the table with evaluated test cases."""
        self._table.setRowCount(len(self._evaluated_cases))

        for row, tc in enumerate(self._evaluated_cases):
            # Index
            idx_item = QTableWidgetItem(str(row + 1))
            idx_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, idx_item)

            # Name
            name_item = QTableWidgetItem(str(tc.get("name") or f"Test Case {row + 1}"))
            self._table.setItem(row, 1, name_item)

            # Method
            method = tc.get("method", "GET")
            method_item = QTableWidgetItem(method)
            method_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 2, method_item)

            # URL
            url_item = QTableWidgetItem(str(tc.get("url", "")))
            self._table.setItem(row, 3, url_item)

            # Scope Status Badge
            in_scope = tc.get("in_scope", True)
            badge_widget = StatusBadge(
                "IN-SCOPE" if in_scope else "OUT-OF-SCOPE",
                variant="ALLOW" if in_scope else "DENY",
            )
            badge_widget.setToolTip(tc.get("scope_reason", ""))
            cell_widget = QWidget()
            cw_layout = QHBoxLayout(cell_widget)
            cw_layout.setContentsMargins(4, 2, 4, 2)
            cw_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cw_layout.addWidget(badge_widget)
            self._table.setCellWidget(row, 4, cell_widget)

            # Rate Limit
            rate_item = QTableWidgetItem(f"{tc.get('rate_limit', self._default_rate_limit)} req/s")
            rate_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 5, rate_item)

    def _on_confirm_run(self) -> None:
        """Emit executable tests and accept dialog."""
        executable = [tc for tc in self._evaluated_cases if tc.get("in_scope", True)]
        self.run_confirmed.emit(executable)
        self.accept()

    def get_evaluated_test_cases(self) -> list[dict[str, Any]]:
        """Return all evaluated test cases."""
        return list(self._evaluated_cases)

    def get_executable_test_cases(self) -> list[dict[str, Any]]:
        """Return only in-scope executable test cases."""
        return [tc for tc in self._evaluated_cases if tc.get("in_scope", True)]
