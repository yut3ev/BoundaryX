"""HTTP Request and Response inspection code viewer component for BoundaryX.

Provides split or tabbed viewing of HTTP requests and responses, JSON formatting,
large body truncation safeguards, syntax inspection, and cURL export.
"""

from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from boundaryx.ui.resources.styles import apply_button_class
from boundaryx.ui.resources.themes import get_current_palette


class HttpViewer(QWidget):
    """High-contrast HTTP Request and Response inspector widget.

    Supports split and tabbed modes, JSON auto-formatting, header inspection,
    response truncation safeguards, and clipboard exports.
    """

    MAX_DISPLAY_BYTES = 512 * 1024  # 512 KB safeguard limit

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the HttpViewer widget."""
        super().__init__(parent)

        self._raw_request_headers: str = ""
        self._raw_request_body: str = ""
        self._raw_response_headers: str = ""
        self._raw_response_body: str = ""
        self._http_method: str = "GET"
        self._http_url: str = ""
        self._status_code: int | None = None

        self._init_ui()

    def _init_ui(self) -> None:
        """Construct the UI layout and controls."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(6)

        # Toolbar
        toolbar = QFrame()
        toolbar.setObjectName("httpViewerToolbar")
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(8, 6, 8, 6)
        toolbar_layout.setSpacing(8)

        # Status & Method indicator
        self._method_badge = QLabel("GET")
        self._method_badge.setObjectName("httpMethodBadge")
        self._method_badge.setStyleSheet(
            "background-color: #0c2b42; color: #38bdf8; font-weight: 700; "
            "padding: 2px 8px; border-radius: 4px; font-size: 11px;"
        )
        toolbar_layout.addWidget(self._method_badge)

        self._status_badge = QLabel("---")
        self._status_badge.setObjectName("httpStatusBadge")
        self._status_badge.setStyleSheet(
            "background-color: #1e293b; color: #94a3b8; font-weight: 700; "
            "padding: 2px 8px; border-radius: 4px; font-size: 11px;"
        )
        toolbar_layout.addWidget(self._status_badge)

        self._url_label = QLabel("No HTTP transaction loaded")
        self._url_label.setObjectName("httpUrlLabel")
        self._url_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar_layout.addWidget(self._url_label)

        # View Mode Toggle (Tabbed vs Split)
        self._tab_mode_btn = QRadioButton("Tabs")
        self._tab_mode_btn.setChecked(True)
        self._split_mode_btn = QRadioButton("Split")
        self._mode_group = QButtonGroup(self)
        self._mode_group.addButton(self._tab_mode_btn, 0)
        self._mode_group.addButton(self._split_mode_btn, 1)
        self._mode_group.idClicked.connect(self._on_mode_toggled)

        toolbar_layout.addWidget(self._tab_mode_btn)
        toolbar_layout.addWidget(self._split_mode_btn)

        # Action Buttons
        self._copy_curl_btn = QPushButton("Copy cURL")
        apply_button_class(self._copy_curl_btn, "ghost")
        self._copy_curl_btn.clicked.connect(self.copy_as_curl)
        toolbar_layout.addWidget(self._copy_curl_btn)

        self._copy_req_btn = QPushButton("Copy Request")
        apply_button_class(self._copy_req_btn, "ghost")
        self._copy_req_btn.clicked.connect(self.copy_request)
        toolbar_layout.addWidget(self._copy_req_btn)

        self._copy_resp_btn = QPushButton("Copy Response")
        apply_button_class(self._copy_resp_btn, "ghost")
        self._copy_resp_btn.clicked.connect(self.copy_response)
        toolbar_layout.addWidget(self._copy_resp_btn)

        main_layout.addWidget(toolbar)

        # Stack to switch between Tabbed and Split view
        self._view_stack = QStackedWidget()

        # 1. Tabbed View
        self._tabs = QTabWidget()
        self._req_tab = self._create_pane("Request")
        self._resp_tab = self._create_pane("Response")
        self._tabs.addTab(self._req_tab["widget"], "Request")
        self._tabs.addTab(self._resp_tab["widget"], "Response")
        self._view_stack.addWidget(self._tabs)

        # 2. Split View
        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._split_req_pane = self._create_pane("Request", is_split=True)
        self._split_resp_pane = self._create_pane("Response", is_split=True)
        self._splitter.addWidget(self._split_req_pane["widget"])
        self._splitter.addWidget(self._split_resp_pane["widget"])
        self._splitter.setSizes([500, 500])
        self._view_stack.addWidget(self._splitter)

        main_layout.addWidget(self._view_stack)

    def _create_pane(self, title: str, is_split: bool = False) -> dict[str, Any]:
        """Create a request or response sub-pane with headers and body."""
        pane = QWidget()
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        if is_split:
            header_bar = QLabel(f"<b>{title.upper()}</b>")
            header_bar.setStyleSheet("font-size: 11px; color: #94a3b8; padding: 2px;")
            layout.addWidget(header_bar)

        # Warning banner for truncated bodies
        banner = QLabel("")
        banner.setObjectName(f"{title.lower()}Banner")
        banner.setStyleSheet(
            "background-color: #362208; color: #fde047; border: 1px solid #b45309; "
            "border-radius: 4px; padding: 4px 8px; font-size: 11px; font-weight: 600;"
        )
        banner.setVisible(False)
        layout.addWidget(banner)

        # Sub-splitter for Headers (top) and Body (bottom)
        sub_splitter = QSplitter(Qt.Orientation.Vertical)

        # Headers Editor
        headers_frame = QFrame()
        headers_layout = QVBoxLayout(headers_frame)
        headers_layout.setContentsMargins(0, 0, 0, 0)
        headers_layout.setSpacing(2)

        headers_title = QLabel("Headers")
        headers_title.setStyleSheet("font-size: 11px; font-weight: 600; color: #94a3b8;")
        headers_layout.addWidget(headers_title)

        headers_edit = QPlainTextEdit()
        headers_edit.setProperty("codeViewer", "true")
        headers_edit.setReadOnly(True)
        headers_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        headers_edit.setFont(QFont("Consolas", 10))
        headers_layout.addWidget(headers_edit)
        sub_splitter.addWidget(headers_frame)

        # Body Editor
        body_frame = QFrame()
        body_layout = QVBoxLayout(body_frame)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(2)

        body_title = QLabel("Body")
        body_title.setStyleSheet("font-size: 11px; font-weight: 600; color: #94a3b8;")
        body_layout.addWidget(body_title)

        body_edit = QPlainTextEdit()
        body_edit.setProperty("codeViewer", "true")
        body_edit.setReadOnly(True)
        body_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        body_edit.setFont(QFont("Consolas", 10))
        body_layout.addWidget(body_edit)
        sub_splitter.addWidget(body_frame)

        sub_splitter.setSizes([100, 300])
        layout.addWidget(sub_splitter)

        return {
            "widget": pane,
            "banner": banner,
            "headers": headers_edit,
            "body": body_edit,
        }

    def _on_mode_toggled(self, button_id: int) -> None:
        """Switch between Tabbed (0) and Split (1) views."""
        self._view_stack.setCurrentIndex(button_id)
        # Sync content to visible view
        self._refresh_content_views()

    def set_http_data(
        self,
        method: str,
        url: str,
        request_headers: dict[str, Any] | str | None = None,
        request_body: str | bytes | None = None,
        status_code: int | None = None,
        response_headers: dict[str, Any] | str | None = None,
        response_body: str | bytes | None = None,
    ) -> None:
        """Populate the viewer with complete HTTP transaction data.

        Args:
            method: HTTP method (e.g. GET, POST, PUT, DELETE).
            url: Request URL.
            request_headers: Headers dict or formatted string.
            request_body: Raw or string request body.
            status_code: HTTP response status code (e.g. 200, 403).
            response_headers: Headers dict or formatted string.
            response_body: Raw or string response body.
        """
        self._http_method = (method or "GET").upper()
        self._http_url = url or ""
        self._status_code = status_code

        # Format Request Headers
        self._raw_request_headers = self._normalize_headers(request_headers)

        # Format Request Body
        self._raw_request_body = self._normalize_body(request_body)

        # Format Response Headers
        self._raw_response_headers = self._normalize_headers(response_headers)

        # Format Response Body
        self._raw_response_body = self._normalize_body(response_body)

        # Update Toolbar
        self._update_toolbar()

        # Update Panes
        self._refresh_content_views()

    def _update_toolbar(self) -> None:
        """Update toolbar status indicators and method badge."""
        self._method_badge.setText(self._http_method)
        palette = get_current_palette()

        # Method badge styling
        method_colors = {
            "GET": ("#0c2b42", "#38bdf8"),
            "POST": ("#064e3b", "#34d399"),
            "PUT": ("#3b1708", "#fdba74"),
            "PATCH": ("#3b1708", "#fdba74"),
            "DELETE": ("#450a0a", "#fca5a5"),
        }
        bg, fg = method_colors.get(self._http_method, ("#1e293b", palette.text_secondary))
        self._method_badge.setStyleSheet(
            f"background-color: {bg}; color: {fg}; font-weight: 700; "
            f"padding: 2px 8px; border-radius: 4px; font-size: 11px;"
        )

        # Status badge styling
        if self._status_code is not None:
            code = self._status_code
            self._status_badge.setText(str(code))
            if 200 <= code < 300:
                s_bg, s_fg = "#064e3b", "#34d399"
            elif 300 <= code < 400:
                s_bg, s_fg = "#0c2b42", "#38bdf8"
            elif 400 <= code < 500:
                s_bg, s_fg = "#3b1708", "#fdba74"
            else:
                s_bg, s_fg = "#450a0a", "#fca5a5"
            self._status_badge.setStyleSheet(
                f"background-color: {s_bg}; color: {s_fg}; font-weight: 700; "
                f"padding: 2px 8px; border-radius: 4px; font-size: 11px;"
            )
        else:
            self._status_badge.setText("---")
            self._status_badge.setStyleSheet(
                "background-color: #1e293b; color: #94a3b8; font-weight: 700; "
                "padding: 2px 8px; border-radius: 4px; font-size: 11px;"
            )

        self._url_label.setText(self._http_url if self._http_url else "No URL")

    def _normalize_headers(self, headers: dict[str, Any] | str | None) -> str:
        """Format headers into standard HTTP header lines."""
        if not headers:
            return ""
        if isinstance(headers, str):
            return headers
        if isinstance(headers, dict):
            lines = [f"{k}: {v}" for k, v in headers.items()]
            return "\n".join(lines)
        return str(headers)

    def _normalize_body(self, body: str | bytes | None) -> str:
        """Format body text and auto-format JSON if detectable."""
        if body is None:
            return ""
        if isinstance(body, bytes):
            try:
                body_str = body.decode("utf-8")
            except UnicodeDecodeError:
                return f"[Binary data: {len(body)} bytes]"
        else:
            body_str = str(body)

        trimmed = body_str.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                parsed = json.loads(trimmed)
                return json.dumps(parsed, indent=2, ensure_ascii=False)
            except Exception:
                return body_str

        return body_str

    def _format_pane_content(self, pane: dict[str, Any], headers_text: str, body_text: str) -> None:
        """Safely populate a pane with headers and guarded body."""
        pane["headers"].setPlainText(headers_text)

        body_len = len(body_text.encode("utf-8", errors="replace"))
        if body_len > self.MAX_DISPLAY_BYTES:
            display_text = body_text[: self.MAX_DISPLAY_BYTES] + "\n\n... [TRUNCATED DUE TO SIZE] ..."
            size_mb = body_len / (1024 * 1024)
            limit_kb = self.MAX_DISPLAY_BYTES // 1024
            pane["banner"].setText(f"⚠️ Body truncated: displaying {limit_kb} KB of {size_mb:.2f} MB payload")
            pane["banner"].setVisible(True)
            pane["body"].setPlainText(display_text)
        else:
            pane["banner"].setVisible(False)
            pane["body"].setPlainText(body_text)

    def _refresh_content_views(self) -> None:
        """Apply current raw request/response text to all panes."""
        # Tabbed panes
        self._format_pane_content(self._req_tab, self._raw_request_headers, self._raw_request_body)
        self._format_pane_content(self._resp_tab, self._raw_response_headers, self._raw_response_body)

        # Split panes
        self._format_pane_content(self._split_req_pane, self._raw_request_headers, self._raw_request_body)
        self._format_pane_content(self._split_resp_pane, self._raw_response_headers, self._raw_response_body)

    def clear(self) -> None:
        """Reset the viewer to an empty state."""
        self.set_http_data("GET", "", "", "", None, "", "")

    def copy_request(self) -> None:
        """Copy formatted request to system clipboard."""
        raw = f"{self._http_method} {self._http_url}\n{self._raw_request_headers}\n\n{self._raw_request_body}"
        self._copy_to_clipboard(raw)

    def copy_response(self) -> None:
        """Copy formatted response to system clipboard."""
        code_str = f"HTTP/1.1 {self._status_code or 200}\n"
        raw = f"{code_str}{self._raw_response_headers}\n\n{self._raw_response_body}"
        self._copy_to_clipboard(raw)

    def copy_as_curl(self) -> None:
        """Generate and copy equivalent cURL command."""
        curl_parts = [f"curl -X {self._http_method} '{self._http_url}'"]
        for line in self._raw_request_headers.splitlines():
            line = line.strip()
            if line and ":" in line:
                curl_parts.append(f"-H '{line}'")
        if self._raw_request_body and self._http_method in ("POST", "PUT", "PATCH", "DELETE"):
            # Escape single quotes in body
            safe_body = self._raw_request_body.replace("'", "'\\''")
            curl_parts.append(f"--data '{safe_body}'")

        curl_cmd = " \\\n  ".join(curl_parts)
        self._copy_to_clipboard(curl_cmd)

    def _copy_to_clipboard(self, text: str) -> None:
        """Safely copy string to Qt clipboard."""
        clipboard = QGuiApplication.clipboard()
        if clipboard:
            clipboard.setText(text)
