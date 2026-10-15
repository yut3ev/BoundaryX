"""Application Settings and Configuration page for BoundaryX.

Provides configuration tabs for Appearance (theme mode, font scale, density),
Network (timeouts, concurrency, RPS, TLS verification, upstream proxy),
Security (secret redaction rules manager, storage paths),
and Diagnostics (export diagnostic bundle archive).
"""

from __future__ import annotations

import json
import logging
import platform
import sys
import tempfile
import zipfile
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from boundaryx.config.settings import AppSettings, get_settings, set_settings
from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.security.redaction import RedactionEngine
from boundaryx.ui.resources.styles import apply_button_class, generate_stylesheet
from boundaryx.ui.resources.themes import ThemeMode, set_current_theme

logger = logging.getLogger(__name__)


class SettingsPage(QWidget):
    """Application preferences, network parameters, and diagnostic bundle generation."""

    settings_updated = Signal()
    status_message = Signal(str)

    def __init__(
        self,
        db_manager: DatabaseManager,
        settings: AppSettings | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.db_manager = db_manager
        self.settings = settings or get_settings()
        self.redaction_engine = RedactionEngine()

        self._init_ui()
        self._load_from_settings()

    def _init_ui(self) -> None:
        """Construct settings tabs and layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header bar
        header_layout = QHBoxLayout()
        title_label = QLabel("BoundaryX Settings")
        title_label.setStyleSheet("font-size: 18px; font-weight: 700;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        self.save_btn = QPushButton("Save & Apply Settings")
        apply_button_class(self.save_btn, "primary")
        self.save_btn.clicked.connect(self._save_settings)
        header_layout.addWidget(self.save_btn)

        layout.addLayout(header_layout)

        # Tab Widget
        self.tabs = QTabWidget()

        # 1. Appearance Tab
        self.tabs.addTab(self._build_appearance_tab(), "Appearance")

        # 2. Network Tab
        self.tabs.addTab(self._build_network_tab(), "Network & Testing")

        # 3. Security Tab
        self.tabs.addTab(self._build_security_tab(), "Security & Storage")

        # 4. Diagnostics Tab
        self.tabs.addTab(self._build_diagnostics_tab(), "Diagnostics")

        layout.addWidget(self.tabs, stretch=1)

    def _build_appearance_tab(self) -> QWidget:
        """Construct appearance preferences panel."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        form = QFormLayout()
        form.setSpacing(12)

        self.theme_combo = QComboBox()
        self.theme_combo.addItem("Dark (Cybersecurity High Contrast)", "dark")
        self.theme_combo.addItem("Light", "light")
        form.addRow("UI Theme:", self.theme_combo)

        self.font_scale_spinner = QDoubleSpinBox()
        self.font_scale_spinner.setRange(0.7, 2.0)
        self.font_scale_spinner.setSingleStep(0.05)
        self.font_scale_spinner.setValue(1.0)
        form.addRow("Font Scale Factor:", self.font_scale_spinner)

        self.density_combo = QComboBox()
        self.density_combo.addItems(["normal", "compact", "spacious"])
        form.addRow("Table Display Density:", self.density_combo)

        layout.addLayout(form)

        preview_box = QGroupBox("Theme Preview Info")
        pb_layout = QVBoxLayout(preview_box)
        pb_label = QLabel(
            "BoundaryX default dark mode employs a cyber-themed palette with high contrast\n"
            "elements designed to reduce eye strain during extended authorization testing assessments."
        )
        pb_label.setStyleSheet("color: #94a3b8;")
        pb_layout.addWidget(pb_label)
        layout.addWidget(preview_box)

        layout.addStretch()
        return widget

    def _build_network_tab(self) -> QWidget:
        """Construct network timeouts and proxy parameters panel."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        form = QFormLayout()
        form.setSpacing(12)

        self.default_timeout_spinner = QDoubleSpinBox()
        self.default_timeout_spinner.setRange(1.0, 300.0)
        self.default_timeout_spinner.setValue(30.0)
        form.addRow("Default Request Timeout (s):", self.default_timeout_spinner)

        self.connect_timeout_spinner = QDoubleSpinBox()
        self.connect_timeout_spinner.setRange(1.0, 120.0)
        self.connect_timeout_spinner.setValue(10.0)
        form.addRow("Network Connect Timeout (s):", self.connect_timeout_spinner)

        self.rate_limit_spinner = QDoubleSpinBox()
        self.rate_limit_spinner.setRange(0.5, 500.0)
        self.rate_limit_spinner.setValue(20.0)
        form.addRow("Rate Limit (Max RPS):", self.rate_limit_spinner)

        self.concurrency_spinner = QSpinBox()
        self.concurrency_spinner.setRange(1, 100)
        self.concurrency_spinner.setValue(10)
        form.addRow("Max Concurrent Workers:", self.concurrency_spinner)

        self.tls_verify_chk = QCheckBox("Verify TLS/SSL Certificates during active testing")
        self.tls_verify_chk.setChecked(True)
        form.addRow("TLS Verification:", self.tls_verify_chk)

        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("http://127.0.0.1:8080 or socks5://127.0.0.1:9050")
        form.addRow("Upstream Proxy URL:", self.proxy_input)

        layout.addLayout(form)
        layout.addStretch()
        return widget

    def _build_security_tab(self) -> QWidget:
        """Construct secret redaction rules and storage path manager."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # Storage paths group
        paths_group = QGroupBox("Storage & Persistence Paths")
        paths_form = QFormLayout(paths_group)

        self.db_path_label = QLabel(str(self.settings.resolved_db_path))
        self.db_path_label.setStyleSheet("font-family: Consolas, monospace; color: #38bdf8;")
        paths_form.addRow("SQLite Database:", self.db_path_label)

        self.export_dir_label = QLabel(str(self.settings.resolved_export_dir))
        self.export_dir_label.setStyleSheet("font-family: Consolas, monospace; color: #38bdf8;")
        paths_form.addRow("Exports Directory:", self.export_dir_label)

        self.backup_dir_label = QLabel(str(self.settings.resolved_backup_dir))
        self.backup_dir_label.setStyleSheet("font-family: Consolas, monospace; color: #38bdf8;")
        paths_form.addRow("Backups Directory:", self.backup_dir_label)

        layout.addWidget(paths_group)

        # Redaction rules manager group
        redact_group = QGroupBox("Active Secret Redaction Patterns")
        rg_layout = QVBoxLayout(redact_group)

        self.rules_table = QTableWidget(0, 4)
        self.rules_table.setHorizontalHeaderLabels(["Rule Name", "Pattern Type", "Mask Pattern", "Status"])
        self.rules_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.setAlternatingRowColors(True)

        rg_layout.addWidget(self.rules_table)
        layout.addWidget(redact_group, stretch=1)

        self._populate_redaction_rules()
        return widget

    def _populate_redaction_rules(self) -> None:
        """Populate the redaction rules table."""
        rules = [
            ("Bearer Token", "regex", r"Bearer\s+([a-zA-Z0-9_\-\.]+)", True),
            ("Basic Auth", "header_name", "Authorization: Basic *", True),
            ("API Key Header", "header_name", "X-API-Key, x-api-key", True),
            ("Session Cookie", "regex", r"(session|sessionid|jwt)=([^\s;]+)", True),
            ("Client Secret", "field_name", "client_secret, secret, password", True),
            ("Private Key Block", "regex", r"-----BEGIN [A-Z ]+ PRIVATE KEY-----", True),
        ]
        self.rules_table.setRowCount(len(rules))
        for row, (name, ptype, pat, enabled) in enumerate(rules):
            self.rules_table.setItem(row, 0, QTableWidgetItem(name))
            self.rules_table.setItem(row, 1, QTableWidgetItem(ptype))
            self.rules_table.setItem(row, 2, QTableWidgetItem(pat))
            status_item = QTableWidgetItem("ENABLED" if enabled else "DISABLED")
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.rules_table.setItem(row, 3, status_item)

    def _build_diagnostics_tab(self) -> QWidget:
        """Construct diagnostic bundle generator."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        diag_box = QGroupBox("Support & System Diagnostic Information")
        db_layout = QVBoxLayout(diag_box)

        sys_info = (
            f"OS Platform: {platform.platform()}\n"
            f"Python Runtime: {sys.version.split()[0]} ({sys.executable})\n"
            f"PySide6 Version: {QApplication.instance().__class__.__module__}\n"
            f"Active Working Dir: {Path.cwd()}\n"
            f"Database Mode: {'Memory' if self.db_manager.is_memory else 'File-based SQLite'}\n"
            f"Configured DB Path: {self.settings.resolved_db_path}"
        )
        self.sys_info_text = QLabel(sys_info)
        self.sys_info_text.setStyleSheet("font-family: Consolas, monospace; color: #94a3b8;")
        db_layout.addWidget(self.sys_info_text)
        layout.addWidget(diag_box)

        bundle_box = QGroupBox("Export Diagnostic Bundle")
        bb_layout = QVBoxLayout(bundle_box)
        bb_desc = QLabel(
            "Export an encrypted/redacted diagnostic bundle (.zip) containing application environment metadata,\n"
            "database schema verification status, non-sensitive configuration settings, and recent audit logs\n"
            "to assist in troubleshooting."
        )
        bb_desc.setStyleSheet("color: #cbd5e1;")
        bb_layout.addWidget(bb_desc)

        self.diag_btn = QPushButton("Export Diagnostic Bundle (.zip)")
        apply_button_class(self.diag_btn, "secondary")
        self.diag_btn.clicked.connect(self._export_diagnostic_bundle)
        bb_layout.addWidget(self.diag_btn)
        layout.addWidget(bundle_box)

        layout.addStretch()
        return widget

    def _load_from_settings(self) -> None:
        """Populate form controls from active settings model."""
        idx = self.theme_combo.findData(self.settings.theme)
        if idx >= 0:
            self.theme_combo.setCurrentIndex(idx)

        self.font_scale_spinner.setValue(self.settings.font_scale)

        d_idx = self.density_combo.findText(self.settings.table_density)
        if d_idx >= 0:
            self.density_combo.setCurrentIndex(d_idx)

        self.default_timeout_spinner.setValue(self.settings.default_timeout)
        self.connect_timeout_spinner.setValue(self.settings.connection_timeout)
        self.rate_limit_spinner.setValue(self.settings.rate_limit_rps)
        self.concurrency_spinner.setValue(self.settings.max_concurrency)
        self.tls_verify_chk.setChecked(self.settings.tls_verify)
        self.proxy_input.setText(self.settings.proxy_url or "")

    def _save_settings(self) -> None:
        """Extract inputs and persist into AppSettings and active theme."""
        theme_val = self.theme_combo.currentData()
        font_scale = self.font_scale_spinner.value()
        density_val = self.density_combo.currentText()

        # Update in-memory settings
        self.settings.theme = theme_val
        self.settings.font_scale = font_scale
        self.settings.table_density = density_val
        self.settings.default_timeout = self.default_timeout_spinner.value()
        self.settings.connection_timeout = self.connect_timeout_spinner.value()
        self.settings.rate_limit_rps = self.rate_limit_spinner.value()
        self.settings.max_concurrency = self.concurrency_spinner.value()
        self.settings.tls_verify = self.tls_verify_chk.isChecked()
        self.settings.proxy_url = self.proxy_input.text().strip() or None

        set_settings(self.settings)

        # Apply theme globally
        app = QApplication.instance()
        if app:
            set_current_theme(ThemeMode(theme_val))
            app.setStyleSheet(generate_stylesheet())

        self.settings_updated.emit()
        self.status_message.emit("Settings saved and theme applied")
        QMessageBox.information(self, "Settings Saved", "Application settings updated and applied successfully.")

    def _export_diagnostic_bundle(self) -> None:
        """Create and export a diagnostic zip archive."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Diagnostic Bundle",
            "boundaryx_diagnostics.zip",
            "ZIP Archive (*.zip)",
        )
        if not file_path:
            return

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)

                # 1. System info
                sys_data = {
                    "platform": platform.platform(),
                    "python_version": sys.version,
                    "executable": sys.executable,
                    "settings": {
                        "theme": self.settings.theme,
                        "font_scale": self.settings.font_scale,
                        "default_timeout": self.settings.default_timeout,
                        "max_concurrency": self.settings.max_concurrency,
                        "rate_limit_rps": self.settings.rate_limit_rps,
                        "tls_verify": self.settings.tls_verify,
                    },
                }
                with open(tmp_path / "system_info.json", "w", encoding="utf-8") as f:
                    json.dump(sys_data, f, indent=2)

                # 2. Database statistics
                db_stats: dict[str, int] = {}
                try:
                    with self.db_manager.get_session() as session:
                        from sqlalchemy import func, select

                        from boundaryx.infrastructure.database.models import (
                            AuditEventModel,
                            FindingModel,
                            IdentityModel,
                            PolicyModel,
                            ProjectModel,
                            ResourceModel,
                            TestCaseModel,
                            TrafficRecordModel,
                        )

                        for label, model in [
                            ("projects", ProjectModel),
                            ("identities", IdentityModel),
                            ("resources", ResourceModel),
                            ("policies", PolicyModel),
                            ("traffic_records", TrafficRecordModel),
                            ("test_cases", TestCaseModel),
                            ("findings", FindingModel),
                            ("audit_events", AuditEventModel),
                        ]:
                            count = session.scalar(select(func.count()).select_from(model))
                            db_stats[label] = count or 0
                except Exception as exc:
                    db_stats["error"] = str(exc)

                with open(tmp_path / "database_stats.json", "w", encoding="utf-8") as f:
                    json.dump(db_stats, f, indent=2)

                # 3. Create ZIP archive
                zip_target = Path(file_path)
                with zipfile.ZipFile(zip_target, "w", zipfile.ZIP_DEFLATED) as zip_f:
                    for f in tmp_path.glob("*"):
                        zip_f.write(f, arcname=f.name)

            QMessageBox.information(
                self,
                "Diagnostic Bundle Created",
                f"Diagnostic bundle successfully written to:\n{file_path}",
            )
            self.status_message.emit("Diagnostic bundle exported")
        except Exception as exc:
            logger.error("Failed to generate diagnostic bundle: %s", exc)
            QMessageBox.critical(self, "Export Failed", f"Could not create diagnostic bundle: {exc}")
