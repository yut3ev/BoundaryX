"""Security Assessment Report Generation and Export page for BoundaryX.

Provides customizable report generation with live preview, redaction controls,
methodology sections, and multi-format exports (Markdown, Standalone HTML, JSON, CSV).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSplitter,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.infrastructure.database.repositories import (
    EvidenceRepository,
    FindingRepository,
    IdentityRepository,
    PolicyRepository,
    ProjectRepository,
    ResourceRepository,
)
from boundaryx.infrastructure.exports.report_exporter import ReportExporter
from boundaryx.security.audit import REPORT_EXPORTED, AuditLogger
from boundaryx.security.redaction import RedactionEngine
from boundaryx.ui.resources.styles import apply_button_class

logger = logging.getLogger(__name__)


class ReportsPage(QWidget):
    """Security report configuration, live preview, and multi-format export interface."""

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

        self._generated_report_data: dict[str, Any] | None = None
        self._current_format = "markdown"

        self._init_ui()

    def set_project(self, project_id: str | None) -> None:
        """Update active project context and refresh preview."""
        self.project_id = project_id
        self._refresh_report_data()

    def _init_ui(self) -> None:
        """Construct page layout."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        # Left: Configuration Panel
        config_container = QWidget()
        config_layout = QVBoxLayout(config_container)
        config_layout.setContentsMargins(0, 0, 0, 0)
        config_layout.setSpacing(12)

        title_label = QLabel("Report Configuration")
        title_label.setStyleSheet("font-size: 16px; font-weight: 700; color: #f8fafc;")
        config_layout.addWidget(title_label)

        # Format Selection Group
        fmt_group = QGroupBox("Export Format")
        fmt_layout = QVBoxLayout(fmt_group)
        self.radio_md = QRadioButton("Markdown (.md)")
        self.radio_md.setChecked(True)
        self.radio_html = QRadioButton("Standalone HTML (.html)")
        self.radio_json = QRadioButton("Structured JSON (.json)")
        self.radio_csv = QRadioButton("Defects CSV (.csv)")

        self.fmt_btn_group = QButtonGroup(self)
        self.fmt_btn_group.addButton(self.radio_md)
        self.fmt_btn_group.addButton(self.radio_html)
        self.fmt_btn_group.addButton(self.radio_json)
        self.fmt_btn_group.addButton(self.radio_csv)

        fmt_layout.addWidget(self.radio_md)
        fmt_layout.addWidget(self.radio_html)
        fmt_layout.addWidget(self.radio_json)
        fmt_layout.addWidget(self.radio_csv)
        config_layout.addWidget(fmt_group)

        # Content Options Group
        opts_group = QGroupBox("Report Sections & Hardening")
        opts_layout = QVBoxLayout(opts_group)

        self.chk_evidence = QCheckBox("Include Evidence & Request Snapshots")
        self.chk_evidence.setChecked(True)
        self.chk_evidence.stateChanged.connect(self._refresh_report_data)
        opts_layout.addWidget(self.chk_evidence)

        self.chk_redact = QCheckBox("Redact Sensitive Secrets & Tokens")
        self.chk_redact.setChecked(True)
        self.chk_redact.stateChanged.connect(self._refresh_report_data)
        opts_layout.addWidget(self.chk_redact)

        self.chk_methodology = QCheckBox("Include Authorization Testing Methodology")
        self.chk_methodology.setChecked(True)
        self.chk_methodology.stateChanged.connect(self._refresh_report_data)
        opts_layout.addWidget(self.chk_methodology)

        config_layout.addWidget(opts_group)

        # Metadata fields
        meta_group = QGroupBox("Report Metadata")
        meta_layout = QVBoxLayout(meta_group)

        meta_layout.addWidget(QLabel("Custom Assessment Title:"))
        self.title_input = QLineEdit("BoundaryX Authorization Security Assessment")
        self.title_input.textChanged.connect(self._refresh_report_data)
        meta_layout.addWidget(self.title_input)

        meta_layout.addWidget(QLabel("Assessor Notes / Executive Summary:"))
        self.summary_input = QTextEdit()
        self.summary_input.setPlaceholderText("Executive summary of findings, boundary weaknesses, and posture...")
        self.summary_input.setFixedHeight(80)
        self.summary_input.textChanged.connect(self._refresh_report_data)
        meta_layout.addWidget(self.summary_input)

        config_layout.addWidget(meta_group)

        config_layout.addStretch()

        # Action Buttons
        self.export_btn = QPushButton("Export Report")
        apply_button_class(self.export_btn, "primary")
        self.export_btn.clicked.connect(self._export_report)
        config_layout.addWidget(self.export_btn)

        splitter.addWidget(config_container)

        # Right: Live Preview Panel
        preview_container = QWidget()
        prev_layout = QVBoxLayout(preview_container)
        prev_layout.setContentsMargins(0, 0, 0, 0)
        prev_layout.setSpacing(8)

        prev_header = QHBoxLayout()
        prev_title = QLabel("Live Report Preview")
        prev_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #f8fafc;")
        prev_header.addWidget(prev_title)
        prev_header.addStretch()

        self.refresh_preview_btn = QPushButton("Refresh Preview")
        self.refresh_preview_btn.clicked.connect(self._refresh_report_data)
        prev_header.addWidget(self.refresh_preview_btn)

        prev_layout.addLayout(prev_header)

        self.preview_browser = QTextBrowser()
        self.preview_browser.setOpenExternalLinks(False)
        self.preview_browser.setStyleSheet(
            "background-color: #1a1f2c; color: #f8fafc; border: 1px solid #2d354d; border-radius: 6px; padding: 12px;"
        )
        prev_layout.addWidget(self.preview_browser, stretch=1)

        splitter.addWidget(preview_container)
        splitter.setSizes([340, 760])

    def _refresh_report_data(self) -> None:
        """Compile project models into report structure and update preview."""
        if not self.project_id:
            self.preview_browser.setHtml("<p style='color: #94a3b8;'>Select an active project to preview report.</p>")
            return

        try:
            with self.db_manager.get_session() as session:
                proj_repo = ProjectRepository(session)
                find_repo = FindingRepository(session)
                pol_repo = PolicyRepository(session)
                id_repo = IdentityRepository(session)
                res_repo = ResourceRepository(session)
                EvidenceRepository(session)

                project = proj_repo.get_by_id(session, self.project_id)
                if not project:
                    return

                findings_models = find_repo.list_by_project(session, self.project_id)
                policies_models = pol_repo.list_by_project(session, self.project_id)
                identities_models = id_repo.list_by_project(session, self.project_id)
                resources_models = res_repo.list_by_project(session, self.project_id)

                proj_dict = {
                    "id": project.id,
                    "name": project.name,
                    "description": project.description or "",
                    "created_at": str(project.created_at),
                }

                findings_list = []
                for f in findings_models:
                    f_dict = {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity,
                        "status": f.status,
                        "category": f.category,
                        "affected_endpoint": f.affected_endpoint,
                        "expected_decision": f.expected_decision,
                        "observed_decision": f.observed_decision,
                        "reproduction_steps": f.reproduction_steps or [],
                        "reviewer_notes": f.reviewer_notes or "",
                    }
                    if self.chk_evidence.isChecked() and f.evidence_ids:
                        f_dict["evidence_ids"] = f.evidence_ids
                    findings_list.append(f_dict)

                pol_list = [
                    {"name": p.name, "action": p.action, "expected_decision": p.expected_decision}
                    for p in policies_models
                ]
                id_list = [
                    {"display_name": i.display_name, "identity_type": i.identity_type} for i in identities_models
                ]
                res_list = [
                    {"display_name": r.display_name, "method": r.method, "path": r.path} for r in resources_models
                ]

                report_data = ReportExporter.generate_report_data(
                    project=proj_dict,
                    findings=findings_list,
                    policies=pol_list,
                    identities=id_list,
                    resources=res_list,
                    tool_version="0.1.0",
                )

                # Custom summary override if provided
                custom_summary = self.summary_input.toPlainText().strip()
                if custom_summary:
                    report_data["executive_summary"]["analyst_summary"] = custom_summary

                # Redact if enabled
                if self.chk_redact.isChecked():
                    data_str = json.dumps(report_data)
                    data_str = self.redaction_engine.redact_text(data_str)
                    report_data = json.loads(data_str)

                self._generated_report_data = report_data
                self._update_preview()

        except Exception as exc:
            logger.error("Failed to generate report data: %s", exc)
            self.preview_browser.setHtml(f"<p style='color: #ef4444;'>Report Generation Error: {exc}</p>")

    def _update_preview(self) -> None:
        """Render markdown or HTML preview into the text browser."""
        if not self._generated_report_data:
            return

        rep = self._generated_report_data
        proj_name = rep.get("project_name", "BoundaryX Project")
        summary = rep.get("executive_summary", {})
        findings = rep.get("findings", [])

        # Build clean HTML summary preview
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Segoe UI, sans-serif; color: #f8fafc; background-color: #1a1f2c; line-height: 1.5; }}
                h1 {{ color: #00b4d8; border-bottom: 2px solid #2d354d; padding-bottom: 8px; font-size: 20px; }}
                h2 {{ color: #38bdf8; font-size: 16px; margin-top: 18px; }}
                .badge {{ padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
                .CRITICAL {{ background-color: #7f1d1d; color: #f87171; }}
                .HIGH {{ background-color: #7c2d12; color: #fb923c; }}
                .MEDIUM {{ background-color: #78350f; color: #facc15; }}
                .LOW {{ background-color: #1e3a8a; color: #60a5fa; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ border: 1px solid #2d354d; padding: 6px 10px; text-align: left; }}
                th {{ background-color: #12151c; color: #94a3b8; font-size: 12px; }}
                .card {{ background-color: #22283a; border: 1px solid #2d354d; border-radius: 6px; padding: 10px; margin-bottom: 8px; }}
            </style>
        </head>
        <body>
            <h1>{self.title_input.text() or proj_name}</h1>
            <p><b>Target:</b> {proj_name} | <b>Generated:</b> {rep.get("generated_at", "")}</p>

            <div class="card">
                <b>Total Findings:</b> {summary.get("total_findings", 0)} |
                <b>Critical:</b> {summary.get("critical_count", 0)} |
                <b>High:</b> {summary.get("high_count", 0)} |
                <b>Medium:</b> {summary.get("medium_count", 0)} |
                <b>Low:</b> {summary.get("low_count", 0)}
            </div>

            <h2>Executive Summary</h2>
            <p>{summary.get("analyst_summary", "Assessment completed with boundary security testing across identities and resources.")}</p>

            <h2>Defect Findings ({len(findings)})</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Category</th>
                    <th>Affected Endpoint</th>
                    <th>Status</th>
                </tr>
        """
        for f in findings:
            sev = f.get("severity", "MEDIUM")
            html += f"""
                <tr>
                    <td><span class="badge {sev}">{sev}</span></td>
                    <td><b>{f.get("title", "")}</b></td>
                    <td>{f.get("category", "")}</td>
                    <td><code>{f.get("affected_endpoint", "")}</code></td>
                    <td>{f.get("status", "")}</td>
                </tr>
            """

        html += """
            </table>
        </body>
        </html>
        """
        self.preview_browser.setHtml(html)

    def _export_report(self) -> None:
        """Export report data to chosen file format."""
        if not self._generated_report_data or not self.project_id:
            QMessageBox.warning(self, "No Report", "No report data to export.")
            return

        if self.radio_md.isChecked():
            ext = ".md"
            filter_str = "Markdown Report (*.md)"
        elif self.radio_html.isChecked():
            ext = ".html"
            filter_str = "HTML Report (*.html)"
        elif self.radio_json.isChecked():
            ext = ".json"
            filter_str = "JSON Export (*.json)"
        else:
            ext = ".csv"
            filter_str = "CSV Report (*.csv)"

        suggested = f"boundaryx_report_{self._generated_report_data.get('project_name', 'project').lower().replace(' ', '_')}{ext}"
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Security Report", suggested, filter_str)
        if not file_path:
            return

        try:
            target_path = Path(file_path)
            if self.radio_md.isChecked():
                ReportExporter.export_markdown(self._generated_report_data, target_path)
            elif self.radio_html.isChecked():
                ReportExporter.export_html(self._generated_report_data, target_path)
            elif self.radio_json.isChecked():
                ReportExporter.export_json(self._generated_report_data, target_path)
            else:
                findings = self._generated_report_data.get("findings", [])
                ReportExporter.export_csv(findings, target_path)

            # Log audit event
            with self.db_manager.get_session() as session:
                audit = AuditLogger(session)
                audit.log(
                    project_id=self.project_id,
                    event_type=REPORT_EXPORTED,
                    action=f"Exported report to {target_path.name}",
                    entity_type="REPORT",
                    details={"format": ext, "path": str(target_path)},
                )

            QMessageBox.information(
                self,
                "Report Exported",
                f"Security report successfully generated and saved to:\n{target_path}",
            )
            self.status_message.emit(f"Report saved: {target_path.name}")
        except Exception as exc:
            logger.error("Failed to export report: %s", exc)
            QMessageBox.critical(self, "Export Failed", f"Could not export report: {exc}")
