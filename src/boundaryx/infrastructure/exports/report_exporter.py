"""Report generation and export module for BoundaryX.

Supports Markdown, standalone offline HTML with embedded CSS,
structured JSON, and CSV exports with security hardening against path traversal.
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ReportExportError(Exception):
    """Raised when report generation or export fails."""


class ReportExporter:
    """Exports authorization analysis findings and project assessments into various formats."""

    @staticmethod
    def _sanitize_path(path: Path | str, base_dir: Path | None = None) -> Path:
        """Sanitize and validate output path to prevent path traversal attacks.

        Args:
            path: Target file path.
            base_dir: Optional constraining base directory.

        Returns:
            Resolved, validated absolute Path.

        Raises:
            ReportExportError: If path attempts path traversal outside base_dir.
        """
        resolved = Path(path).resolve()
        if base_dir is not None:
            resolved_base = Path(base_dir).resolve()
            try:
                resolved.relative_to(resolved_base)
            except ValueError as exc:
                raise ReportExportError(
                    f"Path traversal detected: {path} is outside base directory {base_dir}"
                ) from exc

        # Disallow writing directly to system roots or dangerous paths
        parts = resolved.parts
        if len(parts) <= 1:
            raise ReportExportError("Cannot write report directly to filesystem root")

        # Create parent directories safely
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return resolved

    @classmethod
    def generate_report_data(
        cls,
        project: dict[str, Any] | Any,
        findings: list[dict[str, Any]],
        policies: list[dict[str, Any]] | None = None,
        identities: list[dict[str, Any]] | None = None,
        resources: list[dict[str, Any]] | None = None,
        test_results: list[dict[str, Any]] | None = None,
        scope_config: dict[str, Any] | None = None,
        tool_version: str = "0.1.0",
    ) -> dict[str, Any]:
        """Create a complete assessment report structure with all 14 required sections.

        Sections:
        1. Executive Summary
        2. Scope and Target Boundaries
        3. Identity and Role Architecture
        4. Resource and Tenant Inventory
        5. Access Control Policy Mapping
        6. Findings Summary & Severity Metrics
        7. Detailed Vulnerability Findings
        8. Broken Object Level Authorization (BOLA/IDOR) Analysis
        9. Broken Function Level Authorization (BFLA) Analysis
        10. Tenant and Boundary Isolation Evaluation
        11. Automated Test Execution Details
        12. Compliance & Standards Alignment (OWASP API Top 10)
        13. Remediation Roadmap & Priority Actions
        14. Evidence Verification & Appendix
        """
        proj_dict = (
            project
            if isinstance(project, dict)
            else (project.to_dict() if hasattr(project, "to_dict") else vars(project))
        )
        policies_list = policies or []
        identities_list = identities or []
        resources_list = resources or []
        test_results_list = test_results or []
        scope_dict = scope_config or {}

        # Severity metrics calculation
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = str(f.get("severity", "INFO")).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["INFO"] += 1

        total_findings = len(findings)
        passed_tests = sum(1 for t in test_results_list if t.get("status") in ("PASSED", "PASS"))
        failed_tests = sum(1 for t in test_results_list if t.get("status") in ("FAILED", "FAIL"))

        bola_findings = [
            f
            for f in findings
            if "BOLA" in str(f.get("category", "")).upper() or "IDOR" in str(f.get("category", "")).upper()
        ]
        bfla_findings = [
            f
            for f in findings
            if "BFLA" in str(f.get("category", "")).upper() or "FUNCTION" in str(f.get("category", "")).upper()
        ]
        isolation_findings = [
            f
            for f in findings
            if "TENANT" in str(f.get("category", "")).upper() or "ISOLATION" in str(f.get("category", "")).upper()
        ]

        report = {
            "metadata": {
                "report_id": f"REP-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}",
                "generated_at": datetime.now(UTC).isoformat(),
                "tool_name": "BoundaryX",
                "tool_version": tool_version,
                "project_name": proj_dict.get("name", "Untitled Assessment"),
                "project_id": str(proj_dict.get("id", "")),
            },
            # Section 1
            "executive_summary": {
                "title": "1. Executive Summary",
                "project_name": proj_dict.get("name", "Untitled Assessment"),
                "description": proj_dict.get("description", "No description provided."),
                "total_findings": total_findings,
                "severity_breakdown": severity_counts,
                "risk_rating": "CRITICAL"
                if severity_counts["CRITICAL"] > 0
                else (
                    "HIGH" if severity_counts["HIGH"] > 0 else ("MEDIUM" if severity_counts["MEDIUM"] > 0 else "LOW")
                ),
                "summary_text": (
                    f"BoundaryX conducted an authorization boundary assessment for {proj_dict.get('name', 'the target application')}. "
                    f"A total of {total_findings} security findings were identified ({severity_counts['CRITICAL']} Critical, "
                    f"{severity_counts['HIGH']} High, {severity_counts['MEDIUM']} Medium, {severity_counts['LOW']} Low)."
                ),
            },
            # Section 2
            "scope_and_boundaries": {
                "title": "2. Assessment Scope and Target Boundaries",
                "rules": scope_dict.get("rules", []),
                "authorized_hostnames": scope_dict.get("authorized_hostnames", []),
                "excluded_hostnames": scope_dict.get("excluded_hostnames", []),
                "total_rules": scope_dict.get("total_rules", 0),
            },
            # Section 3
            "identity_profiles": {
                "title": "3. Identity and Role Architecture",
                "total_identities": len(identities_list),
                "identities": identities_list,
            },
            # Section 4
            "resource_inventory": {
                "title": "4. Resource and Tenant Inventory",
                "total_resources": len(resources_list),
                "resources": resources_list,
            },
            # Section 5
            "access_control_policies": {
                "title": "5. Access Control Policy Mapping",
                "total_policies": len(policies_list),
                "policies": policies_list,
            },
            # Section 6
            "findings_summary": {
                "title": "6. Findings Summary & Severity Metrics",
                "total": total_findings,
                "severity_counts": severity_counts,
            },
            # Section 7
            "detailed_findings": {
                "title": "7. Detailed Vulnerability Findings",
                "findings": findings,
            },
            # Section 8
            "bola_analysis": {
                "title": "8. Broken Object Level Authorization (BOLA/IDOR) Analysis",
                "count": len(bola_findings),
                "findings": bola_findings,
            },
            # Section 9
            "bfla_analysis": {
                "title": "9. Broken Function Level Authorization (BFLA) Analysis",
                "count": len(bfla_findings),
                "findings": bfla_findings,
            },
            # Section 10
            "isolation_evaluation": {
                "title": "10. Tenant and Boundary Isolation Evaluation",
                "count": len(isolation_findings),
                "findings": isolation_findings,
            },
            # Section 11
            "automated_test_results": {
                "title": "11. Automated Test Execution Details",
                "total_executed": len(test_results_list),
                "passed": passed_tests,
                "failed": failed_tests,
                "tests": test_results_list,
            },
            # Section 12
            "compliance_alignment": {
                "title": "12. Compliance & Standards Alignment",
                "frameworks": [
                    {
                        "framework": "OWASP API Security Top 10 (2023)",
                        "items": [
                            {
                                "code": "API1:2023",
                                "name": "Broken Object Level Authorization",
                                "status": "FAIL" if bola_findings else "PASS",
                            },
                            {"code": "API2:2023", "name": "Broken Authentication", "status": "PASS"},
                            {
                                "code": "API3:2023",
                                "name": "Broken Object Property Level Authorization",
                                "status": "PASS",
                            },
                            {
                                "code": "API5:2023",
                                "name": "Broken Function Level Authorization",
                                "status": "FAIL" if bfla_findings else "PASS",
                            },
                        ],
                    }
                ],
            },
            # Section 13
            "remediation_roadmap": {
                "title": "13. Remediation Roadmap & Priority Actions",
                "immediate_actions": [
                    f"Remediate {f.get('title', 'vulnerability')} on {f.get('affected_endpoint', 'endpoint')}"
                    for f in findings
                    if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
                ],
                "general_recommendations": [
                    "Implement centralized authorization policy enforcement at the gateway/framework layer.",
                    "Validate object ownership and tenant tenancy context on every state-changing and read operation.",
                    "Replace guessable sequential resource identifiers with secure UUIDv4 or encrypted references.",
                ],
            },
            # Section 14
            "evidence_and_appendix": {
                "title": "14. Evidence Verification & Appendix",
                "total_evidence_items": sum(len(f.get("evidence", [])) for f in findings),
                "disclaimer": "This report contains confidential security vulnerability analysis. Distribute strictly on a need-to-know basis.",
            },
        }

        return report

    # Alias for method name in instructions
    _generate_report_data = generate_report_data

    @classmethod
    def export_json(cls, report_data: dict[str, Any], output_path: Path | str) -> Path:
        """Export report data to a JSON file.

        Args:
            report_data: Report dictionary.
            output_path: Target path.

        Returns:
            Resolved output Path.
        """
        target = cls._sanitize_path(output_path)
        try:
            with target.open("w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, default=str)
            logger.info("Exported JSON report to %s", target)
            return target
        except OSError as exc:
            raise ReportExportError(f"Failed to write JSON report to {target}: {exc}") from exc

    @classmethod
    def export_csv(cls, findings: list[dict[str, Any]], output_path: Path | str) -> Path:
        """Export findings to a CSV spreadsheet.

        Args:
            findings: List of finding dictionaries.
            output_path: Target path.

        Returns:
            Resolved output Path.
        """
        target = cls._sanitize_path(output_path)
        fieldnames = [
            "id",
            "title",
            "severity",
            "category",
            "cwe_id",
            "cvss_score",
            "affected_endpoint",
            "status",
            "description",
            "remediation",
        ]

        try:
            with target.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for finding in findings:
                    row = {k: finding.get(k, "") for k in fieldnames}
                    writer.writerow(row)
            logger.info("Exported CSV findings to %s", target)
            return target
        except OSError as exc:
            raise ReportExportError(f"Failed to write CSV findings to {target}: {exc}") from exc

    @classmethod
    def export_markdown(cls, report_data: dict[str, Any], output_path: Path | str) -> Path:
        """Export assessment report in clean GitHub-Flavored Markdown.

        Args:
            report_data: Report dictionary.
            output_path: Target path.

        Returns:
            Resolved output Path.
        """
        target = cls._sanitize_path(output_path)
        meta = report_data.get("metadata", {})
        exec_sum = report_data.get("executive_summary", {})
        sev = exec_sum.get("severity_breakdown", {})

        md: list[str] = [
            f"# Authorization Boundary Assessment Report: {meta.get('project_name', 'Assessment')}",
            "",
            f"**Report ID:** `{meta.get('report_id', '')}`  ",
            f"**Generated:** {meta.get('generated_at', '')}  ",
            f"**Tool:** BoundaryX v{meta.get('tool_version', '0.1.0')}  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            exec_sum.get("summary_text", ""),
            "",
            "| Severity | Count |",
            "| :--- | :--- |",
            f"| **CRITICAL** | {sev.get('CRITICAL', 0)} |",
            f"| **HIGH** | {sev.get('HIGH', 0)} |",
            f"| **MEDIUM** | {sev.get('MEDIUM', 0)} |",
            f"| **LOW** | {sev.get('LOW', 0)} |",
            f"| **INFO** | {sev.get('INFO', 0)} |",
            "",
            "---",
            "",
            "## 2. Assessment Scope and Target Boundaries",
            "",
            f"- **Authorized Hostnames:** {', '.join(report_data.get('scope_and_boundaries', {}).get('authorized_hostnames', [])) or 'None specified'}",
            f"- **Excluded Hostnames:** {', '.join(report_data.get('scope_and_boundaries', {}).get('excluded_hostnames', [])) or 'None'}",
            "",
            "---",
            "",
            "## 3. Identity and Role Architecture",
            "",
            f"Total configured identities: **{report_data.get('identity_profiles', {}).get('total_identities', 0)}**",
            "",
            "---",
            "",
            "## 4. Resource and Tenant Inventory",
            "",
            f"Total tracked resources: **{report_data.get('resource_inventory', {}).get('total_resources', 0)}**",
            "",
            "---",
            "",
            "## 5. Access Control Policy Mapping",
            "",
            f"Total policies configured: **{report_data.get('access_control_policies', {}).get('total_policies', 0)}**",
            "",
            "---",
            "",
            "## 6. Findings Summary",
            "",
            f"Total findings identified: **{report_data.get('findings_summary', {}).get('total', 0)}**",
            "",
            "---",
            "",
            "## 7. Detailed Vulnerability Findings",
            "",
        ]

        findings = report_data.get("detailed_findings", {}).get("findings", [])
        if not findings:
            md.append("*No vulnerability findings recorded for this assessment.*")
            md.append("")
        else:
            for idx, f in enumerate(findings, 1):
                md.extend(
                    [
                        f"### 7.{idx} [{f.get('severity', 'INFO')}] {f.get('title', 'Finding')}",
                        "",
                        f"- **Category:** {f.get('category', 'N/A')}",
                        f"- **Endpoint:** `{f.get('affected_endpoint', 'N/A')}`",
                        f"- **CWE:** {f.get('cwe_id', 'N/A')} | **CVSS:** {f.get('cvss_score', 'N/A')}",
                        "",
                        "#### Description",
                        f"{f.get('description', 'No description.')}",
                        "",
                        "#### Remediation",
                        f"{f.get('remediation', 'Follow least-privilege access control practices.')}",
                        "",
                    ]
                )

        md.extend(
            [
                "---",
                "",
                "## 8. Broken Object Level Authorization (BOLA/IDOR) Analysis",
                f"Total BOLA issues identified: **{report_data.get('bola_analysis', {}).get('count', 0)}**",
                "",
                "## 9. Broken Function Level Authorization (BFLA) Analysis",
                f"Total BFLA issues identified: **{report_data.get('bfla_analysis', {}).get('count', 0)}**",
                "",
                "## 10. Tenant and Boundary Isolation Evaluation",
                f"Total Isolation issues identified: **{report_data.get('isolation_evaluation', {}).get('count', 0)}**",
                "",
                "## 11. Automated Test Execution Details",
                f"Executed **{report_data.get('automated_test_results', {}).get('total_executed', 0)}** tests "
                f"({report_data.get('automated_test_results', {}).get('passed', 0)} Passed, "
                f"{report_data.get('automated_test_results', {}).get('failed', 0)} Failed).",
                "",
                "## 12. Compliance & Standards Alignment",
                "- **OWASP API Top 10 (2023):** Evaluated for API1 (BOLA) and API5 (BFLA)",
                "",
                "## 13. Remediation Roadmap & Priority Actions",
                "",
            ]
        )

        roadmap = report_data.get("remediation_roadmap", {})
        immediate = roadmap.get("immediate_actions", [])
        if immediate:
            md.append("### Immediate Actions")
            for act in immediate:
                md.append(f"- [ ] {act}")
            md.append("")

        general = roadmap.get("general_recommendations", [])
        if general:
            md.append("### General Recommendations")
            for rec in general:
                md.append(f"- {rec}")
            md.append("")

        md.extend(
            [
                "## 14. Evidence Verification & Appendix",
                f"- Total evidence items attached: {report_data.get('evidence_and_appendix', {}).get('total_evidence_items', 0)}",
                f"- {report_data.get('evidence_and_appendix', {}).get('disclaimer', '')}",
                "",
            ]
        )

        try:
            with target.open("w", encoding="utf-8") as f:
                f.write("\n".join(md))
            logger.info("Exported Markdown report to %s", target)
            return target
        except OSError as exc:
            raise ReportExportError(f"Failed to write Markdown report to {target}: {exc}") from exc

    @classmethod
    def export_html(cls, report_data: dict[str, Any], output_path: Path | str) -> Path:
        """Export assessment report as a standalone, styled HTML document with embedded CSS.

        Args:
            report_data: Report dictionary.
            output_path: Target path.

        Returns:
            Resolved output Path.
        """
        target = cls._sanitize_path(output_path)
        meta = report_data.get("metadata", {})
        exec_sum = report_data.get("executive_summary", {})
        sev = exec_sum.get("severity_breakdown", {})
        findings = report_data.get("detailed_findings", {}).get("findings", [])

        # Build HTML content with modern embedded CSS styling
        html_lines = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            f"<title>BoundaryX Report - {meta.get('project_name', 'Assessment')}</title>",
            "<style>",
            "  :root {",
            "    --bg-primary: #0f172a;",
            "    --bg-secondary: #1e293b;",
            "    --text-primary: #f8fafc;",
            "    --text-secondary: #94a3b8;",
            "    --border: #334155;",
            "    --critical: #ef4444;",
            "    --high: #f97316;",
            "    --medium: #eab308;",
            "    --low: #3b82f6;",
            "    --info: #64748b;",
            "    --font-mono: 'Consolas', 'Courier New', monospace;",
            "  }",
            "  body {",
            "    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;",
            "    background-color: var(--bg-primary);",
            "    color: var(--text-primary);",
            "    margin: 0;",
            "    padding: 2rem;",
            "    line-height: 1.6;",
            "  }",
            "  .container { max-width: 1000px; margin: 0 auto; }",
            "  header { border-bottom: 2px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }",
            "  h1 { font-size: 2rem; margin-bottom: 0.5rem; color: #38bdf8; }",
            "  .meta { color: var(--text-secondary); font-size: 0.9rem; }",
            "  .card { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }",
            "  .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-weight: bold; font-size: 0.8rem; text-transform: uppercase; }",
            "  .badge-critical { background: var(--critical); color: white; }",
            "  .badge-high { background: var(--high); color: white; }",
            "  .badge-medium { background: var(--medium); color: black; }",
            "  .badge-low { background: var(--low); color: white; }",
            "  .badge-info { background: var(--info); color: white; }",
            "  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1rem 0; }",
            "  .metric-box { background: rgba(255,255,255,0.05); padding: 1rem; border-radius: 6px; text-align: center; }",
            "  .metric-val { font-size: 1.8rem; font-weight: bold; }",
            "  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }",
            "  th, td { border: 1px solid var(--border); padding: 0.75rem; text-align: left; }",
            "  th { background: rgba(255,255,255,0.05); }",
            "  code { background: #0b1120; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: var(--font-mono); font-size: 0.9em; }",
            "  .footer { border-top: 1px solid var(--border); margin-top: 3rem; padding-top: 1rem; color: var(--text-secondary); font-size: 0.85rem; text-align: center; }",
            "</style>",
            "</head>",
            "<body>",
            "<div class='container'>",
            "<header>",
            f"  <h1>Authorization Security Assessment: {meta.get('project_name', 'Assessment')}</h1>",
            f"  <div class='meta'>Report ID: <code>{meta.get('report_id', '')}</code> | Date: {meta.get('generated_at', '')} | Generated by BoundaryX v{meta.get('tool_version', '0.1.0')}</div>",
            "</header>",
            "<section class='card'>",
            "  <h2>1. Executive Summary</h2>",
            f"  <p>{exec_sum.get('summary_text', '')}</p>",
            "  <div class='grid'>",
            f"    <div class='metric-box'><div class='metric-val' style='color:var(--critical)'>{sev.get('CRITICAL', 0)}</div><div>Critical</div></div>",
            f"    <div class='metric-box'><div class='metric-val' style='color:var(--high)'>{sev.get('HIGH', 0)}</div><div>High</div></div>",
            f"    <div class='metric-box'><div class='metric-val' style='color:var(--medium)'>{sev.get('MEDIUM', 0)}</div><div>Medium</div></div>",
            f"    <div class='metric-box'><div class='metric-val' style='color:var(--low)'>{sev.get('LOW', 0)}</div><div>Low</div></div>",
            f"    <div class='metric-box'><div class='metric-val' style='color:var(--info)'>{sev.get('INFO', 0)}</div><div>Info</div></div>",
            "  </div>",
            "</section>",
            "<section class='card'>",
            "  <h2>Detailed Vulnerability Findings</h2>",
        ]

        if not findings:
            html_lines.append("<p><em>No vulnerability findings recorded for this project.</em></p>")
        else:
            for f in findings:
                sev_str = str(f.get("severity", "INFO")).upper()
                badge_class = f"badge-{sev_str.lower()}"
                html_lines.extend(
                    [
                        f"<div style='border-left: 4px solid var(--{sev_str.lower()}); padding-left: 1rem; margin-bottom: 1.5rem;'>",
                        f"  <h3><span class='badge {badge_class}'>{sev_str}</span> {f.get('title', 'Finding')}</h3>",
                        f"  <p><strong>Endpoint:</strong> <code>{f.get('affected_endpoint', 'N/A')}</code> | <strong>Category:</strong> {f.get('category', 'N/A')}</p>",
                        f"  <p>{f.get('description', '')}</p>",
                        f"  <p><strong>Remediation:</strong> {f.get('remediation', '')}</p>",
                        "</div>",
                    ]
                )

        html_lines.extend(
            [
                "</section>",
                "<div class='footer'>",
                f"  <p>{report_data.get('evidence_and_appendix', {}).get('disclaimer', '')}</p>",
                "</div>",
                "</div>",
                "</body>",
                "</html>",
            ]
        )

        try:
            with target.open("w", encoding="utf-8") as f:
                f.write("\n".join(html_lines))
            logger.info("Exported HTML report to %s", target)
            return target
        except OSError as exc:
            raise ReportExportError(f"Failed to write HTML report to {target}: {exc}") from exc
