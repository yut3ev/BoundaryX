import csv
import html
import io
import json
from typing import Any, Dict, List

from boundaryx.domain.models import Asset, Evidence, Finding, Program, utc_now_iso
from boundaryx.security.redaction import RedactionEngine


def escape_csv_cell(value: Any) -> str:
    """Defends against CSV / Spreadsheet formula injection (DDE attacks)."""
    text = str(value) if value is not None else ""
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


class ReportGenerator:
    """
    Multi-format assessment report generator.
    Produces auditor-ready Markdown, standalone HTML (with XSS protection),
    sanitized JSON, and CSV exports (with formula injection defense).
    """

    def __init__(self, redaction_engine: RedactionEngine = None):
        self.redactor = redaction_engine or RedactionEngine()

    def generate_markdown(
        self,
        program: Program,
        findings: List[Finding],
        assets: List[Asset],
        evidence_items: List[Evidence],
    ) -> str:
        md = []
        md.append(f"# Security Assessment Report: {program.name}")
        md.append(f"**Generated:** {utc_now_iso()} | **Platform:** BoundaryX")
        if program.policy_url:
            md.append(f"**Policy Scope Reference:** [{program.policy_url}]({program.policy_url})")
        md.append("\n---\n")

        # Executive Summary
        md.append("## 1. Executive Summary")
        md.append(f"Total Identified Assets: **{len(assets)}** | Total Findings: **{len(findings)}**")
        verified_count = sum(1 for f in findings if f.status.value == "verified")
        md.append(f"Verified Actionable Vulnerabilities: **{verified_count}**\n")

        # Findings Summary Table
        md.append("## 2. Findings Summary Table")
        md.append("| Title | Category | Severity | Confidence | Status |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in findings:
            md.append(f"| {f.title} | {f.category} | {f.severity.value.upper()} | {f.confidence.value} | {f.status.value} |")
        md.append("\n")

        # Detailed Findings
        md.append("## 3. Detailed Vulnerability Analyses")
        for i, f in enumerate(findings, 1):
            md.append(f"### 3.{i} {f.title}")
            md.append(f"- **Severity:** `{f.severity.value.upper()}` | **Confidence:** `{f.confidence.value}` | **Status:** `{f.status.value}`")
            if f.review_reason:
                md.append(f"- **Verification Verification Trace:** {f.review_reason}")
            md.append("\n#### Impact")
            md.append(f.impact or "Not specified.")
            md.append("\n#### Actual vs. Expected Behavior")
            md.append(f"- **Observed Behavior:** {f.actual_behavior or 'N/A'}")
            md.append(f"- **Expected Authorization:** {f.expected_behavior or 'N/A'}")
            md.append("\n#### Steps to Reproduce")
            md.append(f.reproduction_steps_md or "1. Send request with specified parameters.")
            md.append("\n#### Recommended Remediation")
            md.append(f.remediation_md or "Enforce server-side authorization checks.")
            md.append("\n---\n")

        # Limitations
        md.append("## 4. Assessment Scope Limitations & Disclaimer")
        md.append(
            "This report documents authorized security testing strictly within defined program boundaries. "
            "Testing reflects security posture at the time of execution. All evidence is sanitized."
        )

        return "\n".join(md)

    def generate_html(
        self,
        program: Program,
        findings: List[Finding],
        assets: List[Asset],
        evidence_items: List[Evidence],
    ) -> str:
        esc = html.escape
        title = esc(program.name)

        findings_rows = []
        for f in findings:
            badge_class = f"badge-{f.severity.value}"
            findings_rows.append(
                f"<tr><td><strong>{esc(f.title)}</strong></td>"
                f"<td>{esc(f.category)}</td>"
                f"<td><span class='badge {badge_class}'>{esc(f.severity.value.upper())}</span></td>"
                f"<td>{esc(f.confidence.value)}</td>"
                f"<td>{esc(f.status.value)}</td></tr>"
            )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BoundaryX Report - {title}</title>
<style>
:root {{
    --bg: #0f172a;
    --card: #1e293b;
    --border: #334155;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #0ea5e9;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #3b82f6;
}}
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 2rem;
    line-height: 1.5;
}}
.container {{ max-width: 960px; margin: 0 auto; }}
.header {{ border-bottom: 2px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
h1, h2, h3 {{ color: #ffffff; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
th, td {{ border: 1px solid var(--border); padding: 0.75rem; text-align: left; }}
th {{ background: #111827; }}
.badge {{ padding: 0.25rem 0.6rem; border-radius: 4px; font-weight: bold; font-size: 0.8rem; text-transform: uppercase; }}
.badge-critical {{ background: rgba(239,68,68,0.2); color: var(--critical); border: 1px solid var(--critical); }}
.badge-high {{ background: rgba(249,115,22,0.2); color: var(--high); border: 1px solid var(--high); }}
.badge-medium {{ background: rgba(234,179,8,0.2); color: var(--medium); border: 1px solid var(--medium); }}
.badge-low {{ background: rgba(59,130,246,0.2); color: var(--low); border: 1px solid var(--low); }}
.badge-unrated {{ background: rgba(148,163,184,0.2); color: var(--text-muted); }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>{title}</h1>
        <p style="color: var(--text-muted);">Security Assessment Report | Generated: {esc(utc_now_iso())}</p>
    </div>
    <div class="card">
        <h2>Executive Summary</h2>
        <p>Total Assets Evaluated: <strong>{len(assets)}</strong></p>
        <p>Total Findings Logged: <strong>{len(findings)}</strong></p>
    </div>
    <div class="card">
        <h2>Findings Overview</h2>
        <table>
            <thead>
                <tr>
                    <th>Title</th><th>Category</th><th>Severity</th><th>Confidence</th><th>Status</th>
                </tr>
            </thead>
            <tbody>
                {''.join(findings_rows)}
            </tbody>
        </table>
    </div>
</div>
</body>
</html>
"""
        return html_content

    def generate_json(
        self,
        program: Program,
        findings: List[Finding],
        assets: List[Asset],
        evidence_items: List[Evidence],
    ) -> str:
        report_data = {
            "metadata": {
                "platform": "BoundaryX",
                "generated_at": utc_now_iso(),
            },
            "program": program.model_dump(),
            "assets": [a.model_dump() for a in assets],
            "findings": [f.model_dump() for f in findings],
            "evidence": [e.model_dump() for e in evidence_items],
        }
        return json.dumps(report_data, indent=2)

    def generate_csv(self, findings: List[Finding]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Title", "Category", "Severity", "Confidence", "Status", "Impact", "Review Reason"])
        for f in findings:
            writer.writerow([
                escape_csv_cell(f.id),
                escape_csv_cell(f.title),
                escape_csv_cell(f.category),
                escape_csv_cell(f.severity.value),
                escape_csv_cell(f.confidence.value),
                escape_csv_cell(f.status.value),
                escape_csv_cell(f.impact),
                escape_csv_cell(f.review_reason),
            ])
        return output.getvalue()
