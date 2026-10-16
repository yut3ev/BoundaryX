"""Reporting and audit documentation service for BoundaryX.

Assembles comprehensive, audit-ready security assessment reports covering
scope boundaries, testing methodology, identity/resource matrices, evaluated policies,
cryptographically verified findings, reproduction guides, and remediation recommendations.
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from boundaryx.domain.findings.models import FindingCategory
from boundaryx.infrastructure.database.models import (
    EvidenceModel,
    FindingModel,
    IdentityModel,
    PolicyModel,
    ProjectModel,
    ResourceModel,
    ScopeRuleModel,
    TestCaseModel,
    TestExecutionModel,
)
from boundaryx.security.audit import REPORT_EXPORTED, AuditLogger
from boundaryx.security.redaction import RedactionEngine

logger = logging.getLogger(__name__)

TOOL_NAME = "BoundaryX"
TOOL_VERSION = "0.1.1"


def _utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class ReportOptions(BaseModel):
    """Configuration options for report generation and export."""

    model_config = ConfigDict(from_attributes=True)

    include_evidence: bool = Field(
        default=True,
        description="Whether to embed full HTTP request/response evidence snapshots",
    )
    redact_secrets: bool = Field(
        default=True,
        description="Whether to scrub tokens, cookies, and secrets from evidence snapshots",
    )
    formats: list[str] = Field(
        default_factory=lambda: ["json", "markdown", "html"],
        description="Target export formats desired",
    )
    include_recommendations: bool = Field(
        default=True,
        description="Whether to generate actionable remediation recommendations",
    )
    title: str | None = Field(
        default=None,
        description="Custom assessment title override",
    )
    organization: str | None = Field(
        default=None,
        description="Target organization or application owner name",
    )


class ReportService:
    """Service responsible for assembling, previewing, and exporting authorization audit reports."""

    def __init__(
        self,
        db_manager: Any,
        report_exporter: Any = None,
        evidence_exporter: Any = None,
        redaction_engine: RedactionEngine | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        """Initialize ReportService.

        Args:
            db_manager: Database connection/session manager.
            report_exporter: Optional custom report exporter hook.
            evidence_exporter: Optional custom evidence exporter hook.
            redaction_engine: RedactionEngine for scrubbing sensitive artifacts.
            audit_logger: AuditLogger for recording report generation milestones.
        """
        self._db_manager = db_manager
        self._report_exporter = report_exporter
        self._evidence_exporter = evidence_exporter
        self._redactor = redaction_engine or RedactionEngine()
        self._audit = audit_logger

    def generate_report(
        self,
        session: Session,
        project_id: UUID | str,
        options: ReportOptions | None = None,
    ) -> dict[str, Any]:
        """Assemble a complete, structured authorization assessment report.

        Covers 13 standardized audit sections:
        1. Project summary
        2. Scope and limitations
        3. Testing methodology
        4. Identities and roles
        5. Resources and endpoints
        6. Policies evaluated
        7. Findings with evidence
        8. Reproduction steps
        9. Expected vs observed
        10. Confidence and limitations
        11. Recommendations
        12. Tool version
        13. Timestamp

        Args:
            session: Active database session.
            project_id: Project identifier.
            options: Optional ReportOptions configuration.

        Returns:
            Dictionary containing the complete assessment report document.

        Raises:
            KeyError: If project does not exist.
        """
        opts = options or ReportOptions()
        proj_str = str(project_id)

        # 1. Fetch Project Record
        project = session.scalars(select(ProjectModel).where(ProjectModel.id == proj_str)).first()
        if not project:
            raise KeyError(f"Project with ID {project_id} not found")

        # 2. Query Domain Collections
        scope_rules = list(
            session.scalars(
                select(ScopeRuleModel)
                .where(ScopeRuleModel.project_id == proj_str)
                .order_by(ScopeRuleModel.created_at.asc())
            ).all()
        )
        identities = list(
            session.scalars(
                select(IdentityModel).where(IdentityModel.project_id == proj_str).order_by(IdentityModel.name.asc())
            ).all()
        )
        resources = list(
            session.scalars(
                select(ResourceModel)
                .where(ResourceModel.project_id == proj_str)
                .order_by(ResourceModel.display_name.asc())
            ).all()
        )
        policies = list(
            session.scalars(
                select(PolicyModel).where(PolicyModel.project_id == proj_str).order_by(PolicyModel.name.asc())
            ).all()
        )
        findings = list(
            session.scalars(
                select(FindingModel).where(FindingModel.project_id == proj_str).order_by(FindingModel.created_at.desc())
            ).all()
        )
        test_cases = list(
            session.scalars(
                select(TestCaseModel)
                .where(TestCaseModel.project_id == proj_str)
                .order_by(TestCaseModel.created_at.asc())
            ).all()
        )
        executions = list(
            session.scalars(
                select(TestExecutionModel)
                .where(TestExecutionModel.project_id == proj_str)
                .order_by(TestExecutionModel.started_at.desc())
            ).all()
        )

        # Query Evidence if requested
        evidence_records: dict[str, EvidenceModel] = {}
        if opts.include_evidence:
            ev_list = session.scalars(select(EvidenceModel).where(EvidenceModel.project_id == proj_str)).all()
            evidence_records = {e.id: e for e in ev_list}

        # SECTION 1: Project Summary
        project_summary = {
            "project_id": project.id,
            "project_name": project.name,
            "description": project.description or "",
            "assessment_title": opts.title or f"{project.name} - Authorization Security Assessment",
            "organization": opts.organization or "Security Assessment Team",
            "created_at": project.created_at.isoformat() if project.created_at else None,
            "updated_at": project.updated_at.isoformat() if project.updated_at else None,
            "counts": {
                "identities": len(identities),
                "resources": len(resources),
                "policies": len(policies),
                "test_cases": len(test_cases),
                "test_executions": len(executions),
                "findings_total": len(findings),
                "findings_critical": sum(1 for f in findings if (f.severity or "").upper() == "CRITICAL"),
                "findings_high": sum(1 for f in findings if (f.severity or "").upper() == "HIGH"),
                "findings_medium": sum(1 for f in findings if (f.severity or "").upper() == "MEDIUM"),
                "findings_low": sum(1 for f in findings if (f.severity or "").upper() == "LOW"),
            },
        }

        # SECTION 2: Scope and Limitations
        scope_and_limitations = {
            "authorized_hostnames": sorted(list({r.hostname for r in scope_rules if not r.is_excluded})),
            "excluded_hostnames": sorted(list({r.hostname for r in scope_rules if r.is_excluded})),
            "rules": [
                {
                    "hostname": r.hostname,
                    "scheme": r.scheme,
                    "port": r.port,
                    "path_prefix": r.path_prefix,
                    "path_exclusions": list(r.path_exclusions or []),
                    "is_excluded": r.is_excluded,
                    "notes": r.notes or "",
                }
                for r in scope_rules
            ],
            "limitations": [
                "Testing was strictly constrained to authorized hostnames and port numbers.",
                "Redirections were verified hop-by-hop; out-of-scope targets were automatically blocked.",
                "Rate limiting was applied to protect target system stability.",
            ],
        }

        # SECTION 3: Testing Methodology
        testing_methodology = {
            "framework": "BoundaryX Authorization Analysis Engine",
            "modes_utilized": ["OFFLINE", "PREVIEW", "ACTIVE"],
            "verification_principles": [
                "Strict scope boundary re-check enforced prior to every active HTTP request.",
                "Conservative classification: 200 OK without verified resource payload is marked INCONCLUSIVE.",
                "Defense-in-depth masking: 404 responses evaluated against expected denial policies.",
                "Full cryptographic hashing of collected evidence artifacts (SHA-256).",
            ],
        }

        # SECTION 4: Identities and Roles
        identities_and_roles = [
            {
                "id": i.id,
                "name": i.name,
                "role_type": i.role_type,
                "custom_role_name": i.custom_role_name,
                "status": i.status,
                "tags": list(i.tags or []),
                "notes": i.notes or "",
            }
            for i in identities
        ]

        # SECTION 5: Resources and Endpoints
        resources_and_endpoints = [
            {
                "id": r.id,
                "display_name": r.display_name,
                "resource_type": r.resource_type,
                "sensitivity": r.sensitivity,
                "external_id": r.external_id,
                "associated_endpoints": list(r.associated_endpoints or []),
                "owning_identity_id": r.owning_identity_id,
                "owning_tenant_id": r.owning_tenant_id,
            }
            for r in resources
        ]

        # SECTION 6: Policies Evaluated
        policies_evaluated = [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description or "",
                "action": p.action,
                "expected_decision": p.expected_decision,
                "subject_selector": p.subject_selector or {},
                "resource_selector": p.resource_selector or {},
                "preconditions": p.preconditions or {},
                "enabled": p.enabled,
            }
            for p in policies
        ]

        # SECTION 7: Findings with Evidence
        findings_with_evidence = []
        for f in findings:
            ev_snapshots = []
            if opts.include_evidence and f.evidence_ids:
                for eid in f.evidence_ids:
                    ev_item = evidence_records.get(eid)
                    if ev_item:
                        req_snap = ev_item.request_snapshot or {}
                        resp_snap = ev_item.response_snapshot or {}
                        if opts.redact_secrets:
                            req_snap = self._redactor.redact_evidence(req_snap)
                            resp_snap = self._redactor.redact_evidence(resp_snap)
                        ev_snapshots.append(
                            {
                                "evidence_id": ev_item.id,
                                "type": ev_item.evidence_type,
                                "content_hash": ev_item.content_hash,
                                "request": req_snap,
                                "response": resp_snap,
                                "timestamp": ev_item.timestamp.isoformat() if ev_item.timestamp else None,
                            }
                        )

            findings_with_evidence.append(
                {
                    "id": f.id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "status": f.status,
                    "affected_endpoint": f.affected_endpoint,
                    "affected_resource_id": f.affected_resource_id,
                    "subject_identity_id": f.subject_identity_id,
                    "expected_decision": f.expected_decision,
                    "observed_decision": f.observed_decision,
                    "confidence": f.confidence_data or {},
                    "reproduction_steps": list(f.reproduction_steps or []),
                    "evidence": ev_snapshots,
                    "reviewer_notes": f.reviewer_notes or "",
                    "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                    "last_verified": f.last_verified.isoformat() if f.last_verified else None,
                }
            )

        # SECTION 8: Reproduction Steps
        reproduction_steps = [
            {
                "finding_id": f.id,
                "title": f.title,
                "severity": f.severity,
                "steps": list(f.reproduction_steps or []),
            }
            for f in findings
            if f.reproduction_steps
        ]

        # SECTION 9: Expected vs Observed Matrix
        expected_vs_observed = [
            {
                "test_case_name": tc.name,
                "action": tc.action,
                "expected": tc.expected_decision,
                "observed_status": tc.result_status,
                "execution_mode": tc.execution_mode,
            }
            for tc in test_cases
        ]

        # SECTION 10: Confidence and Limitations
        confidence_and_limitations = {
            "overall_assessment_confidence": ("HIGH" if len(executions) > 0 and len(findings) > 0 else "MEDIUM"),
            "findings_confidence_summary": [
                {
                    "finding_id": f.id,
                    "title": f.title,
                    "confidence_level": (f.confidence_data or {}).get("level", "MEDIUM"),
                    "factors": (f.confidence_data or {}).get("factors", []),
                    "missing_evidence": (f.confidence_data or {}).get("missing_evidence", []),
                }
                for f in findings
            ],
            "limitations_noted": [
                "Offline traffic analysis relies upon captured historical logs which may become stale.",
                "Active testing was executed with non-destructive payloads to ensure operational integrity.",
            ],
        }

        # SECTION 11: Recommendations
        recommendations = []
        if opts.include_recommendations:
            recommendations = self._generate_recommendations(findings)

        report_data = {
            "project_summary": project_summary,
            "scope_and_limitations": scope_and_limitations,
            "testing_methodology": testing_methodology,
            "identities_and_roles": identities_and_roles,
            "resources_and_endpoints": resources_and_endpoints,
            "policies_evaluated": policies_evaluated,
            "findings_with_evidence": findings_with_evidence,
            "reproduction_steps": reproduction_steps,
            "expected_vs_observed": expected_vs_observed,
            "confidence_and_limitations": confidence_and_limitations,
            "recommendations": recommendations,
            "tool_version": f"{TOOL_NAME} v{TOOL_VERSION}",
            "timestamp": _utc_now().isoformat(),
        }

        return report_data

    def preview_report(
        self,
        session: Session,
        project_id: UUID | str,
        options: ReportOptions | None = None,
    ) -> dict[str, Any]:
        """Return an executive preview and summary of the generated assessment report.

        Args:
            session: Active database session.
            project_id: Project identifier.
            options: Optional ReportOptions.

        Returns:
            Executive summary dictionary with table of contents and severity metrics.
        """
        report = self.generate_report(session, project_id, options)
        summary = report["project_summary"]
        findings = report["findings_with_evidence"]

        toc = [
            "1. Project Summary",
            "2. Scope & Boundaries",
            "3. Testing Methodology",
            "4. Identity & Role Inventory",
            "5. Resource & Endpoint Catalog",
            "6. Policy Rule Matrix",
            "7. Security Findings & Evidence",
            "8. Reproduction Procedures",
            "9. Expected vs Observed Reality",
            "10. Confidence & Limitations",
            "11. Remediation Recommendations",
        ]

        return {
            "assessment_title": summary["assessment_title"],
            "project_name": summary["project_name"],
            "total_findings": summary["counts"]["findings_total"],
            "findings_breakdown": {
                "critical": summary["counts"]["findings_critical"],
                "high": summary["counts"]["findings_high"],
                "medium": summary["counts"]["findings_medium"],
                "low": summary["counts"]["findings_low"],
            },
            "table_of_contents": toc,
            "top_findings": [
                {
                    "title": f["title"],
                    "severity": f["severity"],
                    "endpoint": f["affected_endpoint"],
                }
                for f in findings[:5]
            ],
            "generated_at": report["timestamp"],
        }

    def export_report(
        self,
        session: Session,
        project_id: UUID | str,
        format: str,
        output_path: Path | str,
        options: ReportOptions | None = None,
    ) -> Path:
        """Export the assessment report to a file in the requested format.

        Supported formats: 'json', 'markdown' (or 'md'), 'html', 'csv'.

        Args:
            session: Active database session.
            project_id: Project identifier.
            format: Target serialization format.
            output_path: Destination file path.
            options: Optional ReportOptions configuration.

        Returns:
            Resolved Path of the generated report file.

        Raises:
            ValueError: If unsupported format requested.
        """
        report_data = self.generate_report(session, project_id, options)
        dest = Path(output_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        fmt = format.strip().lower()

        if fmt == "json":
            with dest.open("w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
        elif fmt in ("markdown", "md"):
            content = self._render_markdown(report_data)
            dest.write_text(content, encoding="utf-8")
        elif fmt == "html":
            content = self._render_html(report_data)
            dest.write_text(content, encoding="utf-8")
        elif fmt == "csv":
            self._render_csv(report_data, dest)
        else:
            raise ValueError(f"Unsupported report export format '{format}'. Supported: json, markdown, html, csv.")

        # Log audit event
        if self._audit:
            try:
                self._audit.log(
                    event_type=REPORT_EXPORTED,
                    description=f"Assessment report exported to {dest.name} ({fmt.upper()})",
                    project_id=project_id,
                    details={"format": fmt, "path": str(dest)},
                )
            except Exception as exc:
                logger.warning("Failed to record audit event for report export: %s", exc)

        logger.info("Successfully exported %s report to %s", fmt.upper(), dest)
        return dest

    def _generate_recommendations(self, findings: list[FindingModel]) -> list[dict[str, str]]:
        """Synthesize domain-specific, actionable remediation guidance based on findings."""
        categories = {f.category for f in findings}
        recommendations = []

        if FindingCategory.IDOR.value in categories or any("IDOR" in (f.title or "") for f in findings):
            recommendations.append(
                {
                    "title": "Implement Robust Object-Level Authorization Checks (IDOR/BOLA)",
                    "category": "OBJECT_LEVEL_AUTHORIZATION",
                    "priority": "HIGH",
                    "details": (
                        "Verify that API controllers and repository access queries explicitly validate that the "
                        "authenticated principal owns or has designated authorization on the target record ID "
                        "before returning data or performing state mutations."
                    ),
                }
            )

        if FindingCategory.CROSS_TENANT_ACCESS.value in categories or any(
            "tenant" in (f.title or "").lower() for f in findings
        ):
            recommendations.append(
                {
                    "title": "Enforce Strict Multi-Tenant Boundary Partitioning",
                    "category": "TENANT_ISOLATION",
                    "priority": "CRITICAL",
                    "details": (
                        "Ensure tenant_id is an immutable attribute attached to every resource and enforced "
                        "at the data access layer via row-level security (RLS) or mandatory "
                        "WHERE tenant_id = :tenant_id clauses."
                    ),
                }
            )

        if FindingCategory.MISSING_AUTHORIZATION.value in categories or any(
            "missing" in (f.title or "").lower() for f in findings
        ):
            recommendations.append(
                {
                    "title": "Enforce Default-Deny Authorization Middleware on All Endpoints",
                    "category": "ACCESS_CONTROL_CONFIGURATION",
                    "priority": "HIGH",
                    "details": (
                        "Adopt a secure-by-default architecture where unauthenticated or unspecified access requests "
                        "are rejected by gateway middleware unless explicitly exempted in the security routing policy."
                    ),
                }
            )

        if not recommendations:
            recommendations.append(
                {
                    "title": "Maintain Continuous Policy Monitoring and Matrix Testing",
                    "category": "GOVERNANCE",
                    "priority": "MEDIUM",
                    "details": (
                        "Integrate automated authorization boundary testing into the CI/CD pipeline to detect "
                        "regression flaws and unauthorized endpoint exposures prior to production deployment."
                    ),
                }
            )

        return recommendations

    def _render_markdown(self, data: dict[str, Any]) -> str:
        """Render assessment report data as structured Markdown."""
        summary = data["project_summary"]
        counts = summary["counts"]
        scope = data["scope_and_limitations"]
        findings = data["findings_with_evidence"]
        recs = data["recommendations"]

        md = []
        md.append(f"# {summary['assessment_title']}")
        md.append(f"*Generated by {data['tool_version']} on {data['timestamp']}*\n")

        md.append("## Executive Summary")
        md.append(f"- **Project Name:** {summary['project_name']}")
        md.append(f"- **Total Security Findings:** {counts['findings_total']}")
        md.append(f"  - **Critical:** {counts['findings_critical']}")
        md.append(f"  - **High:** {counts['findings_high']}")
        md.append(f"  - **Medium:** {counts['findings_medium']}")
        md.append(f"  - **Low:** {counts['findings_low']}")
        md.append(f"- **Identities Evaluated:** {counts['identities']}")
        md.append(f"- **Target Resources:** {counts['resources']}")
        md.append(f"- **Authorization Test Cases:** {counts['test_cases']}\n")

        md.append("## Scope & Testing Boundaries")
        md.append(f"- **Authorized Hostnames:** {', '.join(scope['authorized_hostnames']) or 'None specified'}")
        if scope["excluded_hostnames"]:
            md.append(f"- **Excluded Hostnames:** {', '.join(scope['excluded_hostnames'])}")
        md.append("\n### Boundary Limitations")
        for lim in scope["limitations"]:
            md.append(f"- {lim}")
        md.append("")

        md.append("## Security Findings")
        if not findings:
            md.append("*No authorization boundary defects were discovered.*")
        else:
            for idx, f in enumerate(findings, 1):
                md.append(f"### {idx}. [{f['severity']}] {f['title']}")
                md.append(f"- **Affected Endpoint:** `{f['affected_endpoint']}`")
                md.append(f"- **Category:** {f['category']}")
                md.append(f"- **Expected Decision:** `{f['expected_decision']}`")
                md.append(f"- **Observed Decision:** `{f['observed_decision']}`")
                if f["reproduction_steps"]:
                    md.append("- **Reproduction Procedure:**")
                    for step in f["reproduction_steps"]:
                        md.append(f"  - {step}")
                md.append("")

        if recs:
            md.append("## Remediation Recommendations")
            for r in recs:
                md.append(f"### [{r['priority']}] {r['title']}")
                md.append(f"{r['details']}\n")

        return "\n".join(md)

    def _render_html(self, data: dict[str, Any]) -> str:
        """Render assessment report data as self-contained HTML."""
        summary = data["project_summary"]
        counts = summary["counts"]
        findings = data["findings_with_evidence"]

        findings_html = ""
        for f in findings:
            findings_html += (
                f'<div style="border-left: 4px solid #e53e3e; padding-left: 15px; margin-bottom: 20px;">\n'
                f'  <h3 style="margin-top: 0;">[{f["severity"]}] {f["title"]}</h3>\n'
                f"  <p><strong>Endpoint:</strong> <code>{f['affected_endpoint']}</code></p>\n"
                f"  <p><strong>Expected:</strong> {f['expected_decision']} | "
                f"<strong>Observed:</strong> {f['observed_decision']}</p>\n"
                f"</div>\n"
            )

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{summary["assessment_title"]}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 900px;
            margin: 40px auto;
            padding: 0 20px;
        }}
        h1, h2, h3 {{ color: #1a202c; }}
        code {{ background: #edf2f7; padding: 2px 6px; border-radius: 4px; }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            background: #feb2b2;
            color: #9b2c2c;
        }}
    </style>
</head>
<body>
    <h1>{summary["assessment_title"]}</h1>
    <p><em>Generated by {data["tool_version"]} on {data["timestamp"]}</em></p>
    <h2>Executive Summary</h2>
    <p>
        <strong>Project:</strong> {summary["project_name"]} |
        <strong>Total Findings:</strong> {counts["findings_total"]}
    </p>
    <h2>Discovered Boundary Defects</h2>
    {findings_html or "<p>No defects discovered.</p>"}
</body>
</html>"""

    def _render_csv(self, data: dict[str, Any], dest: Path) -> None:
        """Render findings list as CSV file."""
        findings = data["findings_with_evidence"]
        with dest.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "ID",
                    "Severity",
                    "Category",
                    "Title",
                    "Endpoint",
                    "Expected Decision",
                    "Observed Decision",
                    "Status",
                    "First Seen",
                ]
            )
            for item in findings:
                writer.writerow(
                    [
                        item["id"],
                        item["severity"],
                        item["category"],
                        item["title"],
                        item["affected_endpoint"],
                        item["expected_decision"],
                        item["observed_decision"],
                        item["status"],
                        item["first_seen"],
                    ]
                )
