"""Unit tests for ReportExporter, EvidenceExporter, and ProjectExporter."""

import json
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest

from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.infrastructure.database.models import (
    IdentityModel,
    ProjectModel,
    ScopeRuleModel,
)
from boundaryx.infrastructure.exports import (
    EvidenceExporter,
    ProjectExporter,
    ReportExporter,
    ReportExportError,
)
from boundaryx.security.redaction import RedactionEngine


def test_report_exporter_14_sections_generation():
    proj = {"id": str(uuid4()), "name": "E-Commerce App", "description": "Assessment of shop"}
    findings = [
        {
            "id": "find-1",
            "title": "BOLA on user invoices",
            "severity": "CRITICAL",
            "category": "BOLA",
            "affected_endpoint": "/api/invoices/{id}",
            "cwe_id": "CWE-639",
            "cvss_score": 9.1,
            "description": "User A can view User B invoice",
            "remediation": "Validate owner tenant and user ID",
        }
    ]

    report = ReportExporter.generate_report_data(
        project=proj,
        findings=findings,
        scope_config={"authorized_hostnames": ["api.target.com"], "total_rules": 1},
    )

    # Verify all 14 sections are present
    expected_sections = [
        "executive_summary",
        "scope_and_boundaries",
        "identity_profiles",
        "resource_inventory",
        "access_control_policies",
        "findings_summary",
        "detailed_findings",
        "bola_analysis",
        "bfla_analysis",
        "isolation_evaluation",
        "automated_test_results",
        "compliance_alignment",
        "remediation_roadmap",
        "evidence_and_appendix",
    ]
    for sec in expected_sections:
        assert sec in report, f"Section '{sec}' missing from generated report"

    assert report["executive_summary"]["severity_breakdown"]["CRITICAL"] == 1
    assert report["bola_analysis"]["count"] == 1


def test_report_exporter_formats(tmp_path: Path):
    proj = {"id": str(uuid4()), "name": "App Security", "description": "Desc"}
    findings = [
        {
            "id": "f1",
            "title": "BFLA Admin Export",
            "severity": "HIGH",
            "category": "BFLA",
            "affected_endpoint": "/admin/export",
        }
    ]
    report = ReportExporter.generate_report_data(proj, findings)

    # 1. JSON
    json_path = tmp_path / "report.json"
    ReportExporter.export_json(report, json_path)
    assert json_path.exists()
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["metadata"]["project_name"] == "App Security"

    # 2. Markdown
    md_path = tmp_path / "report.md"
    ReportExporter.export_markdown(report, md_path)
    assert md_path.exists()
    assert "# Authorization Boundary Assessment Report: App Security" in md_path.read_text(encoding="utf-8")

    # 3. CSV
    csv_path = tmp_path / "findings.csv"
    ReportExporter.export_csv(findings, csv_path)
    assert csv_path.exists()
    assert "BFLA Admin Export" in csv_path.read_text(encoding="utf-8")

    # 4. HTML
    html_path = tmp_path / "report.html"
    ReportExporter.export_html(report, html_path)
    assert html_path.exists()
    assert "<!DOCTYPE html>" in html_path.read_text(encoding="utf-8")


def test_path_sanitization_defense(tmp_path: Path):
    base_dir = tmp_path / "safe"
    base_dir.mkdir()

    # Traversal attempt outside base_dir
    with pytest.raises(ReportExportError):
        ReportExporter._sanitize_path(base_dir / ".." / "escaped.txt", base_dir=base_dir)


def test_evidence_exporter_and_package(tmp_path: Path):
    evidence_list = [
        {
            "id": "ev-001",
            "url": "https://api.target.com/user/secret",
            "headers": {"Authorization": "Bearer super-secret-token"},
            "body": '{"token": "xyz123"}',
        }
    ]

    redactor = RedactionEngine()
    ev_dir = tmp_path / "evidence_out"
    EvidenceExporter.export_evidence(evidence_list, ev_dir, redaction_engine=redactor)

    exported_file = ev_dir / "evidence_ev-001.json"
    assert exported_file.exists()
    content = json.loads(exported_file.read_text(encoding="utf-8"))
    # Token should be redacted by engine
    assert content["headers"]["Authorization"] == "[REDACTED]"
    assert "[REDACTED]" in content["body"]

    # Package export
    report_data = ReportExporter.generate_report_data({"name": "Test"}, [])
    zip_path = tmp_path / "package.zip"
    EvidenceExporter.export_package(report_data, evidence_list, zip_path, redaction_engine=redactor)

    assert zip_path.exists()
    with zipfile.ZipFile(zip_path, "r") as z:
        names = z.namelist()
        assert "report.json" in names
        assert "report.html" in names
        assert any(n.startswith("evidence/") for n in names)


def test_project_exporter_roundtrip(tmp_path: Path):
    db_path = tmp_path / "test_roundtrip.db"
    db_mgr = DatabaseManager(db_path)
    db_mgr.create_tables()

    proj_id = str(uuid4())
    with db_mgr.get_session() as session:
        proj = ProjectModel(id=proj_id, name="Original Workspace", description="Testing export")
        session.add(proj)
        rule = ScopeRuleModel(id=str(uuid4()), project_id=proj_id, hostname="target.corp")
        session.add(rule)
        ident = IdentityModel(id=str(uuid4()), project_id=proj_id, name="AdminUser", role_type="ADMIN")
        session.add(ident)

    export_file = tmp_path / "project_export.json"
    with db_mgr.get_session() as session:
        ProjectExporter.export_project(session, proj_id, export_file, include_secrets=False)

    assert export_file.exists()

    # Import project into fresh session
    with db_mgr.get_session() as session:
        new_proj_id = ProjectExporter.import_project(session, export_file)
        assert new_proj_id != uuid4()  # valid UUID
        assert str(new_proj_id) != proj_id  # Remapped to new UUID to prevent collisions

        new_proj = session.get(ProjectModel, str(new_proj_id))
        assert new_proj is not None
        assert "Original Workspace (Imported)" in new_proj.name

        # Verify child scope rule remapped
        rules = [r for r in new_proj.scope_rules]
        assert len(rules) == 1
        assert rules[0].hostname == "target.corp"
        assert rules[0].project_id == str(new_proj_id)
