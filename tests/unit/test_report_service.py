"""Unit tests for ReportService and ReportOptions."""

import json
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from boundaryx.application.reporting.service import ReportService
from boundaryx.infrastructure.database.base import Base
from boundaryx.infrastructure.database.models import (
    FindingModel,
    IdentityModel,
    PolicyModel,
    ProjectModel,
    ResourceModel,
    ScopeRuleModel,
    TestCaseModel,
)


@pytest.fixture
def db_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def report_service() -> ReportService:
    return ReportService(db_manager=None)


def test_generate_report_13_sections(db_session: Session, report_service: ReportService) -> None:
    proj_id = uuid4()
    proj = ProjectModel(id=str(proj_id), name="Banking App Assessment")
    rule = ScopeRuleModel(id=str(uuid4()), project_id=str(proj_id), hostname="banking.example.com")
    ident = IdentityModel(id=str(uuid4()), project_id=str(proj_id), name="Regular Customer", role_type="AUTHENTICATED")
    res = ResourceModel(
        id=str(uuid4()),
        project_id=str(proj_id),
        display_name="Account Balance",
        resource_type="USER_PROFILE",
        external_id="acc_999",
    )
    pol = PolicyModel(
        id=str(uuid4()),
        project_id=str(proj_id),
        name="Only Account Owner Allowed",
        action="READ",
        expected_decision="DENY",
        enabled=True,
    )
    finding = FindingModel(
        id=str(uuid4()),
        project_id=str(proj_id),
        title="BOLA on /api/accounts/balance",
        category="IDOR",
        affected_endpoint="/api/accounts/balance",
        expected_decision="DENY",
        observed_decision="ALLOW",
        severity="HIGH",
        reproduction_steps=["1. Login as user A", "2. Request balance for user B"],
    )
    tc = TestCaseModel(
        id=str(uuid4()),
        project_id=str(proj_id),
        name="Test BOLA Balance",
        subject_identity_id=ident.id,
        target_resource_id=res.id,
        action="READ",
        expected_decision="DENY",
        request_template={"method": "GET", "url_template": "/api/accounts/balance"},
    )
    db_session.add_all([proj, rule, ident, res, pol, finding, tc])
    db_session.commit()

    report = report_service.generate_report(db_session, proj_id)

    # Verify all 13 sections
    assert "project_summary" in report
    assert "scope_and_limitations" in report
    assert "testing_methodology" in report
    assert "identities_and_roles" in report
    assert "resources_and_endpoints" in report
    assert "policies_evaluated" in report
    assert "findings_with_evidence" in report
    assert "reproduction_steps" in report
    assert "expected_vs_observed" in report
    assert "confidence_and_limitations" in report
    assert "recommendations" in report
    assert "tool_version" in report
    assert "timestamp" in report

    # Verify section contents
    assert report["project_summary"]["project_name"] == "Banking App Assessment"
    assert len(report["findings_with_evidence"]) == 1
    assert report["findings_with_evidence"][0]["severity"] == "HIGH"
    assert len(report["recommendations"]) >= 1


def test_preview_report(db_session: Session, report_service: ReportService) -> None:
    proj_id = uuid4()
    proj = ProjectModel(id=str(proj_id), name="Preview Project")
    db_session.add(proj)
    db_session.commit()

    preview = report_service.preview_report(db_session, proj_id)
    assert preview["project_name"] == "Preview Project"
    assert "table_of_contents" in preview
    assert len(preview["table_of_contents"]) > 5


def test_export_report_formats(db_session: Session, report_service: ReportService, tmp_path: Path) -> None:
    proj_id = uuid4()
    proj = ProjectModel(id=str(proj_id), name="Export Project")
    finding = FindingModel(
        id=str(uuid4()),
        project_id=str(proj_id),
        title="IDOR Issue",
        category="IDOR",
        affected_endpoint="/api/test",
        expected_decision="DENY",
        observed_decision="ALLOW",
        severity="MEDIUM",
    )
    db_session.add_all([proj, finding])
    db_session.commit()

    # JSON export
    json_path = tmp_path / "report.json"
    exported_json = report_service.export_report(db_session, proj_id, format="json", output_path=json_path)
    assert exported_json.exists()
    with open(exported_json, encoding="utf-8") as f:
        data = json.load(f)
        assert data["project_summary"]["project_name"] == "Export Project"

    # Markdown export
    md_path = tmp_path / "report.md"
    exported_md = report_service.export_report(db_session, proj_id, format="markdown", output_path=md_path)
    assert exported_md.exists()
    content_md = exported_md.read_text(encoding="utf-8")
    assert "# Export Project - Authorization Security Assessment" in content_md
    assert "## Executive Summary" in content_md

    # HTML export
    html_path = tmp_path / "report.html"
    exported_html = report_service.export_report(db_session, proj_id, format="html", output_path=html_path)
    assert exported_html.exists()
    content_html = exported_html.read_text(encoding="utf-8")
    assert "<title>" in content_html

    # CSV export
    csv_path = tmp_path / "findings.csv"
    exported_csv = report_service.export_report(db_session, proj_id, format="csv", output_path=csv_path)
    assert exported_csv.exists()
    content_csv = exported_csv.read_text(encoding="utf-8")
    assert "IDOR Issue" in content_csv
