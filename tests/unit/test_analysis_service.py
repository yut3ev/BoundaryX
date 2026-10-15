"""Unit tests for AnalysisService."""

from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from boundaryx.application.analysis.service import AnalysisService
from boundaryx.domain.identities.models import RoleType
from boundaryx.domain.policies.engine import PolicyEngine
from boundaryx.domain.policies.models import ExpectedDecision, Policy, PolicyAction, ResourceSelector, SubjectSelector
from boundaryx.domain.resources.models import ResourceType
from boundaryx.infrastructure.database.base import Base
from boundaryx.infrastructure.database.models import (
    FindingModel,
    IdentityModel,
    ProjectModel,
    ResourceModel,
    TrafficRecordModel,
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
def analysis_service() -> AnalysisService:
    pe = PolicyEngine()
    policy = Policy(
        name="Block Guests from Invoices",
        action=PolicyAction.READ,
        expected_decision=ExpectedDecision.DENY,
        subject_selector=SubjectSelector(role_type=RoleType.ANONYMOUS),
        resource_selector=ResourceSelector(resource_type=ResourceType.INVOICE),
    )
    pe.add_policy(policy)
    return AnalysisService(db_manager=None, policy_engine=pe)


def test_analyze_traffic_record_violation_detection(db_session: Session, analysis_service: AnalysisService) -> None:
    proj_id = uuid4()
    ident_id = uuid4()
    res_id = uuid4()
    rec_id = uuid4()

    proj = ProjectModel(id=str(proj_id), name="Finance Project")
    ident = IdentityModel(id=str(ident_id), project_id=str(proj_id), name="Guest User", role_type="ANONYMOUS")
    res = ResourceModel(
        id=str(res_id),
        project_id=str(proj_id),
        display_name="Confidential Invoice",
        resource_type="INVOICE",
        external_id="inv_99",
        associated_endpoints=["/api/invoices/inv_99"],
    )
    # Traffic record: Guest accessed invoice and got 200 OK (violation of DENY policy!)
    record = TrafficRecordModel(
        id=str(rec_id),
        project_id=str(proj_id),
        method="GET",
        url="https://api.finance.com/api/invoices/inv_99",
        scheme="https",
        host="api.finance.com",
        path="/api/invoices/inv_99",
        identity_id=str(ident_id),
        resource_id=str(res_id),
        response_status=200,
        response_body='{"invoice_id": "inv_99", "amount": 5000}',
    )
    db_session.add_all([proj, ident, res, record])
    db_session.commit()

    analysis = analysis_service.analyze_traffic_record(db_session, rec_id)

    assert analysis["record_id"] == str(rec_id)
    assert analysis["expected_decision"] == "DENY"
    assert analysis["observed_decision"] == "ALLOW"
    assert analysis["is_violation"] is True
    assert analysis["violation_type"] == "UNEXPECTED_ALLOW"
    assert analysis["severity"] == "HIGH"


def test_bulk_analyze(db_session: Session, analysis_service: AnalysisService) -> None:
    proj_id = uuid4()
    proj = ProjectModel(id=str(proj_id), name="Bulk Project")
    rec1 = TrafficRecordModel(
        id=str(uuid4()),
        project_id=str(proj_id),
        method="GET",
        url="https://api.test/a",
        scheme="https",
        host="api.test",
        path="/a",
        response_status=200,
    )
    rec2 = TrafficRecordModel(
        id=str(uuid4()),
        project_id=str(proj_id),
        method="POST",
        url="https://api.test/b",
        scheme="https",
        host="api.test",
        path="/b",
        response_status=403,
    )
    db_session.add_all([proj, rec1, rec2])
    db_session.commit()

    progress_calls = []

    def on_prog(processed: int, total: int) -> None:
        progress_calls.append((processed, total))

    result = analysis_service.bulk_analyze(db_session, proj_id, progress_callback=on_prog)
    assert result["total_records"] == 2
    assert len(progress_calls) == 2


def test_compare_responses(analysis_service: AnalysisService) -> None:
    resp_a = {"status_code": 200, "headers": {"Server": "nginx"}, "body": '{"ok": true}'}
    resp_b = {"status_code": 200, "headers": {"Server": "apache"}, "body": '{"ok": true}'}

    result = analysis_service.compare_responses(resp_a, resp_b)
    # Since 'Server' is in default ignored headers, they are considered identical!
    assert result["identical"] is True
    assert result["similarity_score"] == 1.0


def test_get_analysis_summary(db_session: Session, analysis_service: AnalysisService) -> None:
    proj_id = uuid4()
    proj = ProjectModel(id=str(proj_id), name="Summary Project")
    finding = FindingModel(
        id=str(uuid4()),
        project_id=str(proj_id),
        title="IDOR on Profile",
        category="IDOR",
        affected_endpoint="/api/profile/1",
        expected_decision="DENY",
        observed_decision="ALLOW",
        severity="HIGH",
        status="open",
    )
    db_session.add_all([proj, finding])
    db_session.commit()

    summary = analysis_service.get_analysis_summary(db_session, proj_id)
    assert summary["counts"]["findings"] == 1
    assert summary["findings_by_severity"]["HIGH"] == 1
    assert summary["security_posture_score"] == 85  # 100 - 15 (HIGH deduction)
