from pathlib import Path
import tempfile

import pytest

from boundaryx.domain.enums import Confidence, FindingStatus, Severity
from boundaryx.domain.models import Finding, Program
from boundaryx.findings.dedup import DuplicateDetector
from boundaryx.findings.service import FindingService, FindingTransitionError
from boundaryx.reporting.generator import ReportGenerator, escape_csv_cell
from boundaryx.storage.database import Database
from boundaryx.storage.migrations import MigrationRunner
from boundaryx.storage.repositories import FindingRepository, ProgramRepository


def test_finding_state_transitions():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(Path(tmpdir) / "findings_test.db")
        try:
            migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
            MigrationRunner(db, migrations_dir).run_pending_migrations()
            prog_repo = ProgramRepository(db)
            finding_repo = FindingRepository(db)
            service = FindingService(finding_repo)

            prog_repo.create(Program(id="p1", name="Test"))

            f1 = Finding(
                program_id="p1",
                title="BOLA on /api/users/{id}",
                category="BOLA",
                status=FindingStatus.CANDIDATE,
            )
            finding_repo.create(f1)

            # Direct candidate -> verified without review is illegal
            with pytest.raises(FindingTransitionError, match="Illegal finding state transition"):
                service.transition_status(f1.id, FindingStatus.VERIFIED, "Verified")

            # candidate -> needs_review
            service.transition_status(f1.id, FindingStatus.NEEDS_REVIEW, "Triage review needed")
            assert finding_repo.get(f1.id).status == FindingStatus.NEEDS_REVIEW

            # needs_review -> verified requires evidence and review reason
            with pytest.raises(FindingTransitionError, match="requires at least one linked evidence ID"):
                service.transition_status(f1.id, FindingStatus.VERIFIED, "Human confirmed")

            # Create actual evidence record in DB
            cur = db.conn.cursor()
            cur.execute(
                """
                INSERT INTO evidence (id, program_id, evidence_type, title, content_ref, content_sha256, size_bytes, redaction_state, created_at, retention_class)
                VALUES ('ev-123', 'p1', 'http_exchange', 'Evidence 1', '/evidence/1', 'sha256_dummy', 100, 'redacted', '2026-10-16T10:00:00Z', 'standard');
                """
            )

            # Link evidence and retry
            finding_repo.link_evidence(f1.id, "ev-123")

            verified = service.transition_status(f1.id, FindingStatus.VERIFIED, "Manual reproduction verified via Burp Suite")
            assert verified.status == FindingStatus.VERIFIED
            assert verified.verified_at is not None
        finally:
            db.close()


def test_duplicate_detector():
    detector = DuplicateDetector(threshold=0.7)
    f1 = Finding(program_id="p1", asset_id="a1", title="Broken Object Level Authorization on /api/order/1", category="BOLA")
    f2 = Finding(program_id="p1", asset_id="a1", title="Broken Object Level Authorization on /api/order/2", category="BOLA")
    f3 = Finding(program_id="p1", asset_id="a2", title="SQL Injection in login endpoint", category="SQLi")

    suggestions = detector.find_duplicates(f1, [f1, f2, f3])
    assert len(suggestions) == 1
    assert suggestions[0].target_duplicate_id == f2.id
    assert suggestions[0].similarity_score > 0.8


def test_report_generator_html_xss_protection():
    generator = ReportGenerator()
    prog = Program(name="<script>alert('XSS_PROG')</script>")
    f = Finding(
        program_id=prog.id,
        title="<img src=x onerror=alert('XSS_TITLE')>",
        category="Injection",
    )
    html_output = generator.generate_html(prog, [f], [], [])

    # Ensure dangerous tags are escaped
    assert "<script>" not in html_output
    assert "&lt;script&gt;" in html_output
    assert "<img src=x onerror" not in html_output
    assert "&lt;img src=x onerror" in html_output


def test_report_generator_csv_formula_injection_defense():
    generator = ReportGenerator()
    f = Finding(
        program_id="p1",
        title="=cmd|'/C calc'!A0",
        category="+SUM(A1:A10)",
        impact="@HYPERLINK('http://evil.com')",
    )
    csv_output = generator.generate_csv([f])

    # Formula injection characters must be prepended with a single quote
    assert "'=cmd|" in csv_output
    assert "'+SUM" in csv_output
    assert "'@HYPERLINK" in csv_output
