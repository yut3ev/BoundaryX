from pathlib import Path
import sys
import tempfile
from typing import Any, Dict, List

from boundaryx.adapters.base import ToolAdapter
from boundaryx.domain.enums import JobStatus, JobType, MatcherType, ScopeRuleType
from boundaryx.domain.models import Job, Program, ScopeRule
from boundaryx.jobs.orchestrator import JobOrchestrator, RateLimiter
from boundaryx.storage.database import Database
from boundaryx.storage.migrations import MigrationRunner
from boundaryx.storage.repositories import (
    AssetRepository,
    JobRepository,
    ProgramRepository,
    ScopeRuleRepository,
)


class MockSubprocessAdapter(ToolAdapter):
    """Fake adapter that echoes back discovered subdomains using Python."""

    def __init__(self):
        super().__init__("python")

    def version(self) -> str:
        return "1.0.0"

    def capabilities(self) -> Dict[str, Any]:
        return {"name": "MockTool", "supports_cancellation": True}

    def validate_config(self, config: Dict[str, Any]) -> None:
        pass

    def build_argv(self, targets: List[str], config: Dict[str, Any]) -> List[str]:
        script = 'import json; print(json.dumps({"host": "api.example.com", "source": "mock"})); print(json.dumps({"host": "app.example.com", "source": "mock"}))'
        return [sys.executable, "-c", script]

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        import json
        res = []
        for line in stdout.splitlines():
            if line.strip():
                data = json.loads(line)
                res.append({"asset_type": "subdomain", "value": data["host"], "source": data["source"]})
        return res


def test_rate_limiter_acquires():
    limiter = RateLimiter(requests_per_second=20.0)
    limiter.acquire()
    assert True


def test_job_orchestrator_scope_enforcement_and_execution():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(Path(tmpdir) / "jobs_test.db")
        try:
            migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
            MigrationRunner(db, migrations_dir).run_pending_migrations()

            job_repo = JobRepository(db)
            scope_repo = ScopeRuleRepository(db)
            asset_repo = AssetRepository(db)
            prog_repo = ProgramRepository(db)

            # Create in-scope rule
            prog_id = "prog-1"
            prog_repo.create(Program(id=prog_id, name="Test Program"))
            scope_repo.create(
                ScopeRule(
                    program_id=prog_id,
                    rule_type=ScopeRuleType.INCLUDE,
                    matcher_type=MatcherType.DOMAIN,
                    pattern="example.com",
                    wildcard=True,
                )
            )

            orchestrator = JobOrchestrator(job_repo, scope_repo, asset_repo)

            job = Job(
                program_id=prog_id,
                job_type=JobType.SUBDOMAIN_DISCOVERY,
            )
            job_repo.create(job)

            adapter = MockSubprocessAdapter()
            # Targets: 1 in scope, 1 out of scope
            targets = ["example.com", "evil-attacker.com"]
            status = orchestrator.run_adapter_job_sync(job, adapter, targets)

            assert status == JobStatus.COMPLETED

            # Verify assets were registered
            assets = asset_repo.list_by_program(prog_id)
            assert len(assets) == 2
            values = [a.display_value for a in assets]
            assert "api.example.com" in values
            assert "app.example.com" in values

            # Verify events
            events = job_repo.list_events(job.id)
            event_types = [e.event_type for e in events]
            assert "SCOPE_VALIDATION" in event_types
            assert "SCOPE_DENIAL" in event_types
            assert "JOB_FINISHED" in event_types
        finally:
            db.close()
