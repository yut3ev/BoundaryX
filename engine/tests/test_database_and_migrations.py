from pathlib import Path
import tempfile

from boundaryx.domain.enums import ScopeRuleType
from boundaryx.domain.models import Program, ScopeRule
from boundaryx.storage.database import Database
from boundaryx.storage.migrations import MigrationRunner
from boundaryx.storage.repositories import ProgramRepository, ScopeRuleRepository


def test_migrations_and_repositories_workflow():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        try:
            # Ensure foreign keys and WAL mode are enabled
            cur = db.conn.cursor()
            cur.execute("PRAGMA foreign_keys;")
            assert cur.fetchone()[0] == 1
            cur.execute("PRAGMA journal_mode;")
            assert cur.fetchone()[0].lower() == "wal"

            migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
            runner = MigrationRunner(db, migrations_dir)
            applied = runner.run_pending_migrations()
            assert 1 in applied

            # Second run should apply nothing
            applied_second = runner.run_pending_migrations()
            assert applied_second == []

            # Test Program and Scope repos
            prog_repo = ProgramRepository(db)
            scope_repo = ScopeRuleRepository(db)

            program = Program(name="HackerOne Program A", policy_url="https://hackerone.com/proga")
            prog_repo.create(program)

            retrieved = prog_repo.get(program.id)
            assert retrieved is not None
            assert retrieved.name == "HackerOne Program A"

            rule = ScopeRule(
                program_id=program.id,
                rule_type=ScopeRuleType.INCLUDE,
                pattern="*.proga.com",
                wildcard=True,
            )
            scope_repo.create(rule)

            rules = scope_repo.list_by_program(program.id)
            assert len(rules) == 1
            assert rules[0].pattern == "*.proga.com"
            assert rules[0].wildcard is True

            # Test database backup
            backup_path = Path(tmpdir) / "backup.db"
            db.backup(backup_path)
            assert backup_path.exists()
            assert backup_path.stat().st_size > 0
        finally:
            db.close()
