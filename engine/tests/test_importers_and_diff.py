from pathlib import Path
import tempfile

from boundaryx.domain.diff import calculate_asset_diff
from boundaryx.domain.enums import AssetType, MatcherType, ScopeRuleType, ScopeStatus
from boundaryx.domain.models import Asset, Program, ScopeRule
from boundaryx.http.har_importer import HarImporter
from boundaryx.http.openapi_importer import OpenAPIImporter
from boundaryx.scope.guard import ScopeGuard
from boundaryx.storage.database import Database
from boundaryx.storage.migrations import MigrationRunner
from boundaryx.storage.repositories import AssetRepository, ProgramRepository


def test_har_importer_and_redaction():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(Path(tmpdir) / "har_test.db")
        try:
            migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
            MigrationRunner(db, migrations_dir).run_pending_migrations()
            prog_repo = ProgramRepository(db)
            asset_repo = AssetRepository(db)
            prog_repo.create(Program(id="p1", name="Program 1"))

            # Create sample HAR
            har_file = Path(tmpdir) / "test.har"
            har_file.write_text(
                """{
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "startedDateTime": "2026-10-16T10:00:00Z",
                            "time": 45,
                            "request": {
                                "method": "GET",
                                "url": "https://api.example.com/users?token=supersecret123",
                                "headers": [
                                    {"name": "Authorization", "value": "Bearer jwt_secret_value"},
                                    {"name": "Cookie", "value": "session=abc"}
                                ]
                            },
                            "response": {
                                "status": 200,
                                "headers": []
                            }
                        }
                    ]
                }
            }""",
                encoding="utf-8",
            )

            guard = ScopeGuard([
                ScopeRule(
                    program_id="p1",
                    rule_type=ScopeRuleType.INCLUDE,
                    matcher_type=MatcherType.DOMAIN,
                    pattern="example.com",
                    wildcard=True,
                )
            ])

            importer = HarImporter(asset_repo)
            exchanges = importer.import_file(har_file, "p1", guard)

            assert len(exchanges) == 1
            ex = exchanges[0]
            assert "token=[REDACTED]" in ex.url_redacted
            assert ex.request_headers_redacted_json["Authorization"] == "Bearer [REDACTED_TOKEN]"
            assert ex.request_headers_redacted_json["Cookie"] == "[REDACTED]"
        finally:
            db.close()


def test_openapi_importer_yaml():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(Path(tmpdir) / "openapi_test.db")
        try:
            migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
            MigrationRunner(db, migrations_dir).run_pending_migrations()
            prog_repo = ProgramRepository(db)
            asset_repo = AssetRepository(db)
            prog_repo.create(Program(id="p1", name="Program 1"))

            openapi_file = Path(tmpdir) / "openapi.yaml"
            openapi_file.write_text(
                """
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
servers:
  - url: https://api.example.com/v1
paths:
  /auth/login:
    post:
      summary: Login endpoint
  /users/{id}:
    get:
      summary: Get user profile
            """,
                encoding="utf-8",
            )

            guard = ScopeGuard([
                ScopeRule(
                    program_id="p1",
                    rule_type=ScopeRuleType.INCLUDE,
                    matcher_type=MatcherType.DOMAIN,
                    pattern="example.com",
                    wildcard=True,
                )
            ])

            importer = OpenAPIImporter(asset_repo)
            assets = importer.import_file(openapi_file, "p1", guard)

            assert len(assets) == 2
            values = [a.canonical_value for a in assets]
            assert "POST /auth/login" in values
            assert "GET /users/{id}" in values
        finally:
            db.close()


def test_asset_diff_calculation():
    a1 = Asset(program_id="p1", asset_type=AssetType.DOMAIN, canonical_value="api.example.com", display_value="api.example.com")
    a2 = Asset(program_id="p1", asset_type=AssetType.DOMAIN, canonical_value="auth.example.com", display_value="auth.example.com")
    a3 = Asset(program_id="p1", asset_type=AssetType.DOMAIN, canonical_value="new.example.com", display_value="new.example.com")

    prior = [a1, a2]
    current = [a2, a3]

    diff = calculate_asset_diff(prior, current)
    assert len(diff.new_assets) == 1
    assert diff.new_assets[0].canonical_value == "new.example.com"
    assert len(diff.missing_assets) == 1
    assert diff.missing_assets[0].canonical_value == "api.example.com"
    assert len(diff.retained_assets) == 1
    assert diff.retained_assets[0].canonical_value == "auth.example.com"
