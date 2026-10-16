from pathlib import Path
import tempfile

import pytest

from boundaryx.ipc.dispatcher import CommandDispatcher
from boundaryx.ipc.protocol import (
    MAX_PAYLOAD_BYTES,
    IPCError,
    parse_ipc_line,
)
from boundaryx.storage.database import Database
from boundaryx.storage.migrations import MigrationRunner
from boundaryx.storage.repositories import (
    AssetRepository,
    AuditRepository,
    FindingRepository,
    JobRepository,
    ProgramRepository,
    ScopeRuleRepository,
    SettingsRepository,
)


def test_ipc_protocol_parsing_and_oversized_rejection():
    # Valid line
    valid_line = '{"protocol_version":"1.0","request_id":"req-1","command":"ping","payload":{}}'
    req = parse_ipc_line(valid_line)
    assert req.request_id == "req-1"
    assert req.command == "ping"

    # Oversized payload rejection
    huge_data = "a" * (MAX_PAYLOAD_BYTES + 100)
    huge_line = f'{{"protocol_version":"1.0","request_id":"req-2","command":"ping","payload":{{"d":"{huge_data}"}}}}'
    with pytest.raises(IPCError, match="exceeded maximum allowed size"):
        parse_ipc_line(huge_line)


def test_ipc_dispatcher_execution():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(Path(tmpdir) / "ipc_test.db")
        try:
            migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
            MigrationRunner(db, migrations_dir).run_pending_migrations()

            dispatcher = CommandDispatcher(
                program_repo=ProgramRepository(db),
                scope_repo=ScopeRuleRepository(db),
                asset_repo=AssetRepository(db),
                job_repo=JobRepository(db),
                finding_repo=FindingRepository(db),
                settings_repo=SettingsRepository(db),
                audit_repo=AuditRepository(db),
            )

            # 1. Ping
            ping_req = parse_ipc_line('{"request_id":"1","command":"ping","payload":{}}')
            ping_resp = dispatcher.dispatch(ping_req)
            assert ping_resp.success is True
            assert ping_resp.data["pong"] is True

            # 2. Create program
            create_req = parse_ipc_line('{"request_id":"2","command":"programs.create","payload":{"name":"Test Program"}}')
            create_resp = dispatcher.dispatch(create_req)
            assert create_resp.success is True
            prog_id = create_resp.data["id"]

            # 3. Add scope rule
            scope_req = parse_ipc_line(
                f'{{"request_id":"3","command":"scope.create_rule","payload":{{"program_id":"{prog_id}","pattern":"example.com","wildcard":true}}}}'
            )
            scope_resp = dispatcher.dispatch(scope_req)
            assert scope_resp.success is True

            # 4. Evaluate scope
            eval_req = parse_ipc_line(
                f'{{"request_id":"4","command":"scope.evaluate","payload":{{"program_id":"{prog_id}","target":"https://sub.example.com/api"}}}}'
            )
            eval_resp = dispatcher.dispatch(eval_req)
            assert eval_resp.success is True
            assert eval_resp.data["is_in_scope"] is True

            # 5. Unknown command rejection
            bad_req = parse_ipc_line('{"request_id":"5","command":"arbitrary_command","payload":{}}')
            bad_resp = dispatcher.dispatch(bad_req)
            assert bad_resp.success is False
            assert bad_resp.error["code"] == "COMMAND_NOT_FOUND"
        finally:
            db.close()
