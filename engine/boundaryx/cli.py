import argparse
import logging
from pathlib import Path
import signal
import sys

from boundaryx.config import get_default_data_dir, setup_engine_logging
from boundaryx.ipc.dispatcher import CommandDispatcher
from boundaryx.ipc.protocol import IPCError, parse_ipc_line, serialize_ipc_response
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

logger = logging.getLogger("boundaryx.engine")


def run_ipc_loop(dispatcher: CommandDispatcher) -> None:
    """
    Main IPC server loop reading newline-delimited JSON messages from STDIN
    and writing serialized JSON responses to STDOUT.
    """
    logger.info("BoundaryX IPC sidecar loop started. Listening on STDIN...")

    # Set up signal handlers for graceful shutdown
    def handle_signal(sig, frame):
        logger.info("Received termination signal %s, exiting cleanly...", sig)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    for line in sys.stdin:
        clean_line = line.strip()
        if not clean_line:
            continue
        try:
            req = parse_ipc_line(clean_line)
            resp = dispatcher.dispatch(req)
            out_str = serialize_ipc_response(resp)
            # Output directly to stdout followed by newline, then flush
            sys.stdout.write(out_str + "\n")
            sys.stdout.flush()
        except IPCError as err:
            err_resp = {
                "protocol_version": "1.0",
                "request_id": "unknown",
                "success": False,
                "error": err.to_dict(),
            }
            sys.stdout.write(serialize_ipc_response(err_resp) + "\n")
            sys.stdout.flush()
        except Exception as err:
            logger.exception("Unexpected error in IPC loop: %s", err)
            err_resp = {
                "protocol_version": "1.0",
                "request_id": "unknown",
                "success": False,
                "error": {"code": "FATAL_ERROR", "message": str(err)},
            }
            sys.stdout.write(serialize_ipc_response(err_resp) + "\n")
            sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="BoundaryX Security Engine Sidecar & CLI")
    parser.add_argument("--ipc", action="store_true", help="Start engine in IPC sidecar mode (stdin/stdout)")
    parser.add_argument("--data-dir", type=str, default=None, help="Custom application data directory")
    parser.add_argument("--migrate", action="store_true", help="Run database migrations and exit")
    parser.add_argument("--ping", action="store_true", help="Quick self-check and exit")

    args = parser.parse_args()

    data_dir = Path(args.data_dir) if args.data_dir else get_default_data_dir()
    log_dir = data_dir / "logs"
    setup_engine_logging(log_dir)

    logger.info("Initializing BoundaryX Engine with data dir: %s", data_dir)

    db_path = data_dir / "boundaryx.db"
    db = Database(db_path)

    # Migrations
    migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
    migration_runner = MigrationRunner(db, migrations_dir)
    applied = migration_runner.run_pending_migrations()
    if applied:
        logger.info("Applied migrations: %s", applied)

    if args.migrate:
        print(f"Migrations complete. Applied: {applied}")
        sys.exit(0)

    if args.ping:
        print("BoundaryX Engine OK")
        sys.exit(0)

    # Initialize Repositories
    program_repo = ProgramRepository(db)
    scope_repo = ScopeRuleRepository(db)
    asset_repo = AssetRepository(db)
    job_repo = JobRepository(db)
    finding_repo = FindingRepository(db)
    settings_repo = SettingsRepository(db)
    audit_repo = AuditRepository(db)

    dispatcher = CommandDispatcher(
        program_repo=program_repo,
        scope_repo=scope_repo,
        asset_repo=asset_repo,
        job_repo=job_repo,
        finding_repo=finding_repo,
        settings_repo=settings_repo,
        audit_repo=audit_repo,
    )

    if args.ipc:
        run_ipc_loop(dispatcher)
    else:
        print("BoundaryX Engine v0.1.0 ready. Use --ipc for sidecar mode or --help for options.")


if __name__ == "__main__":
    main()
