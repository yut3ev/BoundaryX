from datetime import datetime, timezone
import logging
from pathlib import Path
import re
from typing import List, Tuple

from boundaryx.storage.database import Database

logger = logging.getLogger("boundaryx.migrations")


class MigrationRunner:
    def __init__(self, db: Database, migrations_dir: Path):
        self.db = db
        self.migrations_dir = Path(migrations_dir)

    def get_applied_migrations(self) -> List[int]:
        # Check if table exists
        cursor = self.db.conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='_schema_migrations';"
        )
        if not cursor.fetchone():
            return []
        cursor.execute("SELECT version FROM _schema_migrations ORDER BY version ASC;")
        return [row[0] for row in cursor.fetchall()]

    def get_migration_files(self) -> List[Tuple[int, str, Path]]:
        files = []
        if not self.migrations_dir.exists():
            return []
        for file in sorted(self.migrations_dir.glob("*.sql")):
            match = re.match(r"^(\d+)_(.+)\.sql$", file.name)
            if match:
                version = int(match.group(1))
                name = match.group(2)
                files.append((version, name, file))
        return sorted(files, key=lambda x: x[0])

    def run_pending_migrations(self) -> List[int]:
        applied = self.get_applied_migrations()
        all_migrations = self.get_migration_files()
        pending = [m for m in all_migrations if m[0] not in applied]

        if not pending:
            logger.info("No pending migrations to run.")
            return []

        # Backup before migration if DB already has data
        if applied and self.db.db_path.exists() and self.db.db_path.stat().st_size > 0:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_path = self.db.db_path.parent / "backups" / f"pre_migration_{timestamp}.db"
            self.db.backup(backup_path)

        applied_versions = []
        for version, name, file_path in pending:
            logger.info("Applying migration %03d_%s...", version, name)
            sql_content = file_path.read_text(encoding="utf-8")
            cur = self.db.conn.cursor()
            try:
                cur.executescript(sql_content)
                cur.execute(
                    "INSERT INTO _schema_migrations (version, name, applied_at) VALUES (?, ?, ?);",
                    (version, name, datetime.now(timezone.utc).isoformat()),
                )
            finally:
                cur.close()
            applied_versions.append(version)

        return applied_versions
