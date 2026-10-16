from contextlib import contextmanager
import logging
from pathlib import Path
import sqlite3
from typing import Generator, Optional

logger = logging.getLogger("boundaryx.storage")


class Database:
    """
    SQLite storage engine for BoundaryX.
    Enforces Foreign Keys, WAL mode, transaction safety, and automatic backups.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection: Optional[sqlite3.Connection] = None
        self._init_connection()

    def _init_connection(self) -> None:
        self._connection = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode by default, explicit BEGIN for transactions
        )
        self._connection.row_factory = sqlite3.Row
        with self._connection:
            self._connection.execute("PRAGMA foreign_keys = ON;")
            self._connection.execute("PRAGMA journal_mode = WAL;")
            self._connection.execute("PRAGMA synchronous = NORMAL;")

    @property
    def conn(self) -> sqlite3.Connection:
        if self._connection is None:
            self._init_connection()
        return self._connection

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        """Context manager for explicit atomic transactions."""
        cursor = self.conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            yield cursor
            if self.conn.in_transaction:
                cursor.execute("COMMIT;")
        except Exception:
            if self.conn.in_transaction:
                cursor.execute("ROLLBACK;")
            raise
        finally:
            cursor.close()

    def backup(self, destination_path: Path) -> Path:
        """Creates a consistent online snapshot of the database using SQLite backup API."""
        dest = Path(destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        backup_conn = sqlite3.connect(str(dest))
        try:
            with backup_conn:
                self.conn.backup(backup_conn, pages=100)
            logger.info("Database backup created successfully at %s", dest)
            return dest
        finally:
            backup_conn.close()

    def close(self) -> None:
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None
