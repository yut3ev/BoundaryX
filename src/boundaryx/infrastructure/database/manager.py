"""Database connection and lifecycle manager for BoundaryX.

This module provides the DatabaseManager class responsible for initializing the
SQLite database engine with performance and integrity pragmas (WAL mode, foreign keys),
managing sessions, running schema creation, integrity verification, and atomic
backups and restores.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Generator

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from boundaryx.infrastructure.database.models import Base

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages SQLite database connections, schema lifecycle, and backup operations.

    Ensures proper SQLite pragmas:
    - Foreign keys enforced (PRAGMA foreign_keys = ON)
    - Write-Ahead Logging for concurrency (PRAGMA journal_mode = WAL)
    - Synchronous normal mode for optimal WAL performance (PRAGMA synchronous = NORMAL)
    - Busy timeout for lock mitigation (PRAGMA busy_timeout = 10000)
    """

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        """Initialize the database manager with a database path or in-memory URI.

        Args:
            db_path: File system Path or ':memory:' string.
        """
        if str(db_path) == ":memory:":
            self.db_path: Path | str = ":memory:"
            self.is_memory = True
        else:
            self.db_path = Path(db_path).resolve()
            self.is_memory = False
            # Ensure target directory exists
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._engine: Engine | None = None
        self._session_factory: sessionmaker[Session] | None = None
        self._init_engine()

    @property
    def engine(self) -> Engine:
        """Return the active SQLAlchemy engine, creating one if not present."""
        if self._engine is None:
            self._init_engine()
        assert self._engine is not None
        return self._engine

    @property
    def session_factory(self) -> sessionmaker[Session]:
        """Return the session factory, creating one if not present."""
        if self._session_factory is None:
            self._init_engine()
        assert self._session_factory is not None
        return self._session_factory

    def _init_engine(self) -> None:
        """Create and configure the SQLAlchemy engine and session factory."""
        self._engine = self.create_engine()
        self._session_factory = sessionmaker(
            bind=self._engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )

    def create_engine(self) -> Engine:
        """Create a new SQLite engine configured with required pragmas.

        Returns:
            Configured SQLAlchemy Engine.
        """
        url = "sqlite:///:memory:" if self.is_memory else f"sqlite:///{self.db_path}"

        engine = create_engine(
            url,
            echo=False,
            future=True,
            connect_args={"check_same_thread": False},
        )

        # Configure SQLite connection hooks
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection: Any, connection_record: Any) -> None:
            if isinstance(dbapi_connection, sqlite3.Connection):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys = ON")
                cursor.execute("PRAGMA busy_timeout = 10000")
                if not self.is_memory:
                    cursor.execute("PRAGMA journal_mode = WAL")
                    cursor.execute("PRAGMA synchronous = NORMAL")
                cursor.close()

        return engine

    def create_tables(self) -> None:
        """Create all defined ORM tables in the database."""
        logger.info("Creating all database tables for BoundaryX...")
        Base.metadata.create_all(self.engine)

    def drop_tables(self) -> None:
        """Drop all defined ORM tables in the database (caution: destructive)."""
        logger.warning("Dropping all database tables...")
        Base.metadata.drop_all(self.engine)

    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Context manager yielding a transactional database session.

        Commits automatically on successful block exit, rolls back on exception,
        and guarantees the session is closed upon departure.

        Yields:
            SQLAlchemy Session object.
        """
        session: Session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def backup(self, backup_path: Path | str) -> Path:
        """Safely create an online backup of the database to the specified path.

        Uses the native SQLite online backup API to ensure snapshot consistency
        even with concurrent read/write transactions.

        Args:
            backup_path: Target destination path for backup file.

        Returns:
            Resolved Path of the created backup file.
        """
        target = Path(backup_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)

        # Use SQLite's online backup API via SQLAlchemy driver connection
        with self.engine.connect() as conn:
            raw_connection = conn.connection.driver_connection
            target_conn = sqlite3.connect(str(target))
            try:
                raw_connection.backup(target_conn)
            finally:
                target_conn.close()

        logger.info("Database backup created successfully at: %s", target)
        return target

    def restore(self, backup_path: Path | str) -> None:
        """Restore the database from a backup file.

        Uses the native SQLite online backup API in reverse to restore
        the snapshot into the active database without invalidating open engines.

        Args:
            backup_path: Path of the backup file to restore from.

        Raises:
            FileNotFoundError: If the backup file does not exist.
        """
        source = Path(backup_path).resolve()
        if not source.exists():
            raise FileNotFoundError(f"Backup file not found at: {source}")

        source_conn = sqlite3.connect(str(source))
        try:
            with self.engine.connect() as conn:
                raw_connection = conn.connection.driver_connection
                source_conn.backup(raw_connection)
        finally:
            source_conn.close()

        logger.info("Database restored successfully from: %s", source)

    def verify_integrity(self) -> bool:
        """Run SQLite PRAGMA integrity_check to verify database health.

        Returns:
            True if the database passed integrity check ('ok'), False otherwise.
        """
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text("PRAGMA integrity_check")).scalar()
                is_ok = result == "ok"
                if not is_ok:
                    logger.error("PRAGMA integrity_check failed with result: %s", result)
                return is_ok
        except Exception as exc:
            logger.error("Integrity check failed with exception: %s", exc)
            return False

    def get_schema_version(self) -> int:
        """Retrieve the current schema user_version from SQLite PRAGMA.

        Returns:
            Integer version number (defaults to 0 if not set).
        """
        with self.engine.connect() as conn:
            version = conn.execute(text("PRAGMA user_version")).scalar()
            return int(version or 0)

    def set_schema_version(self, version: int) -> None:
        """Set the schema user_version via SQLite PRAGMA.

        Args:
            version: New integer schema version.
        """
        with self.engine.connect() as conn:
            conn.execute(text(f"PRAGMA user_version = {int(version)}"))
            conn.commit()

    def close(self) -> None:
        """Dispose of the engine and close connection pools."""
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("Database engine disposed.")


# Global default manager instance for module-level convenience functions
_default_manager: DatabaseManager | None = None


def get_engine(db_path: Path | str | None = None) -> Engine:
    """Convenience function to get or create an engine.

    Args:
        db_path: Path to database file or ':memory:'. If None, uses default manager.

    Returns:
        SQLAlchemy Engine.
    """
    global _default_manager
    if db_path is not None:
        manager = DatabaseManager(db_path)
        return manager.engine
    if _default_manager is None:
        _default_manager = DatabaseManager(":memory:")
    return _default_manager.engine


@contextmanager
def get_session(
    db_path: Path | str | None = None,
    engine: Engine | None = None,
) -> Generator[Session, None, None]:
    """Convenience context manager to obtain a transactional session.

    Args:
        db_path: Optional path to database file.
        engine: Optional existing SQLAlchemy engine.

    Yields:
        Active SQLAlchemy Session.
    """
    global _default_manager
    if engine is not None:
        factory = sessionmaker(
            bind=engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    elif db_path is not None:
        manager = DatabaseManager(db_path)
        with manager.get_session() as session:
            yield session
    else:
        if _default_manager is None:
            _default_manager = DatabaseManager(":memory:")
            _default_manager.create_tables()
        with _default_manager.get_session() as session:
            yield session
