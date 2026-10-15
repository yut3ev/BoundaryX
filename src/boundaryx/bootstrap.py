"""Application bootstrap, argument parsing, and subsystem initialization for BoundaryX.

Orchestrates environment configuration, portable/installed mode resolution,
logging initialization with secret scrubbing, SQLite schema creation,
PySide6 QApplication configuration, and MainWindow instantiation.
"""

from __future__ import annotations

import argparse
import atexit
import contextlib
import logging
import sys
from pathlib import Path
from uuid import UUID

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from boundaryx.config.settings import AppSettings, get_settings, set_settings
from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.infrastructure.imports.har_importer import HarImporter
from boundaryx.infrastructure.logging.logger import setup_logging
from boundaryx.ui.resources.styles import generate_stylesheet
from boundaryx.ui.resources.themes import ThemeMode, set_current_theme
from boundaryx.ui.windows.main_window import MainWindow
from boundaryx.workers.async_worker import cancel_all_workers

logger = logging.getLogger(__name__)


def parse_arguments(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments for BoundaryX execution."""
    parser = argparse.ArgumentParser(
        prog="boundaryx",
        description="BoundaryX - Desktop Application Security Testing & Authorization Boundary Analysis",
    )
    parser.add_argument(
        "--project",
        type=str,
        default=None,
        help="UUID or name of the project workspace to load on launch",
    )
    parser.add_argument(
        "--portable",
        action="store_true",
        help="Run in portable mode (persist database, logs, and exports in local working directory)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose DEBUG logging and console traces",
    )
    parser.add_argument(
        "--import-har",
        type=str,
        default=None,
        help="Path to a HAR 1.2 traffic capture file to import immediately into the active project",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Custom file path or ':memory:' URI for the SQLite database",
    )
    parser.add_argument(
        "--theme",
        type=str,
        choices=["dark", "light"],
        default=None,
        help="Override UI theme mode ('dark' or 'light')",
    )

    return parser.parse_args(args)


def bootstrap_application(
    cli_args: list[str] | None = None,
) -> tuple[QApplication, MainWindow, DatabaseManager, AppSettings]:
    """Initialize application subsystems and instantiate MainWindow.

    Returns:
        Tuple of (QApplication, MainWindow, DatabaseManager, AppSettings).
    """
    args = parse_arguments(cli_args)

    # 1. Load and configure AppSettings
    settings = get_settings()
    if args.portable:
        settings.portable_mode = True
    if args.db_path:
        settings.db_path = Path(args.db_path)
    if args.debug:
        settings.log_level = "DEBUG"
    if args.theme:
        settings.theme = args.theme

    set_settings(settings)
    settings.ensure_directories()

    # 2. Setup Logging with secret scrubbing filter
    setup_logging(
        log_dir=settings.resolved_log_dir,
        level=settings.log_level,
        rotation=True,
    )
    logger.info("Initializing BoundaryX v%s [Portable: %s]", settings.version, settings.portable_mode)

    # 3. Initialize Database and verify schema tables
    effective_db_path = (
        ":memory:"
        if str(args.db_path) == ":memory:" or str(settings.db_path) == ":memory:"
        else settings.resolved_db_path
    )
    db_manager = DatabaseManager(effective_db_path)
    db_manager.create_tables()
    logger.info("Database schema initialized at: %s", effective_db_path)

    # 4. Configure PySide6 High-DPI and Application
    # PySide6 handles High DPI automatically; ensure scaling policies are friendly
    if hasattr(Qt.ApplicationAttribute, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    if hasattr(Qt.ApplicationAttribute, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv if cli_args is None else [sys.argv[0]] + cli_args)

    app.setApplicationName("BoundaryX")
    app.setApplicationDisplayName("BoundaryX - Desktop Security Testing")
    app.setOrganizationName("BoundaryX Security")
    app.setOrganizationDomain("boundaryx.io")

    # Set base font
    default_font = QFont("Segoe UI, -apple-system, Roboto, sans-serif", 10)
    app.setFont(default_font)

    # Apply Theme and Global Stylesheet
    theme_mode = ThemeMode(settings.theme)
    set_current_theme(theme_mode)
    app.setStyleSheet(generate_stylesheet())

    # 5. Instantiate MainWindow
    window = MainWindow(
        db_manager=db_manager,
        settings=settings,
        initial_project_id=args.project,
    )

    # 6. Optional CLI HAR import
    if args.import_har and window.active_project_id:
        har_path = Path(args.import_har)
        if har_path.is_file():
            logger.info("Importing CLI specified HAR file: %s", har_path)
            try:
                with db_manager.get_session() as session:
                    importer = HarImporter(session=session)
                    result = importer.import_file(har_path, UUID(window.active_project_id))
                    logger.info("Imported %d records from HAR", result.records_imported)
            except Exception as exc:
                logger.error("CLI HAR import failed: %s", exc)

    # 7. Register Clean Shutdown Hook
    def _shutdown() -> None:
        logger.info("Executing clean application shutdown...")
        cancel_all_workers()
        with contextlib.suppress(Exception):
            db_manager.engine.dispose()

    app.aboutToQuit.connect(_shutdown)
    atexit.register(_shutdown)

    return app, window, db_manager, settings
