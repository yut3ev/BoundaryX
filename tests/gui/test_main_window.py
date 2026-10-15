"""Tests for MainWindow and application lifecycle."""

import pytest
from PySide6.QtWidgets import QApplication

from boundaryx.config.settings import AppSettings
from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.ui.resources.themes import get_current_theme
from boundaryx.ui.windows.main_window import MainWindow


@pytest.fixture
def app_settings(tmp_path):
    settings = AppSettings()
    settings.db_path = tmp_path / "test_main_window.db"
    settings.portable_mode = True
    return settings


@pytest.fixture
def db_manager(app_settings):
    mgr = DatabaseManager(app_settings.db_path)
    mgr.create_tables()
    return mgr


def test_main_window_instantiation(qapp: QApplication, db_manager: DatabaseManager, app_settings: AppSettings):
    window = MainWindow(db_manager=db_manager, settings=app_settings)
    assert window is not None
    assert "BoundaryX" in window.windowTitle()

    # Check that navigation items exist
    assert window._nav_buttons
    assert len(window._nav_buttons) == len(MainWindow.SECTIONS)

    # Test navigating to each section
    for section_id, title, icon in MainWindow.SECTIONS:
        window.navigate_to(section_id)
        current_widget = window.stacked_widget.currentWidget()
        assert current_widget is not None

    # Test theme toggle
    initial_theme = get_current_theme()
    window._toggle_theme()
    new_theme = get_current_theme()
    assert initial_theme != new_theme

    window.close()
