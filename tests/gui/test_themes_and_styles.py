"""Unit tests for theme palettes, QSS stylesheet generation, and styling helpers."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QWidget

from boundaryx.ui.resources.styles import (
    apply_button_class,
    apply_label_class,
    generate_stylesheet,
)
from boundaryx.ui.resources.themes import (
    DARK_PALETTE,
    LIGHT_PALETTE,
    ThemeMode,
    apply_theme,
    get_current_palette,
    get_current_theme,
    set_current_theme,
)


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Fixture providing QApplication instance initialized for offscreen headless execution."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(["-platform", "offscreen"])
    return app


def test_theme_palettes_definition() -> None:
    """Verify that dark and light theme palettes meet cybersecurity contrast and color requirements."""
    # Dark palette colors
    assert DARK_PALETTE.mode == ThemeMode.DARK
    assert DARK_PALETTE.background == "#12151c"
    assert DARK_PALETTE.surface == "#1a1f2c"
    assert DARK_PALETTE.card == "#22283a"
    assert DARK_PALETTE.border == "#2d354d"
    assert DARK_PALETTE.accent == "#00b4d8"
    assert DARK_PALETTE.blue == "#0077b6"
    assert DARK_PALETTE.success == "#10b981"
    assert DARK_PALETTE.warning == "#f59e0b"
    assert DARK_PALETTE.danger == "#ef4444"
    assert DARK_PALETTE.text_primary == "#f8fafc"
    assert DARK_PALETTE.text_secondary == "#94a3b8"
    assert DARK_PALETTE.text_muted == "#64748b"

    # Light palette colors
    assert LIGHT_PALETTE.mode == ThemeMode.LIGHT
    assert LIGHT_PALETTE.background == "#f8fafc"
    assert LIGHT_PALETTE.surface == "#ffffff"
    assert LIGHT_PALETTE.card == "#ffffff"
    assert LIGHT_PALETTE.border == "#cbd5e1"
    assert LIGHT_PALETTE.text_primary == "#0f172a"


def test_theme_manager_switching() -> None:
    """Test switching themes and retrieving palettes."""
    set_current_theme(ThemeMode.DARK)
    assert get_current_theme() == ThemeMode.DARK
    assert get_current_palette().mode == ThemeMode.DARK

    set_current_theme(ThemeMode.LIGHT)
    assert get_current_theme() == ThemeMode.LIGHT
    assert get_current_palette().mode == ThemeMode.LIGHT

    # Switch using string
    palette = set_current_theme("dark")
    assert palette.mode == ThemeMode.DARK
    assert get_current_theme() == ThemeMode.DARK


def test_stylesheet_generation() -> None:
    """Ensure stylesheet generator creates valid QSS containing all required selectors."""
    qss_dark = generate_stylesheet(DARK_PALETTE)
    assert isinstance(qss_dark, str)
    assert len(qss_dark) > 500

    # Verify critical widget selectors exist
    assert "QMainWindow" in qss_dark
    assert "QWidget" in qss_dark
    assert "QFrame" in qss_dark
    assert "QSplitter" in qss_dark
    assert "QTableView" in qss_dark
    assert "QHeaderView" in qss_dark
    assert "QPushButton" in qss_dark
    assert 'QPushButton[btnClass="primary"]' in qss_dark
    assert 'QPushButton[btnClass="secondary"]' in qss_dark
    assert 'QPushButton[btnClass="danger"]' in qss_dark
    assert 'QPushButton[btnClass="ghost"]' in qss_dark
    assert "QLineEdit" in qss_dark
    assert "QTextEdit" in qss_dark
    assert "QComboBox" in qss_dark
    assert "QCheckBox" in qss_dark
    assert "QTabWidget" in qss_dark
    assert "QScrollBar" in qss_dark
    assert "QProgressBar" in qss_dark
    assert "QLabel" in qss_dark
    assert "QStatusBar" in qss_dark
    assert "QDialog" in qss_dark

    # Check color injection
    assert DARK_PALETTE.background in qss_dark
    assert DARK_PALETTE.accent in qss_dark

    # Light stylesheet
    qss_light = generate_stylesheet(LIGHT_PALETTE)
    assert LIGHT_PALETTE.background in qss_light
    assert LIGHT_PALETTE.text_primary in qss_light


def test_apply_theme_to_widget(qapp: QApplication) -> None:
    """Verify applying theme directly to a widget."""
    widget = QWidget()
    apply_theme(widget, ThemeMode.DARK)
    assert widget.styleSheet() != ""
    assert DARK_PALETTE.background in widget.styleSheet()


def test_apply_button_and_label_classes(qapp: QApplication) -> None:
    """Verify button and label dynamic property helpers."""
    button = QPushButton("Click Me")
    apply_button_class(button, "primary")
    assert button.property("btnClass") == "primary"

    apply_button_class(button, "danger")
    assert button.property("btnClass") == "danger"

    label = QLabel("Metric")
    apply_label_class(label, "title")
    assert label.property("labelClass") == "title"
