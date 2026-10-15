"""UI Resources Package for BoundaryX.

Contains theme definitions, palette configurations, and stylesheet generators.
"""

from __future__ import annotations

from boundaryx.ui.resources.styles import apply_button_class, generate_stylesheet
from boundaryx.ui.resources.themes import (
    DARK_PALETTE,
    LIGHT_PALETTE,
    ThemeMode,
    ThemePalette,
    apply_theme,
    get_current_palette,
    get_current_theme,
    get_theme_palette,
    set_current_theme,
)

__all__ = [
    "DARK_PALETTE",
    "LIGHT_PALETTE",
    "ThemeMode",
    "ThemePalette",
    "apply_button_class",
    "apply_theme",
    "generate_stylesheet",
    "get_current_palette",
    "get_current_theme",
    "get_theme_palette",
    "set_current_theme",
]
