"""Theme system and color palettes for BoundaryX.

Provides dark (cybersecurity default) and light palettes, palette models,
and theme application helpers.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ThemeMode(str, Enum):
    """Supported UI theme modes."""

    DARK = "dark"
    LIGHT = "light"


class ThemePalette(BaseModel):
    """Complete color and styling palette specification."""

    model_config = ConfigDict(frozen=True)

    mode: ThemeMode = ThemeMode.DARK

    # Core background & surfaces
    background: str = Field(description="Primary window background")
    surface: str = Field(description="Sidebar, secondary panels, and toolbar background")
    card: str = Field(description="Card and content container background")
    card_hover: str = Field(description="Hover state for card containers")
    border: str = Field(description="Default border and divider color")
    border_subtle: str = Field(description="Subtle borders and separators")
    border_focus: str = Field(description="Focus outline color")

    # Brand & Accent
    accent: str = Field(description="Brand accent cyan")
    accent_hover: str = Field(description="Hover state for accent elements")
    accent_active: str = Field(description="Pressed state for accent elements")
    blue: str = Field(description="Secondary brand blue")
    blue_hover: str = Field(description="Hover state for secondary blue")

    # Semantic Status Colors
    success: str = Field(description="Success and pass indicators")
    success_hover: str = Field(description="Hover state for success elements")
    warning: str = Field(description="Warning and medium risk indicators")
    warning_hover: str = Field(description="Hover state for warning elements")
    danger: str = Field(description="Danger, critical defect, and error indicators")
    danger_hover: str = Field(description="Hover state for danger elements")

    # Typography
    text_primary: str = Field(description="High-contrast primary text")
    text_secondary: str = Field(description="Medium-contrast secondary text")
    text_muted: str = Field(description="Muted text, metadata, and timestamps")
    text_disabled: str = Field(description="Disabled text")

    # Inputs & Controls
    input_bg: str = Field(description="Background for text inputs and dropdowns")
    input_border: str = Field(description="Border for text inputs")
    input_placeholder: str = Field(description="Placeholder text color")
    selection_bg: str = Field(description="Text and item selection background")
    selection_text: str = Field(description="Text color in selection")

    # Scrollbars & Sliders
    scrollbar_track: str = Field(description="Scrollbar track background")
    scrollbar_thumb: str = Field(description="Scrollbar thumb color")
    scrollbar_thumb_hover: str = Field(description="Scrollbar thumb hover color")

    # Tooltips & Overlays
    tooltip_bg: str = Field(description="Tooltip background")
    tooltip_text: str = Field(description="Tooltip text color")
    tooltip_border: str = Field(description="Tooltip border")

    # Header & Tables
    header_bg: str = Field(description="Table header background")
    table_alt_row: str = Field(description="Alternating table row background")
    table_grid: str = Field(description="Table grid line color")

    # Status Badges
    badge_critical_bg: str = Field(description="Critical badge background")
    badge_critical_text: str = Field(description="Critical badge text")
    badge_critical_border: str = Field(description="Critical badge border")

    badge_high_bg: str = Field(description="High severity badge background")
    badge_high_text: str = Field(description="High severity badge text")
    badge_high_border: str = Field(description="High severity badge border")

    badge_medium_bg: str = Field(description="Medium severity badge background")
    badge_medium_text: str = Field(description="Medium severity badge text")
    badge_medium_border: str = Field(description="Medium severity badge border")

    badge_low_bg: str = Field(description="Low severity badge background")
    badge_low_text: str = Field(description="Low severity badge text")
    badge_low_border: str = Field(description="Low severity badge border")

    badge_info_bg: str = Field(description="Info badge background")
    badge_info_text: str = Field(description="Info badge text")
    badge_info_border: str = Field(description="Info badge border")

    badge_allow_bg: str = Field(description="Allow decision badge background")
    badge_allow_text: str = Field(description="Allow decision badge text")
    badge_allow_border: str = Field(description="Allow decision badge border")

    badge_deny_bg: str = Field(description="Deny decision badge background")
    badge_deny_text: str = Field(description="Deny decision badge text")
    badge_deny_border: str = Field(description="Deny decision badge border")

    # Typography Families
    font_family_ui: str = Field(
        default="Segoe UI, -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif"
    )
    font_family_mono: str = Field(
        default="'JetBrains Mono', 'Cascadia Code', Consolas, 'Fira Code', 'Courier New', monospace"
    )


# Professional Cybersecurity Dark Palette
DARK_PALETTE = ThemePalette(
    mode=ThemeMode.DARK,
    background="#12151c",
    surface="#1a1f2c",
    card="#22283a",
    card_hover="#2a3248",
    border="#2d354d",
    border_subtle="#1f2538",
    border_focus="#00b4d8",
    accent="#00b4d8",
    accent_hover="#48cae4",
    accent_active="#0096c7",
    blue="#0077b6",
    blue_hover="#0096c7",
    success="#10b981",
    success_hover="#34d399",
    warning="#f59e0b",
    warning_hover="#fbbf24",
    danger="#ef4444",
    danger_hover="#f87171",
    text_primary="#f8fafc",
    text_secondary="#94a3b8",
    text_muted="#64748b",
    text_disabled="#475569",
    input_bg="#151924",
    input_border="#2d354d",
    input_placeholder="#64748b",
    selection_bg="#1e3a5f",
    selection_text="#ffffff",
    scrollbar_track="#12151c",
    scrollbar_thumb="#2f384f",
    scrollbar_thumb_hover="#435275",
    tooltip_bg="#1a1f2c",
    tooltip_text="#f8fafc",
    tooltip_border="#2d354d",
    header_bg="#161a25",
    table_alt_row="#161b27",
    table_grid="#232a3d",
    badge_critical_bg="#381014",
    badge_critical_text="#fca5a5",
    badge_critical_border="#991b1b",
    badge_high_bg="#3b1708",
    badge_high_text="#fdba74",
    badge_high_border="#c2410c",
    badge_medium_bg="#362208",
    badge_medium_text="#fde047",
    badge_medium_border="#b45309",
    badge_low_bg="#082b45",
    badge_low_text="#7dd3fc",
    badge_low_border="#0284c7",
    badge_info_bg="#1e293b",
    badge_info_text="#cbd5e1",
    badge_info_border="#475569",
    badge_allow_bg="#064e3b",
    badge_allow_text="#6ee7b7",
    badge_allow_border="#059669",
    badge_deny_bg="#450a0a",
    badge_deny_text="#fca5a5",
    badge_deny_border="#dc2626",
)

# Clean Modern Light Palette
LIGHT_PALETTE = ThemePalette(
    mode=ThemeMode.LIGHT,
    background="#f8fafc",
    surface="#ffffff",
    card="#ffffff",
    card_hover="#f1f5f9",
    border="#cbd5e1",
    border_subtle="#e2e8f0",
    border_focus="#0284c7",
    accent="#0284c7",
    accent_hover="#0369a1",
    accent_active="#075985",
    blue="#0369a1",
    blue_hover="#0284c7",
    success="#059669",
    success_hover="#10b981",
    warning="#d97706",
    warning_hover="#f59e0b",
    danger="#dc2626",
    danger_hover="#ef4444",
    text_primary="#0f172a",
    text_secondary="#475569",
    text_muted="#94a3b8",
    text_disabled="#cbd5e1",
    input_bg="#ffffff",
    input_border="#cbd5e1",
    input_placeholder="#94a3b8",
    selection_bg="#bae6fd",
    selection_text="#0f172a",
    scrollbar_track="#f8fafc",
    scrollbar_thumb="#cbd5e1",
    scrollbar_thumb_hover="#94a3b8",
    tooltip_bg="#1e293b",
    tooltip_text="#ffffff",
    tooltip_border="#334155",
    header_bg="#f1f5f9",
    table_alt_row="#f8fafc",
    table_grid="#e2e8f0",
    badge_critical_bg="#fee2e2",
    badge_critical_text="#b91c1c",
    badge_critical_border="#fca5a5",
    badge_high_bg="#ffedd5",
    badge_high_text="#c2410c",
    badge_high_border="#fed7aa",
    badge_medium_bg="#fef3c7",
    badge_medium_text="#b45309",
    badge_medium_border="#fde68a",
    badge_low_bg="#e0f2fe",
    badge_low_text="#0369a1",
    badge_low_border="#bae6fd",
    badge_info_bg="#f1f5f9",
    badge_info_text="#475569",
    badge_info_border="#cbd5e1",
    badge_allow_bg="#d1fae5",
    badge_allow_text="#065f46",
    badge_allow_border="#a7f3d0",
    badge_deny_bg="#fee2e2",
    badge_deny_text="#991b1b",
    badge_deny_border="#fca5a5",
)

# Active state tracking
_ACTIVE_MODE: ThemeMode = ThemeMode.DARK


def get_theme_palette(mode: ThemeMode | str = ThemeMode.DARK) -> ThemePalette:
    """Retrieve the ThemePalette specification for the requested mode."""
    if isinstance(mode, str):
        normalized = mode.lower().strip()
        if normalized == "light":
            return LIGHT_PALETTE
        return DARK_PALETTE

    if mode == ThemeMode.LIGHT:
        return LIGHT_PALETTE
    return DARK_PALETTE


def get_current_theme() -> ThemeMode:
    """Return the currently selected global ThemeMode."""
    return _ACTIVE_MODE


def get_current_palette() -> ThemePalette:
    """Return the palette for the current active theme."""
    return get_theme_palette(_ACTIVE_MODE)


def set_current_theme(mode: ThemeMode | str) -> ThemePalette:
    """Set the active theme mode and return its palette."""
    global _ACTIVE_MODE
    if isinstance(mode, str):
        mode = ThemeMode.LIGHT if mode.lower().strip() == "light" else ThemeMode.DARK
    _ACTIVE_MODE = mode
    return get_theme_palette(_ACTIVE_MODE)


def apply_theme(target: Any, mode: ThemeMode | str = ThemeMode.DARK) -> None:
    """Apply theme stylesheet to a QWidget or QApplication instance.

    Args:
        target: QApplication or QWidget instance.
        mode: ThemeMode or string ('dark' or 'light').
    """
    from boundaryx.ui.resources.styles import generate_stylesheet

    palette = set_current_theme(mode)
    stylesheet = generate_stylesheet(palette)
    if hasattr(target, "setStyleSheet"):
        target.setStyleSheet(stylesheet)
