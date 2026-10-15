"""Status and severity pill badge widget for BoundaryX.

Displays color-coded badges for Vulnerability Severity, Triage Lifecycle Status,
and Authorization Evaluation Decisions.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QSizePolicy, QWidget

from boundaryx.ui.resources.themes import get_current_palette


class StatusBadge(QLabel):
    """Pill-shaped color-coded badge widget."""

    def __init__(
        self,
        text: str = "",
        variant: str = "neutral",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the StatusBadge widget.

        Args:
            text: Text to display in the badge pill.
            variant: Color variant name or category.
            parent: Optional parent widget.
        """
        super().__init__(text, parent)

        self._text = text
        self._variant = variant

        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(22)
        self.setMaximumHeight(24)

        self._apply_style()

    def _apply_style(self) -> None:
        """Apply color-coded pill styling based on variant."""
        palette = get_current_palette()

        # Severity mapping
        severity_styles = {
            "CRITICAL": (palette.badge_critical_bg, palette.badge_critical_text, palette.badge_critical_border),
            "HIGH": (palette.badge_high_bg, palette.badge_high_text, palette.badge_high_border),
            "MEDIUM": (palette.badge_medium_bg, palette.badge_medium_text, palette.badge_medium_border),
            "LOW": (palette.badge_low_bg, palette.badge_low_text, palette.badge_low_border),
            "INFORMATIONAL": (palette.badge_info_bg, palette.badge_info_text, palette.badge_info_border),
            "INFO": (palette.badge_info_bg, palette.badge_info_text, palette.badge_info_border),
        }

        # Decision mapping
        decision_styles = {
            "ALLOW": (palette.badge_allow_bg, palette.badge_allow_text, palette.badge_allow_border),
            "DENY": (palette.badge_deny_bg, palette.badge_deny_text, palette.badge_deny_border),
            "UNKNOWN": (palette.badge_info_bg, palette.badge_info_text, palette.badge_info_border),
            "NOT_APPLICABLE": (palette.surface, palette.text_muted, palette.border),
        }

        # Status mapping
        status_styles = {
            "NEW": ("rgba(0, 180, 216, 0.18)", palette.accent, palette.accent),
            "NEEDS_REVIEW": (palette.badge_medium_bg, palette.badge_medium_text, palette.badge_medium_border),
            "CONFIRMED": (palette.badge_critical_bg, palette.badge_critical_text, palette.badge_critical_border),
            "FALSE_POSITIVE": (palette.surface, palette.text_muted, palette.border),
            "ACCEPTED_RISK": ("rgba(245, 158, 11, 0.15)", palette.warning, palette.border),
            "FIXED": (palette.badge_allow_bg, palette.badge_allow_text, palette.badge_allow_border),
            "REOPENED": (palette.badge_high_bg, palette.badge_high_text, palette.badge_high_border),
        }

        # General variants
        general_styles = {
            "danger": (palette.badge_critical_bg, palette.badge_critical_text, palette.badge_critical_border),
            "warning": (palette.badge_medium_bg, palette.badge_medium_text, palette.badge_medium_border),
            "success": (palette.badge_allow_bg, palette.badge_allow_text, palette.badge_allow_border),
            "info": (palette.badge_low_bg, palette.badge_low_text, palette.badge_low_border),
            "accent": ("rgba(0, 180, 216, 0.18)", palette.accent, palette.accent),
            "neutral": (palette.card, palette.text_secondary, palette.border),
        }

        key = self._variant.upper()
        if key in severity_styles:
            bg, fg, border = severity_styles[key]
        elif key in decision_styles:
            bg, fg, border = decision_styles[key]
        elif key in status_styles:
            bg, fg, border = status_styles[key]
        elif self._variant.lower() in general_styles:
            bg, fg, border = general_styles[self._variant.lower()]
        else:
            bg, fg, border = general_styles["neutral"]

        self.setStyleSheet(f"""
            QLabel {{
                background-color: {bg};
                color: {fg};
                border: 1px solid {border};
                border-radius: 11px;
                padding: 1px 10px;
                font-size: 11px;
                font-weight: 600;
                letter-spacing: 0.5px;
            }}
        """)

    def set_badge_text(self, text: str) -> None:
        """Update badge text."""
        self._text = text
        self.setText(text)

    def set_variant(self, variant: str) -> None:
        """Update the styling variant."""
        self._variant = variant
        self._apply_style()

    def set_custom_colors(self, bg_color: str, text_color: str, border_color: str) -> None:
        """Apply explicit custom colors to the pill badge."""
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {bg_color};
                color: {text_color};
                border: 1px solid {border_color};
                border-radius: 11px;
                padding: 1px 10px;
                font-size: 11px;
                font-weight: 600;
            }}
        """)

    @classmethod
    def for_severity(cls, severity: Any, parent: QWidget | None = None) -> StatusBadge:
        """Factory method to construct a badge for a vulnerability severity."""
        raw_val = severity.value if hasattr(severity, "value") else str(severity)
        normalized = raw_val.upper()
        display = "INFO" if normalized == "INFORMATIONAL" else normalized
        return cls(text=display, variant=normalized, parent=parent)

    @classmethod
    def for_status(cls, status: Any, parent: QWidget | None = None) -> StatusBadge:
        """Factory method to construct a badge for a defect triage status."""
        raw_val = status.value if hasattr(status, "value") else str(status)
        display = raw_val.replace("_", " ").upper()
        return cls(text=display, variant=raw_val.upper(), parent=parent)

    @classmethod
    def for_decision(cls, decision: Any, parent: QWidget | None = None) -> StatusBadge:
        """Factory method to construct a badge for an authorization decision."""
        raw_val = decision.value if hasattr(decision, "value") else str(decision)
        display = raw_val.replace("_", " ").upper()
        return cls(text=display, variant=raw_val.upper(), parent=parent)

    @classmethod
    def create(cls, text: str, variant: str = "neutral", parent: QWidget | None = None) -> StatusBadge:
        """General factory method for a status badge."""
        return cls(text=text, variant=variant, parent=parent)
