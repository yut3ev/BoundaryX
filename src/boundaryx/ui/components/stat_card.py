"""Statistical metric display card widget for BoundaryX.

Displays an icon indicator, primary numeric value, metric label, and optional
trend/status badge with cybersecurity-tuned color variants.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from boundaryx.ui.resources.themes import get_current_palette


class StatCard(QFrame):
    """Statistical KPI card displaying a metric, icon, title, and status badge."""

    clicked = Signal()

    def __init__(
        self,
        title: str = "",
        value: int | str = 0,
        icon: str = "",
        badge: str = "",
        subtitle: str = "",
        variant: str = "accent",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the StatCard widget.

        Args:
            title: Human-readable metric title (e.g. 'Critical Findings').
            value: Main numeric or text value to display.
            icon: Icon text, emoji, or symbol (e.g. '🚨', '🛡️', '⚡').
            badge: Optional badge text (e.g. '+12%', 'High Risk').
            subtitle: Optional secondary descriptive line.
            variant: Color accent variant ('accent', 'danger', 'warning', 'success', 'neutral').
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._title = title
        self._value = str(value)
        self._icon = icon
        self._badge = badge
        self._subtitle = subtitle
        self._variant = variant

        self.setProperty("card", "true")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.setMinimumWidth(180)
        self.setMinimumHeight(105)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self._init_ui()
        self._apply_styling()

    def _init_ui(self) -> None:
        """Build layout and widget structure."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 12, 14, 12)
        main_layout.setSpacing(6)

        # Top row: Icon container and Badge
        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)

        self._icon_label = QLabel(self._icon)
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon_label.setFixedSize(28, 28)
        self._icon_label.setVisible(bool(self._icon))
        top_row.addWidget(self._icon_label)

        top_row.addStretch()

        self._badge_label = QLabel(self._badge)
        self._badge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._badge_label.setVisible(bool(self._badge))
        top_row.addWidget(self._badge_label)

        main_layout.addLayout(top_row)

        # Center: Metric Value
        self._value_label = QLabel(self._value)
        self._value_label.setObjectName("statValue")
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        main_layout.addWidget(self._value_label)

        # Bottom: Title and optional Subtitle
        self._title_label = QLabel(self._title)
        self._title_label.setObjectName("statTitle")
        self._title_label.setWordWrap(True)
        main_layout.addWidget(self._title_label)

        self._subtitle_label = QLabel(self._subtitle)
        self._subtitle_label.setObjectName("statSubtitle")
        self._subtitle_label.setWordWrap(True)
        self._subtitle_label.setVisible(bool(self._subtitle))
        main_layout.addWidget(self._subtitle_label)

    def _apply_styling(self) -> None:
        """Apply theme-aware styles based on the active variant."""
        palette = get_current_palette()

        # Variant colors
        variant_colors = {
            "accent": {
                "color": palette.accent,
                "icon_bg": "rgba(0, 180, 216, 0.15)",
                "border": palette.border,
            },
            "danger": {
                "color": palette.danger,
                "icon_bg": "rgba(239, 68, 68, 0.15)",
                "border": "rgba(239, 68, 68, 0.35)",
            },
            "warning": {
                "color": palette.warning,
                "icon_bg": "rgba(245, 158, 11, 0.15)",
                "border": "rgba(245, 158, 11, 0.35)",
            },
            "success": {
                "color": palette.success,
                "icon_bg": "rgba(16, 185, 129, 0.15)",
                "border": "rgba(16, 185, 129, 0.35)",
            },
            "neutral": {
                "color": palette.text_primary,
                "icon_bg": "rgba(148, 163, 184, 0.15)",
                "border": palette.border,
            },
        }

        conf = variant_colors.get(self._variant, variant_colors["accent"])
        accent_color = conf["color"]
        icon_bg = conf["icon_bg"]
        card_border = conf["border"]

        self.setStyleSheet(f"""
            QFrame[card="true"] {{
                background-color: {palette.card};
                border: 1px solid {card_border};
                border-radius: 8px;
            }}
            QFrame[card="true"]:hover {{
                background-color: {palette.card_hover};
                border: 1px solid {accent_color};
            }}
            QLabel#statValue {{
                font-size: 24px;
                font-weight: 700;
                color: {accent_color};
                background: transparent;
                border: none;
            }}
            QLabel#statTitle {{
                font-size: 13px;
                font-weight: 600;
                color: {palette.text_secondary};
                background: transparent;
                border: none;
            }}
            QLabel#statSubtitle {{
                font-size: 11px;
                color: {palette.text_muted};
                background: transparent;
                border: none;
            }}
        """)

        self._icon_label.setStyleSheet(f"""
            background-color: {icon_bg};
            color: {accent_color};
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
        """)

        self._badge_label.setStyleSheet(f"""
            background-color: {palette.surface};
            color: {palette.text_secondary};
            border: 1px solid {palette.border};
            border-radius: 10px;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: 600;
        """)

    def set_value(self, value: int | str) -> None:
        """Update the displayed metric value."""
        self._value = str(value)
        self._value_label.setText(self._value)

    def get_value(self) -> str:
        """Return the current displayed value."""
        return self._value

    def set_title(self, title: str) -> None:
        """Update the card title."""
        self._title = title
        self._title_label.setText(title)

    def set_icon(self, icon: str) -> None:
        """Update the icon symbol."""
        self._icon = icon
        self._icon_label.setText(icon)
        self._icon_label.setVisible(bool(icon))

    def set_badge(self, badge: str, variant: str = "neutral") -> None:
        """Set or update the badge text and optional variant."""
        self._badge = badge
        self._badge_label.setText(badge)
        self._badge_label.setVisible(bool(badge))

        palette = get_current_palette()
        if variant == "danger":
            self._badge_label.setStyleSheet(f"""
                background-color: {palette.badge_critical_bg};
                color: {palette.badge_critical_text};
                border: 1px solid {palette.badge_critical_border};
                border-radius: 10px;
                padding: 2px 8px;
                font-size: 11px;
                font-weight: 600;
            """)
        elif variant == "warning":
            self._badge_label.setStyleSheet(f"""
                background-color: {palette.badge_medium_bg};
                color: {palette.badge_medium_text};
                border: 1px solid {palette.badge_medium_border};
                border-radius: 10px;
                padding: 2px 8px;
                font-size: 11px;
                font-weight: 600;
            """)
        elif variant == "success":
            self._badge_label.setStyleSheet(f"""
                background-color: {palette.badge_allow_bg};
                color: {palette.badge_allow_text};
                border: 1px solid {palette.badge_allow_border};
                border-radius: 10px;
                padding: 2px 8px;
                font-size: 11px;
                font-weight: 600;
            """)
        else:
            self._badge_label.setStyleSheet(f"""
                background-color: {palette.surface};
                color: {palette.text_secondary};
                border: 1px solid {palette.border};
                border-radius: 10px;
                padding: 2px 8px;
                font-size: 11px;
                font-weight: 600;
            """)

    def set_subtitle(self, subtitle: str) -> None:
        """Update the subtitle description."""
        self._subtitle = subtitle
        self._subtitle_label.setText(subtitle)
        self._subtitle_label.setVisible(bool(subtitle))

    def set_variant(self, variant: str) -> None:
        """Change color variant ('accent', 'danger', 'warning', 'success', 'neutral')."""
        self._variant = variant
        self._apply_styling()

    def mousePressEvent(self, event: Any) -> None:
        """Handle mouse click to emit clicked signal."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)
