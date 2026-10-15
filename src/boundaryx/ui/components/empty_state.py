"""Empty state placeholder widget for BoundaryX.

Displays an iconography badge, informative message, and guided primary/secondary
actions when views or datasets have no records to show.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from boundaryx.ui.resources.styles import apply_button_class
from boundaryx.ui.resources.themes import get_current_palette


class EmptyStateWidget(QWidget):
    """Empty state placeholder with title, explanation, icon, and action triggers."""

    primary_action_clicked = Signal()
    secondary_action_clicked = Signal()

    def __init__(
        self,
        title: str = "No Items Found",
        description: str = "Get started by creating a new resource or importing data.",
        icon: str = "🔍",
        primary_button_text: str = "",
        secondary_button_text: str = "",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the EmptyStateWidget.

        Args:
            title: Headline text.
            description: Informational explanation or instructions.
            icon: Icon glyph or emoji symbol.
            primary_button_text: Text for primary call-to-action button (hidden if empty).
            secondary_button_text: Text for secondary action button (hidden if empty).
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._title = title
        self._description = description
        self._icon = icon
        self._primary_text = primary_button_text
        self._secondary_text = secondary_button_text

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._init_ui()
        self._apply_styling()

    def _init_ui(self) -> None:
        """Construct the centered empty state layout."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 48, 32, 48)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Center Container Frame
        self._container = QFrame()
        self._container.setMaximumWidth(480)
        self._container.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        container_layout = QVBoxLayout(self._container)
        container_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.setSpacing(14)

        # Icon Circle Badge
        self._icon_label = QLabel(self._icon)
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon_label.setFixedSize(64, 64)
        container_layout.addWidget(self._icon_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Title Label
        self._title_label = QLabel(self._title)
        self._title_label.setObjectName("emptyStateTitle")
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title_label.setWordWrap(True)
        container_layout.addWidget(self._title_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Description Label
        self._desc_label = QLabel(self._description)
        self._desc_label.setObjectName("emptyStateDesc")
        self._desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._desc_label.setWordWrap(True)
        container_layout.addWidget(self._desc_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Button Row
        self._button_row = QWidget()
        btn_layout = QHBoxLayout(self._button_row)
        btn_layout.setContentsMargins(0, 10, 0, 0)
        btn_layout.setSpacing(10)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._secondary_btn = QPushButton(self._secondary_text)
        apply_button_class(self._secondary_btn, "secondary")
        self._secondary_btn.setVisible(bool(self._secondary_text))
        self._secondary_btn.clicked.connect(self.secondary_action_clicked.emit)
        btn_layout.addWidget(self._secondary_btn)

        self._primary_btn = QPushButton(self._primary_text)
        apply_button_class(self._primary_btn, "primary")
        self._primary_btn.setVisible(bool(self._primary_text))
        self._primary_btn.clicked.connect(self.primary_action_clicked.emit)
        btn_layout.addWidget(self._primary_btn)

        container_layout.addWidget(self._button_row, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self._container, alignment=Qt.AlignmentFlag.AlignCenter)

    def _apply_styling(self) -> None:
        """Apply theme styling."""
        palette = get_current_palette()

        self._icon_label.setStyleSheet(f"""
            QLabel {{
                background-color: {palette.card};
                color: {palette.accent};
                border: 1px solid {palette.border};
                border-radius: 32px;
                font-size: 26px;
            }}
        """)

        self._title_label.setStyleSheet(f"""
            QLabel#emptyStateTitle {{
                font-size: 18px;
                font-weight: 700;
                color: {palette.text_primary};
                background: transparent;
            }}
        """)

        self._desc_label.setStyleSheet(f"""
            QLabel#emptyStateDesc {{
                font-size: 13px;
                line-height: 1.5;
                color: {palette.text_secondary};
                background: transparent;
            }}
        """)

    def set_title(self, title: str) -> None:
        """Update headline text."""
        self._title = title
        self._title_label.setText(title)

    def set_description(self, description: str) -> None:
        """Update explanation text."""
        self._description = description
        self._desc_label.setText(description)

    def set_icon(self, icon: str) -> None:
        """Update icon glyph or symbol."""
        self._icon = icon
        self._icon_label.setText(icon)

    def set_primary_action(
        self,
        text: str,
        callback: Callable[[], Any] | None = None,
    ) -> None:
        """Configure the primary action button.

        Args:
            text: Button label text.
            callback: Optional callback to invoke when clicked.
        """
        self._primary_text = text
        self._primary_btn.setText(text)
        self._primary_btn.setVisible(bool(text))
        if callback is not None:
            self.primary_action_clicked.connect(callback)

    def set_secondary_action(
        self,
        text: str,
        callback: Callable[[], Any] | None = None,
    ) -> None:
        """Configure the secondary action button.

        Args:
            text: Button label text.
            callback: Optional callback to invoke when clicked.
        """
        self._secondary_text = text
        self._secondary_btn.setText(text)
        self._secondary_btn.setVisible(bool(text))
        if callback is not None:
            self.secondary_action_clicked.connect(callback)
