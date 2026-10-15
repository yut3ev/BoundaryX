"""Search and filtering bar component for BoundaryX.

Provides debounced text query input with inline clear action, dynamic filter dropdowns,
and customizable action triggers.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QWidget,
)

from boundaryx.ui.resources.styles import apply_button_class


class SearchFilterBar(QWidget):
    """Interactive search and filter bar for tables, trees, and lists."""

    search_changed = Signal(str)
    search_submitted = Signal(str)
    filter_changed = Signal(str, str)  # (filter_key, selected_value)
    filters_updated = Signal(dict)  # complete state: {"query": ..., ...}
    reset_clicked = Signal()

    def __init__(
        self,
        placeholder: str = "Search endpoints, findings, parameters...",
        debounce_ms: int = 250,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the SearchFilterBar.

        Args:
            placeholder: Search input placeholder text.
            debounce_ms: Delay in milliseconds before search_changed is emitted.
            parent: Optional parent widget.
        """
        super().__init__(parent)

        self._debounce_ms = debounce_ms
        self._filter_combos: dict[str, QComboBox] = {}

        # Search debounce timer
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(self._debounce_ms)
        self._debounce_timer.timeout.connect(self._on_debounce_timeout)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._init_ui(placeholder)

    def _init_ui(self, placeholder: str) -> None:
        """Construct the search bar layout and controls."""
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(8)

        # Search Input
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText(placeholder)
        self._search_input.setClearButtonEnabled(True)
        self._search_input.setMinimumWidth(220)
        self._search_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._search_input.textChanged.connect(self._on_text_changed)
        self._search_input.returnPressed.connect(self._on_return_pressed)
        main_layout.addWidget(self._search_input)

        # Container for Filter Dropdowns
        self._filters_container = QWidget()
        self._filters_layout = QHBoxLayout(self._filters_container)
        self._filters_layout.setContentsMargins(0, 0, 0, 0)
        self._filters_layout.setSpacing(6)
        main_layout.addWidget(self._filters_container)

        # Action Buttons Container
        self._actions_container = QWidget()
        self._actions_layout = QHBoxLayout(self._actions_container)
        self._actions_layout.setContentsMargins(0, 0, 0, 0)
        self._actions_layout.setSpacing(6)
        main_layout.addWidget(self._actions_container)

        # Separator Line
        self._separator = QFrame()
        self._separator.setFrameShape(QFrame.Shape.VLine)
        self._separator.setFrameShadow(QFrame.Shadow.Sunken)
        self._separator.setVisible(False)
        main_layout.addWidget(self._separator)

    def set_placeholder(self, text: str) -> None:
        """Update placeholder text for search input."""
        self._search_input.setPlaceholderText(text)

    def get_search_text(self) -> str:
        """Return the current search query string."""
        return self._search_input.text().strip()

    def set_search_text(self, text: str) -> None:
        """Set search input text programmatically."""
        self._search_input.setText(text)

    def clear_search(self) -> None:
        """Clear search input text."""
        self._search_input.clear()

    def add_filter(
        self,
        key: str,
        options: list[str],
        default: str = "All",
        min_width: int = 120,
    ) -> QComboBox:
        """Add a dropdown filter to the bar.

        Args:
            key: Unique identifier for the filter.
            options: List of selectable option strings.
            default: Default selected option.
            min_width: Minimum width for the combobox.

        Returns:
            The created QComboBox instance.
        """
        combo = QComboBox()
        combo.setMinimumWidth(min_width)
        for opt in options:
            combo.addItem(opt)

        if default in options:
            combo.setCurrentText(default)

        combo.currentTextChanged.connect(lambda val, k=key: self._on_filter_changed(k, val))

        self._filter_combos[key] = combo
        self._filters_layout.addWidget(combo)
        return combo

    def get_filter_value(self, key: str) -> str:
        """Retrieve current value for a filter key."""
        combo = self._filter_combos.get(key)
        return combo.currentText() if combo else ""

    def set_filter_value(self, key: str, value: str) -> None:
        """Set active value for a filter key."""
        combo = self._filter_combos.get(key)
        if combo:
            idx = combo.findText(value)
            if idx >= 0:
                combo.setCurrentIndex(idx)

    def add_action_button(
        self,
        text: str,
        callback: Callable[[], Any] | None = None,
        variant: str = "secondary",
        tooltip: str = "",
    ) -> QPushButton:
        """Add an action button to the right side of the bar.

        Args:
            text: Button label.
            callback: Click handler.
            variant: Style variant ('primary', 'secondary', 'danger', 'ghost').
            tooltip: Optional button tooltip.

        Returns:
            The created QPushButton instance.
        """
        btn = QPushButton(text)
        apply_button_class(btn, variant)
        if tooltip:
            btn.setToolTip(tooltip)
        if callback is not None:
            btn.clicked.connect(callback)
        self._actions_layout.addWidget(btn)
        return btn

    def get_all_filter_values(self) -> dict[str, str]:
        """Return dict of all current filter keys and their selected values."""
        return {key: combo.currentText() for key, combo in self._filter_combos.items()}

    def get_state(self) -> dict[str, Any]:
        """Return complete search bar state (query and all filters)."""
        return {
            "query": self.get_search_text(),
            "filters": self.get_all_filter_values(),
        }

    def reset_all(self) -> None:
        """Reset search query and all filters to their initial option."""
        self._search_input.clear()
        for combo in self._filter_combos.values():
            if combo.count() > 0:
                combo.setCurrentIndex(0)
        self.reset_clicked.emit()
        self._emit_state()

    def _on_text_changed(self, text: str) -> None:
        """Handle text change by debouncing the query."""
        if not text:
            # Immediate emit on clear
            self._debounce_timer.stop()
            self.search_changed.emit("")
            self._emit_state()
        else:
            self._debounce_timer.start()

    def _on_debounce_timeout(self) -> None:
        """Emit search query after debounce timeout."""
        query = self.get_search_text()
        self.search_changed.emit(query)
        self._emit_state()

    def _on_return_pressed(self) -> None:
        """Immediate emit on enter press."""
        self._debounce_timer.stop()
        query = self.get_search_text()
        self.search_submitted.emit(query)
        self.search_changed.emit(query)
        self._emit_state()

    def _on_filter_changed(self, key: str, value: str) -> None:
        """Handle individual filter change."""
        self.filter_changed.emit(key, value)
        self._emit_state()

    def _emit_state(self) -> None:
        """Emit complete filter updated dictionary."""
        self.filters_updated.emit(self.get_state())
