"""QSS Stylesheet generator and UI style helpers for BoundaryX.

Provides comprehensive styling for all standard Qt and PySide6 widgets,
tuned for cybersecurity operations with high contrast, readable typography,
and subtle interactive feedback.
"""

from __future__ import annotations

from typing import Any

from boundaryx.ui.resources.themes import ThemePalette, get_current_palette


def generate_stylesheet(palette: ThemePalette | None = None) -> str:
    """Generate a complete Qt Stylesheet (QSS) using the given theme palette.

    Args:
        palette: The ThemePalette to use. If None, current active palette is used.

    Returns:
        Complete QSS string ready to be applied to QApplication or QWidget.
    """
    if palette is None:
        palette = get_current_palette()

    return f"""
/* ==========================================================================
   BoundaryX Global Application Stylesheet
   Theme: {palette.mode.value.upper()}
   ========================================================================== */

/* --- Base Widget & Window --- */
QMainWindow, QDialog {{
    background-color: {palette.background};
    color: {palette.text_primary};
    font-family: {palette.font_family_ui};
    font-size: 13px;
}}

QWidget {{
    background-color: transparent;
    color: {palette.text_primary};
    font-family: {palette.font_family_ui};
    font-size: 13px;
    selection-background-color: {palette.selection_bg};
    selection-color: {palette.selection_text};
}}

QWidget#centralWidget, QWidget#contentPane {{
    background-color: {palette.background};
}}

/* --- Frames, Cards & Panels --- */
QFrame {{
    border: none;
}}

QFrame[frameShape="4"], /* HLine */
QFrame[frameShape="5"]  /* VLine */ {{
    background-color: {palette.border};
    border: none;
    max-height: 1px;
    max-width: 1px;
}}

QFrame[card="true"],
.card-frame {{
    background-color: {palette.card};
    border: 1px solid {palette.border};
    border-radius: 6px;
    padding: 12px;
}}

QFrame[panel="surface"] {{
    background-color: {palette.surface};
    border: 1px solid {palette.border};
    border-radius: 6px;
}}

/* --- Splitter --- */
QSplitter {{
    background-color: transparent;
}}

QSplitter::handle {{
    background-color: {palette.border};
}}

QSplitter::handle:horizontal {{
    width: 2px;
    margin: 0px 1px;
}}

QSplitter::handle:vertical {{
    height: 2px;
    margin: 1px 0px;
}}

QSplitter::handle:hover {{
    background-color: {palette.accent};
}}

/* --- Labels --- */
QLabel {{
    background-color: transparent;
    color: {palette.text_primary};
    font-size: 13px;
}}

QLabel[labelClass="title"] {{
    font-size: 18px;
    font-weight: 600;
    color: {palette.text_primary};
}}

QLabel[labelClass="subtitle"] {{
    font-size: 14px;
    font-weight: 500;
    color: {palette.text_secondary};
}}

QLabel[labelClass="muted"] {{
    font-size: 12px;
    color: {palette.text_muted};
}}

QLabel[labelClass="metric-value"] {{
    font-size: 26px;
    font-weight: 700;
    color: {palette.text_primary};
}}

QLabel[labelClass="badge"] {{
    padding: 3px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
}}

/* --- Push Buttons --- */
QPushButton {{
    background-color: {palette.card};
    color: {palette.text_primary};
    border: 1px solid {palette.border};
    border-radius: 4px;
    padding: 6px 14px;
    font-size: 13px;
    font-weight: 500;
    min-height: 20px;
    outline: none;
}}

QPushButton:hover {{
    background-color: {palette.card_hover};
    border-color: {palette.border_focus};
}}

QPushButton:pressed {{
    background-color: {palette.surface};
    border-color: {palette.accent};
}}

QPushButton:focus {{
    border: 1px solid {palette.border_focus};
}}

QPushButton:disabled {{
    background-color: {palette.surface};
    color: {palette.text_disabled};
    border-color: {palette.border_subtle};
}}

/* Button Variant: Primary */
QPushButton[btnClass="primary"],
QPushButton.primary-btn {{
    background-color: {palette.accent};
    color: #ffffff;
    border: 1px solid {palette.accent};
    font-weight: 600;
}}

QPushButton[btnClass="primary"]:hover,
QPushButton.primary-btn:hover {{
    background-color: {palette.accent_hover};
    border-color: {palette.accent_hover};
}}

QPushButton[btnClass="primary"]:pressed,
QPushButton.primary-btn:pressed {{
    background-color: {palette.accent_active};
    border-color: {palette.accent_active};
}}

QPushButton[btnClass="primary"]:disabled,
QPushButton.primary-btn:disabled {{
    background-color: {palette.card};
    color: {palette.text_disabled};
    border-color: {palette.border};
}}

/* Button Variant: Secondary */
QPushButton[btnClass="secondary"],
QPushButton.secondary-btn {{
    background-color: {palette.surface};
    color: {palette.text_primary};
    border: 1px solid {palette.border};
}}

QPushButton[btnClass="secondary"]:hover,
QPushButton.secondary-btn:hover {{
    background-color: {palette.card};
    border-color: {palette.text_secondary};
}}

QPushButton[btnClass="secondary"]:pressed,
QPushButton.secondary-btn:pressed {{
    background-color: {palette.card_hover};
}}

/* Button Variant: Danger */
QPushButton[btnClass="danger"],
QPushButton.danger-btn {{
    background-color: {palette.danger};
    color: #ffffff;
    border: 1px solid {palette.danger};
    font-weight: 600;
}}

QPushButton[btnClass="danger"]:hover,
QPushButton.danger-btn:hover {{
    background-color: {palette.danger_hover};
    border-color: {palette.danger_hover};
}}

QPushButton[btnClass="danger"]:pressed,
QPushButton.danger-btn:pressed {{
    background-color: {palette.danger};
}}

QPushButton[btnClass="danger"]:disabled,
QPushButton.danger-btn:disabled {{
    background-color: {palette.card};
    color: {palette.text_disabled};
    border-color: {palette.border};
}}

/* Button Variant: Ghost */
QPushButton[btnClass="ghost"],
QPushButton.ghost-btn {{
    background-color: transparent;
    color: {palette.text_secondary};
    border: 1px solid transparent;
}}

QPushButton[btnClass="ghost"]:hover,
QPushButton.ghost-btn:hover {{
    background-color: {palette.card_hover};
    color: {palette.text_primary};
    border-color: {palette.border};
}}

QPushButton[btnClass="ghost"]:pressed,
QPushButton.ghost-btn:pressed {{
    background-color: {palette.surface};
}}

/* --- Input Fields (QLineEdit, QTextEdit, QPlainTextEdit) --- */
QLineEdit,
QTextEdit,
QPlainTextEdit {{
    background-color: {palette.input_bg};
    color: {palette.text_primary};
    border: 1px solid {palette.input_border};
    border-radius: 4px;
    padding: 6px 10px;
    selection-background-color: {palette.selection_bg};
    selection-color: {palette.selection_text};
    font-size: 13px;
}}

QLineEdit:focus,
QTextEdit:focus,
QPlainTextEdit:focus {{
    border: 1px solid {palette.border_focus};
    background-color: {palette.input_bg};
}}

QLineEdit:disabled,
QTextEdit:disabled,
QPlainTextEdit:disabled {{
    background-color: {palette.surface};
    color: {palette.text_disabled};
    border-color: {palette.border_subtle};
}}

/* --- Code & Monospace Viewers --- */
QPlainTextEdit[codeViewer="true"],
QTextEdit[codeViewer="true"] {{
    font-family: {palette.font_family_mono};
    font-size: 12px;
    background-color: {palette.input_bg};
    border: 1px solid {palette.border};
    border-radius: 4px;
    line-height: 1.5;
}}

/* --- Combo Boxes --- */
QComboBox {{
    background-color: {palette.input_bg};
    color: {palette.text_primary};
    border: 1px solid {palette.input_border};
    border-radius: 4px;
    padding: 5px 10px;
    min-height: 20px;
    font-size: 13px;
}}

QComboBox:hover {{
    border-color: {palette.border_focus};
}}

QComboBox:focus {{
    border: 1px solid {palette.border_focus};
}}

QComboBox:disabled {{
    background-color: {palette.surface};
    color: {palette.text_disabled};
    border-color: {palette.border_subtle};
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border-left: 1px solid {palette.border};
    border-top-right-radius: 4px;
    border-bottom-right-radius: 4px;
    background-color: {palette.card};
}}

QComboBox::down-arrow {{
    width: 8px;
    height: 8px;
    border-left: 2px solid {palette.text_secondary};
    border-bottom: 2px solid {palette.text_secondary};
    transform: rotate(-45deg);
    margin-right: 4px;
    margin-bottom: 2px;
}}

QComboBox QAbstractItemView {{
    background-color: {palette.card};
    color: {palette.text_primary};
    border: 1px solid {palette.border};
    selection-background-color: {palette.selection_bg};
    selection-color: {palette.selection_text};
    outline: none;
    padding: 4px;
    border-radius: 4px;
}}

/* --- Checkboxes & Radio Buttons --- */
QCheckBox, QRadioButton {{
    spacing: 8px;
    color: {palette.text_primary};
    font-size: 13px;
    background-color: transparent;
}}

QCheckBox:disabled, QRadioButton:disabled {{
    color: {palette.text_disabled};
}}

QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {palette.border};
    border-radius: 3px;
    background-color: {palette.input_bg};
}}

QCheckBox::indicator:hover {{
    border-color: {palette.accent};
}}

QCheckBox::indicator:checked {{
    background-color: {palette.accent};
    border-color: {palette.accent};
    image: none;
}}

QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {palette.border};
    border-radius: 8px;
    background-color: {palette.input_bg};
}}

QRadioButton::indicator:hover {{
    border-color: {palette.accent};
}}

QRadioButton::indicator:checked {{
    background-color: {palette.card};
    border: 5px solid {palette.accent};
}}

/* --- Tables & Tree Views --- */
QTableView,
QTableWidget,
QTreeView,
QListView {{
    background-color: {palette.surface};
    color: {palette.text_primary};
    border: 1px solid {palette.border};
    border-radius: 4px;
    gridline-color: {palette.table_grid};
    selection-background-color: {palette.selection_bg};
    selection-color: {palette.selection_text};
    alternate-background-color: {palette.table_alt_row};
    outline: none;
    font-size: 13px;
}}

QTableView::item,
QTableWidget::item,
QTreeView::item,
QListView::item {{
    padding: 6px 8px;
    border-bottom: 1px solid {palette.border_subtle};
}}

QTableView::item:selected,
QTableWidget::item:selected,
QTreeView::item:selected,
QListView::item:selected {{
    background-color: {palette.selection_bg};
    color: {palette.selection_text};
}}

QTableView::item:hover,
QTableWidget::item:hover,
QTreeView::item:hover,
QListView::item:hover {{
    background-color: {palette.card_hover};
}}

/* Table Headers */
QHeaderView {{
    background-color: {palette.header_bg};
    border: none;
}}

QHeaderView::section {{
    background-color: {palette.header_bg};
    color: {palette.text_secondary};
    padding: 6px 8px;
    border: none;
    border-right: 1px solid {palette.border_subtle};
    border-bottom: 1px solid {palette.border};
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
}}

QHeaderView::section:hover {{
    background-color: {palette.card};
    color: {palette.text_primary};
}}

/* --- Tab Widget --- */
QTabWidget::pane {{
    border: 1px solid {palette.border};
    border-radius: 4px;
    background-color: {palette.surface};
    top: -1px;
}}

QTabBar::tab {{
    background-color: {palette.card};
    color: {palette.text_secondary};
    border: 1px solid {palette.border};
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    padding: 7px 16px;
    margin-right: 3px;
    font-size: 13px;
    font-weight: 500;
}}

QTabBar::tab:selected {{
    background-color: {palette.surface};
    color: {palette.text_primary};
    border-color: {palette.border};
    border-top: 2px solid {palette.accent};
}}

QTabBar::tab:hover:!selected {{
    background-color: {palette.card_hover};
    color: {palette.text_primary};
}}

/* --- ScrollBars --- */
QScrollBar:vertical {{
    background-color: {palette.scrollbar_track};
    width: 10px;
    margin: 0px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical {{
    background-color: {palette.scrollbar_thumb};
    min-height: 24px;
    border-radius: 5px;
    margin: 2px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {palette.scrollbar_thumb_hover};
}}

QScrollBar:horizontal {{
    background-color: {palette.scrollbar_track};
    height: 10px;
    margin: 0px;
    border-radius: 5px;
}}

QScrollBar::handle:horizontal {{
    background-color: {palette.scrollbar_thumb};
    min-width: 24px;
    border-radius: 5px;
    margin: 2px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {palette.scrollbar_thumb_hover};
}}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical,
QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {{
    width: 0px;
    height: 0px;
    background: none;
    border: none;
}}

QScrollBar::add-page:vertical,
QScrollBar::sub-page:vertical,
QScrollBar::add-page:horizontal,
QScrollBar::sub-page:horizontal {{
    background: none;
}}

/* --- Progress Bar --- */
QProgressBar {{
    background-color: {palette.input_bg};
    border: 1px solid {palette.border};
    border-radius: 4px;
    text-align: center;
    color: {palette.text_primary};
    font-size: 11px;
    font-weight: 600;
    min-height: 14px;
    max-height: 14px;
}}

QProgressBar::chunk {{
    background-color: {palette.accent};
    border-radius: 3px;
}}

/* --- Status Bar --- */
QStatusBar {{
    background-color: {palette.surface};
    color: {palette.text_secondary};
    border-top: 1px solid {palette.border};
    font-size: 12px;
    min-height: 24px;
    padding: 2px 6px;
}}

QStatusBar QLabel {{
    color: {palette.text_secondary};
    font-size: 12px;
}}

/* --- Menus & Tooltips --- */
QMenuBar {{
    background-color: {palette.surface};
    color: {palette.text_primary};
    border-bottom: 1px solid {palette.border};
    padding: 2px;
}}

QMenuBar::item {{
    background-color: transparent;
    padding: 4px 8px;
    border-radius: 3px;
}}

QMenuBar::item:selected {{
    background-color: {palette.card_hover};
}}

QMenu {{
    background-color: {palette.card};
    color: {palette.text_primary};
    border: 1px solid {palette.border};
    border-radius: 4px;
    padding: 4px;
}}

QMenu::item {{
    padding: 6px 20px 6px 12px;
    border-radius: 3px;
}}

QMenu::item:selected {{
    background-color: {palette.selection_bg};
    color: {palette.selection_text};
}}

QMenu::separator {{
    height: 1px;
    background-color: {palette.border};
    margin: 4px 0px;
}}

QToolTip {{
    background-color: {palette.tooltip_bg};
    color: {palette.tooltip_text};
    border: 1px solid {palette.tooltip_border};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}}

/* --- Group Box --- */
QGroupBox {{
    font-weight: 600;
    border: 1px solid {palette.border};
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 12px;
    background-color: {palette.surface};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    color: {palette.text_secondary};
}}
"""


def apply_button_class(button: Any, btn_class: str) -> None:
    """Apply styling variant class to a QPushButton and force Qt style refresh.

    Supported variants: 'primary', 'secondary', 'danger', 'ghost'.
    """
    button.setProperty("btnClass", btn_class)
    style = button.style()
    if style:
        style.unpolish(button)
        style.polish(button)
    button.update()


def apply_label_class(label: Any, label_class: str) -> None:
    """Apply styling variant class to a QLabel and force Qt style refresh.

    Supported variants: 'title', 'subtitle', 'muted', 'metric-value', 'badge'.
    """
    label.setProperty("labelClass", label_class)
    style = label.style()
    if style:
        style.unpolish(label)
        style.polish(label)
    label.update()
