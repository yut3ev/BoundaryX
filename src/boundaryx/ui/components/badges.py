"""Badge and tag UI components for BoundaryX.

Provides reusable color-coded badges for HTTP methods, status codes,
vulnerability severities, authorization decisions, and triage statuses.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QWidget


class BaseBadge(QLabel):
    """Base stylized pill badge widget with rounded corners and high contrast."""

    def __init__(
        self,
        text: str,
        bg_color: str,
        text_color: str,
        border_color: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        border_css = f"border: 1px solid {border_color};" if border_color else "border: none;"
        self.setStyleSheet(
            f"""
            QLabel {{
                background-color: {bg_color};
                color: {text_color};
                {border_css}
                border-radius: 9px;
                padding: 2px 8px;
                font-size: 11px;
                font-weight: 700;
                font-family: Segoe UI, sans-serif;
            }}
            """
        )
        self.setFixedHeight(20)


class MethodBadge(BaseBadge):
    """HTTP Method badge (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)."""

    METHOD_COLORS: dict[str, tuple[str, str, str]] = {
        "GET": ("#064e3b", "#34d399", "#059669"),
        "POST": ("#1e3a8a", "#60a5fa", "#2563eb"),
        "PUT": ("#78350f", "#fbbf24", "#d97706"),
        "PATCH": ("#4c1d95", "#c084fc", "#7c3aed"),
        "DELETE": ("#7f1d1d", "#f87171", "#dc2626"),
        "OPTIONS": ("#1f2937", "#9ca3af", "#4b5563"),
        "HEAD": ("#134e4a", "#2dd4bf", "#0d9488"),
    }

    def __init__(self, method: str, parent: QWidget | None = None) -> None:
        norm_method = method.upper().strip()
        bg, fg, border = self.METHOD_COLORS.get(norm_method, ("#1f2937", "#9ca3af", "#4b5563"))
        super().__init__(norm_method, bg, fg, border, parent)


class StatusCodeBadge(BaseBadge):
    """HTTP response status code badge (2xx green, 3xx blue, 4xx orange, 5xx red)."""

    def __init__(self, code: int | str, parent: QWidget | None = None) -> None:
        try:
            num = int(code)
        except (ValueError, TypeError):
            num = 0

        if 200 <= num < 300:
            bg, fg, border = ("#064e3b", "#34d399", "#059669")
        elif 300 <= num < 400:
            bg, fg, border = ("#1e3a8a", "#60a5fa", "#2563eb")
        elif 400 <= num < 500:
            bg, fg, border = ("#78350f", "#fbbf24", "#d97706")
        elif num >= 500:
            bg, fg, border = ("#7f1d1d", "#f87171", "#dc2626")
        else:
            bg, fg, border = ("#1f2937", "#9ca3af", "#4b5563")

        super().__init__(str(code), bg, fg, border, parent)


class SeverityBadge(BaseBadge):
    """Finding severity rating badge (CRITICAL, HIGH, MEDIUM, LOW, INFO)."""

    SEVERITY_STYLES: dict[str, tuple[str, str, str]] = {
        "CRITICAL": ("#450a0a", "#f87171", "#b91c1c"),
        "HIGH": ("#431407", "#fb923c", "#c2410c"),
        "MEDIUM": ("#451a03", "#facc15", "#b45309"),
        "LOW": ("#172554", "#60a5fa", "#1d4ed8"),
        "INFO": ("#0f172a", "#94a3b8", "#334155"),
        "INFORMATIONAL": ("#0f172a", "#94a3b8", "#334155"),
    }

    def __init__(self, severity: str, parent: QWidget | None = None) -> None:
        norm_sev = severity.upper().strip()
        bg, fg, border = self.SEVERITY_STYLES.get(norm_sev, ("#0f172a", "#94a3b8", "#334155"))
        super().__init__(norm_sev, bg, fg, border, parent)


class DecisionBadge(BaseBadge):
    """Authorization policy decision badge (ALLOW vs DENY)."""

    def __init__(self, decision: str, parent: QWidget | None = None) -> None:
        dec = decision.upper().strip()
        if dec == "ALLOW":
            bg, fg, border = ("#064e3b", "#34d399", "#059669")
        elif dec == "DENY":
            bg, fg, border = ("#7f1d1d", "#f87171", "#dc2626")
        else:
            bg, fg, border = ("#1f2937", "#9ca3af", "#4b5563")
        super().__init__(dec, bg, fg, border, parent)


class StatusBadge(BaseBadge):
    """Lifecycle / execution status badge."""

    STATUS_STYLES: dict[str, tuple[str, str, str]] = {
        "PASSED": ("#064e3b", "#34d399", "#059669"),
        "CONFIRMED": ("#450a0a", "#f87171", "#b91c1c"),
        "NEW": ("#1e3a8a", "#60a5fa", "#2563eb"),
        "NEEDS_REVIEW": ("#451a03", "#facc15", "#b45309"),
        "FAILED": ("#7f1d1d", "#f87171", "#dc2626"),
        "ERROR": ("#7f1d1d", "#f87171", "#dc2626"),
        "BLOCKED_BY_SCOPE": ("#3b0764", "#c084fc", "#7e22ce"),
        "FALSE_POSITIVE": ("#1e293b", "#94a3b8", "#475569"),
        "FIXED": ("#064e3b", "#34d399", "#059669"),
        "REOPENED": ("#431407", "#fb923c", "#c2410c"),
        "RUNNING": ("#0284c7", "#e0f2fe", "#0369a1"),
        "QUEUED": ("#334155", "#cbd5e1", "#475569"),
        "NOT_RUN": ("#1e293b", "#64748b", "#334155"),
    }

    def __init__(self, status: str, parent: QWidget | None = None) -> None:
        norm = status.upper().strip()
        bg, fg, border = self.STATUS_STYLES.get(norm, ("#1e293b", "#94a3b8", "#475569"))
        super().__init__(norm, bg, fg, border, parent)


def create_badge(
    text: str,
    bg_color: str,
    text_color: str,
    border_color: str | None = None,
    parent: QWidget | None = None,
) -> QLabel:
    """Helper function to create a stylized pill badge."""
    return BaseBadge(text, bg_color, text_color, border_color, parent)
