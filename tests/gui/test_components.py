"""Unit and widget tests for BoundaryX base UI components."""

from __future__ import annotations

import json

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from boundaryx.domain.findings.models import FindingSeverity, FindingStatus
from boundaryx.domain.policies.models import ExpectedDecision
from boundaryx.ui.components import (
    EmptyStateWidget,
    HttpViewer,
    SearchFilterBar,
    StatCard,
    StatusBadge,
)


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Fixture providing QApplication for offscreen widget testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(["-platform", "offscreen"])
    return app


# ============================================================================
# StatCard Tests
# ============================================================================


def test_stat_card_initialization(qapp: QApplication) -> None:
    """Verify StatCard sets initial values, labels, and variant."""
    card = StatCard(
        title="Active Endpoints",
        value=142,
        icon="🌐",
        badge="+8%",
        subtitle="Across all microservices",
        variant="accent",
    )

    assert card.get_value() == "142"
    assert card._title == "Active Endpoints"
    assert card._icon == "🌐"
    assert card._badge == "+8%"
    assert card._subtitle == "Across all microservices"
    assert card.property("card") == "true"


def test_stat_card_mutators(qapp: QApplication) -> None:
    """Verify StatCard update methods for values, titles, and variants."""
    card = StatCard()

    card.set_value(99)
    assert card.get_value() == "99"

    card.set_title("Critical Defects")
    assert card._title_label.text() == "Critical Defects"

    card.set_icon("🚨")
    assert card._icon_label.text() == "🚨"

    card.set_badge("HIGH", variant="danger")
    assert card._badge_label.text() == "HIGH"
    assert not card._badge_label.isHidden()

    card.set_subtitle("Requires immediate triage")
    assert card._subtitle_label.text() == "Requires immediate triage"

    # Test all variants without exceptions
    for variant in ["accent", "danger", "warning", "success", "neutral"]:
        card.set_variant(variant)
        assert card._variant == variant


def test_stat_card_click_signal(qapp: QApplication) -> None:
    """Verify clicking StatCard emits clicked signal."""
    from PySide6.QtTest import QTest

    card = StatCard(title="Test Card")
    clicked = False

    def on_click() -> None:
        nonlocal clicked
        clicked = True

    card.clicked.connect(on_click)

    # Simulate mouse press event using QTest
    QTest.mouseClick(card, Qt.MouseButton.LeftButton)
    assert clicked is True


# ============================================================================
# StatusBadge Tests
# ============================================================================


def test_status_badge_severities(qapp: QApplication) -> None:
    """Verify StatusBadge factory for vulnerability severities."""
    badge_crit = StatusBadge.for_severity(FindingSeverity.CRITICAL)
    assert badge_crit.text() == "CRITICAL"

    badge_high = StatusBadge.for_severity(FindingSeverity.HIGH)
    assert badge_high.text() == "HIGH"

    badge_med = StatusBadge.for_severity(FindingSeverity.MEDIUM)
    assert badge_med.text() == "MEDIUM"

    badge_low = StatusBadge.for_severity(FindingSeverity.LOW)
    assert badge_low.text() == "LOW"

    badge_info = StatusBadge.for_severity(FindingSeverity.INFORMATIONAL)
    assert badge_info.text() == "INFO"


def test_status_badge_decisions(qapp: QApplication) -> None:
    """Verify StatusBadge factory for authorization decisions."""
    badge_allow = StatusBadge.for_decision(ExpectedDecision.ALLOW)
    assert badge_allow.text() == "ALLOW"

    badge_deny = StatusBadge.for_decision(ExpectedDecision.DENY)
    assert badge_deny.text() == "DENY"

    badge_unknown = StatusBadge.for_decision(ExpectedDecision.UNKNOWN)
    assert badge_unknown.text() == "UNKNOWN"


def test_status_badge_statuses(qapp: QApplication) -> None:
    """Verify StatusBadge factory for defect lifecycle statuses."""
    badge_new = StatusBadge.for_status(FindingStatus.NEW)
    assert badge_new.text() == "NEW"

    badge_confirmed = StatusBadge.for_status(FindingStatus.CONFIRMED)
    assert badge_confirmed.text() == "CONFIRMED"

    badge_needs_review = StatusBadge.for_status(FindingStatus.NEEDS_REVIEW)
    assert badge_needs_review.text() == "NEEDS REVIEW"


def test_status_badge_custom_colors(qapp: QApplication) -> None:
    """Verify setting custom color scheme on StatusBadge."""
    badge = StatusBadge.create("CUSTOM", variant="neutral")
    badge.set_custom_colors("#112233", "#445566", "#778899")
    qss = badge.styleSheet()
    assert "#112233" in qss
    assert "#445566" in qss
    assert "#778899" in qss


# ============================================================================
# HttpViewer Tests
# ============================================================================


def test_http_viewer_data_formatting(qapp: QApplication) -> None:
    """Verify HttpViewer formats request and response, handles JSON, and sets badges."""
    viewer = HttpViewer()

    payload = {"user_id": 101, "role": "admin", "action": "read"}
    headers = {"Authorization": "Bearer token123", "Content-Type": "application/json"}

    viewer.set_http_data(
        method="POST",
        url="https://api.example.com/v1/users",
        request_headers=headers,
        request_body=json.dumps(payload),
        status_code=201,
        response_headers={"Content-Type": "application/json"},
        response_body=json.dumps({"success": True}),
    )

    assert viewer._method_badge.text() == "POST"
    assert viewer._status_badge.text() == "201"
    assert "https://api.example.com/v1/users" in viewer._url_label.text()

    # Request headers formatted
    req_headers_text = viewer._req_tab["headers"].toPlainText()
    assert "Authorization: Bearer token123" in req_headers_text

    # Request body JSON formatted
    req_body_text = viewer._req_tab["body"].toPlainText()
    assert '"role": "admin"' in req_body_text

    # Mode switching
    viewer._on_mode_toggled(1)  # Switch to Split view
    assert viewer._view_stack.currentIndex() == 1

    viewer._on_mode_toggled(0)  # Switch back to Tab view
    assert viewer._view_stack.currentIndex() == 0


def test_http_viewer_truncation_safeguard(qapp: QApplication) -> None:
    """Verify HttpViewer protects against gigantic response payloads freezing the UI."""
    viewer = HttpViewer()

    huge_size = 600 * 1024  # 600 KB (above 512 KB threshold)
    huge_body = "A" * huge_size

    viewer.set_http_data(
        method="GET",
        url="https://api.example.com/huge",
        status_code=200,
        response_body=huge_body,
    )

    # Banner should be visible with warning
    assert not viewer._resp_tab["banner"].isHidden()
    assert "Body truncated" in viewer._resp_tab["banner"].text()
    assert "[TRUNCATED DUE TO SIZE]" in viewer._resp_tab["body"].toPlainText()


def test_http_viewer_curl_and_clear(qapp: QApplication) -> None:
    """Verify HttpViewer cURL generation and clear operation."""
    viewer = HttpViewer()
    viewer.set_http_data(
        method="GET",
        url="https://api.example.com/test",
        request_headers={"X-Test": "1"},
    )

    # cURL generation should not error
    viewer.copy_as_curl()
    viewer.copy_request()
    viewer.copy_response()

    viewer.clear()
    assert viewer._url_label.text() == "No URL"


# ============================================================================
# EmptyStateWidget Tests
# ============================================================================


def test_empty_state_initialization(qapp: QApplication) -> None:
    """Verify EmptyStateWidget text, icon, and button setup."""
    empty = EmptyStateWidget(
        title="No Test Sessions",
        description="Run an automated policy evaluation to view boundaries.",
        icon="🛡️",
        primary_button_text="Run New Test",
        secondary_button_text="Import HAR",
    )

    assert empty._title_label.text() == "No Test Sessions"
    assert "automated policy evaluation" in empty._desc_label.text()
    assert empty._icon_label.text() == "🛡️"
    assert not empty._primary_btn.isHidden()
    assert not empty._secondary_btn.isHidden()


def test_empty_state_actions(qapp: QApplication) -> None:
    """Verify EmptyStateWidget button actions and signal emissions."""
    empty = EmptyStateWidget()

    primary_clicked = False
    secondary_clicked = False

    def on_primary() -> None:
        nonlocal primary_clicked
        primary_clicked = True

    def on_secondary() -> None:
        nonlocal secondary_clicked
        secondary_clicked = True

    empty.set_primary_action("Create Project", callback=on_primary)
    empty.set_secondary_action("Browse Templates", callback=on_secondary)

    empty._primary_btn.click()
    empty._secondary_btn.click()

    assert primary_clicked is True
    assert secondary_clicked is True


# ============================================================================
# SearchFilterBar Tests
# ============================================================================


def test_search_filter_bar_query(qapp: QApplication) -> None:
    """Verify SearchFilterBar input, return pressed, and clearing."""
    bar = SearchFilterBar(placeholder="Search...")

    received_queries: list[str] = []
    bar.search_changed.connect(lambda q: received_queries.append(q))

    bar.set_search_text("users/api")
    assert bar.get_search_text() == "users/api"

    # Simulate pressing enter
    bar._on_return_pressed()
    assert "users/api" in received_queries

    # Clear search
    bar.clear_search()
    assert bar.get_search_text() == ""
    assert "" in received_queries


def test_search_filter_bar_filters(qapp: QApplication) -> None:
    """Verify SearchFilterBar dropdown filters and state emission."""
    bar = SearchFilterBar()

    bar.add_filter("severity", ["All", "CRITICAL", "HIGH", "MEDIUM"], default="All")
    bar.add_filter("status", ["All", "OPEN", "FIXED"], default="All")

    filter_events: list[tuple[str, str]] = []
    bar.filter_changed.connect(lambda k, v: filter_events.append((k, v)))

    bar.set_filter_value("severity", "CRITICAL")
    assert bar.get_filter_value("severity") == "CRITICAL"
    assert ("severity", "CRITICAL") in filter_events

    state = bar.get_state()
    assert state["filters"]["severity"] == "CRITICAL"
    assert state["filters"]["status"] == "All"


def test_search_filter_bar_action_buttons_and_reset(qapp: QApplication) -> None:
    """Verify action buttons and reset_all on SearchFilterBar."""
    bar = SearchFilterBar()
    action_clicked = False

    def on_action() -> None:
        nonlocal action_clicked
        action_clicked = True

    bar.add_action_button("Add Rule", callback=on_action, variant="primary")
    bar.add_filter("type", ["All", "Role", "Group"], default="All")
    bar.set_search_text("test query")
    bar.set_filter_value("type", "Role")

    # Click action button
    btn = bar._actions_layout.itemAt(0).widget()
    btn.click()
    assert action_clicked is True

    # Reset all
    reset_called = False
    bar.reset_clicked.connect(lambda: nonlocal_set())

    def nonlocal_set() -> None:
        nonlocal reset_called
        reset_called = True

    bar.reset_all()
    assert reset_called is True
    assert bar.get_search_text() == ""
    assert bar.get_filter_value("type") == "All"
