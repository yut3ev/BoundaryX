"""Overview Dashboard page for BoundaryX.

Displays high-level authorization metrics, scope enforcement indicators, policy
matrix coverage progress, and tamper-evident audit trail activity.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from boundaryx.infrastructure.database.models import (
    AuditEventModel,
    FindingModel,
    IdentityModel,
    PolicyModel,
    ProjectModel,
    ResourceModel,
    ScopeRuleModel,
    TenantModel,
    TestExecutionModel,
)
from boundaryx.ui.components.empty_state import EmptyStateWidget
from boundaryx.ui.components.stat_card import StatCard
from boundaryx.ui.components.status_badge import StatusBadge
from boundaryx.ui.resources.styles import apply_button_class, apply_label_class
from boundaryx.ui.resources.themes import get_current_palette

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class OverviewPage(QWidget):
    """Main overview dashboard page displaying authorization posture and activity."""

    open_projects_requested = Signal()
    navigation_requested = Signal(str)  # Target page name e.g. "identities", "policies"

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the OverviewPage."""
        super().__init__(parent)

        self._active_project_id: str | None = None
        self._active_project_name: str | None = None

        self._init_ui()
        self._show_empty_state(True)

    def _init_ui(self) -> None:
        """Build overview dashboard layout."""
        palette = get_current_palette()
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # Top Header Bar
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        self._title_label = QLabel("Authorization Security Dashboard")
        apply_label_class(self._title_label, "title")
        self._title_label.setStyleSheet("font-size: 20px; font-weight: 700;")

        self._project_subtitle = QLabel("No active project loaded")
        apply_label_class(self._project_subtitle, "subtitle")

        title_col.addWidget(self._title_label)
        title_col.addWidget(self._project_subtitle)
        header_layout.addLayout(title_col, 1)

        # Refresh button
        self._refresh_btn = QPushButton("Refresh")
        apply_button_class(self._refresh_btn, "secondary")
        self._refresh_btn.clicked.connect(self.refresh_data)
        header_layout.addWidget(self._refresh_btn)

        main_layout.addLayout(header_layout)

        # Empty State Placeholder
        self._empty_state = EmptyStateWidget(
            title="No Active Project Selected",
            description="Select or create a security testing project to visualize authorization boundaries, policy coverage, and findings.",
            icon="🛡️",
            primary_button_text="Open Projects",
            secondary_button_text="",
        )
        self._empty_state.primary_action_clicked.connect(self.open_projects_requested.emit)
        main_layout.addWidget(self._empty_state)

        # Dashboard Content Scroll Area
        self._content_widget = QWidget()
        content_layout = QVBoxLayout(self._content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(18)

        # 1. KPI Metric Stat Cards (Grid Layout: 6 cards)
        self._cards_grid = QGridLayout()
        self._cards_grid.setSpacing(12)

        self._card_identities = StatCard(
            title="Subject Identities",
            value="0",
            icon="👤",
            badge="Identities",
            subtitle="Testing personas & service accounts",
            variant="accent",
        )
        self._card_identities.clicked.connect(lambda: self.navigation_requested.emit("identities"))

        self._card_tenants = StatCard(
            title="Tenants / Orgs",
            value="0",
            icon="🏢",
            badge="Isolation",
            subtitle="Multi-tenant boundaries",
            variant="accent",
        )
        self._card_tenants.clicked.connect(lambda: self.navigation_requested.emit("identities"))

        self._card_resources = StatCard(
            title="Target Resources",
            value="0",
            icon="📦",
            badge="Assets",
            subtitle="Endpoints & data entities",
            variant="accent",
        )
        self._card_resources.clicked.connect(lambda: self.navigation_requested.emit("resources"))

        self._card_policies = StatCard(
            title="Defined Policies",
            value="0",
            icon="📜",
            badge="Rules",
            subtitle="Expected access invariants",
            variant="accent",
        )
        self._card_policies.clicked.connect(lambda: self.navigation_requested.emit("policies"))

        self._card_tests = StatCard(
            title="Executed Tests",
            value="0",
            icon="🧪",
            badge="Execution",
            subtitle="Fired authorization test cases",
            variant="neutral",
        )
        self._card_tests.clicked.connect(lambda: self.navigation_requested.emit("policies"))

        self._card_findings = StatCard(
            title="Confirmed Findings",
            value="0",
            icon="🚨",
            badge="Vulnerabilities",
            subtitle="Verified authorization defects",
            variant="danger",
        )
        self._card_findings.clicked.connect(lambda: self.navigation_requested.emit("overview"))

        self._cards_grid.addWidget(self._card_identities, 0, 0)
        self._cards_grid.addWidget(self._card_tenants, 0, 1)
        self._cards_grid.addWidget(self._card_resources, 0, 2)
        self._cards_grid.addWidget(self._card_policies, 1, 0)
        self._cards_grid.addWidget(self._card_tests, 1, 1)
        self._cards_grid.addWidget(self._card_findings, 1, 2)

        content_layout.addLayout(self._cards_grid)

        # 2. Middle Row: Scope Status Card & Policy Coverage Progress Card
        mid_row = QHBoxLayout()
        mid_row.setSpacing(14)

        # Scope Status Indicator Widget
        self._scope_card = self._build_scope_card(palette)
        mid_row.addWidget(self._scope_card, 1)

        # Policy Coverage Progress Card
        self._coverage_card = self._build_coverage_card(palette)
        mid_row.addWidget(self._coverage_card, 1)

        content_layout.addLayout(mid_row)

        # 3. Bottom Row: Recent Activity / Audit Log Table
        self._activity_frame = self._build_activity_frame(palette)
        content_layout.addWidget(self._activity_frame, 1)

        # Wrap in scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self._content_widget)
        main_layout.addWidget(scroll, 1)

        self._scroll_area = scroll

    def _build_scope_card(self, palette: Any) -> QFrame:
        """Create the target scope status indicator widget."""
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {palette.surface};
                border: 1px solid {palette.border};
                border-radius: 8px;
                padding: 14px;
            }}
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # Top line: Title & Badge
        top_line = QHBoxLayout()
        title = QLabel("Target Scope Enforcement")
        title.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {palette.text_primary};")
        self._scope_status_badge = StatusBadge("STRICT ENFORCEMENT", variant="ALLOW")

        top_line.addWidget(title)
        top_line.addStretch()
        top_line.addWidget(self._scope_status_badge)
        layout.addLayout(top_line)

        # Details
        self._scope_detail_label = QLabel(
            "Boundary validation strictly prevents requests to unlisted domains, third parties, and cloud metadata endpoints."
        )
        self._scope_detail_label.setWordWrap(True)
        self._scope_detail_label.setStyleSheet(f"font-size: 12px; color: {palette.text_secondary};")
        layout.addWidget(self._scope_detail_label)

        # Scope stats summary
        stats_line = QHBoxLayout()
        self._scope_rules_count_lbl = QLabel("Active Rules: 0")
        self._scope_rules_count_lbl.setStyleSheet(f"font-size: 12px; font-weight: 600; color: {palette.accent};")
        self._scope_hosts_lbl = QLabel("Allowed Hosts: (None)")
        self._scope_hosts_lbl.setStyleSheet(f"font-size: 12px; color: {palette.text_muted};")

        stats_line.addWidget(self._scope_rules_count_lbl)
        stats_line.addSpacing(16)
        stats_line.addWidget(self._scope_hosts_lbl, 1)

        layout.addLayout(stats_line)

        # Scope Action Button
        scope_btn = QPushButton("Manage Scope Boundaries →")
        apply_button_class(scope_btn, "ghost")
        scope_btn.setStyleSheet("text-align: left; padding: 2px 0;")
        scope_btn.clicked.connect(lambda: self.navigation_requested.emit("scope"))
        layout.addWidget(scope_btn)

        return frame

    def _build_coverage_card(self, palette: Any) -> QFrame:
        """Create the authorization policy matrix coverage widget."""
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {palette.surface};
                border: 1px solid {palette.border};
                border-radius: 8px;
                padding: 14px;
            }}
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # Top line: Title & Percentage
        top_line = QHBoxLayout()
        title = QLabel("Policy Matrix Coverage")
        title.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {palette.text_primary};")
        self._coverage_pct_label = QLabel("0%")
        self._coverage_pct_label.setStyleSheet(f"font-size: 16px; font-weight: 800; color: {palette.accent};")

        top_line.addWidget(title)
        top_line.addStretch()
        top_line.addWidget(self._coverage_pct_label)
        layout.addLayout(top_line)

        # Progress bar
        self._coverage_bar = QProgressBar()
        self._coverage_bar.setRange(0, 100)
        self._coverage_bar.setValue(0)
        self._coverage_bar.setTextVisible(False)
        self._coverage_bar.setFixedHeight(8)
        self._coverage_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {palette.card};
                border: 1px solid {palette.border};
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background-color: {palette.accent};
                border-radius: 3px;
            }}
        """)
        layout.addWidget(self._coverage_bar)

        # Breakdown summary
        self._coverage_detail_label = QLabel(
            "Coverage reflects the proportion of (Identity x Resource x Action) tuples covered by explicit authorization rules."
        )
        self._coverage_detail_label.setWordWrap(True)
        self._coverage_detail_label.setStyleSheet(f"font-size: 12px; color: {palette.text_secondary};")
        layout.addWidget(self._coverage_detail_label)

        # Policy Action Button
        policy_btn = QPushButton("Explore Policy Matrix →")
        apply_button_class(policy_btn, "ghost")
        policy_btn.setStyleSheet("text-align: left; padding: 2px 0;")
        policy_btn.clicked.connect(lambda: self.navigation_requested.emit("policies"))
        layout.addWidget(policy_btn)

        return frame

    def _build_activity_frame(self, palette: Any) -> QFrame:
        """Create the recent activity and security audit trail panel."""
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {palette.surface};
                border: 1px solid {palette.border};
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Title
        top_line = QHBoxLayout()
        title = QLabel("Recent Security Audit & Operational Activity")
        title.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {palette.text_primary};")
        top_line.addWidget(title)
        top_line.addStretch()

        self._audit_count_lbl = QLabel("0 events")
        self._audit_count_lbl.setStyleSheet(f"font-size: 12px; color: {palette.text_muted};")
        top_line.addWidget(self._audit_count_lbl)
        layout.addLayout(top_line)

        # Audit Table
        self._audit_table = QTableWidget()
        self._audit_table.setColumnCount(4)
        self._audit_table.setHorizontalHeaderLabels(["Timestamp (UTC)", "Event Type", "Actor", "Details"])
        self._audit_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._audit_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._audit_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._audit_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._audit_table.setAlternatingRowColors(True)
        self._audit_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._audit_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._audit_table.setMinimumHeight(180)

        layout.addWidget(self._audit_table, 1)
        return frame

    def _show_empty_state(self, show: bool) -> None:
        """Toggle between empty state placeholder and populated dashboard."""
        self._empty_state.setVisible(show)
        self._scroll_area.setVisible(not show)

    def load_project_data(
        self,
        project_id: str | None,
        session: Session | None = None,
        project_name: str | None = None,
    ) -> None:
        """Load and display metrics, scope, and audit trail for a project.

        Args:
            project_id: Target project UUID string.
            session: Optional active database session to query live data.
            project_name: Optional human-readable project title.
        """
        self._active_project_id = project_id

        if not project_id:
            self._active_project_name = None
            self._project_subtitle.setText("No active project loaded")
            self._show_empty_state(True)
            return

        self._active_project_name = project_name or f"Project {project_id[:8]}"
        self._project_subtitle.setText(f"Active Project: {self._active_project_name}")
        self._show_empty_state(False)

        if session is None:
            # Keep defaults or pre-existing values
            return

        try:
            self._query_and_render_project_stats(session, project_id)
        except Exception as exc:
            logger.error("Failed to query project metrics for %s: %s", project_id, exc)

    def _query_and_render_project_stats(self, session: Session, project_id: str) -> None:
        """Execute database queries to retrieve metrics and populate widgets."""
        proj = session.get(ProjectModel, str(project_id))
        if proj:
            self._active_project_name = proj.name
            self._project_subtitle.setText(f"Active Project: {proj.name}")

        # Counts
        identities_count = len(session.query(IdentityModel).filter_by(project_id=str(project_id)).all())
        tenants_count = len(session.query(TenantModel).filter_by(project_id=str(project_id)).all())
        resources_count = len(session.query(ResourceModel).filter_by(project_id=str(project_id)).all())
        policies_list = session.query(PolicyModel).filter_by(project_id=str(project_id)).all()
        policies_count = len(policies_list)
        tests_count = len(session.query(TestExecutionModel).filter_by(project_id=str(project_id)).all())
        findings_count = len(
            session.query(FindingModel).filter_by(project_id=str(project_id), status="confirmed").all()
        )

        self._card_identities.set_value(identities_count)
        self._card_tenants.set_value(tenants_count)
        self._card_resources.set_value(resources_count)
        self._card_policies.set_value(policies_count)
        self._card_tests.set_value(tests_count)
        self._card_findings.set_value(findings_count)

        # Scope status
        scope_rules = session.query(ScopeRuleModel).filter_by(project_id=str(project_id)).all()
        active_rules_count = len(scope_rules)
        hosts = [r.hostname for r in scope_rules if not r.is_excluded]
        hosts_str = ", ".join(hosts[:3]) + (f" (+{len(hosts) - 3} more)" if len(hosts) > 3 else "")

        self._scope_rules_count_lbl.setText(f"Active Rules: {active_rules_count}")
        self._scope_hosts_lbl.setText(f"Allowed Hosts: {hosts_str if hosts else '(None)'}")

        if active_rules_count > 0:
            self._scope_status_badge.setText("ACTIVE RULES ENFORCED")
            self._scope_status_badge._variant = "ALLOW"
            self._scope_status_badge._apply_style()
        else:
            self._scope_status_badge.setText("NO RULES DEFINED")
            self._scope_status_badge._variant = "WARNING"
            self._scope_status_badge._apply_style()

        # Coverage Calculation
        max(identities_count * resources_count, 1)
        # Approximate coverage by proportion of distinct resources touched by policies
        covered_resources = set()
        for p in policies_list:
            if isinstance(p.resource_selector, dict):
                r_id = p.resource_selector.get("resource_id")
                if r_id:
                    covered_resources.add(r_id)

        coverage_pct = (
            min(int((len(covered_resources) / max(resources_count, 1)) * 100), 100)
            if resources_count > 0
            else (100 if policies_count > 0 else 0)
        )
        self._coverage_bar.setValue(coverage_pct)
        self._coverage_pct_label.setText(f"{coverage_pct}%")
        self._coverage_detail_label.setText(
            f"{policies_count} active authorization policies covering target resources and roles."
        )

        # Audit events
        audit_events = (
            session.query(AuditEventModel)
            .filter_by(project_id=str(project_id))
            .order_by(AuditEventModel.timestamp.desc())
            .limit(20)
            .all()
        )
        self._audit_count_lbl.setText(f"{len(audit_events)} events")
        self._audit_table.setRowCount(len(audit_events))

        for row, evt in enumerate(audit_events):
            t_str = evt.timestamp.strftime("%Y-%m-%d %H:%M:%S") if evt.timestamp else ""
            t_item = QTableWidgetItem(t_str)
            t_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table_item_styled(t_item)
            self._audit_table.setItem(row, 0, t_item)

            type_item = QTableWidgetItem(evt.event_type)
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table_item_styled(type_item)
            self._audit_table.setItem(row, 1, type_item)

            actor_item = QTableWidgetItem(evt.actor_identity_id or "System")
            self._table_item_styled(actor_item)
            self._audit_table.setItem(row, 2, actor_item)

            detail_str = str(evt.details) if evt.details else ""
            detail_item = QTableWidgetItem(detail_str)
            self._table_item_styled(detail_item)
            self._audit_table.setItem(row, 3, detail_item)

    def _table_item_styled(self, item: QTableWidgetItem) -> None:
        """Apply non-editable flag to item."""
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)

    def set_metrics(
        self,
        identities: int = 0,
        tenants: int = 0,
        resources: int = 0,
        policies: int = 0,
        tests: int = 0,
        findings: int = 0,
        scope_rules_count: int = 0,
        coverage_pct: int = 0,
    ) -> None:
        """Directly update dashboard metrics (for mock, offline, or test setups)."""
        self._card_identities.set_value(identities)
        self._card_tenants.set_value(tenants)
        self._card_resources.set_value(resources)
        self._card_policies.set_value(policies)
        self._card_tests.set_value(tests)
        self._card_findings.set_value(findings)

        self._scope_rules_count_lbl.setText(f"Active Rules: {scope_rules_count}")
        self._coverage_bar.setValue(coverage_pct)
        self._coverage_pct_label.setText(f"{coverage_pct}%")
        self._show_empty_state(False)

    def refresh_data(self) -> None:
        """Refresh current project data if project is active."""
        if self._active_project_id:
            logger.info("Refreshing overview page for project %s", self._active_project_id)
