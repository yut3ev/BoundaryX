"""Main Application Window for BoundaryX.

Provides top header with project status, scope indicators, theme toggle,
left sidebar navigation for all 13 core security assessment modules,
central QStackedWidget containing all pages, bottom status bar, and keyboard shortcuts.
"""

from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import QTimer
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from boundaryx.config.settings import AppSettings, get_settings, set_settings
from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.infrastructure.database.repositories import ProjectRepository
from boundaryx.ui.components.badges import create_badge
from boundaryx.ui.dialogs.project_dialog import ProjectDialog
from boundaryx.ui.pages import (
    AuditLogPage,
    EvidenceVaultPage,
    FindingsPage,
    GraphPage,
    IdentitiesPage,
    OverviewPage,
    PoliciesPage,
    ProjectsPage,
    ReportsPage,
    ResourcesPage,
    ScopePage,
    SettingsPage,
    TestLabPage,
    TrafficPage,
)
from boundaryx.ui.resources.styles import generate_stylesheet
from boundaryx.ui.resources.themes import ThemeMode, get_current_theme, set_current_theme
from boundaryx.workers.async_worker import cancel_all_workers, get_active_worker_count

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Primary application window for BoundaryX desktop security testing platform."""

    SECTIONS = [
        ("overview", "Overview", "📊"),
        ("projects", "Projects", "📁"),
        ("scope", "Scope Guard", "🎯"),
        ("identities", "Identities", "👤"),
        ("resources", "Resources", "📦"),
        ("traffic", "HTTP Traffic", "🌐"),
        ("policies", "Policies", "📜"),
        ("graph", "Auth Graph", "🕸️"),
        ("test_lab", "Test Lab", "🧪"),
        ("findings", "Findings", "🚨"),
        ("evidence", "Evidence Vault", "🔐"),
        ("reports", "Reports", "📑"),
        ("audit_log", "Audit Log", "📋"),
    ]

    def __init__(
        self,
        db_manager: DatabaseManager,
        settings: AppSettings | None = None,
        initial_project_id: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.db_manager = db_manager
        self.settings = settings or get_settings()
        self.active_project_id: str | None = initial_project_id
        self.active_project_name: str = "No Project Selected"

        self._nav_buttons: dict[str, QPushButton] = {}
        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)

        self._init_window()
        self._init_ui()
        self._init_shortcuts()
        self._init_status_timer()

        # Load initial project if available, or fetch first project from DB
        self._load_initial_project()

    def _init_window(self) -> None:
        """Set window geometry, title, and flags."""
        self.setWindowTitle("BoundaryX - Desktop Application Security Testing")
        self.setMinimumSize(1200, 780)
        self.resize(1380, 880)

    def _init_ui(self) -> None:
        """Construct top bar, left sidebar, central stacked widget, and status bar."""
        central_widget = QWidget(self)
        central_widget.setObjectName("centralWidget")
        self.setCentralWidget(central_widget)

        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Top Bar
        top_bar = self._create_top_bar()
        root_layout.addWidget(top_bar)

        # 2. Body Splitter (Sidebar + Pages)
        body_widget = QWidget()
        body_layout = QHBoxLayout(body_widget)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        sidebar = self._create_sidebar()
        body_layout.addWidget(sidebar)

        # Central Stacked Widget
        self.stacked_widget = QStackedWidget()
        self._stack = self.stacked_widget
        self._create_pages()
        body_layout.addWidget(self.stacked_widget, stretch=1)

        root_layout.addWidget(body_widget, stretch=1)

        # 3. Bottom Status Bar
        self._create_status_bar()

    def _create_top_bar(self) -> QWidget:
        """Build top navigation header bar."""
        top_frame = QFrame()
        top_frame.setObjectName("topBar")
        top_frame.setStyleSheet(
            """
            QFrame#topBar {
                background-color: #1a1f2c;
                border-bottom: 1px solid #2d354d;
                min-height: 52px;
                max-height: 52px;
            }
            """
        )

        top_layout = QHBoxLayout(top_frame)
        top_layout.setContentsMargins(16, 6, 16, 6)
        top_layout.setSpacing(14)

        # Brand Logo + Title
        brand_icon = QLabel("🛡️")
        brand_icon.setStyleSheet("font-size: 20px;")
        top_layout.addWidget(brand_icon)

        brand_title = QLabel("BoundaryX")
        brand_title.setStyleSheet("font-size: 16px; font-weight: 800; color: #00b4d8; letter-spacing: 0.5px;")
        top_layout.addWidget(brand_title)

        tagline = QLabel("Desktop AppSec & Boundary Analysis")
        tagline.setStyleSheet("font-size: 11px; color: #64748b; font-weight: 500;")
        top_layout.addWidget(tagline)

        # Vertical separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setStyleSheet("color: #2d354d;")
        top_layout.addWidget(sep)

        # Project Switcher Button
        self.project_btn = QPushButton("Project: None")
        self.project_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #22283a;
                color: #f8fafc;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 4px 12px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2a3248;
                border-color: #00b4d8;
            }
            """
        )
        self.project_btn.setToolTip("Click to switch or manage security assessment projects")
        self.project_btn.clicked.connect(lambda: self.navigate_to("projects"))
        top_layout.addWidget(self.project_btn)

        # Scope Status Badge
        self.scope_badge = create_badge("SCOPE: ENFORCED", "#064e3b", "#34d399", "#059669")
        self.scope_badge.setToolTip("ScopeGuard actively restricts outbound requests to project boundaries")
        top_layout.addWidget(self.scope_badge)

        top_layout.addStretch()

        # Active Worker Status
        self.worker_status_label = QLabel("Workers: Idle")
        self.worker_status_label.setStyleSheet("font-size: 12px; color: #94a3b8; font-family: Segoe UI, sans-serif;")
        top_layout.addWidget(self.worker_status_label)

        # Theme Toggle
        current_mode = get_current_theme()
        theme_icon = "☀️" if current_mode == ThemeMode.DARK else "🌙"
        self.theme_btn = QPushButton(theme_icon)
        self.theme_btn.setToolTip("Toggle Theme (Dark / Light)")
        self.theme_btn.setFixedSize(34, 34)
        self.theme_btn.setStyleSheet("font-size: 14px; border-radius: 17px;")
        self.theme_btn.clicked.connect(self._toggle_theme)
        top_layout.addWidget(self.theme_btn)

        # Settings Button
        self.settings_btn = QPushButton("⚙️ Settings")
        self.settings_btn.setStyleSheet("font-size: 12px;")
        self.settings_btn.clicked.connect(lambda: self.navigate_to("settings"))
        top_layout.addWidget(self.settings_btn)

        # Help / About Button
        self.help_btn = QPushButton("❓ About")
        self.help_btn.setStyleSheet("font-size: 12px;")
        self.help_btn.clicked.connect(self._show_about_dialog)
        top_layout.addWidget(self.help_btn)

        return top_frame

    def _create_sidebar(self) -> QWidget:
        """Build left vertical navigation sidebar."""
        sidebar_frame = QFrame()
        sidebar_frame.setObjectName("sidebarFrame")
        sidebar_frame.setStyleSheet(
            """
            QFrame#sidebarFrame {
                background-color: #1a1f2c;
                border-right: 1px solid #2d354d;
                min-width: 200px;
                max-width: 200px;
            }
            """
        )

        sb_layout = QVBoxLayout(sidebar_frame)
        sb_layout.setContentsMargins(8, 12, 8, 12)
        sb_layout.setSpacing(4)

        nav_title = QLabel("NAVIGATION")
        nav_title.setStyleSheet(
            "font-size: 10px; font-weight: 700; color: #64748b; padding-left: 8px; margin-bottom: 4px;"
        )
        sb_layout.addWidget(nav_title)

        for tag, label, icon in self.SECTIONS:
            btn = QPushButton(f" {icon}  {label}")
            btn.setCheckable(True)
            btn.setStyleSheet(
                """
                QPushButton {
                    background-color: transparent;
                    color: #cbd5e1;
                    border: none;
                    border-radius: 6px;
                    text-align: left;
                    padding: 8px 12px;
                    font-size: 13px;
                    font-weight: 500;
                }
                QPushButton:hover {
                    background-color: #22283a;
                    color: #f8fafc;
                }
                QPushButton:checked {
                    background-color: #00b4d8;
                    color: #ffffff;
                    font-weight: 700;
                }
                """
            )
            btn.clicked.connect(lambda checked=False, t=tag: self.navigate_to(t))
            self._nav_group.addButton(btn)
            self._nav_buttons[tag] = btn
            sb_layout.addWidget(btn)

        sb_layout.addStretch()

        # Version tag in sidebar bottom
        version_label = QLabel("BoundaryX v0.1.0")
        version_label.setStyleSheet("font-size: 11px; color: #64748b; text-align: center; padding-left: 8px;")
        sb_layout.addWidget(version_label)

        return sidebar_frame

    def _create_pages(self) -> None:
        """Instantiate and register all pages into the QStackedWidget."""
        # Section 0: Overview
        self.page_overview = OverviewPage()
        self.page_overview.open_projects_requested.connect(lambda: self.navigate_to("projects"))
        self.page_overview.navigation_requested.connect(self.navigate_to)
        self.stacked_widget.addWidget(self.page_overview)

        # Section 1: Projects
        self.page_projects = ProjectsPage(db_manager=self.db_manager)
        self.page_projects.project_selected.connect(lambda uid: self.set_active_project(str(uid)))
        self.page_projects.project_selected_str.connect(self.set_active_project)
        self.stacked_widget.addWidget(self.page_projects)

        # Section 2: Scope
        self.page_scope = ScopePage(db_manager=self.db_manager)
        self.stacked_widget.addWidget(self.page_scope)

        # Section 3: Identities
        self.page_identities = IdentitiesPage(db_manager=self.db_manager)
        self.stacked_widget.addWidget(self.page_identities)

        # Section 4: Resources
        self.page_resources = ResourcesPage(db_manager=self.db_manager)
        self.stacked_widget.addWidget(self.page_resources)

        # Section 5: Traffic
        self.page_traffic = TrafficPage(db_manager=self.db_manager, project_id=self.active_project_id)
        self.page_traffic.status_message.connect(self.show_status_message)
        self.stacked_widget.addWidget(self.page_traffic)

        # Section 6: Policies
        self.page_policies = PoliciesPage(db_manager=self.db_manager)
        self.stacked_widget.addWidget(self.page_policies)

        # Section 7: Graph
        self.page_graph = GraphPage(db_manager=self.db_manager, project_id=self.active_project_id)
        self.stacked_widget.addWidget(self.page_graph)

        # Section 8: Test Lab
        self.page_test_lab = TestLabPage(db_manager=self.db_manager, project_id=self.active_project_id)
        self.page_test_lab.status_message.connect(self.show_status_message)
        self.stacked_widget.addWidget(self.page_test_lab)

        # Section 9: Findings
        self.page_findings = FindingsPage(db_manager=self.db_manager, project_id=self.active_project_id)
        self.page_findings.status_message.connect(self.show_status_message)
        self.stacked_widget.addWidget(self.page_findings)

        # Section 10: Evidence Vault
        self.page_evidence = EvidenceVaultPage(db_manager=self.db_manager, project_id=self.active_project_id)
        self.page_evidence.status_message.connect(self.show_status_message)
        self.stacked_widget.addWidget(self.page_evidence)

        # Section 11: Reports
        self.page_reports = ReportsPage(db_manager=self.db_manager, project_id=self.active_project_id)
        self.page_reports.status_message.connect(self.show_status_message)
        self.stacked_widget.addWidget(self.page_reports)

        # Section 12: Audit Log
        self.page_audit_log = AuditLogPage(db_manager=self.db_manager, project_id=self.active_project_id)
        self.page_audit_log.status_message.connect(self.show_status_message)
        self.stacked_widget.addWidget(self.page_audit_log)

        # Section 13: Settings (accessible via Top Bar settings button)
        self.page_settings = SettingsPage(db_manager=self.db_manager, settings=self.settings)
        self.page_settings.status_message.connect(self.show_status_message)
        self.page_settings.settings_updated.connect(self._on_settings_updated)
        self.stacked_widget.addWidget(self.page_settings)

        # Set default active view
        self.navigate_to("overview")

    def _create_status_bar(self) -> None:
        """Build status bar with connection, workers, scope, and version status."""
        status = QStatusBar(self)
        status.setStyleSheet(
            """
            QStatusBar {
                background-color: #12151c;
                border-top: 1px solid #2d354d;
                color: #94a3b8;
                font-size: 11px;
            }
            """
        )
        self.setStatusBar(status)

        # Status message
        self.status_msg_label = QLabel("Ready")
        status.addWidget(self.status_msg_label, stretch=1)

        # Database connection indicator
        db_mode_str = "Memory" if self.db_manager.is_memory else self.settings.resolved_db_path.name
        self.db_status_label = QLabel(f"🗄️ DB: {db_mode_str} [WAL]")
        self.db_status_label.setStyleSheet("color: #38bdf8; margin-right: 16px;")
        status.addPermanentWidget(self.db_status_label)

        # Active Workers
        self.workers_status_perm = QLabel("⚙️ Workers: 0")
        self.workers_status_perm.setStyleSheet("color: #94a3b8; margin-right: 16px;")
        status.addPermanentWidget(self.workers_status_perm)

        # Scope Guard
        self.scope_status_perm = QLabel("🛡️ Scope Guard: Active")
        self.scope_status_perm.setStyleSheet("color: #34d399; margin-right: 16px;")
        status.addPermanentWidget(self.scope_status_perm)

        # Version
        version_perm = QLabel("BoundaryX v0.1.0")
        version_perm.setStyleSheet("color: #64748b; margin-right: 8px;")
        status.addPermanentWidget(version_perm)

    def _init_shortcuts(self) -> None:
        """Register global keyboard shortcuts."""
        # Ctrl+O: Open Projects
        open_act = QAction(self)
        open_act.setShortcut(QKeySequence("Ctrl+O"))
        open_act.triggered.connect(lambda: self.navigate_to("projects"))
        self.addAction(open_act)

        # Ctrl+N: New Project
        new_act = QAction(self)
        new_act.setShortcut(QKeySequence("Ctrl+N"))
        new_act.triggered.connect(self._create_new_project_dialog)
        self.addAction(new_act)

        # Ctrl+S: Save / Sync
        save_act = QAction(self)
        save_act.setShortcut(QKeySequence("Ctrl+S"))
        save_act.triggered.connect(self._sync_and_save)
        self.addAction(save_act)

        # Ctrl+Q: Quit
        quit_act = QAction(self)
        quit_act.setShortcut(QKeySequence("Ctrl+Q"))
        quit_act.triggered.connect(self.close)
        self.addAction(quit_act)

        # F5: Refresh
        refresh_act = QAction(self)
        refresh_act.setShortcut(QKeySequence("F5"))
        refresh_act.triggered.connect(self._refresh_current_page)
        self.addAction(refresh_act)

    def _init_status_timer(self) -> None:
        """Timer to update background worker counts and active tasks."""
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(1000)
        self._status_timer.timeout.connect(self._update_worker_counts)
        self._status_timer.start()

    def _update_worker_counts(self) -> None:
        """Update worker counter widgets."""
        count = get_active_worker_count()
        if count == 0:
            self.worker_status_label.setText("Workers: Idle")
            self.workers_status_perm.setText("⚙️ Workers: 0")
        else:
            self.worker_status_label.setText(f"Workers: {count} running")
            self.workers_status_perm.setText(f"⚙️ Workers: {count} active")

    def _load_initial_project(self) -> None:
        """Query DB for initial project or create default if database is empty."""
        try:
            with self.db_manager.get_session() as session:
                repo = ProjectRepository(session)
                projects = repo.list_all(session)
                if projects:
                    proj = projects[0]
                    self.set_active_project(proj.id, proj.name)
                else:
                    # Create default assessment project
                    default_proj = repo.create(
                        session=session,
                        name="Default Security Assessment",
                        description="Initial project workspace for BoundaryX testing.",
                    )
                    self.set_active_project(default_proj.id, default_proj.name)
        except Exception as exc:
            logger.error("Failed to load initial project: %s", exc)

    def set_active_project(self, project_id: str, project_name: str | None = None) -> None:
        """Switch current active project and notify all subpages."""
        self.active_project_id = project_id

        # Resolve name if not provided
        if not project_name:
            try:
                with self.db_manager.get_session() as session:
                    repo = ProjectRepository(session)
                    p = repo.get_by_id(session, project_id)
                    if p:
                        self.active_project_name = p.name
            except Exception:
                self.active_project_name = f"Project: {project_id[:8]}"
        else:
            self.active_project_name = project_name

        self.project_btn.setText(f"Project: {self.active_project_name}")
        self.show_status_message(f"Switched active project to '{self.active_project_name}'")

        # Propagate to all pages
        with self.db_manager.get_session() as session:
            self.page_overview.load_project_data(project_id, session=session, project_name=self.active_project_name)
            self.page_scope.set_project(project_id, session=session)

        self.page_identities.set_project(project_id)
        self.page_resources.set_project(project_id)
        self.page_traffic.set_project(project_id)
        self.page_policies.set_project(project_id)
        self.page_graph.set_project(project_id)
        self.page_test_lab.set_project(project_id)
        self.page_findings.set_project(project_id)
        self.page_evidence.set_project(project_id)
        self.page_reports.set_project(project_id)
        self.page_audit_log.set_project(project_id)

    def navigate_to(self, target: str) -> None:
        """Switch active page in QStackedWidget and update sidebar highlighting."""
        tag_index_map = {
            "overview": 0,
            "projects": 1,
            "scope": 2,
            "identities": 3,
            "resources": 4,
            "traffic": 5,
            "policies": 6,
            "graph": 7,
            "test_lab": 8,
            "findings": 9,
            "evidence": 10,
            "reports": 11,
            "audit_log": 12,
            "settings": 13,
        }

        idx = tag_index_map.get(target.lower(), 0)
        self.stacked_widget.setCurrentIndex(idx)

        # Highlight sidebar button
        btn = self._nav_buttons.get(target.lower())
        if btn:
            btn.setChecked(True)
        else:
            # If navigating to settings, uncheck sidebar items
            checked_btn = self._nav_group.checkedButton()
            if checked_btn:
                self._nav_group.setExclusive(False)
                checked_btn.setChecked(False)
                self._nav_group.setExclusive(True)

    def _toggle_theme(self) -> None:
        """Toggle dark/light theme."""
        current = get_current_theme()
        new_mode = ThemeMode.LIGHT if current == ThemeMode.DARK else ThemeMode.DARK
        set_current_theme(new_mode)
        self.settings.theme = new_mode.value
        set_settings(self.settings)

        app = QApplication.instance()
        if app:
            app.setStyleSheet(generate_stylesheet())

        self.theme_btn.setText("☀️" if new_mode == ThemeMode.DARK else "🌙")
        self.show_status_message(f"Theme switched to {new_mode.value.title()}")

    def _on_settings_updated(self) -> None:
        """Handle settings page update."""
        current = get_current_theme()
        self.theme_btn.setText("☀️" if current == ThemeMode.DARK else "🌙")

    def _create_new_project_dialog(self) -> None:
        """Open dialog to create a new project."""
        dialog = ProjectDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_project_data()
            try:
                with self.db_manager.get_session() as session:
                    repo = ProjectRepository(session)
                    new_proj = repo.create(
                        session=session,
                        name=data.get("name", "New Project"),
                        description=data.get("description"),
                    )
                    self.set_active_project(new_proj.id, new_proj.name)
                    self.page_projects.refresh_projects()
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Failed to create project: {exc}")

    def _sync_and_save(self) -> None:
        """Synchronize in-memory configurations and database state."""
        self.settings.save_to_file(self.settings.resolve_path("boundaryx_settings.json"))
        self.show_status_message("State synchronized and settings saved.")

    def _refresh_current_page(self) -> None:
        """Refresh current visible page."""
        idx = self.stacked_widget.currentIndex()
        page = self.stacked_widget.widget(idx)
        if hasattr(page, "refresh_data"):
            page.refresh_data()
        elif hasattr(page, "load_traffic"):
            page.load_traffic()
        elif hasattr(page, "build_graph"):
            page.build_graph()
        elif hasattr(page, "load_tests"):
            page.load_tests()
        elif hasattr(page, "load_findings"):
            page.load_findings()
        elif hasattr(page, "load_evidence"):
            page.load_evidence()
        elif hasattr(page, "load_audit_logs"):
            page.load_audit_logs()

        self.show_status_message("View refreshed.")

    def _show_about_dialog(self) -> None:
        """Show About BoundaryX modal dialog."""
        about_text = (
            "<h2>BoundaryX</h2>"
            "<p><b>Desktop Application Security Testing & Authorization Boundary Analysis</b></p>"
            "<p>Version: 0.1.0</p>"
            "<hr/>"
            "<p>BoundaryX detects access control vulnerabilities, IDOR defects, tenant boundary leaks, "
            "and privilege escalation paths across APIs and cloud applications.</p>"
            "<ul>"
            "<li>Clean Layered Architecture (Domain, Application, Infrastructure, Security, Presentation)</li>"
            "<li>Cryptographic SHA-256 Tamper-Proof Evidence Vault</li>"
            "<li>ScopeGuard Out-of-Scope Network Interception Prevention</li>"
            "<li>Interactive Directed Access Relationship Graph</li>"
            "<li>HAR 1.2 & Raw HTTP Traffic Analysis & Policy Synthesis</li>"
            "</ul>"
            "<p>© 2026 BoundaryX Security Engineering.</p>"
        )
        QMessageBox.about(self, "About BoundaryX", about_text)

    def show_status_message(self, message: str) -> None:
        """Display status message in status bar."""
        self.status_msg_label.setText(message)

    def closeEvent(self, event: Any) -> None:
        """Gracefully terminate running background workers before quitting."""
        count = get_active_worker_count()
        if count > 0:
            reply = QMessageBox.question(
                self,
                "Active Tasks Running",
                f"There are {count} background tasks currently running.\n"
                f"Are you sure you want to abort them and exit BoundaryX?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

        cancel_all_workers()
        self._status_timer.stop()
        event.accept()
