"""Interactive Authorization and Access Relationship Graph page for BoundaryX.

Provides node/edge visualization using QGraphicsView & QGraphicsScene,
visual anomaly highlights (cross-tenant paths, orphaned resources),
zoom/pan controls, node selection inspector, filtering, and PNG/SVG export.
"""

from __future__ import annotations

import logging
import math
from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QImage,
    QPainter,
    QPen,
    QPolygonF,
)
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsPolygonItem,
    QGraphicsScene,
    QGraphicsTextItem,
    QGraphicsView,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.ui.resources.styles import apply_button_class

logger = logging.getLogger(__name__)


class GraphNodeItem(QGraphicsItem):
    """Visual interactive node item in the authorization graph."""

    def __init__(
        self,
        node_id: str,
        node_type: str,
        name: str,
        data: dict[str, Any],
        is_anomaly: bool = False,
        anomaly_msg: str = "",
        parent: QGraphicsItem | None = None,
    ) -> None:
        super().__init__(parent)
        self.node_id = node_id
        self.node_type = node_type.upper()
        self.name = name
        self.data = data
        self.is_anomaly = is_anomaly
        self.anomaly_msg = anomaly_msg

        self.width = 130
        self.height = 48
        self.edges: list[GraphEdgeItem] = []

        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsMovable
            | QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
            | QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )
        self.setAcceptHoverEvents(True)

    def boundingRect(self) -> QRectF:
        adjust = 6.0
        return QRectF(
            -self.width / 2 - adjust, -self.height / 2 - adjust, self.width + adjust * 2, self.height + adjust * 2
        )

    def _get_colors(self) -> tuple[QColor, QColor, QColor]:
        """Return (fill_color, border_color, text_color)."""
        if self.node_type == "IDENTITY":
            return QColor("#0369a1"), QColor("#38bdf8"), QColor("#ffffff")
        elif self.node_type == "TENANT":
            return QColor("#581c87"), QColor("#c084fc"), QColor("#ffffff")
        elif self.node_type == "RESOURCE":
            return QColor("#065f46"), QColor("#34d399"), QColor("#ffffff")
        elif self.node_type == "POLICY":
            return QColor("#78350f"), QColor("#fbbf24"), QColor("#ffffff")
        elif self.node_type == "FINDING":
            return QColor("#7f1d1d"), QColor("#f87171"), QColor("#ffffff")
        return QColor("#1e293b"), QColor("#94a3b8"), QColor("#ffffff")

    def paint(self, painter: QPainter, option: Any, widget: QWidget | None = None) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        fill, border, text_color = self._get_colors()

        rect = QRectF(-self.width / 2, -self.height / 2, self.width, self.height)

        # Highlight anomaly or selection
        if self.isSelected():
            border_pen = QPen(QColor("#00b4d8"), 3, Qt.PenStyle.SolidLine)
        elif self.is_anomaly:
            border_pen = QPen(QColor("#ef4444"), 2.5, Qt.PenStyle.DashLine)
        else:
            border_pen = QPen(border, 1.5, Qt.PenStyle.SolidLine)

        painter.setPen(border_pen)
        painter.setBrush(QBrush(fill))

        if self.node_type == "IDENTITY":
            # Pill shape
            painter.drawRoundedRect(rect, 24, 24)
        elif self.node_type == "TENANT":
            # Rounded box
            painter.drawRoundedRect(rect, 10, 10)
        else:
            painter.drawRoundedRect(rect, 6, 6)

        # Draw type tag & name
        painter.setPen(QColor("#94a3b8"))
        font_sub = QFont("Segoe UI", 8)
        painter.setFont(font_sub)
        painter.drawText(
            QRectF(-self.width / 2 + 6, -self.height / 2 + 4, self.width - 12, 14),
            Qt.AlignmentFlag.AlignLeft,
            self.node_type,
        )

        painter.setPen(text_color)
        font_main = QFont("Segoe UI", 9, QFont.Weight.Bold)
        painter.setFont(font_main)
        display_text = self.name if len(self.name) <= 16 else self.name[:14] + ".."
        painter.drawText(
            QRectF(-self.width / 2 + 6, -self.height / 2 + 18, self.width - 12, 24),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            display_text,
        )

        # Anomaly badge indicator
        if self.is_anomaly:
            painter.setBrush(QBrush(QColor("#ef4444")))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(QPointF(self.width / 2 - 4, -self.height / 2 + 4), 6, 6)

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value: Any) -> Any:
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self.edges:
                edge.update_position()
        return super().itemChange(change, value)


class GraphEdgeItem(QGraphicsLineItem):
    """Visual directed edge between two graph nodes."""

    def __init__(
        self,
        source: GraphNodeItem,
        dest: GraphNodeItem,
        edge_type: str,
        confidence: str = "CONFIRMED",
        is_anomaly: bool = False,
        parent: QGraphicsItem | None = None,
    ) -> None:
        super().__init__(parent)
        self.source = source
        self.dest = dest
        self.edge_type = edge_type.upper()
        self.confidence = confidence.upper()
        self.is_anomaly = is_anomaly

        self.arrow_head = QGraphicsPolygonItem(self)
        self.label_item = QGraphicsTextItem(self.edge_type, self)
        font = QFont("Segoe UI", 7)
        self.label_item.setFont(font)

        self.source.edges.append(self)
        self.dest.edges.append(self)
        self.setZValue(-1)
        self.update_position()

    def update_position(self) -> None:
        p1 = self.source.scenePos()
        p2 = self.dest.scenePos()

        # Connect outer bounds
        line_theta = math.atan2(p2.y() - p1.y(), p2.x() - p1.x())
        dist = math.hypot(p2.x() - p1.x(), p2.y() - p1.y())
        if dist < 1:
            return

        offset_x = (self.dest.width / 2) * math.cos(line_theta)
        offset_y = (self.dest.height / 2) * math.sin(line_theta)
        arrow_tip = QPointF(p2.x() - offset_x, p2.y() - offset_y)

        self.setLine(p1.x(), p1.y(), arrow_tip.x(), arrow_tip.y())

        # Styling
        if self.is_anomaly or self.edge_type == "VIOLATES":
            color = QColor("#ef4444")
            pen = QPen(color, 2, Qt.PenStyle.DashLine)
        elif self.edge_type == "DENIED_ACCESS":
            color = QColor("#f59e0b")
            pen = QPen(color, 1.8, Qt.PenStyle.DashLine)
        elif self.edge_type == "HAS_ACCESS":
            color = QColor("#10b981")
            pen = QPen(color, 1.8, Qt.PenStyle.SolidLine)
        elif self.edge_type == "MEMBER_OF":
            color = QColor("#c084fc")
            pen = QPen(color, 1.5, Qt.PenStyle.DotLine)
        elif self.edge_type == "OWNS":
            color = QColor("#00b4d8")
            pen = QPen(color, 1.8, Qt.PenStyle.SolidLine)
        else:
            color = QColor("#64748b")
            pen = QPen(color, 1.2, Qt.PenStyle.SolidLine)

        self.setPen(pen)

        # Arrow head
        arrow_size = 10.0
        angle = line_theta + math.pi
        p_arrow1 = arrow_tip + QPointF(math.cos(angle - 0.4) * arrow_size, math.sin(angle - 0.4) * arrow_size)
        p_arrow2 = arrow_tip + QPointF(math.cos(angle + 0.4) * arrow_size, math.sin(angle + 0.4) * arrow_size)

        arrow_poly = QPolygonF([arrow_tip, p_arrow1, p_arrow2])
        self.arrow_head.setPolygon(arrow_poly)
        self.arrow_head.setBrush(QBrush(color))
        self.arrow_head.setPen(Qt.PenStyle.NoPen)

        # Label position
        mid_x = (p1.x() + arrow_tip.x()) / 2
        mid_y = (p1.y() + arrow_tip.y()) / 2
        self.label_item.setPos(mid_x - 15, mid_y - 12)
        self.label_item.setDefaultTextColor(color)


class InteractiveGraphView(QGraphicsView):
    """Interactive viewport supporting smooth mouse zoom and pan."""

    def __init__(self, scene: QGraphicsScene, parent: QWidget | None = None) -> None:
        super().__init__(scene, parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setBackgroundBrush(QBrush(QColor("#12151c")))

    def wheelEvent(self, event: Any) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)


class GraphPage(QWidget):
    """Relationship graph visualization and anomaly exploration page."""

    node_selected_signal = Signal(object)

    def __init__(
        self,
        db_manager: DatabaseManager,
        project_id: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.db_manager = db_manager
        self.project_id = project_id

        self.scene = QGraphicsScene(self)
        self.nodes: dict[str, GraphNodeItem] = {}
        self.edges: list[GraphEdgeItem] = []

        self._init_ui()

    def set_project(self, project_id: str | None) -> None:
        """Switch current project and refresh graph model."""
        self.project_id = project_id
        self.build_graph()

    def _init_ui(self) -> None:
        """Construct UI layout and graph panels."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        # Left / Center: Graph View & Toolbar
        graph_container = QWidget()
        graph_layout = QVBoxLayout(graph_container)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        graph_layout.setSpacing(8)

        # Top Controls Toolbar
        toolbar = QFrame()
        toolbar.setStyleSheet("background-color: #1a1f2c; border: 1px solid #2d354d; border-radius: 6px; padding: 4px;")
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(8, 4, 8, 4)
        tb_layout.setSpacing(8)

        self.zoom_in_btn = QPushButton("Zoom In (+)")
        self.zoom_in_btn.clicked.connect(self._zoom_in)
        tb_layout.addWidget(self.zoom_in_btn)

        self.zoom_out_btn = QPushButton("Zoom Out (-)")
        self.zoom_out_btn.clicked.connect(self._zoom_out)
        tb_layout.addWidget(self.zoom_out_btn)

        self.reset_btn = QPushButton("Reset View")
        self.reset_btn.clicked.connect(self._reset_view)
        tb_layout.addWidget(self.reset_btn)

        self.layout_btn = QPushButton("Auto Layout")
        self.layout_btn.clicked.connect(self._auto_layout)
        tb_layout.addWidget(self.layout_btn)

        tb_layout.addStretch()

        # Filters
        tb_layout.addWidget(QLabel("Confidence:"))
        self.confidence_combo = QComboBox()
        self.confidence_combo.addItems(["All", "CONFIRMED", "USER_DEFINED", "INFERRED", "SUSPECTED_VIOLATION"])
        self.confidence_combo.currentIndexChanged.connect(self._apply_filters)
        tb_layout.addWidget(self.confidence_combo)

        # Export button
        self.export_btn = QPushButton("Export Graph")
        apply_button_class(self.export_btn, "primary")
        self.export_btn.clicked.connect(self._export_graph)
        tb_layout.addWidget(self.export_btn)

        graph_layout.addWidget(toolbar)

        # Node Type Toggles Bar
        toggles_frame = QFrame()
        toggles_layout = QHBoxLayout(toggles_frame)
        toggles_layout.setContentsMargins(4, 2, 4, 2)
        toggles_layout.setSpacing(12)

        toggles_layout.addWidget(QLabel("Visible Entities:"))
        self.chk_identities = QCheckBox("Identities")
        self.chk_identities.setChecked(True)
        self.chk_identities.stateChanged.connect(self._apply_filters)
        toggles_layout.addWidget(self.chk_identities)

        self.chk_tenants = QCheckBox("Tenants")
        self.chk_tenants.setChecked(True)
        self.chk_tenants.stateChanged.connect(self._apply_filters)
        toggles_layout.addWidget(self.chk_tenants)

        self.chk_resources = QCheckBox("Resources")
        self.chk_resources.setChecked(True)
        self.chk_resources.stateChanged.connect(self._apply_filters)
        toggles_layout.addWidget(self.chk_resources)

        self.chk_policies = QCheckBox("Policies")
        self.chk_policies.setChecked(True)
        self.chk_policies.stateChanged.connect(self._apply_filters)
        toggles_layout.addWidget(self.chk_policies)

        self.chk_findings = QCheckBox("Findings")
        self.chk_findings.setChecked(True)
        self.chk_findings.stateChanged.connect(self._apply_filters)
        toggles_layout.addWidget(self.chk_findings)

        toggles_layout.addStretch()
        graph_layout.addWidget(toggles_frame)

        # Graphics View
        self.view = InteractiveGraphView(self.scene)
        self.scene.selectionChanged.connect(self._on_scene_selection_changed)
        graph_layout.addWidget(self.view, stretch=1)

        splitter.addWidget(graph_container)

        # Right: Selection Inspector Panel
        self.inspector_panel = QFrame()
        self.inspector_panel.setStyleSheet(
            "background-color: #1a1f2c; border: 1px solid #2d354d; border-radius: 6px; padding: 12px;"
        )
        ins_layout = QVBoxLayout(self.inspector_panel)
        ins_layout.setContentsMargins(12, 12, 12, 12)
        ins_layout.setSpacing(10)

        ins_title = QLabel("Entity Inspector")
        ins_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #f8fafc;")
        ins_layout.addWidget(ins_title)

        self.node_type_badge = QLabel("NO SELECTION")
        self.node_type_badge.setStyleSheet(
            "background-color: #334155; color: #cbd5e1; border-radius: 8px; padding: 3px 8px; font-weight: 600;"
        )
        ins_layout.addWidget(self.node_type_badge)

        self.node_name_label = QLabel("Click any node in the graph to inspect its properties and connected edges.")
        self.node_name_label.setWordWrap(True)
        self.node_name_label.setStyleSheet("color: #94a3b8;")
        ins_layout.addWidget(self.node_name_label)

        # Anomaly Box
        self.anomaly_box = QGroupBox("Detected Anomaly")
        self.anomaly_box.setStyleSheet(
            "QGroupBox { color: #f87171; border: 1px solid #7f1d1d; border-radius: 4px; padding-top: 10px; margin-top: 6px; }"
        )
        self.anomaly_box.setVisible(False)
        anom_layout = QVBoxLayout(self.anomaly_box)
        self.anomaly_desc = QLabel("")
        self.anomaly_desc.setWordWrap(True)
        self.anomaly_desc.setStyleSheet("color: #fca5a5; font-size: 12px;")
        anom_layout.addWidget(self.anomaly_desc)
        ins_layout.addWidget(self.anomaly_box)

        # Properties Table
        ins_layout.addWidget(QLabel("Properties:"))
        self.prop_table = QTableWidget(0, 2)
        self.prop_table.setHorizontalHeaderLabels(["Key", "Value"])
        self.prop_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.prop_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.prop_table.setAlternatingRowColors(True)
        ins_layout.addWidget(self.prop_table, stretch=1)

        # Connected Edges list
        ins_layout.addWidget(QLabel("Connected Edges:"))
        self.edges_text = QTextEdit()
        self.edges_text.setReadOnly(True)
        self.edges_text.setFixedHeight(120)
        self.edges_text.setFontFamily("Consolas, monospace")
        ins_layout.addWidget(self.edges_text)

        splitter.addWidget(self.inspector_panel)
        splitter.setSizes([750, 320])

    def build_graph(self) -> None:
        """Load data from database and construct node/edge items."""
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()

        if not self.project_id:
            return

        try:
            with self.db_manager.get_session() as session:
                # Load tenants
                from sqlalchemy import select

                from boundaryx.infrastructure.database.models import (
                    FindingModel,
                    IdentityModel,
                    PolicyModel,
                    ResourceModel,
                    TenantMembershipModel,
                    TenantModel,
                )

                tenants = session.scalars(select(TenantModel).where(TenantModel.project_id == self.project_id)).all()
                identities = session.scalars(
                    select(IdentityModel).where(IdentityModel.project_id == self.project_id)
                ).all()
                resources = session.scalars(
                    select(ResourceModel).where(ResourceModel.project_id == self.project_id)
                ).all()
                policies = session.scalars(select(PolicyModel).where(PolicyModel.project_id == self.project_id)).all()
                findings = session.scalars(select(FindingModel).where(FindingModel.project_id == self.project_id)).all()
                memberships = session.scalars(select(TenantMembershipModel)).all()

                # 1. Create Tenant Nodes
                for t in tenants:
                    node = GraphNodeItem(
                        node_id=t.id,
                        node_type="TENANT",
                        name=t.name,
                        data={"id": t.id, "name": t.name, "created_at": str(t.created_at)},
                    )
                    self.scene.addItem(node)
                    self.nodes[t.id] = node

                # 2. Create Identity Nodes
                for i in identities:
                    node = GraphNodeItem(
                        node_id=i.id,
                        node_type="IDENTITY",
                        name=i.display_name,
                        data={
                            "id": i.id,
                            "name": i.display_name,
                            "type": i.identity_type,
                            "roles": i.roles,
                            "primary_tenant_id": i.primary_tenant_id,
                        },
                    )
                    self.scene.addItem(node)
                    self.nodes[i.id] = node

                # 3. Create Resource Nodes (detect orphaned resources)
                resource_policy_counts: dict[str, int] = {r.id: 0 for r in resources}
                for p in policies:
                    res_sel = p.resource_selector or {}
                    target_res_id = res_sel.get("resource_id")
                    if target_res_id and target_res_id in resource_policy_counts:
                        resource_policy_counts[target_res_id] += 1

                for r in resources:
                    is_orphaned = resource_policy_counts.get(r.id, 0) == 0 and r.tenant_id is None
                    node = GraphNodeItem(
                        node_id=r.id,
                        node_type="RESOURCE",
                        name=f"{r.method} {r.path}" if r.method else r.display_name,
                        data={
                            "id": r.id,
                            "name": r.display_name,
                            "path": r.path,
                            "method": r.method,
                            "sensitivity": r.sensitivity,
                            "tenant_id": r.tenant_id,
                        },
                        is_anomaly=is_orphaned,
                        anomaly_msg="Orphaned Resource: No access control policies or owning tenant assigned"
                        if is_orphaned
                        else "",
                    )
                    self.scene.addItem(node)
                    self.nodes[r.id] = node

                # 4. Create Policy Nodes
                for p in policies:
                    node = GraphNodeItem(
                        node_id=p.id,
                        node_type="POLICY",
                        name=p.name,
                        data={
                            "id": p.id,
                            "name": p.name,
                            "action": p.action,
                            "decision": p.expected_decision,
                        },
                    )
                    self.scene.addItem(node)
                    self.nodes[p.id] = node

                # 5. Create Finding Nodes
                for f in findings:
                    node = GraphNodeItem(
                        node_id=f.id,
                        node_type="FINDING",
                        name=f.title,
                        data={
                            "id": f.id,
                            "title": f.title,
                            "severity": f.severity,
                            "status": f.status,
                            "identity_id": f.identity_id,
                            "resource_id": f.resource_id,
                        },
                        is_anomaly=True,
                        anomaly_msg=f"Active Finding: {f.title} ({f.severity})",
                    )
                    self.scene.addItem(node)
                    self.nodes[f.id] = node

                # 6. Create Edges
                # Membership edges (Identity -> Tenant)
                for i in identities:
                    if i.primary_tenant_id and i.primary_tenant_id in self.nodes:
                        edge = GraphEdgeItem(self.nodes[i.id], self.nodes[i.primary_tenant_id], "MEMBER_OF")
                        self.scene.addItem(edge)
                        self.edges.append(edge)

                for m in memberships:
                    if m.identity_id in self.nodes and m.tenant_id in self.nodes:
                        edge = GraphEdgeItem(self.nodes[m.identity_id], self.nodes[m.tenant_id], "MEMBER_OF")
                        self.scene.addItem(edge)
                        self.edges.append(edge)

                # Resource -> Tenant (OWNS)
                for r in resources:
                    if r.tenant_id and r.tenant_id in self.nodes:
                        edge = GraphEdgeItem(self.nodes[r.tenant_id], self.nodes[r.id], "OWNS")
                        self.scene.addItem(edge)
                        self.edges.append(edge)

                # Policy Edges (Policy -> Resource and Subject -> Policy)
                for p in policies:
                    if p.id in self.nodes:
                        subj_id = (p.subject_selector or {}).get("identity_id")
                        res_id = (p.resource_selector or {}).get("resource_id")
                        if subj_id and subj_id in self.nodes:
                            rel_type = "HAS_ACCESS" if p.expected_decision.upper() == "ALLOW" else "DENIED_ACCESS"
                            edge = GraphEdgeItem(self.nodes[subj_id], self.nodes[p.id], rel_type)
                            self.scene.addItem(edge)
                            self.edges.append(edge)
                        if res_id and res_id in self.nodes:
                            edge = GraphEdgeItem(self.nodes[p.id], self.nodes[res_id], "TARGETS")
                            self.scene.addItem(edge)
                            self.edges.append(edge)

                # Finding Edges (Finding -> Resource or Finding -> Identity)
                for f in findings:
                    if f.id in self.nodes:
                        if f.resource_id and f.resource_id in self.nodes:
                            edge = GraphEdgeItem(
                                self.nodes[f.id], self.nodes[f.resource_id], "VIOLATES", is_anomaly=True
                            )
                            self.scene.addItem(edge)
                            self.edges.append(edge)
                        if f.identity_id and f.identity_id in self.nodes:
                            edge = GraphEdgeItem(self.nodes[f.identity_id], self.nodes[f.id], "TESTED_BY")
                            self.scene.addItem(edge)
                            self.edges.append(edge)

            self._auto_layout()
            self._apply_filters()
        except Exception as exc:
            logger.error("Failed to build authorization graph: %s", exc)

    def _auto_layout(self) -> None:
        """Arrange nodes in structured hierarchical tiers (Tenants, Identities, Policies, Resources, Findings)."""
        tiers: dict[str, list[GraphNodeItem]] = {
            "TENANT": [],
            "IDENTITY": [],
            "POLICY": [],
            "RESOURCE": [],
            "FINDING": [],
        }

        for node in self.nodes.values():
            nt = node.node_type
            if nt in tiers:
                tiers[nt].append(node)
            else:
                tiers["RESOURCE"].append(node)

        y_positions = {
            "TENANT": 0,
            "IDENTITY": 140,
            "POLICY": 280,
            "RESOURCE": 420,
            "FINDING": 560,
        }

        for tier_name, node_list in tiers.items():
            count = len(node_list)
            if count == 0:
                continue
            spacing = 180
            total_w = count * spacing
            start_x = -total_w / 2 + spacing / 2
            y = y_positions[tier_name]

            for idx, node in enumerate(node_list):
                node.setPos(start_x + idx * spacing, y)

        self._reset_view()

    def _zoom_in(self) -> None:
        self.view.scale(1.2, 1.2)

    def _zoom_out(self) -> None:
        self.view.scale(0.8, 0.8)

    def _reset_view(self) -> None:
        rect = self.scene.itemsBoundingRect()
        if not rect.isNull():
            self.view.fitInView(rect.adjusted(-50, -50, 50, 50), Qt.AspectRatioMode.KeepAspectRatio)

    def _apply_filters(self) -> None:
        """Apply visibility filters based on node type checkboxes and edge confidence."""
        type_visibility = {
            "IDENTITY": self.chk_identities.isChecked(),
            "TENANT": self.chk_tenants.isChecked(),
            "RESOURCE": self.chk_resources.isChecked(),
            "POLICY": self.chk_policies.isChecked(),
            "FINDING": self.chk_findings.isChecked(),
        }

        for node in self.nodes.values():
            node.setVisible(type_visibility.get(node.node_type, True))

        conf_filter = self.confidence_combo.currentText()
        for edge in self.edges:
            nodes_visible = edge.source.isVisible() and edge.dest.isVisible()
            conf_match = (conf_filter == "All") or (edge.confidence == conf_filter)
            edge.setVisible(nodes_visible and conf_match)

    def _on_scene_selection_changed(self) -> None:
        """Populate inspector panel when node is clicked."""
        selected = self.scene.selectedItems()
        node_items = [it for it in selected if isinstance(it, GraphNodeItem)]
        if not node_items:
            self.node_type_badge.setText("NO SELECTION")
            self.node_name_label.setText("Click any node in the graph to inspect its properties.")
            self.anomaly_box.setVisible(False)
            self.prop_table.setRowCount(0)
            self.edges_text.clear()
            return

        node = node_items[0]
        self.node_type_badge.setText(node.node_type)
        self.node_name_label.setText(f"<b>{node.name}</b>")

        if node.is_anomaly:
            self.anomaly_box.setVisible(True)
            self.anomaly_desc.setText(node.anomaly_msg)
        else:
            self.anomaly_box.setVisible(False)

        # Properties
        data = node.data
        self.prop_table.setRowCount(len(data))
        for row, (k, v) in enumerate(data.items()):
            self.prop_table.setItem(row, 0, QTableWidgetItem(str(k)))
            self.prop_table.setItem(row, 1, QTableWidgetItem(str(v)))

        # Edges
        edge_lines: list[str] = []
        for edge in node.edges:
            if edge.source == node:
                edge_lines.append(f"--[{edge.edge_type}]--> {edge.dest.name} ({edge.dest.node_type})")
            else:
                edge_lines.append(f"<--[{edge.edge_type}]-- {edge.source.name} ({edge.source.node_type})")
        self.edges_text.setPlainText("\n".join(edge_lines))

    def _export_graph(self) -> None:
        """Export current scene to PNG image."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Graph",
            "relationship_graph.png",
            "PNG Image (*.png);;SVG Image (*.svg)",
        )
        if not file_path:
            return

        try:
            rect = self.scene.itemsBoundingRect().adjusted(-30, -30, 30, 30)
            if rect.width() <= 0 or rect.height() <= 0:
                rect = QRectF(0, 0, 800, 600)

            image = QImage(int(rect.width()), int(rect.height()), QImage.Format.Format_ARGB32)
            image.fill(QColor("#12151c"))
            painter = QPainter(image)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            self.scene.render(painter, QRectF(image.rect()), rect)
            painter.end()

            image.save(file_path)
            QMessageBox.information(self, "Graph Exported", f"Graph exported successfully to:\n{file_path}")
        except Exception as exc:
            logger.error("Failed to export graph: %s", exc)
            QMessageBox.critical(self, "Export Failed", f"Could not export graph: {exc}")
