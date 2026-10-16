import React from "react";
import {
  LayoutDashboard,
  ShieldAlert,
  Globe2,
  Terminal,
  Network,
  FileCode2,
  Bug,
  FileSpreadsheet,
  Wrench,
  Settings,
} from "lucide-react";
import { Program } from "../../services/ipc";

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  programs: Program[];
  selectedProgramId: string;
  onSelectProgram: (id: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  programs,
  selectedProgramId,
  onSelectProgram,
}) => {
  const navItems = [
    { id: "overview", label: "Overview", icon: LayoutDashboard },
    { id: "programs", label: "Programs & Scope", icon: ShieldAlert },
    { id: "assets", label: "Assets", icon: Globe2 },
    { id: "jobs", label: "Recon Jobs", icon: Terminal },
    { id: "traffic", label: "Traffic & API", icon: Network },
    { id: "planner", label: "Test Planner", icon: FileCode2 },
    { id: "findings", label: "Findings", icon: Bug },
    { id: "reports", label: "Reports", icon: FileSpreadsheet },
    { id: "toolchain", label: "Toolchain", icon: Wrench },
    { id: "settings", label: "Settings", icon: Settings },
  ];

  return (
    <aside className="sidebar">
      {/* Brand */}
      <div style={{ padding: "1.25rem 1.5rem", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: "0.5rem" }}>
        <div style={{ width: "24px", height: "24px", borderRadius: "4px", background: "var(--accent)", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: "bold", fontSize: "14px" }}>
          BX
        </div>
        <span style={{ fontWeight: 700, fontSize: "1.1rem", letterSpacing: "0.5px" }}>BoundaryX</span>
      </div>

      {/* Program Selector */}
      <div style={{ padding: "1rem 1.5rem", borderBottom: "1px solid var(--border)" }}>
        <label className="form-label">Active Workspace</label>
        <select
          className="form-input"
          value={selectedProgramId}
          onChange={(e) => onSelectProgram(e.target.value)}
          style={{ fontSize: "0.8rem", padding: "0.35rem 0.5rem" }}
        >
          {programs.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
          {programs.length === 0 && <option value="">No Programs</option>}
        </select>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: "0.75rem 0.5rem", display: "flex", flexDirection: "column", gap: "2px" }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.75rem",
                padding: "0.55rem 0.75rem",
                borderRadius: "var(--radius-md)",
                background: active ? "var(--accent-light)" : "transparent",
                color: active ? "var(--border-focus)" : "var(--text-secondary)",
                border: "none",
                fontWeight: active ? 600 : 500,
                fontSize: "0.85rem",
                cursor: "pointer",
                textAlign: "left",
                transition: "all 0.15s ease",
              }}
            >
              <Icon size={16} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div style={{ padding: "0.75rem 1.5rem", borderTop: "1px solid var(--border)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
        <span>v0.1.1 (No-AI Default)</span>
      </div>
    </aside>
  );
};
