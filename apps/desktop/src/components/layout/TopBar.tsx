import React from "react";
import { Search, ShieldCheck, Activity } from "lucide-react";
import { Program } from "../../services/ipc";

interface TopBarProps {
  activeProgram?: Program;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  activeJobCount: number;
}

export const TopBar: React.FC<TopBarProps> = ({
  activeProgram,
  searchQuery,
  onSearchChange,
  activeJobCount,
}) => {
  return (
    <header className="topbar">
      <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <ShieldCheck size={18} color="var(--accent)" />
          <span style={{ fontWeight: 600, fontSize: "0.9rem" }}>
            {activeProgram ? activeProgram.name : "Select Program"}
          </span>
        </div>
        {activeProgram?.policy_url && (
          <a
            href={activeProgram.policy_url}
            target="_blank"
            rel="noreferrer"
            style={{ fontSize: "0.75rem", color: "var(--accent)", textDecoration: "none" }}
          >
            Policy Reference ↗
          </a>
        )}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "1.25rem" }}>
        {/* Search Bar */}
        <div style={{ position: "relative", width: "240px" }}>
          <Search size={14} color="var(--text-muted)" style={{ position: "absolute", left: "10px", top: "10px" }} />
          <input
            type="text"
            className="form-input"
            placeholder="Search assets, findings..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            style={{ paddingLeft: "32px", fontSize: "0.8rem", height: "32px" }}
          />
        </div>

        {/* Active Jobs Pill */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.4rem",
            fontSize: "0.8rem",
            padding: "4px 10px",
            borderRadius: "20px",
            background: activeJobCount > 0 ? "rgba(16, 185, 129, 0.15)" : "var(--bg-surface)",
            color: activeJobCount > 0 ? "var(--success)" : "var(--text-muted)",
          }}
        >
          <Activity size={14} />
          <span>{activeJobCount} active jobs</span>
        </div>
      </div>
    </header>
  );
};
