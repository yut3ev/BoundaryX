import React from "react";
import { Shield, Globe, Bug, PlayCircle } from "lucide-react";
import { Program, Asset, Finding, Job } from "../services/ipc";

interface OverviewPageProps {
  program?: Program;
  assets: Asset[];
  findings: Finding[];
  jobs: Job[];
  onNavigate: (tab: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  program,
  assets,
  findings,
  jobs,
  onNavigate,
}) => {
  const inScopeCount = assets.filter((a) => a.scope_status === "in_scope").length;
  const verifiedFindings = findings.filter((f) => f.status === "verified").length;

  return (
    <div className="page-body">
      <div style={{ marginBottom: "1.5rem" }}>
        <h2 style={{ fontSize: "1.4rem", fontWeight: 700 }}>Workspace Dashboard</h2>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
          Active Target: <strong>{program ? program.name : "None selected"}</strong>
        </p>
      </div>

      {/* Metric Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "1rem", marginBottom: "1.5rem" }}>
        <div className="card" style={{ marginBottom: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>Total Assets</span>
            <Globe size={18} color="var(--accent)" />
          </div>
          <div style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: "0.5rem" }}>{assets.length}</div>
          <span style={{ fontSize: "0.75rem", color: "var(--success)" }}>{inScopeCount} in scope</span>
        </div>

        <div className="card" style={{ marginBottom: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>Findings</span>
            <Bug size={18} color="var(--high)" />
          </div>
          <div style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: "0.5rem" }}>{findings.length}</div>
          <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>{verifiedFindings} verified</span>
        </div>

        <div className="card" style={{ marginBottom: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>Recon Tasks</span>
            <PlayCircle size={18} color="var(--border-focus)" />
          </div>
          <div style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: "0.5rem" }}>{jobs.length}</div>
          <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>Recent jobs run</span>
        </div>

        <div className="card" style={{ marginBottom: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>Authorization Status</span>
            <Shield size={18} color="var(--success)" />
          </div>
          <div style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: "0.5rem" }}>Active</div>
          <span style={{ fontSize: "0.75rem", color: "var(--success)" }}>Scope Guard Enforcing</span>
        </div>
      </div>

      {/* Quick Launch & Recent Findings */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
        <div className="card">
          <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "0.75rem" }}>Quick Actions</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            <button className="btn btn-secondary" onClick={() => onNavigate("programs")}>
              Configure Target Scope Rules
            </button>
            <button className="btn btn-secondary" onClick={() => onNavigate("jobs")}>
              Launch Discovery / Recon Job
            </button>
            <button className="btn btn-secondary" onClick={() => onNavigate("traffic")}>
              Import HAR / OpenAPI Traffic
            </button>
            <button className="btn btn-secondary" onClick={() => onNavigate("reports")}>
              Preview Assessment Report
            </button>
          </div>
        </div>

        <div className="card">
          <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "0.75rem" }}>Recent Findings</h3>
          {findings.length === 0 ? (
            <p style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>No findings logged yet.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              {findings.slice(0, 3).map((f) => (
                <div key={f.id} style={{ display: "flex", justifyContent: "space-between", padding: "0.4rem 0", borderBottom: "1px solid var(--border)" }}>
                  <span style={{ fontSize: "0.85rem" }}>{f.title}</span>
                  <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
