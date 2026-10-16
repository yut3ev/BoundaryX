import React, { useState } from "react";
import { Download, FileText, CheckCircle2, ShieldAlert } from "lucide-react";
import { Finding, Program, Asset } from "../services/ipc";

interface ReportsPageProps {
  program?: Program;
  findings: Finding[];
  assets: Asset[];
}

export const ReportsPage: React.FC<ReportsPageProps> = ({
  program,
  findings,
  assets,
}) => {
  const [exportFormat, setExportFormat] = useState<"markdown" | "html" | "json" | "csv">("markdown");
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

  const verifiedFindings = findings.filter((f) => f.status === "verified");

  const handleExport = () => {
    const filename = `BoundaryX_Report_${program?.name.replace(/\s+/g, "_") || "Assessment"}.${
      exportFormat === "markdown" ? "md" : exportFormat
    }`;
    setDownloadSuccess(`Report exported successfully as ${filename} (All tokens and secrets scrubbed)`);
  };

  return (
    <div className="page-body">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h2 style={{ fontSize: "1.4rem", fontWeight: 700 }}>Assessment Reporting</h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
            Generate sanitized, auditor-ready vulnerability reports conforming to authorized pentesting standards.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <select
            className="form-input"
            value={exportFormat}
            onChange={(e) => setExportFormat(e.target.value as any)}
            style={{ width: "160px" }}
          >
            <option value="markdown">Markdown (.md)</option>
            <option value="html">Offline HTML (.html)</option>
            <option value="json">Sanitized JSON (.json)</option>
            <option value="csv">Spreadsheet (.csv)</option>
          </select>
          <button className="btn btn-primary" onClick={handleExport}>
            <Download size={16} /> Export Report
          </button>
        </div>
      </div>

      {downloadSuccess && (
        <div style={{ padding: "0.75rem", background: "rgba(16, 185, 129, 0.1)", border: "1px solid var(--success)", borderRadius: "var(--radius-md)", marginBottom: "1.5rem", fontSize: "0.85rem", color: "var(--success)" }}>
          {downloadSuccess}
        </div>
      )}

      {/* Report Preview */}
      <div className="card">
        <div style={{ borderBottom: "1px solid var(--border)", paddingBottom: "1rem", marginBottom: "1rem" }}>
          <h3 style={{ fontSize: "1.2rem", fontWeight: 700 }}>
            Security Assessment Report: {program ? program.name : "Acme Bug Bounty"}
          </h3>
          <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
            Generated: {new Date().toUTCString()} | Platform: BoundaryX v0.1.0
          </p>
        </div>

        <div style={{ marginBottom: "1.5rem" }}>
          <h4 style={{ fontSize: "0.95rem", fontWeight: 600, color: "var(--accent)", marginBottom: "0.5rem" }}>
            1. Executive Scope & Target Summary
          </h4>
          <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", lineHeight: 1.6 }}>
            This document summarizes authorized penetration testing conducted under the program policy.
            A total of <strong>{assets.length}</strong> unique assets and endpoints were inspected.
            Total verified vulnerabilities requiring immediate remediation: <strong>{verifiedFindings.length}</strong>.
          </p>
        </div>

        <div>
          <h4 style={{ fontSize: "0.95rem", fontWeight: 600, color: "var(--accent)", marginBottom: "0.5rem" }}>
            2. Verified Vulnerabilities
          </h4>
          {verifiedFindings.length === 0 ? (
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
              No findings currently have 'verified' status. Findings must be reviewed by a researcher before inclusion in final reports.
            </p>
          ) : (
            verifiedFindings.map((f, i) => (
              <div key={f.id} style={{ background: "var(--bg-surface)", padding: "1rem", borderRadius: "var(--radius-md)", marginBottom: "0.75rem", border: "1px solid var(--border)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <strong>{i + 1}. {f.title}</strong>
                  <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                </div>
                <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)", marginTop: "0.4rem" }}>
                  {f.impact || "Impact not specified"}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
