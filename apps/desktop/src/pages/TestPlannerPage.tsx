import React, { useState } from "react";
import { Program } from "../services/ipc";

interface TestPlannerPageProps {
  program?: Program;
}

export const TestPlannerPage: React.FC<TestPlannerPageProps> = ({ program }) => {
  const [activeMode, setActiveMode] = useState<"matrix" | "hypotheses">("matrix");

  const matrixRows = [
    { endpoint: "/api/v1/organizations/{orgId}", verb: "GET", role: "TENANT_MEMBER", expected: "ALLOW", observed: "ALLOW", status: "VERIFIED" },
    { endpoint: "/api/v1/organizations/{orgId}", verb: "DELETE", role: "TENANT_MEMBER", expected: "DENY", observed: "DENY (403)", status: "VERIFIED" },
    { endpoint: "/api/v1/organizations/{orgId}/billing", verb: "GET", role: "TENANT_MEMBER", expected: "DENY", observed: "ALLOW (200)", status: "DEFECT_CANDIDATE" },
    { endpoint: "/api/v1/users/{userId}/keys", verb: "GET", role: "ANONYMOUS", expected: "DENY", observed: "DENY (401)", status: "VERIFIED" },
  ];

  return (
    <div className="page-body">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h2 style={{ fontSize: "1.4rem", fontWeight: 700 }}>Authorization Test Planner</h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
            Deterministic authorization invariants, cross-tenant matrices, and structured test hypotheses{program ? ` for ${program.name}` : ""}.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button
            className={`btn ${activeMode === "matrix" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setActiveMode("matrix")}
          >
            Access Matrix
          </button>
          <button
            className={`btn ${activeMode === "hypotheses" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setActiveMode("hypotheses")}
          >
            Hypotheses Vault
          </button>
        </div>
      </div>

      {activeMode === "matrix" ? (
        <div className="card">
          <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "1rem" }}>
            Deterministic Policy Evaluation Matrix
          </h3>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Protected Resource / Path</th>
                  <th>Verb</th>
                  <th>Tested Subject Role</th>
                  <th>Expected Policy</th>
                  <th>Observed Result</th>
                  <th>Outcome</th>
                </tr>
              </thead>
              <tbody>
                {matrixRows.map((row, idx) => (
                  <tr key={idx}>
                    <td style={{ fontFamily: "var(--font-mono)" }}>{row.endpoint}</td>
                    <td><span className="badge badge-unrated">{row.verb}</span></td>
                    <td>{row.role}</td>
                    <td><strong>{row.expected}</strong></td>
                    <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem" }}>{row.observed}</td>
                    <td>
                      <span className={`badge ${row.status === "VERIFIED" ? "badge-in-scope" : "badge-critical"}`}>
                        {row.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="card">
          <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "1rem" }}>
            Structured Test Hypotheses
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            <div style={{ padding: "1rem", background: "var(--bg-surface)", borderRadius: "var(--radius-md)", border: "1px solid var(--border)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
                <strong style={{ color: "var(--accent)" }}>HYP-01: Cross-Tenant Billing Exfiltration</strong>
                <span className="badge badge-medium">Confidence: Medium</span>
              </div>
              <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                Statement: Authenticated member of Tenant A can access billing details of Tenant B by substituting the orgId path parameter.
              </p>
              <div style={{ marginTop: "0.5rem", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Supporting Evidence: HTTP Exchange #ex-1 | Verification: Requires manual preview replay.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
