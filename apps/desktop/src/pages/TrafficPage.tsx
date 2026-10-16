import React, { useState } from "react";
import { Upload, FileCode, CheckCircle, Shield } from "lucide-react";
import { Program } from "../services/ipc";

interface TrafficPageProps {
  program?: Program;
}

export const TrafficPage: React.FC<TrafficPageProps> = ({ program }) => {
  const [selectedFormat, setSelectedFormat] = useState<"har" | "openapi">("har");
  const [importStatus, setImportStatus] = useState<string | null>(null);

  const sampleHttpExchanges = [
    {
      id: "ex-1",
      method: "GET",
      url: "https://api.target.com/v1/users/profile",
      status: 200,
      duration: "42ms",
      headers: {
        Authorization: "Bearer [REDACTED_TOKEN]",
        Cookie: "[REDACTED]",
        Accept: "application/json",
      },
      responseBody: '{\n  "id": 1042,\n  "role": "MEMBER",\n  "tenant_id": "tenant-99"\n}',
    },
    {
      id: "ex-2",
      method: "POST",
      url: "https://api.target.com/v1/orders/create",
      status: 403,
      duration: "88ms",
      headers: {
        Authorization: "Bearer [REDACTED_TOKEN]",
        "Content-Type": "application/json",
      },
      responseBody: '{\n  "error": "Forbidden: Cross-tenant modification denied"\n}',
    },
  ];

  const [selectedExchange, setSelectedExchange] = useState(sampleHttpExchanges[0]);

  return (
    <div className="page-body">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h2 style={{ fontSize: "1.4rem", fontWeight: 700 }}>Traffic & API Explorer</h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
            Analyze HTTP Archive (HAR 1.2) traces and OpenAPI/Swagger specifications with automatic credential scrubbing.
          </p>
        </div>
        <button
          className="btn btn-secondary"
          onClick={() => setImportStatus("Import simulated: 42 endpoints and 28 exchanges ingested with secret scrubbing")}
        >
          <Upload size={16} /> Import HAR / OpenAPI
        </button>
      </div>

      {importStatus && (
        <div style={{ padding: "0.75rem", background: "rgba(16, 185, 129, 0.1)", border: "1px solid var(--success)", borderRadius: "var(--radius-md)", marginBottom: "1rem", fontSize: "0.85rem", color: "var(--success)" }}>
          {importStatus}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1.8fr", gap: "1.5rem" }}>
        {/* Exchanges List */}
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Method</th>
                <th>URL</th>
                <th>Status</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {sampleHttpExchanges.map((ex) => (
                <tr
                  key={ex.id}
                  onClick={() => setSelectedExchange(ex)}
                  style={{
                    cursor: "pointer",
                    background: selectedExchange.id === ex.id ? "var(--bg-surface)" : undefined,
                  }}
                >
                  <td>
                    <span className={`badge ${ex.method === "GET" ? "badge-low" : "badge-medium"}`}>
                      {ex.method}
                    </span>
                  </td>
                  <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem" }}>{ex.url}</td>
                  <td>
                    <span style={{ color: ex.status < 400 ? "var(--success)" : "var(--error)" }}>
                      {ex.status}
                    </span>
                  </td>
                  <td style={{ color: "var(--text-muted)" }}>{ex.duration}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Request / Response Split Viewer */}
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
            <span style={{ fontWeight: 600, fontSize: "0.9rem" }}>HTTP Evidence Inspection</span>
            <span className="badge badge-in-scope" style={{ gap: "4px" }}>
              <Shield size={12} /> Redaction Applied
            </span>
          </div>

          <div style={{ marginBottom: "1rem" }}>
            <label className="form-label">Request Headers (Redacted)</label>
            <pre style={{ background: "var(--bg-primary)", padding: "0.75rem", borderRadius: "4px", fontSize: "0.75rem", fontFamily: "var(--font-mono)", overflowX: "auto" }}>
              {JSON.stringify(selectedExchange.headers, null, 2)}
            </pre>
          </div>

          <div>
            <label className="form-label">Response Body (HTTP {selectedExchange.status})</label>
            <pre style={{ background: "var(--bg-primary)", padding: "0.75rem", borderRadius: "4px", fontSize: "0.75rem", fontFamily: "var(--font-mono)", color: "#a5f3fc", overflowX: "auto" }}>
              {selectedExchange.responseBody}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
