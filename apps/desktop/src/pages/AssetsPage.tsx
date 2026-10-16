import React, { useState } from "react";
import { Globe, Plus, Filter, ArrowUpDown } from "lucide-react";
import { Asset, Program } from "../services/ipc";

interface AssetsPageProps {
  program?: Program;
  assets: Asset[];
}

export const AssetsPage: React.FC<AssetsPageProps> = ({ program, assets }) => {
  const [filterType, setFilterType] = useState<string>("all");
  const [filterScope, setFilterScope] = useState<string>("all");
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);

  const filtered = assets.filter((a) => {
    if (filterType !== "all" && a.asset_type !== filterType) return false;
    if (filterScope !== "all" && a.scope_status !== filterScope) return false;
    return true;
  });

  return (
    <div className="page-body">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h2 style={{ fontSize: "1.4rem", fontWeight: 700 }}>Asset Inventory</h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
            Discovered subdomains, web endpoints, API routes, and network services.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <select
            className="form-input"
            value={filterScope}
            onChange={(e) => setFilterScope(e.target.value)}
            style={{ width: "130px", fontSize: "0.8rem" }}
          >
            <option value="all">All Scopes</option>
            <option value="in_scope">In Scope Only</option>
            <option value="out_of_scope">Out of Scope</option>
          </select>
          <select
            className="form-input"
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            style={{ width: "130px", fontSize: "0.8rem" }}
          >
            <option value="all">All Types</option>
            <option value="subdomain">Subdomain</option>
            <option value="url">URL</option>
            <option value="endpoint">API Endpoint</option>
          </select>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: selectedAsset ? "1fr 340px" : "1fr", gap: "1.5rem" }}>
        {/* Table */}
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Asset Value</th>
                <th>Type</th>
                <th>Scope Status</th>
                <th>Importance</th>
                <th>Discovered</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: "center", padding: "2.5rem", color: "var(--text-muted)" }}>
                    No assets recorded. Run a recon job or import HAR/OpenAPI traffic to populate.
                  </td>
                </tr>
              ) : (
                filtered.map((a) => (
                  <tr
                    key={a.id}
                    onClick={() => setSelectedAsset(a)}
                    style={{ cursor: "pointer", background: selectedAsset?.id === a.id ? "var(--bg-surface)" : undefined }}
                  >
                    <td style={{ fontFamily: "var(--font-mono)", fontWeight: 500 }}>{a.display_value}</td>
                    <td><span className="badge badge-unrated">{a.asset_type}</span></td>
                    <td>
                      <span className={`badge ${a.scope_status === "in_scope" ? "badge-in-scope" : "badge-out-of-scope"}`}>
                        {a.scope_status.replace("_", " ")}
                      </span>
                    </td>
                    <td>⭐ {a.importance}</td>
                    <td style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>
                      {new Date(a.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Detail Drawer */}
        {selectedAsset && (
          <div className="card" style={{ height: "fit-content" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
              <h3 style={{ fontSize: "1rem", fontWeight: 600 }}>Asset Details</h3>
              <button
                onClick={() => setSelectedAsset(null)}
                style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                ✕
              </button>
            </div>
            <div style={{ fontSize: "0.85rem", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              <div>
                <label className="form-label">Canonical Representation</label>
                <div style={{ fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{selectedAsset.canonical_value}</div>
              </div>
              <div>
                <label className="form-label">Asset Type</label>
                <div>{selectedAsset.asset_type.toUpperCase()}</div>
              </div>
              <div>
                <label className="form-label">Authorization Scope</label>
                <span className={`badge ${selectedAsset.scope_status === "in_scope" ? "badge-in-scope" : "badge-out-of-scope"}`}>
                  {selectedAsset.scope_status}
                </span>
              </div>
              <div>
                <label className="form-label">First Seen</label>
                <div style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>{selectedAsset.created_at}</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
