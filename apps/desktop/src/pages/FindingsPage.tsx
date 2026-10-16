import React, { useState } from "react";
import { Bug, CheckCircle2, XCircle, AlertCircle, CopyCheck } from "lucide-react";
import { Finding, Program, ipc } from "../services/ipc";

interface FindingsPageProps {
  program?: Program;
  findings: Finding[];
  onRefreshFindings: () => void;
}

export const FindingsPage: React.FC<FindingsPageProps> = ({
  program,
  findings,
  onRefreshFindings,
}) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [reviewNote, setReviewNote] = useState("");
  const [reviewAction, setReviewAction] = useState<string>("verified");

  const handleUpdateStatus = async () => {
    if (!selectedFinding || !reviewNote.trim()) return;

    await ipc.sendCommand("findings.update_status", {
      finding_id: selectedFinding.id,
      new_status: reviewAction,
      review_reason: reviewNote.trim(),
    });

    setReviewNote("");
    onRefreshFindings();
    setSelectedFinding(null);
  };

  return (
    <div className="page-body">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h2 style={{ fontSize: "1.4rem", fontWeight: 700 }}>Findings Triage Workbench</h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
            Candidate authorization flaws require explicit human review and cryptographic evidence before release.
          </p>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: selectedFinding ? "1.4fr 1fr" : "1fr", gap: "1.5rem" }}>
        {/* Findings Table */}
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: "center", padding: "2.5rem", color: "var(--text-muted)" }}>
                    No findings recorded for this program. Run test evaluations or import evidence to discover.
                  </td>
                </tr>
              ) : (
                findings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    style={{ cursor: "pointer", background: selectedFinding?.id === f.id ? "var(--bg-surface)" : undefined }}
                  >
                    <td style={{ fontWeight: 600 }}>{f.title}</td>
                    <td><span className="badge badge-unrated">{f.category}</span></td>
                    <td><span className={`badge badge-${f.severity}`}>{f.severity}</span></td>
                    <td>{f.confidence}</td>
                    <td>
                      <span
                        className={`badge ${
                          f.status === "verified"
                            ? "badge-in-scope"
                            : f.status === "false_positive"
                            ? "badge-out-of-scope"
                            : "badge-medium"
                        }`}
                      >
                        {f.status.replace("_", " ")}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Finding Detail & Human Review Drawer */}
        {selectedFinding && (
          <div className="card">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
              <h3 style={{ fontSize: "1rem", fontWeight: 600 }}>Triage & Human Verification</h3>
              <button
                onClick={() => setSelectedFinding(null)}
                style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem", fontSize: "0.85rem" }}>
              <div>
                <label className="form-label">Finding Title</label>
                <div style={{ fontWeight: 600 }}>{selectedFinding.title}</div>
              </div>

              <div>
                <label className="form-label">Observed Impact</label>
                <p style={{ color: "var(--text-secondary)" }}>{selectedFinding.impact || "Not documented."}</p>
              </div>

              <div>
                <label className="form-label">Linked Evidence IDs</label>
                <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                  {selectedFinding.evidence_ids.length === 0 ? (
                    <span style={{ color: "var(--error)", fontSize: "0.75rem" }}>No evidence linked!</span>
                  ) : (
                    selectedFinding.evidence_ids.map((eid) => (
                      <span key={eid} className="badge badge-unrated" style={{ fontFamily: "var(--font-mono)" }}>
                        {eid}
                      </span>
                    ))
                  )}
                </div>
              </div>

              {/* Review Action */}
              <div style={{ marginTop: "0.75rem", padding: "1rem", background: "var(--bg-surface)", borderRadius: "var(--radius-md)", border: "1px solid var(--border)" }}>
                <label className="form-label">Decision & Verification Reason (Mandatory)</label>
                <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.5rem" }}>
                  <select
                    className="form-input"
                    value={reviewAction}
                    onChange={(e) => setReviewAction(e.target.value)}
                    style={{ width: "160px" }}
                  >
                    <option value="verified">Mark as Verified</option>
                    <option value="false_positive">Mark False Positive</option>
                    <option value="accepted_risk">Mark Accepted Risk</option>
                    <option value="needs_review">Needs More Review</option>
                  </select>
                </div>
                <textarea
                  className="form-input"
                  rows={3}
                  placeholder="Document reproduction steps, tool version, and verification evidence..."
                  value={reviewNote}
                  onChange={(e) => setReviewNote(e.target.value)}
                  style={{ marginBottom: "0.5rem" }}
                />
                <button
                  className="btn btn-primary"
                  style={{ width: "100%", justifyContent: "center" }}
                  onClick={handleUpdateStatus}
                  disabled={!reviewNote.trim()}
                >
                  Confirm Review Decision
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
