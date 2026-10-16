import React, { useState, useEffect } from "react";
import { Plus, Trash2, CheckCircle2, XCircle } from "lucide-react";
import { Program, ScopeRule, ScopeDecision, ipc } from "../services/ipc";

interface ProgramsPageProps {
  programs: Program[];
  activeProgramId: string;
  onRefreshPrograms: () => void;
}

export const ProgramsPage: React.FC<ProgramsPageProps> = ({
  programs,
  activeProgramId,
  onRefreshPrograms,
}) => {
  const [rules, setRules] = useState<ScopeRule[]>([]);
  const [newProgramName, setNewProgramName] = useState("");
  const [newPolicyUrl, setNewPolicyUrl] = useState("");
  const [showNewProgramModal, setShowNewProgramModal] = useState(false);

  // New Rule Form
  const [newPattern, setNewPattern] = useState("");
  const [newRuleType, setNewRuleType] = useState<"include" | "exclude">("include");
  const [isWildcard, setIsWildcard] = useState(false);

  // Live Scope Checker
  const [testTarget, setTestTarget] = useState("");
  const [testDecision, setTestDecision] = useState<ScopeDecision | null>(null);

  useEffect(() => {
    if (activeProgramId) {
      loadRules(activeProgramId);
    }
  }, [activeProgramId]);

  const loadRules = async (pid: string) => {
    const list = await ipc.sendCommand<ScopeRule[]>("scope.list", { program_id: pid });
    setRules(list);
  };

  const handleCreateProgram = async () => {
    if (!newProgramName.trim()) return;
    await ipc.sendCommand("programs.create", {
      name: newProgramName.trim(),
      policy_url: newPolicyUrl.trim() || undefined,
    });
    setNewProgramName("");
    setNewPolicyUrl("");
    setShowNewProgramModal(false);
    onRefreshPrograms();
  };

  const handleAddRule = async () => {
    if (!newPattern.trim() || !activeProgramId) return;
    await ipc.sendCommand("scope.create_rule", {
      program_id: activeProgramId,
      rule_type: newRuleType,
      matcher_type: "domain",
      pattern: newPattern.trim(),
      wildcard: isWildcard,
    });
    setNewPattern("");
    loadRules(activeProgramId);
  };

  const handleTestScope = async () => {
    if (!testTarget.trim() || !activeProgramId) return;
    const dec = await ipc.sendCommand<ScopeDecision>("scope.evaluate", {
      program_id: activeProgramId,
      target: testTarget.trim(),
    });
    setTestDecision(dec);
  };

  const activeProgram = programs.find((p) => p.id === activeProgramId);

  return (
    <div className="page-body">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h2 style={{ fontSize: "1.4rem", fontWeight: 700 }}>
            Program &amp; Scope Management {activeProgram ? `— ${activeProgram.name}` : ""}
          </h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
            Define authorized target boundaries, explicit exclusions, and verified wildcards.
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowNewProgramModal(true)}>
          <Plus size={16} /> New Program
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr", gap: "1.5rem" }}>
        {/* Scope Rules List */}
        <div>
          <div className="card">
            <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "1rem" }}>
              Active Scope Rules ({rules.length})
            </h3>

            {/* Add Rule Inline Form */}
            <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem", alignItems: "center" }}>
              <select
                className="form-input"
                style={{ width: "110px" }}
                value={newRuleType}
                onChange={(e) => setNewRuleType(e.target.value as any)}
              >
                <option value="include">Include</option>
                <option value="exclude">Exclude</option>
              </select>

              <input
                type="text"
                className="form-input"
                placeholder="domain.com or *.domain.com"
                value={newPattern}
                onChange={(e) => setNewPattern(e.target.value)}
                style={{ flex: 1 }}
              />

              <label style={{ display: "flex", alignItems: "center", gap: "0.3rem", fontSize: "0.8rem", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={isWildcard}
                  onChange={(e) => setIsWildcard(e.target.checked)}
                />
                Wildcard
              </label>

              <button className="btn btn-primary" onClick={handleAddRule}>
                Add Rule
              </button>
            </div>

            {/* Table */}
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Pattern</th>
                    <th>Wildcard</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.length === 0 ? (
                    <tr>
                      <td colSpan={4} style={{ textAlign: "center", color: "var(--text-muted)", padding: "1.5rem" }}>
                        No scope rules configured yet. Add inclusion rules above.
                      </td>
                    </tr>
                  ) : (
                    rules.map((r) => (
                      <tr key={r.id}>
                        <td>
                          <span className={`badge ${r.rule_type === "include" ? "badge-in-scope" : "badge-out-of-scope"}`}>
                            {r.rule_type}
                          </span>
                        </td>
                        <td style={{ fontFamily: "var(--font-mono)" }}>{r.pattern}</td>
                        <td>{r.wildcard ? "Yes (*.domain)" : "Exact Match"}</td>
                        <td>
                          <button
                            onClick={async () => {
                              await ipc.sendCommand("scope.delete_rule", { rule_id: r.id });
                              loadRules(activeProgramId);
                            }}
                            style={{ background: "none", border: "none", color: "var(--error)", cursor: "pointer" }}
                          >
                            <Trash2 size={14} />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Live Scope Checker Tool */}
        <div>
          <div className="card">
            <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "0.75rem" }}>
              Live Boundary Guard Checker
            </h3>
            <p style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "1rem" }}>
              Test any URL, hostname, or IP against the active ScopeGuard rules before scanning.
            </p>

            <div className="form-group">
              <input
                type="text"
                className="form-input"
                placeholder="https://staging.target.com/api"
                value={testTarget}
                onChange={(e) => setTestTarget(e.target.value)}
              />
            </div>
            <button className="btn btn-secondary" style={{ width: "100%", justifyContent: "center" }} onClick={handleTestScope}>
              Check Scope Decision
            </button>

            {testDecision && (
              <div
                style={{
                  marginTop: "1.25rem",
                  padding: "1rem",
                  borderRadius: "var(--radius-md)",
                  background: testDecision.is_in_scope ? "rgba(16, 185, 129, 0.1)" : "rgba(239, 68, 68, 0.1)",
                  border: `1px solid ${testDecision.is_in_scope ? "var(--success)" : "var(--error)"}`,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
                  {testDecision.is_in_scope ? (
                    <CheckCircle2 color="var(--success)" size={18} />
                  ) : (
                    <XCircle color="var(--error)" size={18} />
                  )}
                  <strong style={{ color: testDecision.is_in_scope ? "var(--success)" : "var(--error)" }}>
                    {testDecision.is_in_scope ? "AUTHORIZED IN SCOPE" : "OUT OF SCOPE / DENIED"}
                  </strong>
                </div>
                <div style={{ fontSize: "0.75rem", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                  <div>Canonical Host: {testDecision.canonical_host}</div>
                  {testDecision.denial_reason && (
                    <div style={{ marginTop: "4px", color: "var(--error)" }}>
                      Reason: {testDecision.denial_reason}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* New Program Modal */}
      {showNewProgramModal && (
        <div className="modal-overlay" onClick={() => setShowNewProgramModal(false)}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <h3 style={{ marginBottom: "1rem" }}>Create New Assessment Program</h3>
            <div className="form-group">
              <label className="form-label">Program Name</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. Stripe Bug Bounty"
                value={newProgramName}
                onChange={(e) => setNewProgramName(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Official Policy URL</label>
              <input
                type="text"
                className="form-input"
                placeholder="https://hackerone.com/stripe"
                value={newPolicyUrl}
                onChange={(e) => setNewPolicyUrl(e.target.value)}
              />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem", marginTop: "1.5rem" }}>
              <button className="btn btn-secondary" onClick={() => setShowNewProgramModal(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleCreateProgram}>
                Create Program
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
