import React, { useState } from "react";
import { Play, XCircle } from "lucide-react";
import { Job, Program, ipc } from "../services/ipc";

interface JobsPageProps {
  program?: Program;
  jobs: Job[];
  onRefreshJobs: () => void;
  onCancelJob: (id: string) => void;
}

export const JobsPage: React.FC<JobsPageProps> = ({
  program,
  jobs,
  onRefreshJobs,
  onCancelJob,
}) => {
  const [showLaunchModal, setShowLaunchModal] = useState(false);
  const [selectedTool, setSelectedTool] = useState("subfinder");
  const [targetsInput, setTargetsInput] = useState("");
  const [rateLimit, setRateLimit] = useState(2);
  const [selectedJob, setSelectedJob] = useState<Job | null>(null);

  const handleLaunch = async () => {
    if (!program || !targetsInput.trim()) return;
    const rawTargets = targetsInput.split("\n").map((t) => t.trim()).filter(Boolean);

    await ipc.sendCommand("jobs.create", {
      program_id: program.id,
      job_type: selectedTool === "subfinder" ? "subdomain_discovery" : "web_probing",
      tool: selectedTool,
      targets: rawTargets,
      config: { rate_limit: rateLimit },
    });

    setShowLaunchModal(false);
    setTargetsInput("");
    onRefreshJobs();
  };

  return (
    <div className="page-body">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h2 style={{ fontSize: "1.4rem", fontWeight: 700 }}>Reconnaissance & Jobs</h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
            Supervised recon pipelines with strict scope pre-validation, token-bucket rate limits, and child process isolation.
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowLaunchModal(true)}>
          <Play size={16} /> Launch Recon Task
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: selectedJob ? "1.4fr 1fr" : "1fr", gap: "1.5rem" }}>
        {/* Jobs Table */}
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Task Type</th>
                <th>Status</th>
                <th>Discovered</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {jobs.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: "center", padding: "2.5rem", color: "var(--text-muted)" }}>
                    No recon jobs have been executed yet. Click 'Launch Recon Task' to start discovery.
                  </td>
                </tr>
              ) : (
                jobs.map((job) => {
                  const isRunning = job.status === "running" || job.status === "validating_scope";
                  return (
                    <tr
                      key={job.id}
                      onClick={() => setSelectedJob(job)}
                      style={{ cursor: "pointer", background: selectedJob?.id === job.id ? "var(--bg-surface)" : undefined }}
                    >
                      <td style={{ fontFamily: "var(--font-mono)", fontWeight: 600 }}>{job.job_type}</td>
                      <td>
                        <span
                          className={`badge ${
                            job.status === "completed"
                              ? "badge-in-scope"
                              : isRunning
                              ? "badge-low"
                              : "badge-high"
                          }`}
                        >
                          {job.status}
                        </span>
                      </td>
                      <td>{job.summary_json?.discovered_count ?? 0} assets</td>
                      <td style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>
                        {new Date(job.created_at).toLocaleTimeString()}
                      </td>
                      <td>
                        {isRunning && (
                          <button
                            className="btn btn-danger"
                            style={{ padding: "2px 6px", fontSize: "0.75rem" }}
                            onClick={(e) => {
                              e.stopPropagation();
                              onCancelJob(job.id);
                            }}
                          >
                            <XCircle size={12} /> Cancel
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Selected Job Drawer */}
        {selectedJob && (
          <div className="card">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
              <h3 style={{ fontSize: "1rem", fontWeight: 600 }}>Task Execution Summary</h3>
              <button
                onClick={() => setSelectedJob(null)}
                style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                ✕
              </button>
            </div>
            <div style={{ fontSize: "0.85rem", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              <div>
                <label className="form-label">Task ID</label>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>{selectedJob.id}</div>
              </div>
              <div>
                <label className="form-label">Summary Metrics</label>
                <pre style={{ background: "var(--bg-primary)", padding: "0.5rem", borderRadius: "4px", fontSize: "0.75rem" }}>
                  {JSON.stringify(selectedJob.summary_json, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Launch Modal */}
      {showLaunchModal && (
        <div className="modal-overlay" onClick={() => setShowLaunchModal(false)}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <h3 style={{ marginBottom: "1rem" }}>Configure & Launch Recon Task</h3>
            <div className="form-group">
              <label className="form-label">Select Tool</label>
              <select className="form-input" value={selectedTool} onChange={(e) => setSelectedTool(e.target.value)}>
                <option value="subfinder">Subfinder (Passive Subdomain Discovery)</option>
                <option value="httpx">httpx (Web Probe & Metadata Detection)</option>
                <option value="dnsx">dnsx (Active DNS Resolution)</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Target List (One per line)</label>
              <textarea
                className="form-input"
                rows={4}
                placeholder="example.com&#10;api.example.com"
                value={targetsInput}
                onChange={(e) => setTargetsInput(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Rate Limit (Requests / sec): {rateLimit}</label>
              <input
                type="range"
                min="1"
                max="20"
                value={rateLimit}
                onChange={(e) => setRateLimit(Number(e.target.value))}
                style={{ width: "100%" }}
              />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem", marginTop: "1.5rem" }}>
              <button className="btn btn-secondary" onClick={() => setShowLaunchModal(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleLaunch}>
                Verify Scope & Run
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
