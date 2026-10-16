import { XCircle, CheckCircle2, AlertTriangle, Loader2 } from "lucide-react";
import { Job } from "../../services/ipc";

interface JobTrayProps {
  jobs: Job[];
  onCancelJob: (id: string) => void;
}

export const JobTray: React.FC<JobTrayProps> = ({ jobs, onCancelJob }) => {
  if (jobs.length === 0) return null;

  return (
    <div
      style={{
        background: "var(--bg-secondary)",
        borderTop: "1px solid var(--border)",
        padding: "0.5rem 1.5rem",
        display: "flex",
        alignItems: "center",
        gap: "1.5rem",
        fontSize: "0.8rem",
        maxHeight: "60px",
        overflowX: "auto",
      }}
    >
      <span style={{ fontWeight: 600, color: "var(--text-muted)" }}>Recent Tasks:</span>
      {jobs.slice(0, 3).map((job) => {
        const isRunning = job.status === "running" || job.status === "validating_scope";
        return (
          <div
            key={job.id}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              background: "var(--bg-surface)",
              padding: "4px 8px",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--border)",
            }}
          >
            {isRunning ? (
              <Loader2 size={12} className="animate-spin" color="var(--accent)" />
            ) : job.status === "completed" ? (
              <CheckCircle2 size={12} color="var(--success)" />
            ) : (
              <AlertTriangle size={12} color="var(--warning)" />
            )}
            <span style={{ fontFamily: "var(--font-mono)" }}>{job.job_type}</span>
            <span style={{ color: "var(--text-muted)" }}>({job.status})</span>
            {isRunning && (
              <button
                onClick={() => onCancelJob(job.id)}
                style={{
                  background: "transparent",
                  border: "none",
                  cursor: "pointer",
                  color: "var(--error)",
                  display: "flex",
                  alignItems: "center",
                }}
                title="Cancel Job"
              >
                <XCircle size={14} />
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
};
