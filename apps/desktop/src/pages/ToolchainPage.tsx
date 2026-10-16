import React, { useState, useEffect } from "react";
import { Copy, ExternalLink, RefreshCw } from "lucide-react";
import { ToolStatus, ipc } from "../services/ipc";

export const ToolchainPage: React.FC = () => {
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    loadTools();
  }, []);

  const loadTools = async () => {
    const list = await ipc.sendCommand<ToolStatus[]>("tools.registry");
    setTools(list);
  };

  const copyCommand = (toolId: string, cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedId(toolId);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const installCommands: Record<string, string> = {
    subfinder: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    dnsx: "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    httpx: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    katana: "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    nuclei: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ffuf: "go install github.com/ffuf/ffuf/v2@latest",
  };

  return (
    <div className="page-body">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h2 style={{ fontSize: "1.4rem", fontWeight: 700 }}>Toolchain & External Registry</h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
            Modular integrations via ToolAdapter. BoundaryX never downloads or runs install scripts silently.
          </p>
        </div>
        <button className="btn btn-secondary" onClick={loadTools}>
          <RefreshCw size={14} /> Recheck Installed Tools
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: "1rem" }}>
        {tools.map((tool) => {
          const isInstalled = tool.status === "installed";
          return (
            <div
              key={tool.id}
              className="card"
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: 0,
                borderLeft: `4px solid ${isInstalled ? "var(--success)" : "var(--error)"}`,
              }}
            >
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <h3 style={{ fontSize: "1.05rem", fontWeight: 600 }}>{tool.title}</h3>
                  <span
                    className={`badge ${
                      isInstalled ? "badge-in-scope" : "badge-out-of-scope"
                    }`}
                  >
                    {tool.status}
                  </span>
                  <span className="badge badge-unrated">{tool.network_activity.replace("_", " ")}</span>
                </div>
                <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)", marginTop: "0.3rem" }}>
                  Detected Version: <strong>{tool.detected_version}</strong> | Executable: <code>{tool.executable}</code>
                </div>
              </div>

              <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                {installCommands[tool.id] && (
                  <button
                    className="btn btn-secondary"
                    style={{ fontSize: "0.75rem" }}
                    onClick={() => copyCommand(tool.id, installCommands[tool.id])}
                  >
                    <Copy size={12} /> {copiedId === tool.id ? "Copied!" : "Copy Install Command"}
                  </button>
                )}
                {tool.official_homepage && (
                  <a
                    href={tool.official_homepage}
                    target="_blank"
                    rel="noreferrer"
                    className="btn btn-secondary"
                    style={{ fontSize: "0.75rem", textDecoration: "none" }}
                  >
                    <ExternalLink size={12} /> Official Docs
                  </a>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
