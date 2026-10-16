export interface Program {
  id: string;
  name: string;
  policy_url?: string;
  description?: string;
  created_at: string;
}

export interface ScopeRule {
  id: string;
  program_id: string;
  rule_type: "include" | "exclude";
  matcher_type: "domain" | "url_prefix" | "ip" | "cidr";
  pattern: string;
  scheme?: string;
  port?: number;
  wildcard: boolean;
  notes?: string;
}

export interface ScopeDecision {
  is_in_scope: boolean;
  status: "in_scope" | "out_of_scope" | "unknown";
  canonical_host: string;
  canonical_path: string;
  matched_rule_id?: string;
  denial_reason?: string;
}

export interface Asset {
  id: string;
  program_id: string;
  asset_type: "domain" | "subdomain" | "ip" | "url" | "endpoint" | "service";
  canonical_value: string;
  display_value: string;
  scope_status: "in_scope" | "out_of_scope" | "unknown";
  importance: number;
  created_at: string;
}

export interface Job {
  id: string;
  program_id: string;
  job_type: string;
  status: "queued" | "validating_scope" | "running" | "cancelling" | "cancelled" | "completed" | "partial" | "failed" | "interrupted";
  config_json: Record<string, any>;
  summary_json: Record<string, any>;
  created_at: string;
}

export interface Finding {
  id: string;
  program_id: string;
  asset_id?: string;
  title: string;
  category: string;
  severity: "unrated" | "info" | "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high" | "confirmed";
  status: "candidate" | "needs_review" | "verified" | "false_positive" | "accepted_risk" | "fixed" | "reopened";
  impact?: string;
  actual_behavior?: string;
  expected_behavior?: string;
  reproduction_steps_md?: string;
  remediation_md?: string;
  evidence_ids: string[];
}

export interface ToolStatus {
  id: string;
  title: string;
  executable: string;
  status: "installed" | "missing" | "incompatible";
  detected_version: string;
  is_healthy: boolean;
  health_message: string;
  official_homepage?: string;
  docs_url?: string;
  active_by_default: boolean;
  network_activity: string;
}

class IPCClient {
  private isTauriAvailable(): boolean {
    return typeof window !== "undefined" && (window as any).__TAURI_INTERNALS__ !== undefined;
  }

  async sendCommand<T>(command: string, payload: Record<string, any> = {}): Promise<T> {
    const requestId = `req-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    
    if (this.isTauriAvailable()) {
      const { invoke } = await import("@tauri-apps/api/core");
      return await invoke<T>("ipc_command", { requestId, command, payload });
    }

    // Fallback: Local storage & memory simulation for development/testing
    return this.mockDispatcher<T>(command, payload);
  }

  private mockDispatcher<T>(command: string, payload: Record<string, any>): T {
    // In-memory/localStorage mock when previewing in browser
    const storageKey = `boundaryx_mock_${command.split(".")[0]}`;
    const raw = localStorage.getItem(storageKey);
    let items: any[] = raw ? JSON.parse(raw) : [];

    if (command === "ping") {
      return { pong: true, mode: "browser_preview" } as unknown as T;
    }

    if (command === "programs.list") {
      if (items.length === 0) {
        // Seed default program for empty workbench preview
        items = [{ id: "p-default", name: "Acme Bug Bounty", policy_url: "https://hackerone.com/acme", created_at: new Date().toISOString() }];
        localStorage.setItem(storageKey, JSON.stringify(items));
      }
      return items as unknown as T;
    }

    if (command === "programs.create") {
      const newProg: Program = {
        id: `p-${Date.now()}`,
        name: payload.name,
        policy_url: payload.policy_url,
        description: payload.description,
        created_at: new Date().toISOString(),
      };
      items.unshift(newProg);
      localStorage.setItem(storageKey, JSON.stringify(items));
      return newProg as unknown as T;
    }

    if (command === "scope.list") {
      const rules = JSON.parse(localStorage.getItem("boundaryx_mock_rules") || "[]");
      return rules.filter((r: any) => r.program_id === payload.program_id) as unknown as T;
    }

    if (command === "scope.create_rule") {
      const rules = JSON.parse(localStorage.getItem("boundaryx_mock_rules") || "[]");
      const newRule: ScopeRule = {
        id: `rule-${Date.now()}`,
        program_id: payload.program_id,
        rule_type: payload.rule_type || "include",
        matcher_type: payload.matcher_type || "domain",
        pattern: payload.pattern,
        wildcard: !!payload.wildcard,
        notes: payload.notes,
      };
      rules.push(newRule);
      localStorage.setItem("boundaryx_mock_rules", JSON.stringify(rules));
      return newRule as unknown as T;
    }

    if (command === "scope.evaluate") {
      const target = (payload.target || "").toLowerCase();
      const isOut = target.includes("evil") || target.includes("notallowed");
      return {
        is_in_scope: !isOut,
        status: !isOut ? "in_scope" : "out_of_scope",
        canonical_host: target.replace(/^https?:\/\//, "").split("/")[0],
        canonical_path: "/",
        denial_reason: isOut ? "Target matches explicit exclusion boundary" : undefined,
      } as unknown as T;
    }

    if (command === "tools.registry") {
      return [
        { id: "subfinder", title: "Subfinder", executable: "subfinder", status: "installed", detected_version: "v2.6.8", is_healthy: true, health_message: "Ready", active_by_default: false, network_activity: "passive_provider_dependent" },
        { id: "dnsx", title: "dnsx", executable: "dnsx", status: "installed", detected_version: "v1.2.1", is_healthy: true, health_message: "Ready", active_by_default: false, network_activity: "active_dns" },
        { id: "httpx", title: "httpx", executable: "httpx", status: "installed", detected_version: "v1.6.9", is_healthy: true, health_message: "Ready", active_by_default: false, network_activity: "active_http" },
        { id: "katana", title: "Katana", executable: "katana", status: "missing", detected_version: "not_installed", is_healthy: false, health_message: "Executable not found", active_by_default: false, network_activity: "active_http" },
        { id: "nuclei", title: "Nuclei", executable: "nuclei", status: "missing", detected_version: "not_installed", is_healthy: false, health_message: "Executable not found", active_by_default: false, network_activity: "active_http" },
        { id: "ffuf", title: "ffuf", executable: "ffuf", status: "missing", detected_version: "not_installed", is_healthy: false, health_message: "Executable not found", active_by_default: false, network_activity: "active_http" },
      ] as unknown as T;
    }

    return [] as unknown as T;
  }
}

export const ipc = new IPCClient();
