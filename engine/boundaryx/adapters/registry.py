import logging
from pathlib import Path
import sys
from typing import Any, Dict, List

import yaml

from boundaryx.adapters.base import ToolAdapter
from boundaryx.adapters.httpx import HttpxAdapter
from boundaryx.adapters.subfinder import SubfinderAdapter

logger = logging.getLogger("boundaryx.adapters.registry")


class GenericCliAdapter(ToolAdapter):
    """Fallback adapter for manifest tools like dnsx, katana, nuclei, ffuf."""

    def __init__(self, tool_id: str, executable: str, capability: str, network_activity: str):
        super().__init__(executable)
        self.tool_id = tool_id
        self._capability = capability
        self._network_activity = network_activity

    def version(self) -> str:
        bin_path = self.get_binary_path()
        if not bin_path:
            return "unknown"
        try:
            code, out, err = self.supervisor.run_command([bin_path, "-version"], timeout_seconds=10)
            text = (out + err).strip()
            return text.split("\n")[0] if text else "unknown"
        except Exception:
            return "unknown"

    def capabilities(self) -> Dict[str, Any]:
        return {
            "name": self.tool_id,
            "operation": self._capability,
            "network_activity": self._network_activity,
            "output_format": "jsonl",
            "supports_cancellation": True,
        }

    def validate_config(self, config: Dict[str, Any]) -> None:
        pass

    def build_argv(self, targets: List[str], config: Dict[str, Any]) -> List[str]:
        bin_path = self.get_binary_path()
        if not bin_path:
            raise RuntimeError(f"{self.tool_id} binary not found")
        argv = [bin_path, "-silent"]
        argv.extend(targets)
        return argv

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        return [{"raw": line} for line in stdout.splitlines() if line.strip()]


class ToolRegistry:
    """
    Manages discovery and lifecycle of external security tools based on tool-manifest.yaml.
    Guarantees no silent downloads and transparent capability reporting.
    """

    def __init__(self, manifest_path: Path):
        self.manifest_path = Path(manifest_path)
        self.manifest_data = self._load_manifest()
        self.adapters: Dict[str, ToolAdapter] = {}
        self._init_adapters()

    def _load_manifest(self) -> Dict[str, Any]:
        candidates = [self.manifest_path]
        if hasattr(sys, "_MEIPASS"):
            candidates.append(Path(sys._MEIPASS) / "config" / "tool-manifest.yaml")
        candidates.extend([
            Path(__file__).resolve().parent.parent.parent.parent / "config" / "tool-manifest.yaml",
            Path(__file__).resolve().parent.parent.parent / "config" / "tool-manifest.yaml",
            Path.cwd() / "config" / "tool-manifest.yaml",
        ])

        target = None
        for cand in candidates:
            if cand and cand.exists():
                target = cand
                break

        if not target:
            logger.warning("Manifest not found at %s or fallback paths. Using standard tool registry default.", self.manifest_path)
            return {
                "tools": [
                    {"id": "subfinder", "title": "Subfinder", "executable": "subfinder", "capability": "passive_subdomain_discovery", "network_activity": "provider_dependent_passive"},
                    {"id": "dnsx", "title": "dnsx", "executable": "dnsx", "capability": "dns_resolution", "network_activity": "active_dns"},
                    {"id": "httpx", "title": "httpx", "executable": "httpx", "capability": "http_probe_metadata", "network_activity": "active_http"},
                    {"id": "katana", "title": "Katana", "executable": "katana", "capability": "bounded_web_crawl", "network_activity": "active_http"},
                    {"id": "nuclei", "title": "Nuclei", "executable": "nuclei", "capability": "selected_template_checks", "network_activity": "active_http"},
                    {"id": "ffuf", "title": "ffuf", "executable": "ffuf", "capability": "bounded_path_or_parameter_fuzzing", "network_activity": "active_http"},
                ]
            }

        try:
            with open(target, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {"tools": []}
        except Exception as e:
            logger.error("Failed to parse tool manifest: %s", e)
            return {"tools": []}

    def _init_adapters(self) -> None:
        for tool in self.manifest_data.get("tools", []):
            tid = tool.get("id")
            executable = tool.get("executable", tid)

            if tid == "subfinder":
                self.adapters[tid] = SubfinderAdapter()
            elif tid == "httpx":
                self.adapters[tid] = HttpxAdapter()
            else:
                self.adapters[tid] = GenericCliAdapter(
                    tool_id=tid,
                    executable=executable,
                    capability=tool.get("capability", "unknown"),
                    network_activity=tool.get("network_activity", "passive"),
                )

    def get_tool_status(self, tool_id: str) -> Dict[str, Any]:
        adapter = self.adapters.get(tool_id)
        tool_spec = next((t for t in self.manifest_data.get("tools", []) if t.get("id") == tool_id), {})

        if not adapter:
            return {"id": tool_id, "status": "unknown"}

        installed = adapter.detect()
        ver = adapter.version() if installed else "not_installed"
        healthy, message = adapter.health_check() if installed else (False, "Not installed")

        return {
            "id": tool_id,
            "title": tool_spec.get("title", tool_id),
            "executable": tool_spec.get("executable", tool_id),
            "class": tool_spec.get("class", "recon"),
            "status": "installed" if installed else "missing",
            "detected_version": ver,
            "is_healthy": healthy,
            "health_message": message,
            "official_homepage": tool_spec.get("official_homepage"),
            "docs_url": tool_spec.get("docs_url"),
            "active_by_default": tool_spec.get("active_by_default", False),
            "network_activity": tool_spec.get("network_activity", "passive"),
        }

    def list_all_tools(self) -> List[Dict[str, Any]]:
        return [self.get_tool_status(t.get("id")) for t in self.manifest_data.get("tools", [])]
