import json
import re
from typing import Any, Dict, List, Tuple

from boundaryx.adapters.base import ToolAdapter


class SubfinderAdapter(ToolAdapter):
    def __init__(self, custom_path: str = None):
        super().__init__("subfinder", custom_path)

    def version(self) -> str:
        bin_path = self.get_binary_path()
        if not bin_path:
            return "unknown"
        try:
            code, out, err = self.supervisor.run_command([bin_path, "-version"], timeout_seconds=10)
            combined = out + err
            match = re.search(r"v?(\d+\.\d+\.\d+)", combined)
            return match.group(1) if match else "unknown"
        except Exception:
            return "unknown"

    def capabilities(self) -> Dict[str, Any]:
        return {
            "name": "Subfinder",
            "operation": "passive_subdomain_discovery",
            "network_activity": "passive_provider_dependent",
            "output_format": "jsonl",
            "supports_cancellation": True,
        }

    def validate_config(self, config: Dict[str, Any]) -> None:
        pass

    def build_argv(self, targets: List[str], config: Dict[str, Any]) -> List[str]:
        bin_path = self.get_binary_path()
        if not bin_path:
            raise RuntimeError("subfinder executable not found")

        argv = [bin_path, "-silent", "-json"]
        for t in targets:
            argv.extend(["-d", t])

        # Passive sources only
        if config.get("all_sources", False):
            argv.append("-all")

        return argv

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        results = []
        for line in stdout.splitlines():
            clean = line.strip()
            if not clean or not clean.startswith("{"):
                continue
            try:
                data = json.loads(clean)
                host = data.get("host")
                if host:
                    results.append({
                        "asset_type": "subdomain",
                        "value": host.lower().strip(),
                        "source": data.get("source", "subfinder"),
                        "input": data.get("input"),
                    })
            except json.JSONDecodeError:
                continue
        return results
