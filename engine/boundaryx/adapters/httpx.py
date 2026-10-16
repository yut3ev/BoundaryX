import json
import re
from typing import Any, Dict, List

from boundaryx.adapters.base import ToolAdapter


class HttpxAdapter(ToolAdapter):
    def __init__(self, custom_path: str = None):
        super().__init__("httpx", custom_path)

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
            "name": "httpx",
            "operation": "web_probe",
            "network_activity": "active_http",
            "output_format": "jsonl",
            "supports_cancellation": True,
        }

    def validate_config(self, config: Dict[str, Any]) -> None:
        rps = config.get("rate_limit", 2)
        if rps < 1 or rps > 50:
            raise ValueError("Rate limit must be between 1 and 50 req/sec")

    def build_argv(self, targets: List[str], config: Dict[str, Any]) -> List[str]:
        bin_path = self.get_binary_path()
        if not bin_path:
            raise RuntimeError("httpx executable not found")

        rps = config.get("rate_limit", 2)
        argv = [
            bin_path,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-rate-limit",
            str(rps),
            "-follow-redirects=false",  # Manual redirect verification by BoundaryX policy
        ]
        for t in targets:
            argv.extend(["-u", t])

        return argv

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        results = []
        for line in stdout.splitlines():
            clean = line.strip()
            if not clean or not clean.startswith("{"):
                continue
            try:
                data = json.loads(clean)
                url = data.get("url")
                if url:
                    results.append({
                        "asset_type": "url",
                        "value": url,
                        "status_code": data.get("status_code"),
                        "title": data.get("title"),
                        "technologies": data.get("technologies", []),
                        "webserver": data.get("webserver"),
                        "host": data.get("host"),
                        "port": data.get("port"),
                    })
            except json.JSONDecodeError:
                continue
        return results
