import json
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

import yaml

from boundaryx.domain.enums import AssetType, ScopeStatus
from boundaryx.domain.models import Asset
from boundaryx.scope.guard import ScopeGuard
from boundaryx.storage.repositories import AssetRepository

MAX_OPENAPI_FILE_BYTES = 10 * 1024 * 1024  # 10 MB


class OpenAPIImportError(ValueError):
    pass


class OpenAPIImporter:
    """
    Parses OpenAPI 2.0 / 3.0 / 3.1 specifications in JSON or YAML format.
    Extracts API endpoints and parameters into normalized inventory assets.
    Enforces safe YAML parsing and size bounds.
    """

    def __init__(self, asset_repo: AssetRepository):
        self.asset_repo = asset_repo

    def import_file(self, file_path: Path, program_id: str, scope_guard: ScopeGuard) -> List[Asset]:
        path = Path(file_path)
        if not path.exists():
            raise OpenAPIImportError(f"File not found: {file_path}")

        file_size = path.stat().st_size
        if file_size > MAX_OPENAPI_FILE_BYTES:
            raise OpenAPIImportError(f"OpenAPI file size exceeds limit: {file_size} bytes")

        raw_content = path.read_text(encoding="utf-8", errors="replace")

        # Parse YAML or JSON safely
        try:
            if raw_content.strip().startswith("{"):
                spec = json.loads(raw_content)
            else:
                spec = yaml.safe_load(raw_content)
        except Exception as e:
            raise OpenAPIImportError(f"Failed to parse OpenAPI YAML/JSON: {str(e)}") from e

        if not isinstance(spec, dict):
            raise OpenAPIImportError("OpenAPI specification must be a dictionary")

        # Extract base host / servers
        base_host = ""
        if "servers" in spec and isinstance(spec["servers"], list) and spec["servers"]:
            server_url = spec["servers"][0].get("url", "")
            if server_url.startswith("http"):
                base_host = urlparse(server_url).hostname or ""
            else:
                base_host = server_url
        elif "host" in spec:
            base_host = spec.get("host", "")

        paths = spec.get("paths", {})
        created_assets: List[Asset] = []

        for route, route_item in paths.items():
            if not isinstance(route_item, dict):
                continue

            for method in ("get", "post", "put", "delete", "patch", "options", "head"):
                if method in route_item:
                    op = route_item[method]
                    op_id = op.get("operationId", "")
                    target_repr = f"{base_host}{route}" if base_host else route

                    dec = scope_guard.evaluate(target_repr if "://" in target_repr else f"https://{target_repr}")

                    asset = Asset(
                        program_id=program_id,
                        asset_type=AssetType.ENDPOINT,
                        canonical_value=f"{method.upper()} {route}",
                        display_value=f"[{method.upper()}] {route}",
                        scope_status=dec.status if dec.canonical_host != "invalid" else ScopeStatus.UNKNOWN,
                        importance=2,
                    )
                    self.asset_repo.upsert(asset)
                    created_assets.append(asset)

        return created_assets
