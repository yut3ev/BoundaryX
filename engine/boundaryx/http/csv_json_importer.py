import csv
import json
from pathlib import Path
from typing import List

from boundaryx.domain.enums import AssetType
from boundaryx.domain.models import Asset
from boundaryx.scope.guard import ScopeGuard
from boundaryx.storage.repositories import AssetRepository


class AssetImporter:
    """Imports asset lists from CSV or JSON files with scope checking."""

    def __init__(self, asset_repo: AssetRepository):
        self.asset_repo = asset_repo

    def import_csv(self, file_path: Path, program_id: str, scope_guard: ScopeGuard) -> List[Asset]:
        path = Path(file_path)
        assets = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or not row[0].strip():
                    continue
                target = row[0].strip()
                if target.lower() in ("target", "asset", "host", "domain", "url"):
                    continue  # Header row
                dec = scope_guard.evaluate(target)
                asset = Asset(
                    program_id=program_id,
                    asset_type=AssetType.DOMAIN if "/" not in target else AssetType.URL,
                    canonical_value=dec.canonical_host if dec.canonical_host != "invalid" else target,
                    display_value=target,
                    scope_status=dec.status,
                )
                self.asset_repo.upsert(asset)
                assets.append(asset)
        return assets

    def import_json(self, file_path: Path, program_id: str, scope_guard: ScopeGuard) -> List[Asset]:
        path = Path(file_path)
        content = json.loads(path.read_text(encoding="utf-8"))
        items = content if isinstance(content, list) else content.get("assets", [])
        assets = []
        for item in items:
            val = item if isinstance(item, str) else item.get("value") or item.get("target") or item.get("host")
            if not val:
                continue
            dec = scope_guard.evaluate(val)
            asset = Asset(
                program_id=program_id,
                asset_type=AssetType.DOMAIN if "/" not in val else AssetType.URL,
                canonical_value=dec.canonical_host if dec.canonical_host != "invalid" else val,
                display_value=val,
                scope_status=dec.status,
            )
            self.asset_repo.upsert(asset)
            assets.append(asset)
        return assets
