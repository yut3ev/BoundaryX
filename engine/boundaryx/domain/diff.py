from typing import Any, Dict, List, Set

from pydantic import BaseModel

from boundaryx.domain.models import Asset


class AssetDiffReport(BaseModel):
    new_assets: List[Asset]
    missing_assets: List[Asset]
    retained_assets: List[Asset]
    summary: Dict[str, Any]


def calculate_asset_diff(prior_assets: List[Asset], current_assets: List[Asset]) -> AssetDiffReport:
    """
    Computes differences between two asset snapshots.
    Note: A 'missing' asset indicates non-observation during the scan,
    not deterministic proof of asset decommission.
    """
    prior_map: Dict[str, Asset] = {f"{a.asset_type.value}:{a.canonical_value}": a for a in prior_assets}
    current_map: Dict[str, Asset] = {f"{a.asset_type.value}:{a.canonical_value}": a for a in current_assets}

    prior_keys: Set[str] = set(prior_map.keys())
    current_keys: Set[str] = set(current_map.keys())

    new_keys = current_keys - prior_keys
    missing_keys = prior_keys - current_keys
    retained_keys = prior_keys & current_keys

    new_assets = [current_map[k] for k in sorted(new_keys)]
    missing_assets = [prior_map[k] for k in sorted(missing_keys)]
    retained_assets = [current_map[k] for k in sorted(retained_keys)]

    summary = {
        "prior_count": len(prior_assets),
        "current_count": len(current_assets),
        "new_count": len(new_assets),
        "missing_count": len(missing_assets),
        "retained_count": len(retained_assets),
        "measurement_quality_note": (
            "Missing assets reflect non-observation in the current scan window; "
            "network latency or rate-limiting may cause transient omissions."
        ),
    }

    return AssetDiffReport(
        new_assets=new_assets,
        missing_assets=missing_assets,
        retained_assets=retained_assets,
        summary=summary,
    )
