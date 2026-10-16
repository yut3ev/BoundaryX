import json
from pathlib import Path
from typing import List

from boundaryx.domain.enums import AssetType
from boundaryx.domain.models import Asset, HttpExchange, utc_now_iso
from boundaryx.scope.guard import ScopeGuard
from boundaryx.security.redaction import RedactionEngine
from boundaryx.storage.repositories import AssetRepository

MAX_HAR_FILE_BYTES = 100 * 1024 * 1024  # 100 MB max HAR size


class HarImportError(ValueError):
    pass


class HarImporter:
    """
    Imports HTTP Archive (HAR 1.2) files from Burp Suite, OWASP ZAP, or browser devtools.
    Enforces file size limits and scrubs credentials before returning records.
    """

    def __init__(self, asset_repo: AssetRepository, redaction_engine: RedactionEngine = None):
        self.asset_repo = asset_repo
        self.redactor = redaction_engine or RedactionEngine()

    def import_file(self, file_path: Path, program_id: str, scope_guard: ScopeGuard) -> List[HttpExchange]:
        path = Path(file_path)
        if not path.exists():
            raise HarImportError(f"File not found: {file_path}")

        file_size = path.stat().st_size
        if file_size > MAX_HAR_FILE_BYTES:
            raise HarImportError(f"HAR file size ({file_size} bytes) exceeds limit ({MAX_HAR_FILE_BYTES} bytes)")

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)
        except Exception as e:
            raise HarImportError(f"Failed to parse HAR JSON: {str(e)}") from e

        log_data = data.get("log", {})
        entries = log_data.get("entries", [])
        exchanges: List[HttpExchange] = []

        for entry in entries:
            req = entry.get("request", {})
            resp = entry.get("response", {})
            raw_url = req.get("url", "")
            if not raw_url:
                continue

            # Scope check
            decision = scope_guard.evaluate(raw_url)
            method = req.get("method", "GET").upper()

            # Redact headers
            req_headers = {h.get("name", ""): h.get("value", "") for h in req.get("headers", [])}
            resp_headers = {h.get("name", ""): h.get("value", "") for h in resp.get("headers", [])}
            redacted_req_headers = self.redactor.redact_headers(req_headers)
            redacted_resp_headers = self.redactor.redact_headers(resp_headers)
            redacted_url = self.redactor.redact_url(raw_url)

            # Register asset if in scope
            asset_id = None
            if decision.canonical_host and decision.canonical_host != "invalid":
                asset = Asset(
                    program_id=program_id,
                    asset_type=AssetType.URL,
                    canonical_value=decision.canonical_host,
                    display_value=raw_url,
                    scope_status=decision.status,
                )
                self.asset_repo.upsert(asset)
                asset_id = asset.id

            exchange = HttpExchange(
                program_id=program_id,
                asset_id=asset_id,
                source_type="har_import",
                method=method,
                url_redacted=redacted_url,
                request_headers_redacted_json=redacted_req_headers,
                response_status=resp.get("status"),
                response_headers_redacted_json=redacted_resp_headers,
                duration_ms=int(entry.get("time", 0)),
                observed_at=entry.get("startedDateTime", utc_now_iso()),
            )
            exchanges.append(exchange)

        return exchanges
