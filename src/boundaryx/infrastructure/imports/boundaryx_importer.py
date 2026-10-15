"""BoundaryX native JSON traffic importer."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from boundaryx.infrastructure.imports.har_importer import (
    MAX_ENTRY_BODY_SIZE,
    MAX_FILE_SIZE,
    ImportResult,
)

logger = logging.getLogger(__name__)


class BoundaryXImporter:
    """Importer for native BoundaryX JSON traffic exchange format."""

    MAX_FILE_SIZE = MAX_FILE_SIZE
    MAX_ENTRY_BODY_SIZE = MAX_ENTRY_BODY_SIZE

    @staticmethod
    def get_schema() -> dict[str, Any]:
        """Return the JSON Schema definition for BoundaryX traffic files."""
        return {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "BoundaryXTrafficImportSchema",
            "type": "object",
            "required": ["records"],
            "properties": {
                "boundaryx_version": {
                    "type": "string",
                    "description": "Version of the BoundaryX format",
                },
                "project_id": {
                    "type": "string",
                    "description": "Source project identifier",
                },
                "exported_at": {
                    "type": "string",
                    "format": "date-time",
                    "description": "Export timestamp in ISO format",
                },
                "records": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["method", "url"],
                        "properties": {
                            "id": {"type": "string"},
                            "method": {"type": "string"},
                            "url": {"type": "string"},
                            "http_version": {"type": "string"},
                            "request_headers": {"type": "object"},
                            "request_body": {"type": ["string", "null"]},
                            "status_code": {"type": "integer"},
                            "response_headers": {"type": "object"},
                            "response_body": {"type": ["string", "null"]},
                            "content_type": {"type": "string"},
                            "elapsed_ms": {"type": "number"},
                            "timestamp": {"type": "string"},
                        },
                    },
                },
            },
        }

    def import_file(self, file_path: Path | str, project_id: UUID) -> ImportResult:
        """Import traffic records from a native BoundaryX JSON file.

        Args:
            file_path: Path to the JSON file.
            project_id: UUID of the target project.

        Returns:
            ImportResult containing parsed traffic records and any errors.
        """
        path = Path(file_path).resolve()
        result = ImportResult(source_file=str(path))

        if not path.is_file():
            result.errors.append(
                {
                    "index": -1,
                    "message": "File not found",
                    "details": f"Target file does not exist: {path}",
                }
            )
            return result

        try:
            file_size = path.stat().st_size
            if file_size > self.MAX_FILE_SIZE:
                result.errors.append(
                    {
                        "index": -1,
                        "message": "File size exceeds limit",
                        "details": f"File ({file_size} bytes) exceeds limit of {self.MAX_FILE_SIZE} bytes",
                    }
                )
                return result
        except OSError as exc:
            result.errors.append(
                {
                    "index": -1,
                    "message": "File inspection failed",
                    "details": str(exc),
                }
            )
            return result

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except UnicodeDecodeError:
            try:
                with path.open("r", encoding="latin-1") as f:
                    data = json.load(f)
            except Exception as exc:
                result.errors.append(
                    {
                        "index": -1,
                        "message": "Encoding error",
                        "details": str(exc),
                    }
                )
                return result
        except json.JSONDecodeError as exc:
            result.errors.append(
                {
                    "index": -1,
                    "message": "Invalid JSON syntax",
                    "details": f"Line {exc.lineno}, column {exc.colno}: {exc.msg}",
                }
            )
            return result

        if not isinstance(data, dict):
            result.errors.append(
                {
                    "index": -1,
                    "message": "Invalid root structure",
                    "details": "Root JSON element must be an object",
                }
            )
            return result

        # Also support { "traffic": [...] } or { "records": [...] }
        records_list = data.get("records")
        if records_list is None:
            records_list = data.get("traffic")

        if not isinstance(records_list, list):
            result.errors.append(
                {
                    "index": -1,
                    "message": "Missing records array",
                    "details": "Root object must contain a 'records' or 'traffic' array",
                }
            )
            return result

        result.total_entries = len(records_list)

        for idx, entry in enumerate(records_list):
            if not isinstance(entry, dict):
                result.skipped_count += 1
                result.errors.append(
                    {
                        "index": idx,
                        "message": "Invalid record format",
                        "details": "Entry is not a JSON object",
                    }
                )
                continue

            method = entry.get("method")
            url = entry.get("url")
            if not method or not url:
                result.skipped_count += 1
                result.errors.append(
                    {
                        "index": idx,
                        "message": "Incomplete record",
                        "details": "Entry is missing required 'method' or 'url' fields",
                    }
                )
                continue

            # Safe body extraction and bounding
            req_body = entry.get("request_body")
            if req_body and len(str(req_body).encode("utf-8")) > self.MAX_ENTRY_BODY_SIZE:
                req_body = str(req_body)[: self.MAX_ENTRY_BODY_SIZE]
                result.warnings.append(f"Entry #{idx}: Request body truncated to {self.MAX_ENTRY_BODY_SIZE} bytes.")

            resp_body = entry.get("response_body")
            if resp_body and len(str(resp_body).encode("utf-8")) > self.MAX_ENTRY_BODY_SIZE:
                resp_body = str(resp_body)[: self.MAX_ENTRY_BODY_SIZE]
                result.warnings.append(f"Entry #{idx}: Response body truncated to {self.MAX_ENTRY_BODY_SIZE} bytes.")

            req_headers = entry.get("request_headers")
            if not isinstance(req_headers, dict):
                req_headers = {}

            resp_headers = entry.get("response_headers")
            if not isinstance(resp_headers, dict):
                resp_headers = {}

            status_code = entry.get("status_code", 0)
            try:
                status_code = int(status_code)
            except (ValueError, TypeError):
                status_code = 0

            elapsed_ms = entry.get("elapsed_ms", 0.0)
            try:
                elapsed_ms = float(elapsed_ms)
            except (ValueError, TypeError):
                elapsed_ms = 0.0

            content_type = str(
                entry.get("content_type") or resp_headers.get("Content-Type") or resp_headers.get("content-type") or ""
            )

            timestamp = entry.get("timestamp") or datetime.now(UTC).isoformat()

            rec = {
                "id": str(entry.get("id") or uuid4()),
                "project_id": str(project_id),
                "timestamp": str(timestamp),
                "method": str(method).upper(),
                "url": str(url),
                "http_version": str(entry.get("http_version", "HTTP/1.1")),
                "request_headers": {str(k): str(v) for k, v in req_headers.items()},
                "request_body": req_body,
                "status_code": status_code,
                "response_headers": {str(k): str(v) for k, v in resp_headers.items()},
                "response_body": resp_body,
                "content_type": content_type,
                "elapsed_ms": elapsed_ms,
                "source": "boundaryx",
            }

            result.records.append(rec)
            result.imported_count += 1

        return result
