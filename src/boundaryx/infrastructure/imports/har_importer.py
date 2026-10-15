"""HAR (HTTP Archive) 1.2 file importer for BoundaryX."""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_ENTRY_BODY_SIZE = 5 * 1024 * 1024  # 5MB


@dataclass
class ImportResult:
    """Represents the outcome of a traffic import operation."""

    records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)  # {index, message, details}
    warnings: list[str] = field(default_factory=list)
    total_entries: int = 0
    imported_count: int = 0
    skipped_count: int = 0
    source_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert ImportResult to a dictionary."""
        return {
            "records_count": len(self.records),
            "errors": self.errors,
            "warnings": self.warnings,
            "total_entries": self.total_entries,
            "imported_count": self.imported_count,
            "skipped_count": self.skipped_count,
            "source_file": self.source_file,
        }


class HarImporter:
    """Importer for HTTP Archive (HAR) 1.2 files.

    Performs safe parsing, size bounding, structural validation,
    and extraction of request/response traffic records.
    """

    MAX_FILE_SIZE = MAX_FILE_SIZE
    MAX_ENTRY_BODY_SIZE = MAX_ENTRY_BODY_SIZE

    def import_file(self, file_path: Path | str, project_id: UUID) -> ImportResult:
        """Parse and import traffic entries from a HAR file.

        Args:
            file_path: Path to the .har file.
            project_id: UUID of the owning project.

        Returns:
            ImportResult containing extracted records, warnings, and errors.
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
                        "details": (
                            f"HAR file size ({file_size} bytes) exceeds maximum "
                            f"permitted limit of {self.MAX_FILE_SIZE} bytes"
                        ),
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

        # Read file with encodings fallback
        raw_text: str | None = None
        for enc in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                with path.open("r", encoding=enc) as f:
                    raw_text = f.read()
                break
            except UnicodeDecodeError:
                continue

        if raw_text is None:
            result.errors.append(
                {
                    "index": -1,
                    "message": "Encoding error",
                    "details": "Failed to decode HAR file using UTF-8 or Latin-1",
                }
            )
            return result

        try:
            har_data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            result.errors.append(
                {
                    "index": -1,
                    "message": "Invalid JSON syntax",
                    "details": f"Line {exc.lineno}, column {exc.colno}: {exc.msg}",
                }
            )
            return result

        if not isinstance(har_data, dict):
            result.errors.append(
                {
                    "index": -1,
                    "message": "Invalid HAR structure",
                    "details": "Root JSON element must be an object",
                }
            )
            return result

        log_obj = har_data.get("log")
        if not isinstance(log_obj, dict):
            result.errors.append(
                {
                    "index": -1,
                    "message": "Invalid HAR structure",
                    "details": "Missing or invalid 'log' object in root JSON",
                }
            )
            return result

        entries = log_obj.get("entries")
        if not isinstance(entries, list):
            result.errors.append(
                {
                    "index": -1,
                    "message": "Invalid HAR structure",
                    "details": "Missing or invalid 'entries' list in 'log'",
                }
            )
            return result

        result.total_entries = len(entries)

        for idx, entry in enumerate(entries):
            try:
                record = self._parse_entry(entry, idx, project_id, result)
                if record is not None:
                    result.records.append(record)
                    result.imported_count += 1
                else:
                    result.skipped_count += 1
            except Exception as exc:
                result.skipped_count += 1
                result.errors.append(
                    {
                        "index": idx,
                        "message": "Failed to parse entry",
                        "details": str(exc),
                    }
                )

        return result

    def _parse_entry(
        self,
        entry: Any,
        index: int,
        project_id: UUID,
        result: ImportResult,
    ) -> dict[str, Any] | None:
        """Parse a single HAR entry object."""
        if not isinstance(entry, dict):
            result.errors.append(
                {
                    "index": index,
                    "message": "Malformed entry",
                    "details": "Entry item is not a dictionary",
                }
            )
            return None

        req_obj = entry.get("request")
        if not isinstance(req_obj, dict):
            result.errors.append(
                {
                    "index": index,
                    "message": "Missing request",
                    "details": "Entry has no valid 'request' object",
                }
            )
            return None

        method = req_obj.get("method")
        url = req_obj.get("url")
        if not method or not url:
            result.errors.append(
                {
                    "index": index,
                    "message": "Invalid request definition",
                    "details": "Request missing 'method' or 'url'",
                }
            )
            return None

        http_version = str(req_obj.get("httpVersion", "HTTP/1.1"))
        started_date = entry.get("startedDateTime")
        timestamp = datetime.now(UTC).isoformat() if not started_date else str(started_date)

        time_ms = float(entry.get("time", 0.0) or 0.0)

        # Parse request headers
        req_headers: dict[str, str] = {}
        for h in req_obj.get("headers", []):
            if isinstance(h, dict) and "name" in h and "value" in h:
                req_headers[str(h["name"])] = str(h["value"])

        # Parse request body
        post_data = req_obj.get("postData")
        req_body = None
        if isinstance(post_data, dict):
            text = post_data.get("text", "")
            if text:
                if len(text.encode("utf-8")) > self.MAX_ENTRY_BODY_SIZE:
                    text = text[: self.MAX_ENTRY_BODY_SIZE]
                    result.warnings.append(
                        f"Entry #{index}: Request body exceeded {self.MAX_ENTRY_BODY_SIZE} bytes and was truncated."
                    )
                req_body = text

        # Parse response if present
        resp_obj = entry.get("response")
        status_code = 0
        resp_headers: dict[str, str] = {}
        resp_body = None
        content_type = ""

        if isinstance(resp_obj, dict):
            status_code = int(resp_obj.get("status", 0) or 0)
            for h in resp_obj.get("headers", []):
                if isinstance(h, dict) and "name" in h and "value" in h:
                    name = str(h["name"])
                    val = str(h["value"])
                    resp_headers[name] = val
                    if name.lower() == "content-type":
                        content_type = val

            content = resp_obj.get("content")
            if isinstance(content, dict):
                mime = str(content.get("mimeType", ""))
                if not content_type:
                    content_type = mime

                raw_text = content.get("text")
                encoding = content.get("encoding")

                if raw_text is not None:
                    if encoding == "base64":
                        try:
                            decoded_bytes = base64.b64decode(raw_text)
                            if len(decoded_bytes) > self.MAX_ENTRY_BODY_SIZE:
                                decoded_bytes = decoded_bytes[: self.MAX_ENTRY_BODY_SIZE]
                                result.warnings.append(
                                    f"Entry #{index}: Decoded response body truncated to {self.MAX_ENTRY_BODY_SIZE} bytes."
                                )
                            try:
                                resp_body = decoded_bytes.decode("utf-8")
                            except UnicodeDecodeError:
                                resp_body = f"[Binary data: {len(decoded_bytes)} bytes]"
                        except Exception:
                            resp_body = raw_text
                    else:
                        text_str = str(raw_text)
                        if len(text_str.encode("utf-8")) > self.MAX_ENTRY_BODY_SIZE:
                            text_str = text_str[: self.MAX_ENTRY_BODY_SIZE]
                            result.warnings.append(
                                f"Entry #{index}: Response body truncated to {self.MAX_ENTRY_BODY_SIZE} bytes."
                            )
                        resp_body = text_str
        else:
            result.warnings.append(f"Entry #{index}: Entry has no response object.")

        return {
            "id": str(uuid4()),
            "project_id": str(project_id),
            "timestamp": timestamp,
            "method": str(method).upper(),
            "url": str(url),
            "http_version": http_version,
            "request_headers": req_headers,
            "request_body": req_body,
            "status_code": status_code,
            "response_headers": resp_headers,
            "response_body": resp_body,
            "content_type": content_type,
            "elapsed_ms": time_ms,
            "source": "har",
        }
