"""Raw HTTP request/response text file importer for BoundaryX."""

from __future__ import annotations

import logging
import re
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


class RawHttpImporter:
    """Imports raw HTTP traffic text files.

    Supports:
    - Complete request and response pairs separated by boundaries.
    - Standalone raw HTTP requests (e.g., Burp Suite 'Copy to file' or raw request exports).
    """

    MAX_FILE_SIZE = MAX_FILE_SIZE
    MAX_ENTRY_BODY_SIZE = MAX_ENTRY_BODY_SIZE

    def import_file(self, file_path: Path | str, project_id: UUID) -> ImportResult:
        """Import raw HTTP request/response traffic pairs from a file.

        Args:
            file_path: Path to the raw HTTP file.
            project_id: UUID of the owning project.

        Returns:
            ImportResult containing parsed traffic records.
        """
        path = Path(file_path).resolve()
        result = ImportResult(source_file=str(path))

        raw_content = self._read_file_safely(path, result)
        if raw_content is None:
            return result

        # Split entries by common multi-record delimiters if present
        raw_blocks = self._split_entries(raw_content)
        result.total_entries = len(raw_blocks)

        for idx, block in enumerate(raw_blocks):
            if not block.strip():
                result.skipped_count += 1
                continue

            try:
                record = self._parse_paired_block(block, idx, project_id, result)
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
                        "message": "Failed to parse raw HTTP block",
                        "details": str(exc),
                    }
                )

        return result

    def import_request_file(self, file_path: Path | str, project_id: UUID) -> ImportResult:
        """Import standalone raw HTTP request(s) without response.

        Args:
            file_path: Path to the raw request file.
            project_id: UUID of the owning project.

        Returns:
            ImportResult containing parsed request records.
        """
        path = Path(file_path).resolve()
        result = ImportResult(source_file=str(path))

        raw_content = self._read_file_safely(path, result)
        if raw_content is None:
            return result

        raw_blocks = self._split_entries(raw_content)
        result.total_entries = len(raw_blocks)

        for idx, block in enumerate(raw_blocks):
            if not block.strip():
                result.skipped_count += 1
                continue

            try:
                record = self._parse_request_block(block, idx, project_id, result)
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
                        "message": "Failed to parse raw request block",
                        "details": str(exc),
                    }
                )

        return result

    def _read_file_safely(self, path: Path, result: ImportResult) -> str | None:
        """Safely verify file existence, size, and read text content."""
        if not path.is_file():
            result.errors.append(
                {
                    "index": -1,
                    "message": "File not found",
                    "details": f"Target file does not exist: {path}",
                }
            )
            return None

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
                return None
        except OSError as exc:
            result.errors.append(
                {
                    "index": -1,
                    "message": "File inspection failed",
                    "details": str(exc),
                }
            )
            return None

        for enc in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                with path.open("r", encoding=enc) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue

        result.errors.append(
            {
                "index": -1,
                "message": "Encoding error",
                "details": "Failed to decode raw HTTP file with UTF-8 or Latin-1",
            }
        )
        return None

    def _split_entries(self, text: str) -> list[str]:
        """Split multiple raw traffic blocks by standard boundary delimiters."""
        # Check for standard delimiter patterns:
        # e.g., "\n=== BOUNDARY ===\n", "\n--- END ENTRY ---\n", "\n======\n"
        patterns = [
            r"\r?\n={3,}[^\r\n]*\r?\n",
            r"\r?\n-{3,}[^\r\n]*\r?\n",
        ]
        for pattern in patterns:
            parts = re.split(pattern, text)
            if len(parts) > 1:
                return [p for p in parts if p.strip()]
        return [text]

    def _parse_headers_and_body(self, text: str) -> tuple[dict[str, str], str | None]:
        """Split headers section from body section by first blank line."""
        normalized = text.replace("\r\n", "\n")
        parts = normalized.split("\n\n", 1)
        header_text = parts[0]
        body_text = parts[1] if len(parts) > 1 else None

        headers: dict[str, str] = {}
        for line in header_text.splitlines():
            line_str = line.strip()
            if not line_str or ":" not in line_str:
                continue
            name, val = line_str.split(":", 1)
            headers[name.strip()] = val.strip()

        return headers, body_text

    def _parse_request_block(
        self,
        block: str,
        index: int,
        project_id: UUID,
        result: ImportResult,
    ) -> dict[str, Any] | None:
        """Parse a standalone HTTP request block."""
        normalized = block.replace("\r\n", "\n").lstrip()
        lines = normalized.splitlines()
        if not lines:
            return None

        request_line = lines[0].strip()
        parts = request_line.split()
        if len(parts) < 2:
            result.errors.append(
                {
                    "index": index,
                    "message": "Malformed request line",
                    "details": f"Cannot parse request line: '{request_line}'",
                }
            )
            return None

        method = parts[0].upper()
        raw_path = parts[1]
        http_version = parts[2] if len(parts) >= 3 else "HTTP/1.1"

        # Content after request line
        remaining = "\n".join(lines[1:])
        headers, body = self._parse_headers_and_body(remaining)

        # Reconstruct URL from Host header if relative
        if raw_path.startswith("http://") or raw_path.startswith("https://"):
            url = raw_path
        else:
            host = headers.get("Host") or headers.get("host") or "localhost"
            scheme = "https" if ":443" in host or not host.endswith(":80") else "http"
            clean_path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
            url = f"{scheme}://{host}{clean_path}"

        if body and len(body.encode("utf-8")) > self.MAX_ENTRY_BODY_SIZE:
            body = body[: self.MAX_ENTRY_BODY_SIZE]
            result.warnings.append(f"Entry #{index}: Request body truncated to {self.MAX_ENTRY_BODY_SIZE} bytes.")

        return {
            "id": str(uuid4()),
            "project_id": str(project_id),
            "timestamp": datetime.now(UTC).isoformat(),
            "method": method,
            "url": url,
            "http_version": http_version,
            "request_headers": headers,
            "request_body": body,
            "status_code": 0,
            "response_headers": {},
            "response_body": None,
            "content_type": headers.get("Content-Type", headers.get("content-type", "")),
            "elapsed_ms": 0.0,
            "source": "raw_http_request",
        }

    def _parse_paired_block(
        self,
        block: str,
        index: int,
        project_id: UUID,
        result: ImportResult,
    ) -> dict[str, Any] | None:
        """Parse a paired HTTP request and response block."""
        normalized = block.replace("\r\n", "\n").strip()

        # Check for inline response markers:
        # e.g., "\n--- RESPONSE ---\n", "\n=== RESPONSE ===\n", or status line match "\nHTTP/1."
        resp_match = re.search(
            r"\n(?:---+\s*RESPONSE\s*---+|===+\s*RESPONSE\s*===+|HTTP\/(?:1\.[01]|2(?:\.0)?)\s+\d{3})",
            normalized,
            re.IGNORECASE,
        )

        if not resp_match:
            # Fallback to single request block
            return self._parse_request_block(normalized, index, project_id, result)

        req_text = normalized[: resp_match.start()].strip()
        resp_start_idx = resp_match.start()

        # Find response status line
        resp_section = normalized[resp_start_idx:].lstrip()
        # If response was matched on a header banner, remove the banner line
        resp_lines = resp_section.splitlines()
        first_line = resp_lines[0].strip()
        if not first_line.upper().startswith("HTTP/"):
            resp_lines = resp_lines[1:]

        if not resp_lines:
            return self._parse_request_block(req_text, index, project_id, result)

        status_line = resp_lines[0].strip()
        status_parts = status_line.split()
        status_code = 200
        if len(status_parts) >= 2 and status_parts[1].isdigit():
            status_code = int(status_parts[1])

        resp_remaining = "\n".join(resp_lines[1:])
        resp_headers, resp_body = self._parse_headers_and_body(resp_remaining)

        # Parse request part
        req_record = self._parse_request_block(req_text, index, project_id, result)
        if req_record is None:
            return None

        if resp_body and len(resp_body.encode("utf-8")) > self.MAX_ENTRY_BODY_SIZE:
            resp_body = resp_body[: self.MAX_ENTRY_BODY_SIZE]
            result.warnings.append(f"Entry #{index}: Response body truncated to {self.MAX_ENTRY_BODY_SIZE} bytes.")

        content_type = resp_headers.get("Content-Type", resp_headers.get("content-type", ""))

        req_record["status_code"] = status_code
        req_record["response_headers"] = resp_headers
        req_record["response_body"] = resp_body
        req_record["content_type"] = content_type
        req_record["source"] = "raw_http_pair"

        return req_record
