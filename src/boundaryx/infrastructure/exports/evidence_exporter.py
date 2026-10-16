"""Evidence exporter and bundle packaging module for BoundaryX.

Supports exporting individual evidence files, applying redaction,
and assembling complete evidence packages (ZIP archives) containing reports and evidence.
"""

from __future__ import annotations

import json
import logging
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from boundaryx.infrastructure.exports.report_exporter import ReportExporter

logger = logging.getLogger(__name__)


class EvidenceExportError(Exception):
    """Raised when evidence export or package bundling fails."""


class EvidenceExporter:
    """Exports and packages testing evidence and audit trails."""

    @staticmethod
    def _to_dict(item: Any) -> dict[str, Any]:
        """Convert an evidence item or model to dictionary."""
        if isinstance(item, dict):
            return dict(item)
        if hasattr(item, "to_dict") and callable(item.to_dict):
            return item.to_dict()
        if hasattr(item, "__dict__"):
            return vars(item)
        return {"data": str(item)}

    @classmethod
    def export_evidence(
        cls,
        evidence_list: list[Any],
        output_dir: Path | str,
        redaction_engine: Any | None = None,
    ) -> Path:
        """Export a list of evidence items to individual JSON files in output_dir.

        Args:
            evidence_list: List of evidence records or dictionaries.
            output_dir: Target destination directory.
            redaction_engine: Optional RedactionEngine instance or callable to sanitize data.

        Returns:
            Resolved output directory Path.

        Raises:
            EvidenceExportError: If directory creation or file export fails.
        """
        dest_dir = ReportExporter._sanitize_path(output_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)

        manifest_entries: list[dict[str, Any]] = []

        for idx, raw_item in enumerate(evidence_list):
            item_dict = cls._to_dict(raw_item)

            if redaction_engine is not None:
                if hasattr(redaction_engine, "redact_evidence"):
                    item_dict = redaction_engine.redact_evidence(item_dict)
                elif callable(redaction_engine):
                    item_dict = redaction_engine(item_dict)

            evidence_id = str(item_dict.get("id") or f"ev_{idx:04d}")
            # Ensure filename is safe
            safe_id = "".join(c for c in evidence_id if c.isalnum() or c in ("-", "_"))
            file_name = f"evidence_{safe_id}.json"
            target_file = dest_dir / file_name

            try:
                with target_file.open("w", encoding="utf-8") as f:
                    json.dump(item_dict, f, indent=2, default=str)
                manifest_entries.append(
                    {
                        "id": evidence_id,
                        "file": file_name,
                        "url": item_dict.get("url", ""),
                        "timestamp": item_dict.get("timestamp", ""),
                    }
                )
            except OSError as exc:
                raise EvidenceExportError(f"Failed to write evidence item to {target_file}: {exc}") from exc

        manifest_path = dest_dir / "evidence_manifest.json"
        try:
            with manifest_path.open("w", encoding="utf-8") as f:
                json.dump({"total_items": len(manifest_entries), "items": manifest_entries}, f, indent=2)
        except OSError as exc:
            raise EvidenceExportError(f"Failed to write evidence manifest to {manifest_path}: {exc}") from exc

        logger.info("Successfully exported %d evidence items to %s", len(evidence_list), dest_dir)
        return dest_dir

    @classmethod
    def export_package(
        cls,
        report_data: dict[str, Any],
        evidence_list: list[Any],
        output_path: Path | str,
        redaction_engine: Any | None = None,
    ) -> Path:
        """Create a complete ZIP package with report (JSON, MD, HTML) and evidence files.

        Args:
            report_data: Structured report dictionary.
            evidence_list: List of evidence items to package.
            output_path: Destination path for the ZIP package file.
            redaction_engine: Optional RedactionEngine instance.

        Returns:
            Resolved output zip Path.

        Raises:
            EvidenceExportError: If packaging or zip writing fails.
        """
        zip_target = ReportExporter._sanitize_path(output_path)
        if zip_target.suffix.lower() != ".zip":
            zip_target = zip_target.with_suffix(".zip")

        with tempfile.TemporaryDirectory(prefix="boundaryx_pkg_") as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)
            evidence_sub = tmp_dir / "evidence"

            # 1. Export evidence into temporary evidence subfolder
            cls.export_evidence(evidence_list, evidence_sub, redaction_engine=redaction_engine)

            # 2. Export reports into temp directory
            ReportExporter.export_json(report_data, tmp_dir / "report.json")
            ReportExporter.export_markdown(report_data, tmp_dir / "report.md")
            ReportExporter.export_html(report_data, tmp_dir / "report.html")

            # 3. Create ZIP archive
            try:
                with zipfile.ZipFile(zip_target, "w", zipfile.ZIP_DEFLATED) as zipf:
                    for file_path in tmp_dir.rglob("*"):
                        if file_path.is_file():
                            archive_name = file_path.relative_to(tmp_dir).as_posix()
                            zipf.write(file_path, arcname=archive_name)
                logger.info("Exported evidence package ZIP to %s", zip_target)
                return zip_target
            except OSError as exc:
                raise EvidenceExportError(f"Failed to assemble package ZIP at {zip_target}: {exc}") from exc
