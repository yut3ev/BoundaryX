"""Response normalization and semantic differential engine for BoundaryX.

Provides noise elimination (timestamps, request IDs, volatile headers, token masking),
canonical JSON formatting, and structured response comparison.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

# Standard volatile header names to disregard in differential security analysis
DEFAULT_IGNORE_HEADERS: list[str] = [
    "Date",
    "X-Request-Id",
    "Set-Cookie",
    "ETag",
    "Last-Modified",
    "Server",
    "CF-RAY",
    "X-Amz-Cf-Id",
    "X-Correlation-ID",
    "X-Runtime",
    "Age",
    "Expires",
]

# Patterns for volatile transient values
ISO_TIMESTAMP_REGEX = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
UUID_REGEX = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
BEARER_TOKEN_REGEX = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.\+\/=]+")


class NormalizationConfig(BaseModel):
    """Configuration options governing response normalization and noise removal."""

    model_config = ConfigDict(from_attributes=True)

    remove_request_ids: bool = Field(
        default=True,
        description="Whether to scrub random UUIDs and request-id headers",
    )
    ignore_timestamps: bool = Field(
        default=True,
        description="Whether to scrub temporal headers and ISO-8601 timestamp strings",
    )
    ignore_headers: list[str] = Field(
        default_factory=lambda: list(DEFAULT_IGNORE_HEADERS),
        description="List of HTTP header names to exclude from comparisons (case-insensitive)",
    )
    normalize_json_ordering: bool = True
    mask_tokens: bool = Field(
        default=True,
        description="Whether to mask tokens, auth headers, and JWT patterns",
    )
    compare_fields: list[str] = Field(
        default_factory=list,
        description="Specific fields to restrict comparison to (empty = compare all fields)",
    )


class NormalizationEngine:
    """Engine responsible for normalizing HTTP responses and computing structural diffs."""

    def __init__(self, default_config: NormalizationConfig | None = None) -> None:
        """Initialize NormalizationEngine with default configuration."""
        self._default_config = default_config or NormalizationConfig()

    def normalize_json(self, json_str: str) -> str:
        """Parse JSON string, sort object keys recursively, and format deterministically.

        Args:
            json_str: Raw JSON payload string.

        Returns:
            Normalized, sorted JSON string with consistent indentation,
            or original string if not valid JSON.
        """
        if not json_str or not isinstance(json_str, str):
            return ""

        trimmed = json_str.strip()
        if not (
            (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]"))
        ):
            return trimmed

        try:
            parsed = json.loads(trimmed)
            return json.dumps(parsed, indent=2, sort_keys=True)
        except Exception:
            return trimmed

    def normalize_response(
        self,
        response: dict[str, Any],
        config: NormalizationConfig | None = None,
    ) -> dict[str, Any]:
        """Apply all configured normalizations to an HTTP response snapshot dictionary.

        Args:
            response: Response snapshot dict (status_code, headers, body, content_type, etc.).
            config: Optional NormalizationConfig override.

        Returns:
            Sanitized, normalized response dictionary.
        """
        cfg = config or self._default_config
        norm = copy.deepcopy(response)

        # 1. Normalize Headers
        raw_headers = norm.get("headers") or {}
        if isinstance(raw_headers, dict):
            ignore_set = {h.lower() for h in cfg.ignore_headers}
            clean_headers: dict[str, str] = {}

            for k, v in raw_headers.items():
                lower_k = str(k).strip().lower()

                # Check if ignored header
                if lower_k in ignore_set:
                    continue

                val_str = str(v) if v is not None else ""

                # Token masking in headers
                if cfg.mask_tokens:
                    if lower_k in ("authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"):
                        val_str = "<TOKEN_MASKED>"
                    else:
                        val_str = BEARER_TOKEN_REGEX.sub("Bearer <TOKEN_MASKED>", val_str)
                        val_str = JWT_REGEX.sub("<JWT_MASKED>", val_str)

                # Scrub request IDs in headers
                if cfg.remove_request_ids and ("request" in lower_k or "correlation" in lower_k or "trace" in lower_k):
                    continue

                # Scrub timestamps in headers
                if cfg.ignore_timestamps and lower_k in ("date", "expires", "last-modified", "age"):
                    continue

                clean_headers[k] = val_str

            norm["headers"] = clean_headers

        # 2. Normalize Body
        body = norm.get("body")
        if body and isinstance(body, str):
            norm_body = body

            # Mask tokens in body
            if cfg.mask_tokens:
                norm_body = BEARER_TOKEN_REGEX.sub("Bearer <TOKEN_MASKED>", norm_body)
                norm_body = JWT_REGEX.sub("<JWT_MASKED>", norm_body)

            # Scrub timestamps in body
            if cfg.ignore_timestamps:
                norm_body = ISO_TIMESTAMP_REGEX.sub("<TIMESTAMP_NORMALIZED>", norm_body)

            # Scrub request IDs / UUIDs in body
            if cfg.remove_request_ids:
                norm_body = UUID_REGEX.sub("<UUID_NORMALIZED>", norm_body)

            # Normalize JSON ordering
            if cfg.normalize_json_ordering:
                norm_body = self.normalize_json(norm_body)

            norm["body"] = norm_body

        return norm

    def diff_responses(
        self,
        a: dict[str, Any],
        b: dict[str, Any],
        config: NormalizationConfig | None = None,
    ) -> list[dict[str, Any]]:
        """Compute structured difference items between two response snapshots.

        Normalizes both responses according to configuration before performing diffs.

        Args:
            a: First response snapshot dictionary.
            b: Second response snapshot dictionary.
            config: Optional NormalizationConfig override.

        Returns:
            List of difference dictionaries with format:
            {"field": str, "value_a": Any, "value_b": Any, "difference_type": str}
        """
        cfg = config or self._default_config
        norm_a = self.normalize_response(a, cfg)
        norm_b = self.normalize_response(b, cfg)

        differences: list[dict[str, Any]] = []

        fields_to_compare = cfg.compare_fields if cfg.compare_fields else ["status_code", "headers", "body"]

        # 1. Compare Status Code
        if "status_code" in fields_to_compare:
            sc_a = norm_a.get("status_code")
            sc_b = norm_b.get("status_code")
            if sc_a != sc_b:
                differences.append(
                    {
                        "field": "status_code",
                        "value_a": sc_a,
                        "value_b": sc_b,
                        "difference_type": "VALUE_MISMATCH",
                    }
                )

        # 2. Compare Headers
        if "headers" in fields_to_compare:
            headers_a = norm_a.get("headers") or {}
            headers_b = norm_b.get("headers") or {}

            # Map lowercase keys
            h_map_a = {str(k).lower(): (k, v) for k, v in headers_a.items()}
            h_map_b = {str(k).lower(): (k, v) for k, v in headers_b.items()}

            all_keys = set(h_map_a.keys()).union(h_map_b.keys())
            for k in sorted(all_keys):
                in_a = k in h_map_a
                in_b = k in h_map_b

                if in_a and not in_b:
                    orig_k, val = h_map_a[k]
                    differences.append(
                        {
                            "field": f"headers.{orig_k}",
                            "value_a": val,
                            "value_b": None,
                            "difference_type": "REMOVED",
                        }
                    )
                elif in_b and not in_a:
                    orig_k, val = h_map_b[k]
                    differences.append(
                        {
                            "field": f"headers.{orig_k}",
                            "value_a": None,
                            "value_b": val,
                            "difference_type": "ADDED",
                        }
                    )
                else:
                    orig_k, val_a = h_map_a[k]
                    _, val_b = h_map_b[k]
                    if val_a != val_b:
                        differences.append(
                            {
                                "field": f"headers.{orig_k}",
                                "value_a": val_a,
                                "value_b": val_b,
                                "difference_type": "VALUE_MISMATCH",
                            }
                        )

        # 3. Compare Body
        if "body" in fields_to_compare:
            body_a = norm_a.get("body") or ""
            body_b = norm_b.get("body") or ""

            # Attempt structured JSON diff
            json_diff_done = False
            if (body_a.startswith("{") or body_a.startswith("[")) and (
                body_b.startswith("{") or body_b.startswith("[")
            ):
                try:
                    obj_a = json.loads(body_a)
                    obj_b = json.loads(body_b)
                    self._diff_json_nodes(obj_a, obj_b, "body", differences)
                    json_diff_done = True
                except Exception:
                    json_diff_done = False

            if not json_diff_done and body_a != body_b:
                differences.append(
                    {
                        "field": "body",
                        "value_a": body_a,
                        "value_b": body_b,
                        "difference_type": "VALUE_MISMATCH",
                    }
                )

        return differences

    def _diff_json_nodes(
        self,
        node_a: Any,
        node_b: Any,
        current_path: str,
        differences: list[dict[str, Any]],
    ) -> None:
        """Recursively compare two JSON nodes and record differences."""
        if type(node_a) is not type(node_b):
            differences.append(
                {
                    "field": current_path,
                    "value_a": node_a,
                    "value_b": node_b,
                    "difference_type": "TYPE_MISMATCH",
                }
            )
            return

        if isinstance(node_a, dict):
            keys_a = set(node_a.keys())
            keys_b = set(node_b.keys())
            all_keys = keys_a.union(keys_b)

            for key in sorted(all_keys):
                child_path = f"{current_path}.{key}"
                if key in keys_a and key not in keys_b:
                    differences.append(
                        {
                            "field": child_path,
                            "value_a": node_a[key],
                            "value_b": None,
                            "difference_type": "REMOVED",
                        }
                    )
                elif key in keys_b and key not in keys_a:
                    differences.append(
                        {
                            "field": child_path,
                            "value_a": None,
                            "value_b": node_b[key],
                            "difference_type": "ADDED",
                        }
                    )
                else:
                    self._diff_json_nodes(node_a[key], node_b[key], child_path, differences)
            return

        if isinstance(node_a, list):
            len_a = len(node_a)
            len_b = len(node_b)
            max_len = max(len_a, len_b)

            for i in range(max_len):
                child_path = f"{current_path}[{i}]"
                if i < len_a and i >= len_b:
                    differences.append(
                        {
                            "field": child_path,
                            "value_a": node_a[i],
                            "value_b": None,
                            "difference_type": "REMOVED",
                        }
                    )
                elif i < len_b and i >= len_a:
                    differences.append(
                        {
                            "field": child_path,
                            "value_a": None,
                            "value_b": node_b[i],
                            "difference_type": "ADDED",
                        }
                    )
                else:
                    self._diff_json_nodes(node_a[i], node_b[i], child_path, differences)
            return

        # Scalar values
        if node_a != node_b:
            differences.append(
                {
                    "field": current_path,
                    "value_a": node_a,
                    "value_b": node_b,
                    "difference_type": "VALUE_MISMATCH",
                }
            )
