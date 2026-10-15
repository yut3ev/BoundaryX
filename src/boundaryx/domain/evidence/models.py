"""Evidence models and cryptographic integrity verification for BoundaryX.

Provides immutable HTTP request/response snapshots, policy evaluation snapshots,
and SHA-256 cryptographic proof for authorization test results.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> datetime:
    """Return the current timestamp in UTC timezone."""
    return datetime.now(UTC)


class EvidenceType(StrEnum):
    """Categorization of collected authorization testing evidence."""

    REQUEST_RESPONSE = "REQUEST_RESPONSE"
    POLICY_EVALUATION = "POLICY_EVALUATION"
    SCREENSHOT = "SCREENSHOT"
    LOG_ENTRY = "LOG_ENTRY"
    MANUAL_NOTE = "MANUAL_NOTE"
    IMPORTED_TRAFFIC = "IMPORTED_TRAFFIC"


class HttpSnapshot(BaseModel):
    """Normalized snapshot of an HTTP request or response exchanged during testing."""

    model_config = ConfigDict(from_attributes=True)

    method: str | None = Field(default=None, description="HTTP method (GET, POST, PUT, DELETE, etc.)")
    url: str | None = Field(default=None, description="Target request URL or URI path")
    headers: dict[str, str] = Field(default_factory=dict, description="Captured HTTP headers")
    body: str | None = Field(default=None, description="Request/Response payload content")
    status_code: int | None = Field(default=None, description="HTTP status code (for responses)")
    content_type: str | None = Field(default=None, description="MIME content type")


class Evidence(BaseModel):
    """Cryptographically verifiable evidence record supporting an audit finding or test result."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4, description="Unique evidence record identifier")
    project_id: UUID = Field(default_factory=uuid4, description="Parent project context ID")
    evidence_type: EvidenceType = Field(description="Evidence category")
    title: str = Field(description="Brief evidence title or summary")
    description: str = Field(default="", description="Detailed contextual description")
    request_snapshot: HttpSnapshot | None = Field(
        default=None,
        description="Outbound HTTP test request snapshot (if applicable)",
    )
    response_snapshot: HttpSnapshot | None = Field(
        default=None,
        description="Inbound HTTP test response snapshot (if applicable)",
    )
    policy_evaluation_snapshot: dict[str, Any] | None = Field(
        default=None,
        description="Policy rule snapshot at the time of evaluation",
    )
    identity_context: dict[str, Any] | None = Field(
        default=None,
        description="Identity attributes and claims active during execution",
    )
    resource_context: dict[str, Any] | None = Field(
        default=None,
        description="Resource state and attributes active during execution",
    )
    test_execution_id: UUID | None = Field(
        default=None,
        description="Linked test execution job/run ID",
    )
    timestamp: datetime = Field(
        default_factory=_utc_now,
        description="Evidence capture timestamp (UTC)",
    )
    content_hash: str = Field(
        default="",
        description="Cryptographic SHA-256 hash of the evidence payload",
    )
    sanitization_applied: list[str] = Field(
        default_factory=list,
        description="List of applied redacting or masking sanitizations (e.g. 'token_masked')",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional technical metadata (e.g. latency, worker ID)",
    )
    created_at: datetime = Field(
        default_factory=_utc_now,
        description="Record creation timestamp (UTC)",
    )

    def model_post_init(self, __context: Any) -> None:
        """Ensure content_hash is computed if not explicitly provided."""
        super().model_post_init(__context)
        if not self.content_hash:
            self.compute_content_hash()

    def compute_content_hash(self) -> str:
        """Compute the deterministic SHA-256 cryptographic digest of the evidence content.

        Serializes all core content fields (snapshots, contexts, descriptions)
        into a canonical JSON representation and calculates the SHA-256 digest.

        Returns:
            Hex-encoded SHA-256 hash string.
        """
        canonical_dict = {
            "evidence_type": self.evidence_type.value,
            "title": self.title,
            "description": self.description,
            "request_snapshot": (
                {
                    "method": self.request_snapshot.method,
                    "url": self.request_snapshot.url,
                    "headers": sorted(self.request_snapshot.headers.items()),
                    "body": self.request_snapshot.body,
                    "status_code": self.request_snapshot.status_code,
                    "content_type": self.request_snapshot.content_type,
                }
                if self.request_snapshot
                else None
            ),
            "response_snapshot": (
                {
                    "method": self.response_snapshot.method,
                    "url": self.response_snapshot.url,
                    "headers": sorted(self.response_snapshot.headers.items()),
                    "body": self.response_snapshot.body,
                    "status_code": self.response_snapshot.status_code,
                    "content_type": self.response_snapshot.content_type,
                }
                if self.response_snapshot
                else None
            ),
            "policy_evaluation_snapshot": self.policy_evaluation_snapshot,
            "identity_context": self.identity_context,
            "resource_context": self.resource_context,
        }
        encoded = json.dumps(canonical_dict, sort_keys=True, default=str).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        self.content_hash = digest
        return digest
