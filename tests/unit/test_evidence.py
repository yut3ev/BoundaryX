"""Unit tests for Evidence and cryptographic integrity hashing."""

from uuid import UUID

from boundaryx.domain.evidence.models import (
    Evidence,
    EvidenceType,
    HttpSnapshot,
)


def test_evidence_enums() -> None:
    """Verify EvidenceType enum members."""
    assert EvidenceType.REQUEST_RESPONSE == "REQUEST_RESPONSE"
    assert EvidenceType.POLICY_EVALUATION == "POLICY_EVALUATION"
    assert EvidenceType.SCREENSHOT == "SCREENSHOT"
    assert EvidenceType.LOG_ENTRY == "LOG_ENTRY"
    assert EvidenceType.MANUAL_NOTE == "MANUAL_NOTE"
    assert EvidenceType.IMPORTED_TRAFFIC == "IMPORTED_TRAFFIC"


def test_http_snapshot_model() -> None:
    """Test HttpSnapshot model attributes."""
    snapshot = HttpSnapshot(
        method="POST",
        url="https://api.example.com/v1/orders",
        headers={"Content-Type": "application/json", "Authorization": "Bearer masked"},
        body='{"quantity": 10}',
        status_code=201,
        content_type="application/json",
    )
    assert snapshot.method == "POST"
    assert snapshot.url == "https://api.example.com/v1/orders"
    assert snapshot.status_code == 201
    assert snapshot.content_type == "application/json"
    assert snapshot.headers["Content-Type"] == "application/json"


def test_evidence_automatic_content_hash() -> None:
    """Test that Evidence auto-computes SHA-256 content hash on creation."""
    evidence = Evidence(
        evidence_type=EvidenceType.REQUEST_RESPONSE,
        title="Unauthorized order access",
        description="Captured HTTP conversation demonstrating authorization failure",
        request_snapshot=HttpSnapshot(
            method="GET",
            url="/api/orders/555",
            headers={"Host": "api.example.com"},
        ),
        response_snapshot=HttpSnapshot(
            status_code=200,
            body="Order data",
            content_type="text/plain",
        ),
    )

    assert isinstance(evidence.id, UUID)
    assert len(evidence.content_hash) == 64  # SHA-256 hex string is 64 characters
    # Recomputing manually produces identical hash
    initial_hash = evidence.content_hash
    recomputed = evidence.compute_content_hash()
    assert recomputed == initial_hash


def test_evidence_content_hash_changes_on_tampering() -> None:
    """Test that modifying snapshot content alters the calculated SHA-256 digest."""
    evidence = Evidence(
        evidence_type=EvidenceType.REQUEST_RESPONSE,
        title="Original Title",
        request_snapshot=HttpSnapshot(method="GET", url="/endpoint/1"),
    )
    original_hash = evidence.content_hash

    # Change title and recompute
    evidence.title = "Tampered Title"
    tampered_hash = evidence.compute_content_hash()

    assert original_hash != tampered_hash
