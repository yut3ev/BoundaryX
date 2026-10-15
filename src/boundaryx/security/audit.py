"""Security audit logging module providing tamper-evident and secret-sanitized audit trails."""

from __future__ import annotations

import contextlib
import csv
import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from boundaryx.infrastructure.database.models import AuditEventModel
from boundaryx.security.exceptions import AuditLoggingError
from boundaryx.security.redaction import RedactionEngine

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Standard Audit Event Type Constants
PROJECT_CREATED = "PROJECT_CREATED"
PROJECT_MODIFIED = "PROJECT_MODIFIED"
SCOPE_CHANGED = "SCOPE_CHANGED"
IDENTITY_MODIFIED = "IDENTITY_MODIFIED"
CREDENTIAL_CHANGED = "CREDENTIAL_CHANGED"
POLICY_CHANGED = "POLICY_CHANGED"
TEST_STARTED = "TEST_STARTED"
TEST_STOPPED = "TEST_STOPPED"
FINDING_STATUS_CHANGED = "FINDING_STATUS_CHANGED"
REPORT_EXPORTED = "REPORT_EXPORTED"
BACKUP_CREATED = "BACKUP_CREATED"
BACKUP_RESTORED = "BACKUP_RESTORED"
SECURITY_ERROR = "SECURITY_ERROR"


class AuditLogger:
    """Audit logging manager for security-relevant application events.

    Ensures all logged events are sanitized so credentials or sensitive tokens
    are never written to persistent audit logs.
    """

    PROJECT_CREATED = PROJECT_CREATED
    PROJECT_MODIFIED = PROJECT_MODIFIED
    SCOPE_CHANGED = SCOPE_CHANGED
    IDENTITY_MODIFIED = IDENTITY_MODIFIED
    CREDENTIAL_CHANGED = CREDENTIAL_CHANGED
    POLICY_CHANGED = POLICY_CHANGED
    TEST_STARTED = TEST_STARTED
    TEST_STOPPED = TEST_STOPPED
    FINDING_STATUS_CHANGED = FINDING_STATUS_CHANGED
    REPORT_EXPORTED = REPORT_EXPORTED
    BACKUP_CREATED = BACKUP_CREATED
    BACKUP_RESTORED = BACKUP_RESTORED
    SECURITY_ERROR = SECURITY_ERROR

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        """Initialize AuditLogger with a database session factory.

        Args:
            session_factory: Callable returning an active SQLAlchemy Session.
        """
        self._session_factory = session_factory
        self._redactor = RedactionEngine()

    def _sanitize_details(self, details: dict[str, Any] | None) -> dict[str, Any] | None:
        """Recursively scrub credentials and secret values from audit details."""
        if details is None:
            return None
        return self._redactor.redact_evidence(details)

    def _to_uuid(self, val: uuid.UUID | str | None) -> uuid.UUID | None:
        """Coerce string or UUID representation to uuid.UUID safely."""
        if val is None:
            return None
        if isinstance(val, uuid.UUID):
            return val
        try:
            return uuid.UUID(str(val))
        except (ValueError, AttributeError):
            return None

    def log(
        self,
        event_type: str,
        description: str,
        project_id: uuid.UUID | str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEventModel:
        """Record a sanitized security audit event to the database.

        Args:
            event_type: Identifier of the event type (e.g. SCOPE_CHANGED).
            description: Human-readable description of what transpired.
            project_id: Optional UUID of the relevant project.
            details: Optional dictionary with supplementary contextual details.

        Returns:
            The created and persisted AuditEventModel instance.

        Raises:
            AuditLoggingError: If storing the audit record fails.
        """
        if not event_type:
            raise AuditLoggingError("Audit event_type cannot be empty")
        if not description:
            raise AuditLoggingError("Audit description cannot be empty")

        clean_details = self._sanitize_details(details)
        proj_uuid = self._to_uuid(project_id)

        session = self._session_factory()
        try:
            event = AuditEventModel(
                id=str(uuid.uuid4()),
                event_type=event_type,
                description=description,
                project_id=str(proj_uuid) if proj_uuid else None,
                details=clean_details,
                timestamp=datetime.now(UTC),
            )
            session.add(event)
            session.commit()
            session.refresh(event)
            logger.info("Audit event recorded: [%s] %s", event_type, description)
            return event
        except Exception as exc:
            with contextlib.suppress(Exception):
                session.rollback()
            logger.error("Failed to persist audit log event [%s]: %s", event_type, exc)
            raise AuditLoggingError(f"Failed to record audit event: {exc}") from exc
        finally:
            session.close()

    def get_events(
        self,
        project_id: uuid.UUID | str | None = None,
        event_type: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEventModel]:
        """Query persisted audit events matching filter criteria.

        Args:
            project_id: Optional project UUID to filter by.
            event_type: Optional event type string to filter by.
            since: Optional start datetime boundary (inclusive).
            until: Optional end datetime boundary (inclusive).
            limit: Maximum number of events to return (default 100).

        Returns:
            List of matching AuditEventModel instances ordered chronologically descending.
        """
        proj_uuid = self._to_uuid(project_id)
        session = self._session_factory()
        try:
            stmt = select(AuditEventModel)

            if proj_uuid is not None:
                stmt = stmt.where(AuditEventModel.project_id == str(proj_uuid))
            if event_type is not None:
                stmt = stmt.where(AuditEventModel.event_type == event_type)
            if since is not None:
                stmt = stmt.where(AuditEventModel.timestamp >= since)
            if until is not None:
                stmt = stmt.where(AuditEventModel.timestamp <= until)

            stmt = stmt.order_by(AuditEventModel.timestamp.desc()).limit(limit)
            result = session.scalars(stmt).all()
            return list(result)
        finally:
            session.close()

    def export_audit_log(
        self,
        project_id: uuid.UUID | str | None,
        output_path: Path | str,
        format: str = "json",  # noqa: A002
    ) -> Path:
        """Export audit events to a JSON or CSV file.

        Args:
            project_id: Optional project UUID filter.
            output_path: Destination file path for export.
            format: Target format ('json' or 'csv').

        Returns:
            Path to the written file.

        Raises:
            AuditLoggingError: If file writing fails or format is unsupported.
        """
        dest = Path(output_path).resolve()
        fmt = format.lower().strip()

        # Query all matching events without 100 limit
        proj_uuid = self._to_uuid(project_id)
        session = self._session_factory()
        try:
            stmt = select(AuditEventModel)
            if proj_uuid is not None:
                stmt = stmt.where(AuditEventModel.project_id == str(proj_uuid))
            stmt = stmt.order_by(AuditEventModel.timestamp.asc())
            events = list(session.scalars(stmt).all())
        finally:
            session.close()

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if fmt == "json":
                data = [event.to_dict() for event in events]
                with dest.open("w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            elif fmt == "csv":
                with dest.open("w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["id", "timestamp", "event_type", "project_id", "description", "details"])
                    for event in events:
                        writer.writerow(
                            [
                                str(event.id),
                                event.timestamp.isoformat() if event.timestamp else "",
                                event.event_type,
                                str(event.project_id) if event.project_id else "",
                                event.description,
                                json.dumps(event.details) if event.details else "",
                            ]
                        )
            else:
                raise AuditLoggingError(f"Unsupported export format '{format}'. Use 'json' or 'csv'.")

            logger.info("Exported %d audit events to %s", len(events), dest)
            return dest
        except AuditLoggingError:
            raise
        except Exception as exc:
            raise AuditLoggingError(f"Failed to export audit log to {dest}: {exc}") from exc
