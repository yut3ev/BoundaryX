"""Project management application service for BoundaryX."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import func, select

from boundaryx.infrastructure.database.models import (
    AuditEventModel,
    AuthenticationProfileModel,
    EvidenceModel,
    FindingModel,
    IdentityModel,
    PolicyModel,
    ProjectModel,
    ResourceModel,
    ScopeRuleModel,
    TenantModel,
    TestCaseModel,
    TestExecutionModel,
    TrafficRecordModel,
)
from boundaryx.infrastructure.database.repositories import ProjectRepository
from boundaryx.infrastructure.exports.project_exporter import ProjectExporter

if TYPE_CHECKING:
    from boundaryx.infrastructure.database.manager import DatabaseManager
    from boundaryx.security.audit import AuditLogger

logger = logging.getLogger(__name__)


class ProjectServiceError(Exception):
    """Base exception for ProjectService operations."""


class ProjectNotFoundError(ProjectServiceError):
    """Raised when a specified project cannot be found."""


class ConfirmationRequiredError(ProjectServiceError):
    """Raised when a destructive operation lacks a valid confirmation token."""


class ProjectService:
    """Application service coordinating project lifecycles, backups, statistics, and auditing."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        """Initialize ProjectService with database manager and optional audit logger.

        Args:
            db_manager: DatabaseManager instance managing SQLite connectivity.
            audit_logger: Optional AuditLogger for recording audit events.
        """
        self.db_manager = db_manager
        self.audit_logger = audit_logger
        self.repo = ProjectRepository()
        self._active_project_id: str | None = None

    @property
    def active_project_id(self) -> str | None:
        """Return currently opened project ID if set."""
        return self._active_project_id

    def _to_dict(self, project: ProjectModel) -> dict[str, Any]:
        """Convert ProjectModel to dictionary."""
        return {
            "id": project.id,
            "name": project.name,
            "description": project.description or "",
            "settings": dict(project.settings or {}),
            "archived": bool(project.archived),
            "created_at": project.created_at.isoformat() if project.created_at else None,
            "updated_at": project.updated_at.isoformat() if project.updated_at else None,
        }

    def _log_audit(
        self,
        event_type: str,
        description: str,
        project_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Record an audit event if audit_logger is configured."""
        if self.audit_logger is not None:
            try:
                self.audit_logger.log(
                    event_type=event_type,
                    description=description,
                    project_id=project_id,
                    details=details,
                )
            except Exception as exc:
                logger.warning("Failed to record audit event %s: %s", event_type, exc)

    def create_project(
        self,
        name: str,
        description: str = "",
        settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new security testing project workspace.

        Args:
            name: Human-readable name for the project.
            description: Optional detailed description.
            settings: Optional project configuration settings dictionary.

        Returns:
            Dictionary representing the created project.
        """
        if not name or not name.strip():
            raise ProjectServiceError("Project name cannot be empty")

        clean_name = name.strip()
        proj_id = str(uuid4())

        with self.db_manager.get_session() as session:
            project = self.repo.create(
                session=session,
                name=clean_name,
                description=description.strip() if description else None,
                settings=settings or {},
                id=proj_id,
            )
            result = self._to_dict(project)

        self._log_audit(
            event_type="PROJECT_CREATED",
            description=f"Created security assessment project '{clean_name}'",
            project_id=proj_id,
            details={"name": clean_name},
        )

        self._active_project_id = proj_id
        logger.info("Created project '%s' (ID: %s)", clean_name, proj_id)
        return result

    def open_project(self, project_id: UUID | str) -> dict[str, Any]:
        """Open an existing project and set it as active workspace.

        Args:
            project_id: Project UUID or string ID.

        Returns:
            Dictionary representing the opened project.

        Raises:
            ProjectNotFoundError: If project does not exist.
        """
        proj_str = str(project_id)
        with self.db_manager.get_session() as session:
            project = self.repo.get_by_id(session, proj_str)
            if project is None:
                raise ProjectNotFoundError(f"Project with ID '{proj_str}' not found")
            result = self._to_dict(project)

        self._active_project_id = proj_str
        self._log_audit(
            event_type="PROJECT_OPENED",
            description=f"Opened project '{result['name']}'",
            project_id=proj_str,
        )
        logger.info("Opened project '%s' (ID: %s)", result["name"], proj_str)
        return result

    def list_projects(self, include_archived: bool = False) -> list[dict[str, Any]]:
        """List all projects in the database.

        Args:
            include_archived: Whether to include archived projects.

        Returns:
            List of project dictionaries ordered by creation date descending.
        """
        with self.db_manager.get_session() as session:
            projects = self.repo.list_all(session, include_archived=include_archived)
            return [self._to_dict(p) for p in projects]

    def update_project(
        self,
        project_id: UUID | str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Update metadata or settings on an existing project.

        Args:
            project_id: Project UUID or string ID.
            **kwargs: Attributes to update (e.g. name, description, settings).

        Returns:
            Updated project dictionary.

        Raises:
            ProjectNotFoundError: If project does not exist.
        """
        proj_str = str(project_id)
        with self.db_manager.get_session() as session:
            updated = self.repo.update(session, proj_str, **kwargs)
            if updated is None:
                raise ProjectNotFoundError(f"Project with ID '{proj_str}' not found")
            result = self._to_dict(updated)

        self._log_audit(
            event_type="PROJECT_MODIFIED",
            description=f"Updated project '{result['name']}'",
            project_id=proj_str,
            details={"updated_fields": list(kwargs.keys())},
        )
        return result

    def archive_project(self, project_id: UUID | str) -> dict[str, Any]:
        """Archive a project without deleting its data.

        Args:
            project_id: Project UUID or string ID.

        Returns:
            Archived project dictionary.

        Raises:
            ProjectNotFoundError: If project does not exist.
        """
        proj_str = str(project_id)
        with self.db_manager.get_session() as session:
            archived = self.repo.archive(session, proj_str)
            if archived is None:
                raise ProjectNotFoundError(f"Project with ID '{proj_str}' not found")
            result = self._to_dict(archived)

        if self._active_project_id == proj_str:
            self._active_project_id = None

        self._log_audit(
            event_type="PROJECT_MODIFIED",
            description=f"Archived project '{result['name']}'",
            project_id=proj_str,
            details={"archived": True},
        )
        return result

    def get_delete_confirmation_token(self, project_id: UUID | str) -> str:
        """Generate the required confirmation token to permanently delete a project."""
        return f"DELETE-{project_id}"

    def delete_project(
        self,
        project_id: UUID | str,
        confirmation_token: str | None = None,
    ) -> bool:
        """Permanently delete a project and all associated data with confirmation token protection.

        Args:
            project_id: Project UUID or string ID.
            confirmation_token: Must match 'DELETE-{project_id}'.

        Returns:
            True if deleted successfully.

        Raises:
            ConfirmationRequiredError: If confirmation token is missing or invalid.
            ProjectNotFoundError: If project does not exist.
        """
        proj_str = str(project_id)
        expected_token = self.get_delete_confirmation_token(project_id)

        if confirmation_token != expected_token:
            raise ConfirmationRequiredError(
                f"Destructive operation aborted: Invalid confirmation token. "
                f"Expected confirmation_token='{expected_token}' to confirm permanent deletion."
            )

        with self.db_manager.get_session() as session:
            project = self.repo.get_by_id(session, proj_str)
            if project is None:
                raise ProjectNotFoundError(f"Project with ID '{proj_str}' not found")
            proj_name = project.name
            deleted = self.repo.delete(session, proj_str)

        if self._active_project_id == proj_str:
            self._active_project_id = None

        self._log_audit(
            event_type="PROJECT_MODIFIED",
            description=f"Permanently deleted project '{proj_name}' (ID: {proj_str})",
            project_id=proj_str,
            details={"action": "permanent_deletion"},
        )
        logger.info("Permanently deleted project '%s' (ID: %s)", proj_name, proj_str)
        return deleted

    def backup_project(
        self,
        project_id: UUID | str,
        backup_dir: Path | str,
    ) -> Path:
        """Create a dedicated JSON backup archive for the specified project.

        Args:
            project_id: Project UUID or string ID.
            backup_dir: Directory where the backup file should be placed.

        Returns:
            Resolved Path of the generated backup file.
        """
        proj_str = str(project_id)
        dest_dir = Path(backup_dir).resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)

        timestamp_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        backup_file = dest_dir / f"project_{proj_str}_{timestamp_str}.json"

        with self.db_manager.get_session() as session:
            result_path = ProjectExporter.export_project(
                session=session,
                project_id=proj_str,
                output_path=backup_file,
                include_secrets=False,
            )

        self._log_audit(
            event_type="BACKUP_CREATED",
            description=f"Created backup of project '{proj_str}' at {result_path.name}",
            project_id=proj_str,
            details={"backup_path": str(result_path)},
        )
        return result_path

    def restore_project(self, backup_path: Path | str) -> UUID:
        """Restore a project from a backup file, assigning new IDs to avoid conflicts.

        Args:
            backup_path: Path to the project backup JSON file.

        Returns:
            UUID of the newly restored project.
        """
        file_path = Path(backup_path).resolve()
        with self.db_manager.get_session() as session:
            new_id = ProjectExporter.import_project(session, file_path)

        self._log_audit(
            event_type="BACKUP_RESTORED",
            description=f"Restored project from backup {file_path.name} as new ID {new_id}",
            project_id=str(new_id),
            details={"source_file": str(file_path)},
        )
        return new_id

    def export_project(
        self,
        project_id: UUID | str,
        output_path: Path | str,
        include_secrets: bool = False,
    ) -> Path:
        """Export project data to a JSON file.

        Args:
            project_id: Project UUID or string ID.
            output_path: Target output path.
            include_secrets: Whether to include sensitive credentials in export.

        Returns:
            Resolved output Path.
        """
        proj_str = str(project_id)
        with self.db_manager.get_session() as session:
            return ProjectExporter.export_project(
                session=session,
                project_id=proj_str,
                output_path=output_path,
                include_secrets=include_secrets,
            )

    def get_project_stats(self, project_id: UUID | str) -> dict[str, Any]:
        """Compute entity counts and statistics for a given project.

        Args:
            project_id: Project UUID or string ID.

        Returns:
            Dictionary with counts of all project-associated models.

        Raises:
            ProjectNotFoundError: If project does not exist.
        """
        proj_str = str(project_id)

        with self.db_manager.get_session() as session:
            project = self.repo.get_by_id(session, proj_str)
            if project is None:
                raise ProjectNotFoundError(f"Project with ID '{proj_str}' not found")

            def _count(model: Any) -> int:
                val = session.execute(
                    select(func.count()).select_from(model).where(model.project_id == proj_str)
                ).scalar()
                return int(val or 0)

            stats = {
                "project_id": proj_str,
                "project_name": project.name,
                "archived": bool(project.archived),
                "scope_rules_count": _count(ScopeRuleModel),
                "identities_count": _count(IdentityModel),
                "auth_profiles_count": _count(AuthenticationProfileModel),
                "tenants_count": _count(TenantModel),
                "resources_count": _count(ResourceModel),
                "policies_count": _count(PolicyModel),
                "traffic_records_count": _count(TrafficRecordModel),
                "test_cases_count": _count(TestCaseModel),
                "test_executions_count": _count(TestExecutionModel),
                "findings_count": _count(FindingModel),
                "evidence_records_count": _count(EvidenceModel),
                "audit_events_count": _count(AuditEventModel),
            }

            return stats
