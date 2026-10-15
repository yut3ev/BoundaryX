"""Application service for scope management and persistence orchestration."""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, select

from boundaryx.infrastructure.database.models import ScopeRuleModel
from boundaryx.security.audit import SCOPE_CHANGED, AuditLogger
from boundaryx.security.scope import ScopeManager, ScopeRule

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class ScopeService:
    """Application service coordinating target scope rules, persistence, and audit logging."""

    def __init__(self, scope_manager: ScopeManager, audit_logger: AuditLogger | None = None) -> None:
        """Initialize ScopeService.

        Args:
            scope_manager: ScopeManager instance for in-memory scope rule evaluation.
            audit_logger: Optional AuditLogger instance for recording scope change events.
        """
        self._scope_manager = scope_manager
        self._audit_logger = audit_logger

    @property
    def scope_manager(self) -> ScopeManager:
        """Return the underlying ScopeManager instance."""
        return self._scope_manager

    @property
    def audit_logger(self) -> AuditLogger | None:
        """Return the attached AuditLogger instance."""
        return self._audit_logger

    def _to_uuid(self, project_id: uuid.UUID | str) -> uuid.UUID:
        """Convert a project ID representation to uuid.UUID."""
        if isinstance(project_id, uuid.UUID):
            return project_id
        return uuid.UUID(str(project_id))

    def load_rules_from_db(self, session: Session, project_id: uuid.UUID | str) -> list[ScopeRule]:
        """Load persisted scope rules from the database into the ScopeManager.

        Args:
            session: Active SQLAlchemy database session.
            project_id: UUID of the target project.

        Returns:
            List of loaded ScopeRule instances.
        """
        proj_uuid = self._to_uuid(project_id)
        stmt = (
            select(ScopeRuleModel)
            .where(ScopeRuleModel.project_id == str(proj_uuid))
            .order_by(ScopeRuleModel.created_at.asc())
        )
        models = session.scalars(stmt).all()

        rules = [
            ScopeRule(
                hostname=m.hostname,
                port=m.port,
                scheme=m.scheme,
                path_prefix=m.path_prefix,
                excluded_paths=list(getattr(m, "path_exclusions", None) or getattr(m, "excluded_paths", None) or []),
                is_exclusion=getattr(m, "is_excluded", getattr(m, "is_exclusion", False)),
                notes=m.notes or "",
            )
            for m in models
        ]

        self._scope_manager.set_rules(rules)
        logger.info("Loaded %d scope rules for project %s", len(rules), proj_uuid)
        return rules

    def save_rules_to_db(self, session: Session, project_id: uuid.UUID | str) -> None:
        """Persist current ScopeManager rules to the database.

        Args:
            session: Active SQLAlchemy database session.
            project_id: UUID of the target project.
        """
        proj_uuid = self._to_uuid(project_id)
        rules = self._scope_manager.get_rules()

        # Delete existing persisted rules for this project
        session.execute(delete(ScopeRuleModel).where(ScopeRuleModel.project_id == str(proj_uuid)))

        # Insert updated rules
        for idx, rule in enumerate(rules):
            model = ScopeRuleModel(
                id=str(uuid.uuid4()),
                project_id=str(proj_uuid),
                rule_index=idx,
                hostname=rule.hostname,
                port=rule.port,
                scheme=rule.scheme,
                path_prefix=rule.path_prefix,
                path_exclusions=list(rule.excluded_paths),
                is_excluded=rule.is_exclusion,
                notes=rule.notes,
            )
            session.add(model)

        session.commit()

        if self._audit_logger:
            self._audit_logger.log(
                event_type=SCOPE_CHANGED,
                description=f"Scope rules synchronized for project {proj_uuid}",
                project_id=proj_uuid,
                details={
                    "total_rules": len(rules),
                    "rules": [r.to_dict() for r in rules],
                },
            )

        logger.info("Saved %d scope rules for project %s to database", len(rules), proj_uuid)

    def add_rule(self, session: Session, project_id: uuid.UUID | str, rule: ScopeRule) -> None:
        """Add a new scope rule to memory and database.

        Args:
            session: Active SQLAlchemy database session.
            project_id: UUID of the target project.
            rule: ScopeRule to add.
        """
        proj_uuid = self._to_uuid(project_id)
        self._scope_manager.add_rule(rule)
        self.save_rules_to_db(session, proj_uuid)

    def remove_rule(self, session: Session, project_id: uuid.UUID | str, rule_index: int) -> ScopeRule:
        """Remove a scope rule by index from memory and database.

        Args:
            session: Active SQLAlchemy database session.
            project_id: UUID of the target project.
            rule_index: Zero-based index of the rule to remove.

        Returns:
            The removed ScopeRule instance.
        """
        proj_uuid = self._to_uuid(project_id)
        removed = self._scope_manager.remove_rule(rule_index)
        self.save_rules_to_db(session, proj_uuid)
        return removed

    def check_url(self, url: str) -> tuple[bool, str]:
        """Check whether a URL is within the authorized scope boundaries.

        Args:
            url: Full target URL.

        Returns:
            Tuple of (is_allowed: bool, reason: str).
        """
        return self._scope_manager.is_in_scope(url)

    def check_redirect(self, original: str, redirect: str) -> tuple[bool, str]:
        """Validate whether a redirection destination is within authorized scope.

        Args:
            original: Originating request URL.
            redirect: Redirection target URL.

        Returns:
            Tuple of (is_allowed: bool, reason: str).
        """
        return self._scope_manager.validate_redirect(original, redirect)

    def preview(self) -> dict[str, Any]:
        """Return a preview summary of current active scope rules.

        Returns:
            Summary dictionary of scope configuration.
        """
        return self._scope_manager.preview_scope()
