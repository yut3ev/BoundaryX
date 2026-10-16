import logging
from typing import Optional

from boundaryx.domain.enums import AuditEventType
from boundaryx.domain.models import AuditEvent
from boundaryx.security.redaction import RedactionEngine
from boundaryx.storage.repositories import AuditRepository

logger = logging.getLogger("boundaryx.audit")


class AuditLogger:
    def __init__(self, repo: AuditRepository, redaction_engine: Optional[RedactionEngine] = None):
        self.repo = repo
        self.redaction = redaction_engine or RedactionEngine()

    def log(
        self,
        action: AuditEventType,
        entity_type: str,
        entity_id: str,
        summary: str,
        result: str = "success",
        actor: str = "user",
        correlation_id: Optional[str] = None,
    ) -> AuditEvent:
        safe_summary = self.redaction.redact_text(summary)
        event = AuditEvent(
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            result=result,
            summary_safe=safe_summary,
            correlation_id=correlation_id,
        )
        self.repo.log(event)
        logger.info("[AUDIT] %s %s:%s - %s (%s)", action.value, entity_type, entity_id, safe_summary, result)
        return event
