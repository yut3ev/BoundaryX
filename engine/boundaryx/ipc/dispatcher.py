import logging
from typing import Any, Callable, Dict, List, Optional

from boundaryx.domain.enums import MatcherType, ScopeRuleType
from boundaryx.domain.models import Program, ScopeRule
from boundaryx.ipc.protocol import IPCError, IPCRequest, IPCResponse
from boundaryx.scope.guard import ScopeGuard
from boundaryx.storage.repositories import (
    AssetRepository,
    AuditRepository,
    FindingRepository,
    JobRepository,
    ProgramRepository,
    ScopeRuleRepository,
    SettingsRepository,
)

logger = logging.getLogger("boundaryx.ipc.dispatcher")


class CommandDispatcher:
    """
    Allowlisted command dispatcher routing IPC messages safely.
    Strictly forbids arbitrary shell execution or untrusted paths.
    """

    def __init__(
        self,
        program_repo: ProgramRepository,
        scope_repo: ScopeRuleRepository,
        asset_repo: AssetRepository,
        job_repo: JobRepository,
        finding_repo: FindingRepository,
        settings_repo: SettingsRepository,
        audit_repo: AuditRepository,
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.program_repo = program_repo
        self.scope_repo = scope_repo
        self.asset_repo = asset_repo
        self.job_repo = job_repo
        self.finding_repo = finding_repo
        self.settings_repo = settings_repo
        self.audit_repo = audit_repo
        self.event_sink = event_sink

        self._handlers: Dict[str, Callable[[Dict[str, Any]], Any]] = {
            "ping": self._cmd_ping,
            "programs.list": self._cmd_programs_list,
            "programs.get": self._cmd_programs_get,
            "programs.create": self._cmd_programs_create,
            "scope.list": self._cmd_scope_list,
            "scope.create_rule": self._cmd_scope_create_rule,
            "scope.delete_rule": self._cmd_scope_delete_rule,
            "scope.evaluate": self._cmd_scope_evaluate,
            "assets.list": self._cmd_assets_list,
            "jobs.list": self._cmd_jobs_list,
            "jobs.get": self._cmd_jobs_get,
            "jobs.list_events": self._cmd_jobs_list_events,
            "findings.list": self._cmd_findings_list,
            "findings.get": self._cmd_findings_get,
            "settings.get": self._cmd_settings_get,
            "settings.set": self._cmd_settings_set,
            "settings.list": self._cmd_settings_list,
            "audit.list": self._cmd_audit_list,
        }

    def register_handler(self, command: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
        self._handlers[command] = handler

    def dispatch(self, req: IPCRequest) -> IPCResponse:
        handler = self._handlers.get(req.command)
        if not handler:
            logger.warning("Rejected unpermitted IPC command: %s", req.command)
            return IPCResponse(
                request_id=req.request_id,
                success=False,
                error={
                    "code": "COMMAND_NOT_FOUND",
                    "message": f"Command '{req.command}' is not in allowlisted IPC commands",
                },
            )

        try:
            result = handler(req.payload)
            return IPCResponse(
                request_id=req.request_id,
                success=True,
                data=result,
            )
        except IPCError as err:
            return IPCResponse(
                request_id=req.request_id,
                success=False,
                error=err.to_dict(),
            )
        except Exception as err:
            logger.exception("Internal error processing IPC command: %s", req.command)
            return IPCResponse(
                request_id=req.request_id,
                success=False,
                error={
                    "code": "INTERNAL_ERROR",
                    "message": str(err),
                },
            )

    # Core Handlers
    def _cmd_ping(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"pong": True, "engine": "boundaryx", "version": "0.1.0"}

    def _cmd_programs_list(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        include_archived = payload.get("include_archived", False)
        programs = self.program_repo.list_all(include_archived)
        return [p.model_dump() for p in programs]

    def _cmd_programs_get(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pid = payload.get("program_id")
        if not pid:
            raise IPCError("INVALID_ARGUMENTS", "program_id is required")
        prog = self.program_repo.get(pid)
        return prog.model_dump() if prog else None

    def _cmd_programs_create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        name = payload.get("name")
        if not name or not name.strip():
            raise IPCError("INVALID_ARGUMENTS", "Program name cannot be empty")
        prog = Program(
            name=name.strip(),
            policy_url=payload.get("policy_url"),
            description=payload.get("description"),
        )
        created = self.program_repo.create(prog)
        return created.model_dump()

    def _cmd_scope_list(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        pid = payload.get("program_id")
        if not pid:
            raise IPCError("INVALID_ARGUMENTS", "program_id is required")
        rules = self.scope_repo.list_by_program(pid)
        return [r.model_dump() for r in rules]

    def _cmd_scope_create_rule(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        pid = payload.get("program_id")
        pattern = payload.get("pattern")
        if not pid or not pattern:
            raise IPCError("INVALID_ARGUMENTS", "program_id and pattern are required")

        rule = ScopeRule(
            program_id=pid,
            rule_type=ScopeRuleType(payload.get("rule_type", "include")),
            matcher_type=MatcherType(payload.get("matcher_type", "domain")),
            pattern=pattern.strip(),
            scheme=payload.get("scheme"),
            port=payload.get("port"),
            wildcard=bool(payload.get("wildcard", False)),
            notes=payload.get("notes"),
        )
        created = self.scope_repo.create(rule)
        return created.model_dump()

    def _cmd_scope_delete_rule(self, payload: Dict[str, Any]) -> Dict[str, bool]:
        rid = payload.get("rule_id")
        if not rid:
            raise IPCError("INVALID_ARGUMENTS", "rule_id is required")
        deleted = self.scope_repo.delete(rid)
        return {"deleted": deleted}

    def _cmd_scope_evaluate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        pid = payload.get("program_id")
        target = payload.get("target")
        if not pid or not target:
            raise IPCError("INVALID_ARGUMENTS", "program_id and target are required")

        rules = self.scope_repo.list_by_program(pid)
        guard = ScopeGuard(rules)
        decision = guard.evaluate(target)
        return decision.model_dump()

    def _cmd_assets_list(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        pid = payload.get("program_id")
        if not pid:
            raise IPCError("INVALID_ARGUMENTS", "program_id is required")
        assets = self.asset_repo.list_by_program(pid)
        return [a.model_dump() for a in assets]

    def _cmd_jobs_list(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        pid = payload.get("program_id")
        if not pid:
            raise IPCError("INVALID_ARGUMENTS", "program_id is required")
        jobs = self.job_repo.list_by_program(pid)
        return [j.model_dump() for j in jobs]

    def _cmd_jobs_get(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        jid = payload.get("job_id")
        if not jid:
            raise IPCError("INVALID_ARGUMENTS", "job_id is required")
        job = self.job_repo.get(jid)
        return job.model_dump() if job else None

    def _cmd_jobs_list_events(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        jid = payload.get("job_id")
        if not jid:
            raise IPCError("INVALID_ARGUMENTS", "job_id is required")
        events = self.job_repo.list_events(jid)
        return [e.model_dump() for e in events]

    def _cmd_findings_list(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        pid = payload.get("program_id")
        if not pid:
            raise IPCError("INVALID_ARGUMENTS", "program_id is required")
        findings = self.finding_repo.list_by_program(pid)
        return [f.model_dump() for f in findings]

    def _cmd_findings_get(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        fid = payload.get("finding_id")
        if not fid:
            raise IPCError("INVALID_ARGUMENTS", "finding_id is required")
        finding = self.finding_repo.get(fid)
        return finding.model_dump() if finding else None

    def _cmd_settings_get(self, payload: Dict[str, Any]) -> Any:
        key = payload.get("key")
        if not key:
            raise IPCError("INVALID_ARGUMENTS", "key is required")
        return self.settings_repo.get(key, payload.get("default"))

    def _cmd_settings_set(self, payload: Dict[str, Any]) -> Dict[str, bool]:
        key = payload.get("key")
        value = payload.get("value")
        if not key:
            raise IPCError("INVALID_ARGUMENTS", "key is required")
        self.settings_repo.set(key, value)
        return {"saved": True}

    def _cmd_settings_list(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.settings_repo.list_all()

    def _cmd_audit_list(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        limit = payload.get("limit", 100)
        events = self.audit_repo.list_events(limit)
        return [e.model_dump() for e in events]
