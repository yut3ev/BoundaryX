import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from boundaryx.adapters.base import ToolAdapter
from boundaryx.domain.enums import AssetType, JobStatus
from boundaryx.domain.models import Asset, AssetObservation, Job, JobEvent
from boundaryx.scope.guard import ScopeGuard
from boundaryx.storage.repositories import AssetRepository, JobRepository, ScopeRuleRepository

logger = logging.getLogger("boundaryx.jobs.orchestrator")


class RateLimiter:
    """Token-bucket rate limiter enforcing requests-per-second constraints."""

    def __init__(self, requests_per_second: float = 2.0):
        self.rate = max(0.1, requests_per_second)
        self.tokens = self.rate
        self.last_update = time.time()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self.lock:
                now = time.time()
                elapsed = now - self.last_update
                self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
                self.last_update = now

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
            time.sleep(0.05)


class JobOrchestrator:
    """
    Supervises job queue, concurrent execution, rate limiting, and cancellation.
    Enforces scope checks before launching tools or sending traffic.
    """

    def __init__(
        self,
        job_repo: JobRepository,
        scope_repo: ScopeRuleRepository,
        asset_repo: AssetRepository,
        max_concurrency: int = 3,
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.job_repo = job_repo
        self.scope_repo = scope_repo
        self.asset_repo = asset_repo
        self.max_concurrency = max_concurrency
        self.event_sink = event_sink
        self.semaphore = threading.Semaphore(max_concurrency)
        self._cancel_tokens: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()

        # Mark any active jobs from previous crashes as INTERRUPTED
        self._recover_interrupted_jobs()

    def _recover_interrupted_jobs(self) -> None:
        """Finds any running/queued jobs from previous runs and marks them as interrupted."""
        cur = self.job_repo.db.conn.cursor()
        cur.execute(
            "SELECT id FROM jobs WHERE status IN ('running', 'validating_scope', 'queued');"
        )
        for row in cur.fetchall():
            jid = row[0]
            logger.warning("Recovering interrupted job %s -> marking INTERRUPTED", jid)
            self.job_repo.update_status(jid, JobStatus.INTERRUPTED, error_code="CRASH_RECOVERY")

    def _emit_event(self, job_id: str, level: str, event_type: str, message: str, details: Dict[str, Any] = None) -> None:
        ev = JobEvent(
            job_id=job_id,
            level=level,
            event_type=event_type,
            message_safe=message,
            details_redacted_json=details or {},
        )
        self.job_repo.record_event(ev)
        if self.event_sink:
            try:
                self.event_sink(ev.model_dump())
            except Exception:
                pass

    def request_cancel(self, job_id: str) -> bool:
        with self._lock:
            token = self._cancel_tokens.get(job_id)
            if token:
                token.set()
                self.job_repo.update_status(job_id, JobStatus.CANCELLING)
                self._emit_event(job_id, "warning", "CANCEL_REQUESTED", "Cancellation token signaled by user")
                return True
            return False

    def run_adapter_job_sync(self, job: Job, adapter: ToolAdapter, raw_targets: List[str]) -> JobStatus:
        """Executes a tool recon job synchronously with scope validation, rate bounds, and cancellation."""
        cancel_token = threading.Event()
        with self._lock:
            self._cancel_tokens[job.id] = cancel_token

        try:
            with self.semaphore:
                # 1. Validating Scope
                self.job_repo.update_status(job.id, JobStatus.VALIDATING_SCOPE)
                self._emit_event(job.id, "info", "SCOPE_VALIDATION", "Validating targets against program scope rules...")

                rules = self.scope_repo.list_by_program(job.program_id)
                guard = ScopeGuard(rules)

                in_scope_targets = []
                for t in raw_targets:
                    dec = guard.evaluate(t)
                    if dec.is_in_scope:
                        in_scope_targets.append(t)
                    else:
                        self._emit_event(
                            job.id,
                            "warning",
                            "SCOPE_DENIAL",
                            f"Target '{t}' rejected: {dec.denial_reason}",
                        )

                if not in_scope_targets:
                    self._emit_event(job.id, "error", "JOB_FAILED", "No targets remained after scope validation")
                    self.job_repo.update_status(job.id, JobStatus.FAILED, error_code="ALL_TARGETS_OUT_OF_SCOPE")
                    return JobStatus.FAILED

                if cancel_token.is_set():
                    self.job_repo.update_status(job.id, JobStatus.CANCELLED)
                    return JobStatus.CANCELLED

                # 2. Running Tool
                self.job_repo.update_status(job.id, JobStatus.RUNNING)
                self._emit_event(job.id, "info", "TOOL_STARTED", f"Executing {adapter.capabilities().get('name')}...")

                argv = adapter.build_argv(in_scope_targets, job.config_json)
                code, stdout, stderr = adapter.supervisor.run_command(
                    argv,
                    timeout_seconds=job.config_json.get("timeout", 300),
                    cancel_event=cancel_token,
                )

                if cancel_token.is_set():
                    self._emit_event(job.id, "warning", "JOB_CANCELLED", "Tool execution aborted by user cancellation")
                    self.job_repo.update_status(job.id, JobStatus.CANCELLED)
                    return JobStatus.CANCELLED

                # 3. Parse Output & Populate Assets
                parsed = adapter.parse_output(stdout, stderr)
                discovered_count = 0

                for item in parsed:
                    val = item.get("value")
                    if not val:
                        continue
                    # Re-verify discovered asset with scope guard
                    dec = guard.evaluate(val)
                    asset_type_str = item.get("asset_type", "subdomain")
                    try:
                        atype = AssetType(asset_type_str)
                    except ValueError:
                        atype = AssetType.DOMAIN

                    asset = Asset(
                        program_id=job.program_id,
                        asset_type=atype,
                        canonical_value=dec.canonical_host if dec.canonical_host != "invalid" else val,
                        display_value=val,
                        scope_status=dec.status,
                    )
                    self.asset_repo.upsert(asset)

                    obs = AssetObservation(
                        asset_id=asset.id,
                        source_type="tool",
                        source_name=adapter.capabilities().get("name", "tool"),
                        job_id=job.id,
                        summary_json=item,
                    )
                    self.asset_repo.add_observation(obs)
                    discovered_count += 1

                summary = {
                    "targets_checked": len(in_scope_targets),
                    "discovered_count": discovered_count,
                    "exit_code": code,
                }
                status = JobStatus.COMPLETED if code == 0 else JobStatus.PARTIAL
                self.job_repo.update_status(job.id, status, summary=summary)
                self._emit_event(job.id, "info", "JOB_FINISHED", f"Finished with {discovered_count} discovered assets", summary)
                return status

        except Exception as e:
            logger.exception("Error executing job %s: %s", job.id, e)
            self._emit_event(job.id, "error", "JOB_FAILED", f"Unexpected execution error: {str(e)}")
            self.job_repo.update_status(job.id, JobStatus.FAILED, error_code=str(e))
            return JobStatus.FAILED
        finally:
            with self._lock:
                self._cancel_tokens.pop(job.id, None)
