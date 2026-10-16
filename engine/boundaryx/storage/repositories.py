import json
from typing import Any, Dict, List, Optional

from boundaryx.domain.enums import (
    AssetType,
    Confidence,
    FindingStatus,
    JobStatus,
    MatcherType,
    ScopeRuleType,
    ScopeStatus,
    Severity,
)
from boundaryx.domain.models import (
    Asset,
    AssetObservation,
    AuditEvent,
    Evidence,
    Finding,
    Job,
    JobEvent,
    Program,
    ScopeRule,
    utc_now_iso,
)
from boundaryx.storage.database import Database


class ProgramRepository:
    def __init__(self, db: Database):
        self.db = db

    def create(self, program: Program) -> Program:
        with self.db.transaction() as cur:
            cur.execute(
                """
                INSERT INTO programs (id, name, policy_url, description, created_at, updated_at, archived_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    program.id,
                    program.name,
                    program.policy_url,
                    program.description,
                    program.created_at,
                    program.updated_at,
                    program.archived_at,
                ),
            )
        return program

    def get(self, program_id: str) -> Optional[Program]:
        cur = self.db.conn.cursor()
        cur.execute("SELECT * FROM programs WHERE id = ?;", (program_id,))
        row = cur.fetchone()
        if not row:
            return None
        return Program(**dict(row))

    def list_all(self, include_archived: bool = False) -> List[Program]:
        cur = self.db.conn.cursor()
        if include_archived:
            cur.execute("SELECT * FROM programs ORDER BY created_at DESC;")
        else:
            cur.execute("SELECT * FROM programs WHERE archived_at IS NULL ORDER BY created_at DESC;")
        return [Program(**dict(row)) for row in cur.fetchall()]

    def update(self, program: Program) -> Program:
        program.updated_at = utc_now_iso()
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE programs SET name = ?, policy_url = ?, description = ?, updated_at = ?, archived_at = ?
                WHERE id = ?;
                """,
                (
                    program.name,
                    program.policy_url,
                    program.description,
                    program.updated_at,
                    program.archived_at,
                    program.id,
                ),
            )
        return program


class ScopeRuleRepository:
    def __init__(self, db: Database):
        self.db = db

    def create(self, rule: ScopeRule) -> ScopeRule:
        with self.db.transaction() as cur:
            cur.execute(
                """
                INSERT INTO scope_rules (id, program_id, rule_type, matcher_type, pattern, scheme, port, wildcard, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    rule.id,
                    rule.program_id,
                    rule.rule_type.value,
                    rule.matcher_type.value,
                    rule.pattern,
                    rule.scheme,
                    rule.port,
                    1 if rule.wildcard else 0,
                    rule.notes,
                    rule.created_at,
                ),
            )
        return rule

    def list_by_program(self, program_id: str) -> List[ScopeRule]:
        cur = self.db.conn.cursor()
        cur.execute("SELECT * FROM scope_rules WHERE program_id = ? ORDER BY created_at ASC;", (program_id,))
        rules = []
        for row in cur.fetchall():
            d = dict(row)
            d["rule_type"] = ScopeRuleType(d["rule_type"])
            d["matcher_type"] = MatcherType(d["matcher_type"])
            d["wildcard"] = bool(d["wildcard"])
            rules.append(ScopeRule(**d))
        return rules

    def delete(self, rule_id: str) -> bool:
        with self.db.transaction() as cur:
            cur.execute("DELETE FROM scope_rules WHERE id = ?;", (rule_id,))
            return cur.rowcount > 0


class AssetRepository:
    def __init__(self, db: Database):
        self.db = db

    def upsert(self, asset: Asset) -> Asset:
        with self.db.transaction() as cur:
            cur.execute(
                """
                INSERT INTO assets (id, program_id, asset_type, canonical_value, display_value, scope_status, first_seen_at, last_seen_at, importance, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(program_id, asset_type, canonical_value) DO UPDATE SET
                    display_value = excluded.display_value,
                    scope_status = excluded.scope_status,
                    last_seen_at = excluded.last_seen_at,
                    updated_at = excluded.updated_at;
                """,
                (
                    asset.id,
                    asset.program_id,
                    asset.asset_type.value,
                    asset.canonical_value,
                    asset.display_value,
                    asset.scope_status.value,
                    asset.first_seen_at,
                    asset.last_seen_at,
                    asset.importance,
                    asset.created_at,
                    asset.updated_at,
                ),
            )
        return asset

    def list_by_program(self, program_id: str, scope_status: Optional[ScopeStatus] = None) -> List[Asset]:
        cur = self.db.conn.cursor()
        if scope_status:
            cur.execute(
                "SELECT * FROM assets WHERE program_id = ? AND scope_status = ? ORDER BY updated_at DESC;",
                (program_id, scope_status.value),
            )
        else:
            cur.execute(
                "SELECT * FROM assets WHERE program_id = ? ORDER BY updated_at DESC;",
                (program_id,),
            )
        assets = []
        for row in cur.fetchall():
            d = dict(row)
            d["asset_type"] = AssetType(d["asset_type"])
            d["scope_status"] = ScopeStatus(d["scope_status"])
            assets.append(Asset(**d))
        return assets

    def add_observation(self, obs: AssetObservation) -> AssetObservation:
        with self.db.transaction() as cur:
            cur.execute(
                """
                INSERT INTO asset_observations (id, asset_id, source_type, source_name, tool_version, job_id, observed_at, confidence, summary_json, raw_evidence_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    obs.id,
                    obs.asset_id,
                    obs.source_type,
                    obs.source_name,
                    obs.tool_version,
                    obs.job_id,
                    obs.observed_at,
                    obs.confidence,
                    json.dumps(obs.summary_json),
                    obs.raw_evidence_id,
                ),
            )
        return obs


class JobRepository:
    def __init__(self, db: Database):
        self.db = db

    def create(self, job: Job) -> Job:
        with self.db.transaction() as cur:
            cur.execute(
                """
                INSERT INTO jobs (id, program_id, job_type, status, config_json, scope_snapshot_json, started_at, ended_at, cancel_requested_at, error_code, summary_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    job.id,
                    job.program_id,
                    job.job_type.value,
                    job.status.value,
                    json.dumps(job.config_json),
                    json.dumps(job.scope_snapshot_json),
                    job.started_at,
                    job.ended_at,
                    job.cancel_requested_at,
                    job.error_code,
                    json.dumps(job.summary_json),
                    job.created_at,
                ),
            )
        return job

    def get(self, job_id: str) -> Optional[Job]:
        cur = self.db.conn.cursor()
        cur.execute("SELECT * FROM jobs WHERE id = ?;", (job_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["config_json"] = json.loads(d["config_json"])
        d["scope_snapshot_json"] = json.loads(d["scope_snapshot_json"])
        d["summary_json"] = json.loads(d["summary_json"])
        return Job(**d)

    def list_by_program(self, program_id: str) -> List[Job]:
        cur = self.db.conn.cursor()
        cur.execute("SELECT * FROM jobs WHERE program_id = ? ORDER BY created_at DESC;", (program_id,))
        jobs = []
        for row in cur.fetchall():
            d = dict(row)
            d["config_json"] = json.loads(d["config_json"])
            d["scope_snapshot_json"] = json.loads(d["scope_snapshot_json"])
            d["summary_json"] = json.loads(d["summary_json"])
            jobs.append(Job(**d))
        return jobs

    def update_status(self, job_id: str, status: JobStatus, error_code: Optional[str] = None, summary: Optional[Dict[str, Any]] = None) -> None:
        now = utc_now_iso()
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE jobs SET status = ?, error_code = COALESCE(?, error_code), ended_at = ?, summary_json = COALESCE(?, summary_json)
                WHERE id = ?;
                """,
                (
                    status.value,
                    error_code,
                    now if status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.INTERRUPTED) else None,
                    json.dumps(summary) if summary else None,
                    job_id,
                ),
            )

    def record_event(self, event: JobEvent) -> JobEvent:
        with self.db.transaction() as cur:
            cur.execute(
                """
                INSERT INTO job_events (id, job_id, timestamp, level, event_type, message_safe, details_redacted_json)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event.id,
                    event.job_id,
                    event.timestamp,
                    event.level,
                    event.event_type,
                    event.message_safe,
                    json.dumps(event.details_redacted_json),
                ),
            )
        return event

    def list_events(self, job_id: str) -> List[JobEvent]:
        cur = self.db.conn.cursor()
        cur.execute("SELECT * FROM job_events WHERE job_id = ? ORDER BY timestamp ASC;", (job_id,))
        events = []
        for row in cur.fetchall():
            d = dict(row)
            d["details_redacted_json"] = json.loads(d["details_redacted_json"])
            events.append(JobEvent(**d))
        return events


class FindingRepository:
    def __init__(self, db: Database):
        self.db = db

    def create(self, finding: Finding) -> Finding:
        with self.db.transaction() as cur:
            cur.execute(
                """
                INSERT INTO findings (id, program_id, asset_id, title, category, severity, confidence, status, impact, actual_behavior, expected_behavior, reproduction_steps_md, remediation_md, review_reason, duplicate_of_id, created_at, updated_at, verified_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    finding.id,
                    finding.program_id,
                    finding.asset_id,
                    finding.title,
                    finding.category,
                    finding.severity.value,
                    finding.confidence.value,
                    finding.status.value,
                    finding.impact,
                    finding.actual_behavior,
                    finding.expected_behavior,
                    finding.reproduction_steps_md,
                    finding.remediation_md,
                    finding.review_reason,
                    finding.duplicate_of_id,
                    finding.created_at,
                    finding.updated_at,
                    finding.verified_at,
                ),
            )
            for eid in finding.evidence_ids:
                cur.execute(
                    "INSERT OR IGNORE INTO finding_evidence (finding_id, evidence_id) VALUES (?, ?);",
                    (finding.id, eid),
                )
        return finding

    def get(self, finding_id: str) -> Optional[Finding]:
        cur = self.db.conn.cursor()
        cur.execute("SELECT * FROM findings WHERE id = ?;", (finding_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["severity"] = Severity(d["severity"])
        d["confidence"] = Confidence(d["confidence"])
        d["status"] = FindingStatus(d["status"])

        cur.execute("SELECT evidence_id FROM finding_evidence WHERE finding_id = ?;", (finding_id,))
        d["evidence_ids"] = [r[0] for r in cur.fetchall()]
        return Finding(**d)

    def list_by_program(self, program_id: str) -> List[Finding]:
        cur = self.db.conn.cursor()
        cur.execute("SELECT * FROM findings WHERE program_id = ? ORDER BY created_at DESC;", (program_id,))
        findings = []
        for row in cur.fetchall():
            d = dict(row)
            d["severity"] = Severity(d["severity"])
            d["confidence"] = Confidence(d["confidence"])
            d["status"] = FindingStatus(d["status"])

            cur.execute("SELECT evidence_id FROM finding_evidence WHERE finding_id = ?;", (d["id"],))
            d["evidence_ids"] = [r[0] for r in cur.fetchall()]
            findings.append(Finding(**d))
        return findings

    def link_evidence(self, finding_id: str, evidence_id: str) -> None:
        with self.db.transaction() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO finding_evidence (finding_id, evidence_id) VALUES (?, ?);",
                (finding_id, evidence_id),
            )

    def update_status(self, finding_id: str, new_status: FindingStatus, review_reason: str) -> None:
        now = utc_now_iso()
        verified_at = now if new_status == FindingStatus.VERIFIED else None
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE findings SET status = ?, review_reason = ?, updated_at = ?, verified_at = COALESCE(?, verified_at)
                WHERE id = ?;
                """,
                (new_status.value, review_reason, now, verified_at, finding_id),
            )


class SettingsRepository:
    def __init__(self, db: Database):
        self.db = db

    def get(self, key: str, default: Any = None) -> Any:
        cur = self.db.conn.cursor()
        cur.execute("SELECT value_json FROM settings WHERE key = ?;", (key,))
        row = cur.fetchone()
        if not row:
            return default
        return json.loads(row[0])

    def set(self, key: str, value: Any) -> None:
        with self.db.transaction() as cur:
            cur.execute(
                """
                INSERT INTO settings (key, value_json, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at;
                """,
                (key, json.dumps(value), utc_now_iso()),
            )

    def list_all(self) -> Dict[str, Any]:
        cur = self.db.conn.cursor()
        cur.execute("SELECT key, value_json FROM settings;")
        return {row[0]: json.loads(row[1]) for row in cur.fetchall()}


class AuditRepository:
    def __init__(self, db: Database):
        self.db = db

    def log(self, event: AuditEvent) -> AuditEvent:
        with self.db.transaction() as cur:
            cur.execute(
                """
                INSERT INTO audit_events (id, timestamp, actor, action, entity_type, entity_id, result, summary_safe, correlation_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event.id,
                    event.timestamp,
                    event.actor,
                    event.action.value,
                    event.entity_type,
                    event.entity_id,
                    event.result,
                    event.summary_safe,
                    event.correlation_id,
                ),
            )
        return event

    def list_events(self, limit: int = 100) -> List[AuditEvent]:
        cur = self.db.conn.cursor()
        cur.execute("SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?;", (limit,))
        return [AuditEvent(**dict(row)) for row in cur.fetchall()]
