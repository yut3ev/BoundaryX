from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field

from boundaryx.domain.enums import (
    AnalysisType,
    AssetType,
    AuditEventType,
    Confidence,
    EvidenceType,
    FindingStatus,
    JobStatus,
    JobType,
    MatcherType,
    ScopeRuleType,
    ScopeStatus,
    Severity,
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return str(uuid.uuid4())


class Program(BaseModel):
    id: str = Field(default_factory=new_id)
    name: str
    policy_url: Optional[str] = None
    description: Optional[str] = None
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    archived_at: Optional[str] = None


class ScopeRule(BaseModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    rule_type: ScopeRuleType = ScopeRuleType.INCLUDE
    matcher_type: MatcherType = MatcherType.DOMAIN
    pattern: str
    scheme: Optional[str] = None
    port: Optional[int] = None
    wildcard: bool = False
    notes: Optional[str] = None
    created_at: str = Field(default_factory=utc_now_iso)


class Asset(BaseModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    asset_type: AssetType = AssetType.DOMAIN
    canonical_value: str
    display_value: str
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN
    first_seen_at: str = Field(default_factory=utc_now_iso)
    last_seen_at: str = Field(default_factory=utc_now_iso)
    importance: int = 1  # 1 to 5
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)


class AssetObservation(BaseModel):
    id: str = Field(default_factory=new_id)
    asset_id: str
    source_type: str = "tool"  # manual, tool, import
    source_name: str
    tool_version: Optional[str] = None
    job_id: Optional[str] = None
    observed_at: str = Field(default_factory=utc_now_iso)
    confidence: float = 1.0
    summary_json: Dict[str, Any] = Field(default_factory=dict)
    raw_evidence_id: Optional[str] = None


class Job(BaseModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    job_type: JobType
    status: JobStatus = JobStatus.QUEUED
    config_json: Dict[str, Any] = Field(default_factory=dict)
    scope_snapshot_json: Dict[str, Any] = Field(default_factory=dict)
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    cancel_requested_at: Optional[str] = None
    error_code: Optional[str] = None
    summary_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now_iso)


class JobEvent(BaseModel):
    id: str = Field(default_factory=new_id)
    job_id: str
    timestamp: str = Field(default_factory=utc_now_iso)
    level: str = "info"  # debug, info, warning, error
    event_type: str
    message_safe: str
    details_redacted_json: Dict[str, Any] = Field(default_factory=dict)


class ToolRun(BaseModel):
    id: str = Field(default_factory=new_id)
    job_id: str
    tool_name: str
    tool_version: Optional[str] = None
    argv_redacted_json: List[str] = Field(default_factory=list)
    exit_code: Optional[int] = None
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    status: str = "running"
    stdout_evidence_id: Optional[str] = None
    stderr_evidence_id: Optional[str] = None


class HttpExchange(BaseModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    asset_id: Optional[str] = None
    job_id: Optional[str] = None
    source_type: str = "live"
    method: str
    url_redacted: str
    request_headers_redacted_json: Dict[str, str] = Field(default_factory=dict)
    request_body_evidence_id: Optional[str] = None
    response_status: Optional[int] = None
    response_headers_redacted_json: Dict[str, str] = Field(default_factory=dict)
    response_body_evidence_id: Optional[str] = None
    duration_ms: Optional[int] = None
    observed_at: str = Field(default_factory=utc_now_iso)


class Evidence(BaseModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    evidence_type: EvidenceType
    title: str
    content_ref: str
    content_sha256: str
    size_bytes: int
    redaction_state: str = "redacted"  # raw, redacted
    source_ref: Optional[str] = None
    created_at: str = Field(default_factory=utc_now_iso)
    retention_class: str = "standard"


class Hypothesis(BaseModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    asset_id: Optional[str] = None
    category: str
    statement: str
    confidence: Confidence = Confidence.MEDIUM
    status: str = "open"  # open, tested, confirmed, refuted
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    created_by: str = "rule"  # user, rule, ai
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)


class Finding(BaseModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    asset_id: Optional[str] = None
    title: str
    category: str
    severity: Severity = Severity.UNRATED
    confidence: Confidence = Confidence.MEDIUM
    status: FindingStatus = FindingStatus.CANDIDATE
    impact: Optional[str] = None
    actual_behavior: Optional[str] = None
    expected_behavior: Optional[str] = None
    reproduction_steps_md: Optional[str] = None
    remediation_md: Optional[str] = None
    review_reason: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)
    duplicate_of_id: Optional[str] = None
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    verified_at: Optional[str] = None


class AIAnalysis(BaseModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    analysis_type: AnalysisType
    provider: str = "gemini"
    model_id: str
    schema_version: int = 1
    input_summary_hash: str
    output_json: Dict[str, Any] = Field(default_factory=dict)
    evidence_refs: List[str] = Field(default_factory=list)
    consent_at: str = Field(default_factory=utc_now_iso)
    created_at: str = Field(default_factory=utc_now_iso)
    status: str = "completed"
    error_code: Optional[str] = None


class AuditEvent(BaseModel):
    id: str = Field(default_factory=new_id)
    timestamp: str = Field(default_factory=utc_now_iso)
    actor: str = "user"
    action: AuditEventType
    entity_type: str
    entity_id: str
    result: str = "success"  # success, failure, denied
    summary_safe: str
    correlation_id: Optional[str] = None
