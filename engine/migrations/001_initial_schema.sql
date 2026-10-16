-- Migration 001: Initial BoundaryX Schema

CREATE TABLE IF NOT EXISTS _schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS programs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    policy_url TEXT,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    archived_at TEXT
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    rule_type TEXT NOT NULL, -- include, exclude
    matcher_type TEXT NOT NULL, -- domain, url_prefix, ip, cidr
    pattern TEXT NOT NULL,
    scheme TEXT,
    port INTEGER,
    wildcard INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scope_rules_program ON scope_rules(program_id);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    asset_type TEXT NOT NULL,
    canonical_value TEXT NOT NULL,
    display_value TEXT NOT NULL,
    scope_status TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    importance INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(program_id, asset_type, canonical_value)
);

CREATE INDEX IF NOT EXISTS idx_assets_program_scope ON assets(program_id, scope_status);

CREATE TABLE IF NOT EXISTS asset_observations (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source_type TEXT NOT NULL,
    source_name TEXT NOT NULL,
    tool_version TEXT,
    job_id TEXT,
    observed_at TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    summary_json TEXT NOT NULL DEFAULT '{}',
    raw_evidence_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_observations_asset ON asset_observations(asset_id);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    scope_snapshot_json TEXT NOT NULL DEFAULT '{}',
    started_at TEXT,
    ended_at TEXT,
    cancel_requested_at TEXT,
    error_code TEXT,
    summary_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_program_status ON jobs(program_id, status);

CREATE TABLE IF NOT EXISTS job_events (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    event_type TEXT NOT NULL,
    message_safe TEXT NOT NULL,
    details_redacted_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_job_events_job ON job_events(job_id);

CREATE TABLE IF NOT EXISTS tool_runs (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    tool_version TEXT,
    argv_redacted_json TEXT NOT NULL DEFAULT '[]',
    exit_code INTEGER,
    started_at TEXT,
    ended_at TEXT,
    status TEXT NOT NULL,
    stdout_evidence_id TEXT,
    stderr_evidence_id TEXT
);

CREATE TABLE IF NOT EXISTS http_exchanges (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    source_type TEXT NOT NULL,
    method TEXT NOT NULL,
    url_redacted TEXT NOT NULL,
    request_headers_redacted_json TEXT NOT NULL DEFAULT '{}',
    request_body_evidence_id TEXT,
    response_status INTEGER,
    response_headers_redacted_json TEXT NOT NULL DEFAULT '{}',
    response_body_evidence_id TEXT,
    duration_ms INTEGER,
    observed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    title TEXT NOT NULL,
    content_ref TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    redaction_state TEXT NOT NULL DEFAULT 'redacted',
    source_ref TEXT,
    created_at TEXT NOT NULL,
    retention_class TEXT NOT NULL DEFAULT 'standard'
);

CREATE INDEX IF NOT EXISTS idx_evidence_program ON evidence(program_id);

CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    category TEXT NOT NULL,
    statement TEXT NOT NULL,
    confidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    supporting_evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    missing_evidence_json TEXT NOT NULL DEFAULT '[]',
    created_by TEXT NOT NULL DEFAULT 'rule',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'unrated',
    confidence TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'candidate',
    impact TEXT,
    actual_behavior TEXT,
    expected_behavior TEXT,
    reproduction_steps_md TEXT,
    remediation_md TEXT,
    review_reason TEXT,
    duplicate_of_id TEXT REFERENCES findings(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    verified_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_program_status ON findings(program_id, status);

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    PRIMARY KEY(finding_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS ai_analyses (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    analysis_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    model_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    input_summary_hash TEXT NOT NULL,
    output_json TEXT NOT NULL DEFAULT '{}',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    consent_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL,
    error_code TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    result TEXT NOT NULL,
    summary_safe TEXT NOT NULL,
    correlation_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
