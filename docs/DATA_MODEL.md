# Data Model & Migrations

Use normalized relational tables with UUID/ULID identifiers, UTC timestamps in ISO-8601, foreign keys and indices. Exact SQL should live in versioned migrations; do not auto-create a new schema silently on every launch.

## Core entities

### `programs`
- `id`, `name`, `policy_url`, `description`, `created_at`, `updated_at`, `archived_at`

### `scope_rules`
- `id`, `program_id`, `rule_type` (`include`/`exclude`), `matcher_type` (`domain`, `url_prefix`, `ip`, `cidr` only when permitted), `pattern`, `scheme`, `port`, `wildcard`, `notes`, `created_at`
- Exclusions override inclusions. Define precedence in one tested ScopePolicy function.

### `assets`
- `id`, `program_id`, `asset_type`, `canonical_value`, `display_value`, `scope_status`, `first_seen_at`, `last_seen_at`, `importance`, `created_at`, `updated_at`
- Unique key on program + asset type + canonical value.

### `asset_observations`
- `id`, `asset_id`, `source_type`, `source_name`, `tool_version`, `job_id`, `observed_at`, `confidence`, `summary_json`, `raw_evidence_id`

### `jobs`
- `id`, `program_id`, `job_type`, `status`, `config_json`, `scope_snapshot_json`, `started_at`, `ended_at`, `cancel_requested_at`, `error_code`, `summary_json`, `created_at`

### `job_events`
- `id`, `job_id`, `timestamp`, `level`, `event_type`, `message_safe`, `details_redacted_json`

### `tool_runs`
- `id`, `job_id`, `tool_name`, `tool_version`, `argv_redacted_json`, `exit_code`, `started_at`, `ended_at`, `status`, `stdout_evidence_id`, `stderr_evidence_id`
- Never store API keys/credentials in argv or logs.

### `http_exchanges`
- `id`, `program_id`, `asset_id`, `job_id`, `source_type`, `method`, `url_redacted`, `request_headers_redacted_json`, `request_body_evidence_id`, `response_status`, `response_headers_redacted_json`, `response_body_evidence_id`, `duration_ms`, `observed_at`
- Raw unredacted body, if user explicitly opts in, should be separately gated and never sent to Gemini by default.

### `evidence`
- `id`, `program_id`, `evidence_type`, `title`, `content_ref`, `content_sha256`, `size_bytes`, `redaction_state`, `source_ref`, `created_at`, `retention_class`
- Large blobs may be stored as files under app data with random names; validate all paths remain under the dedicated evidence directory.

### `hypotheses`
- `id`, `program_id`, `asset_id`, `category`, `statement`, `confidence`, `status`, `supporting_evidence_ids_json`, `missing_evidence_json`, `created_by` (`user`/`rule`/`ai`), `created_at`, `updated_at`

### `findings`
- `id`, `program_id`, `asset_id`, `title`, `category`, `severity` (including `unrated`), `confidence`, `status`, `impact`, `actual_behavior`, `expected_behavior`, `reproduction_steps_md`, `remediation_md`, `review_reason`, `created_at`, `updated_at`, `verified_at`

### `finding_evidence` / `finding_duplicates`
Many-to-many evidence relationship; explicit duplicate relationship with human review.

### `ai_analyses`
- `id`, `program_id`, `analysis_type`, `provider`, `model_id`, `schema_version`, `input_summary_hash`, `output_json`, `evidence_refs_json`, `consent_at`, `created_at`, `status`, `error_code`
- No raw API key; output must be schema validated.

### `settings`
- Non-secret settings only (`key`, `value_json`, `updated_at`). Secret values live in OS secret storage.

### `audit_events`
- `id`, `timestamp`, `actor`, `action`, `entity_type`, `entity_id`, `result`, `summary_safe`, `correlation_id`

## Invariants

- Every asset/job/finding belongs to a program, directly or through a required relationship.
- Scope is re-evaluated at execution time; stored scope snapshot is for audit, not permanent authorization.
- `verified` requires an explicit review event and evidence reference; no AI direct transition.
- Deleting a program has a clear cascade/archive policy with confirmation and backup option.
- Schema migrations are deterministic and tested against prior schema versions.
- Store only necessary raw data; redact sensitive fields before routine persistence.
