from enum import Enum


class ScopeRuleType(str, Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class MatcherType(str, Enum):
    DOMAIN = "domain"
    URL_PREFIX = "url_prefix"
    IP = "ip"
    CIDR = "cidr"


class ScopeStatus(str, Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    ENDPOINT = "endpoint"
    JS_FILE = "js_file"
    SERVICE = "service"
    TECHNOLOGY = "technology"


class JobType(str, Enum):
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    DNS_RESOLUTION = "dns_resolution"
    WEB_PROBING = "web_probing"
    CRAWL = "crawl"
    TEMPLATE_SCAN = "template_scan"
    FUZZING = "fuzzing"
    IMPORT = "import"
    VERIFICATION = "verification"


class JobStatus(str, Enum):
    QUEUED = "queued"
    VALIDATING_SCOPE = "validating_scope"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class Severity(str, Enum):
    UNRATED = "unrated"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    NEEDS_REVIEW = "needs_review"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    REOPENED = "reopened"


class EvidenceType(str, Enum):
    HTTP_EXCHANGE = "http_exchange"
    TOOL_OUTPUT = "tool_output"
    SCREENSHOT = "screenshot"
    LOG_SNIPPET = "log_snippet"
    FILE = "file"


class AnalysisType(str, Enum):
    TARGET_OVERVIEW = "target_overview"
    FINDING_EXPLANATION = "finding_explanation"
    CORRELATION = "correlation"
    NEXT_TEST_PLAN = "next_test_plan"
    REPORT_DRAFT = "report_draft"


class AuditEventType(str, Enum):
    PROJECT_CREATED = "PROJECT_CREATED"
    PROJECT_UPDATED = "PROJECT_UPDATED"
    SCOPE_CHANGED = "SCOPE_CHANGED"
    ASSET_DISCOVERED = "ASSET_DISCOVERED"
    JOB_QUEUED = "JOB_QUEUED"
    JOB_STARTED = "JOB_STARTED"
    JOB_COMPLETED = "JOB_COMPLETED"
    JOB_CANCELLED = "JOB_CANCELLED"
    JOB_FAILED = "JOB_FAILED"
    FINDING_CREATED = "FINDING_CREATED"
    FINDING_STATUS_CHANGED = "FINDING_STATUS_CHANGED"
    AI_ANALYSIS_REQUESTED = "AI_ANALYSIS_REQUESTED"
    REPORT_EXPORTED = "REPORT_EXPORTED"
    TOOL_INSTALLED = "TOOL_INSTALLED"
