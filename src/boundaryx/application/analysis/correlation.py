"""Traffic correlation and automated IDOR detection engine for BoundaryX.

Correlates HTTP traffic logs (from proxy captures, HAR imports, or active tests)
with identity profiles and resource models. Provides automatic URL route template
extraction, parameter normalization, multi-identity horizontal privilege
escalation (IDOR) candidate detection, relationship inference, and test case suggestions.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import urllib.parse
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from boundaryx.application.testing.models import (
    ExecutionMode,
    RequestTemplate,
    TestCaseDefinition,
)
from boundaryx.domain.findings.models import FindingCategory, FindingSeverity
from boundaryx.domain.identities.models import Identity
from boundaryx.domain.relationships.models import (
    Relationship,
    RelationshipConfidence,
    RelationshipType,
)
from boundaryx.domain.resources.models import Resource, ResourceType


def _utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


# Regex patterns identifying dynamic path parameters
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_INT_RE = re.compile(r"^\d+$")
_HEX_ID_RE = re.compile(r"^[0-9a-fA-F]{24,64}$")
_PREFIXED_ID_RE = re.compile(r"^[a-zA-Z]{2,6}_[a-zA-Z0-9_-]+$")

_BASE64_SLUG_RE = re.compile(r"^[a-zA-Z0-9_-]{20,}$")


# Auth and Identity Header names
_DEFAULT_AUTH_HEADERS = [
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-user-id",
    "x-identity-id",
    "x-tenant-id",
    "x-account-id",
]

_DEFAULT_AUTH_COOKIES = [
    "session",
    "sessionid",
    "session_id",
    "jwt",
    "token",
    "access_token",
    "auth",
    "authtoken",
    "phpsessid",
    "jsessionid",
    "connect.sid",
]


class PathParameter(BaseModel):
    """Normalized dynamic parameter extracted from an HTTP URL path segment."""

    model_config = ConfigDict(from_attributes=True)

    name: str = Field(description="Parameter token name (e.g. 'user_id', 'order_id')")
    value: str = Field(description="Observed literal parameter value in the request")
    segment_index: int = Field(description="Zero-based index of segment in path")
    param_type: str = Field(description="Inferred data type (e.g. 'uuid', 'integer', 'prefixed', 'slug')")


class TemplateMatchResult(BaseModel):
    """Result of mapping a concrete HTTP URL path into an endpoint route template."""

    model_config = ConfigDict(from_attributes=True)

    template: str = Field(description="Canonical path template (e.g. '/api/v1/users/{user_id}/orders/{order_id}')")
    raw_path: str = Field(description="Original unparameterized URL path")
    parameters: dict[str, str] = Field(
        default_factory=dict,
        description="Dictionary mapping parameter tokens to observed values",
    )
    parameter_details: list[PathParameter] = Field(
        default_factory=list,
        description="Detailed metadata for each dynamic path segment",
    )
    method: str = Field(default="GET", description="HTTP method")
    endpoint_identifier: str = Field(
        description="Full method and template identifier (e.g. 'GET /api/v1/users/{id}')",
    )


class IdentityMatch(BaseModel):
    """Association linking an HTTP traffic record to an authenticated identity."""

    model_config = ConfigDict(from_attributes=True)

    identity_id: UUID | None = Field(
        default=None,
        description="ID of matched identity, or None if inferred/anonymous",
    )
    identity_name: str = Field(description="Display identifier or pseudonym of identity")
    matched_credential_type: str = Field(
        description="Mechanism used for correlation (e.g. 'BEARER_TOKEN', 'COOKIE', 'HEADER', 'ANONYMOUS')",
    )
    credential_key: str = Field(description="Specific header or cookie key detected")
    credential_value_preview: str = Field(
        description="Sanitized preview or hash of credential token",
    )
    is_anonymous: bool = Field(default=False, description="Whether request lacked authentication")
    tenant_ids: list[UUID] = Field(default_factory=list, description="Associated tenant IDs")


class ResourceMatch(BaseModel):
    """Association linking an HTTP traffic record parameter to a target resource entity."""

    model_config = ConfigDict(from_attributes=True)

    resource_id: UUID | None = Field(
        default=None,
        description="ID of known resource matching this target",
    )
    external_id: str = Field(description="External ID token observed in request (e.g. '123')")
    resource_type: str = Field(default="API_RESOURCE", description="Inferred or matched resource type")
    source_location: str = Field(description="Where ID was located ('PATH', 'QUERY', or 'BODY')")
    parameter_name: str = Field(description="Parameter token name (e.g. 'order_id')")


class PotentialIDORCandidate(BaseModel):
    """Identified horizontal/vertical privilege escalation or BOLA/IDOR vulnerability pattern."""

    model_config = ConfigDict(from_attributes=True)

    candidate_id: UUID = Field(default_factory=uuid4, description="Unique candidate identifier")
    endpoint_template: str = Field(description="Affected route template")
    method: str = Field(description="HTTP method")
    resource_external_id: str = Field(description="Target external resource identifier accessed")
    resource_id: UUID | None = Field(default=None, description="Known resource ID if matched")
    resource_type: str = Field(default="API_RESOURCE", description="Resource type classification")
    category: FindingCategory = Field(description="Authorization finding category")
    severity: FindingSeverity = Field(description="Suggested defect severity")
    traffic_record_ids: list[str] = Field(
        default_factory=list,
        description="IDs of traffic records exhibiting cross-user access",
    )
    participating_identity_ids: list[str] = Field(
        default_factory=list,
        description="Identities observed accessing the shared resource",
    )
    participating_identity_names: list[str] = Field(
        default_factory=list,
        description="Display names of participating identities",
    )
    primary_owner_identity_id: str | None = Field(
        default=None,
        description="Identity designated as legitimate resource owner (if known)",
    )
    primary_tenant_id: str | None = Field(
        default=None,
        description="Legitimate owner tenant boundary ID (if known)",
    )
    cross_tenant: bool = Field(
        default=False,
        description="Whether access crossed distinct tenant organizational boundaries",
    )
    title: str = Field(description="Headline summary of suspected IDOR vulnerability")
    description: str = Field(description="Detailed technical reasoning and evidence breakdown")
    reproduction_observations: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Snapshot of requests confirming cross-identity access",
    )
    suggested_action: str = Field(
        default="",
        description="Remediation or verification recommendation",
    )


class CorrelatedTrafficRecord(BaseModel):
    """Normalized traffic record enriched with identity and resource correlation data."""

    model_config = ConfigDict(from_attributes=True)

    record_id: str = Field(description="Identifier of originating traffic record")
    method: str = Field(description="HTTP request method")
    url: str = Field(description="Full URL requested")
    raw_path: str = Field(description="URL path")
    template: str = Field(description="Extracted route template")
    endpoint_identifier: str = Field(description="Method and template key")
    identity_match: IdentityMatch = Field(description="Correlated identity subject")
    resource_matches: list[ResourceMatch] = Field(
        default_factory=list,
        description="Target resource entities referenced in request",
    )
    response_status: int | None = Field(default=None, description="HTTP response status code")
    is_success_status: bool = Field(
        default=False,
        description="True if status indicates successful authorization (200-299)",
    )
    created_at: datetime = Field(default_factory=_utc_now, description="Record timestamp")


class TrafficCorrelationReport(BaseModel):
    """Comprehensive analytical report produced by traffic correlation analysis."""

    model_config = ConfigDict(from_attributes=True)

    total_records_analyzed: int = Field(description="Number of HTTP traffic records processed")
    templates_discovered: list[str] = Field(
        default_factory=list,
        description="Distinct route templates inferred from traffic",
    )
    identities_correlated: dict[str, int] = Field(
        default_factory=dict,
        description="Breakdown of request counts per correlated identity",
    )
    resources_correlated: dict[str, int] = Field(
        default_factory=dict,
        description="Breakdown of request counts per target resource external ID",
    )
    potential_idor_candidates: list[PotentialIDORCandidate] = Field(
        default_factory=list,
        description="Detected IDOR and cross-user authorization anomaly candidates",
    )
    inferred_relationships: list[Relationship] = Field(
        default_factory=list,
        description="Relationship graph edges inferred from traffic interactions",
    )
    test_case_suggestions: list[TestCaseDefinition] = Field(
        default_factory=list,
        description="Recommended authorization test cases to formally verify anomalies",
    )
    correlated_records: list[CorrelatedTrafficRecord] = Field(
        default_factory=list,
        description="Enriched correlated records",
    )
    generated_at: datetime = Field(default_factory=_utc_now, description="Generation timestamp")


class TrafficCorrelator:
    """Traffic analysis and correlation engine.

    Extracts route templates, attributes traffic to subjects, matches target resources,
    identifies IDOR/cross-user requests, and synthesizes test case definitions.
    """

    def __init__(
        self,
        identities: list[Identity] | None = None,
        resources: list[Resource] | None = None,
        known_templates: list[str] | None = None,
        token_map: dict[str, UUID | str] | None = None,
        auth_headers: list[str] | None = None,
        auth_cookies: list[str] | None = None,
    ) -> None:
        """Initialize traffic correlator with optional knowledge baselines.

        Args:
            identities: Known project identities to match against credentials.
            resources: Known project resources to match against extracted IDs.
            known_templates: Predefined route templates (e.g. from OpenAPI / Swagger).
            token_map: Mapping of known token/cookie substrings to identity IDs.
            auth_headers: Custom HTTP header names carrying authentication credentials.
            auth_cookies: Custom cookie names carrying session tokens.
        """
        self._identities: dict[str, Identity] = {str(i.id): i for i in (identities or [])}
        self._resources: dict[str, Resource] = {str(r.id): r for r in (resources or [])}
        self._resources_by_ext_id: dict[str, Resource] = {
            str(r.external_id): r for r in (resources or []) if r.external_id
        }
        self._known_templates: list[str] = list(known_templates or [])
        self._token_map: dict[str, str] = {k: str(v) for k, v in (token_map or {}).items()}
        self._auth_headers = [h.lower() for h in (auth_headers or _DEFAULT_AUTH_HEADERS)]
        self._auth_cookies = [c.lower() for c in (auth_cookies or _DEFAULT_AUTH_COOKIES)]

    # -------------------------------------------------------------------------
    # Route Template Extraction & Matching
    # -------------------------------------------------------------------------

    def extract_template(self, path: str, method: str = "GET") -> TemplateMatchResult:
        """Extract a canonical parameterized route template from a concrete URL path.

        Examples:
            `/api/v1/users/123` -> `/api/v1/users/{user_id}`
            `/api/v1/users/123/orders/987` -> `/api/v1/users/{user_id}/orders/{order_id}`

        Args:
            path: Concrete URL path (e.g. '/api/users/42').
            method: HTTP method.

        Returns:
            TemplateMatchResult containing template string and extracted parameters.
        """
        norm_method = method.upper().strip()
        parsed = urllib.parse.urlparse(path)
        clean_path = parsed.path.rstrip("/")
        if not clean_path:
            clean_path = "/"

        # Check against known predefined templates first
        for known in self._known_templates:
            matched_params = self.match_template(clean_path, known)
            if matched_params is not None:
                details: list[PathParameter] = []
                for p_name, p_val in matched_params.items():
                    details.append(
                        PathParameter(
                            name=p_name,
                            value=p_val,
                            segment_index=-1,
                            param_type=self._classify_token(p_val) or "string",
                        )
                    )

                return TemplateMatchResult(
                    template=known,
                    raw_path=clean_path,
                    parameters=matched_params,
                    parameter_details=details,
                    method=norm_method,
                    endpoint_identifier=f"{norm_method} {known}",
                )

        # Dynamic extraction from raw path segments
        segments = clean_path.split("/")
        template_segments: list[str] = []
        parameters: dict[str, str] = {}
        parameter_details: list[PathParameter] = []
        param_counter: dict[str, int] = {}

        for idx, seg in enumerate(segments):
            if not seg:
                template_segments.append("")
                continue

            token_type = self._classify_token(seg)
            if token_type is None and seg in self._resources_by_ext_id:
                token_type = "resource_id"

            if token_type is not None:
                # Dynamic identifier segment detected
                preceding = segments[idx - 1] if idx > 0 and segments[idx - 1] else "item"
                param_base = self._singularize(preceding)
                param_name = f"{param_base}_id"

                # Ensure unique parameter tokens within same path
                count = param_counter.get(param_name, 0) + 1
                param_counter[param_name] = count
                final_param_name = param_name if count == 1 else f"{param_name}_{count}"

                template_segments.append(f"{{{final_param_name}}}")
                parameters[final_param_name] = seg
                parameter_details.append(
                    PathParameter(
                        name=final_param_name,
                        value=seg,
                        segment_index=idx,
                        param_type=token_type,
                    )
                )
            else:
                template_segments.append(seg)

        generated_template = "/".join(template_segments)
        if not generated_template.startswith("/"):
            generated_template = "/" + generated_template

        return TemplateMatchResult(
            template=generated_template,
            raw_path=clean_path,
            parameters=parameters,
            parameter_details=parameter_details,
            method=norm_method,
            endpoint_identifier=f"{norm_method} {generated_template}",
        )

    def match_template(self, path: str, template: str) -> dict[str, str] | None:
        """Match a concrete path against a parameterized template string.

        Args:
            path: Concrete path string (e.g. '/api/users/123').
            template: Parameterized template (e.g. '/api/users/{id}').

        Returns:
            Dictionary of extracted parameters if matched, or None if no match.
        """
        # Convert template {param} into named regex capture groups
        param_pattern = re.compile(r"\{([a-zA-Z0-9_]+)\}")
        regex_parts: list[str] = []
        last_end = 0

        for match in param_pattern.finditer(template):
            literal = re.escape(template[last_end : match.start()])
            param_name = match.group(1)
            regex_parts.append(literal)
            regex_parts.append(f"(?P<{param_name}>[^/]+)")
            last_end = match.end()

        regex_parts.append(re.escape(template[last_end:]))
        full_regex = f"^{''.join(regex_parts)}$"

        compiled = re.compile(full_regex)
        m = compiled.match(path.rstrip("/"))
        if m:
            return m.groupdict()
        return None

    # -------------------------------------------------------------------------
    # Identity Correlation
    # -------------------------------------------------------------------------

    def correlate_identity(
        self,
        headers: dict[str, Any],
        cookies: dict[str, Any] | None = None,
        explicit_identity_id: UUID | str | None = None,
    ) -> IdentityMatch:
        """Correlate request credential tokens with known or inferred identities.

        Args:
            headers: Captured HTTP request headers.
            cookies: Captured HTTP request cookies.
            explicit_identity_id: Identity ID if already known on traffic record.

        Returns:
            IdentityMatch containing identity ID, display name, and auth mechanism.
        """
        # 1. Explicit ID already associated
        if explicit_identity_id:
            e_id_str = str(explicit_identity_id)
            if e_id_str in self._identities:
                id_obj = self._identities[e_id_str]
                return IdentityMatch(
                    identity_id=id_obj.id,
                    identity_name=id_obj.name,
                    matched_credential_type="EXPLICIT",
                    credential_key="explicit_id",
                    credential_value_preview=e_id_str[:8],
                    is_anonymous=id_obj.is_anonymous,
                    tenant_ids=id_obj.tenant_ids,
                )

        # Normalize headers to lowercase
        norm_headers = {k.lower(): str(v) for k, v in headers.items()}
        cookies_dict = {k.lower(): str(v) for k, v in (cookies or {}).items()}

        # 2. Check Auth Headers
        for h_name in self._auth_headers:
            if h_name in norm_headers:
                raw_val = norm_headers[h_name]
                if not raw_val or raw_val.strip() == "":
                    continue

                token_val = raw_val
                cred_type = "HEADER"
                if h_name == "authorization":
                    if raw_val.lower().startswith("bearer "):
                        token_val = raw_val[7:].strip()
                        cred_type = "BEARER_TOKEN"
                    elif raw_val.lower().startswith("basic "):
                        cred_type = "BASIC_AUTH"

                # Check if matches known token map
                matched_id = self._lookup_token(token_val)
                if matched_id and matched_id in self._identities:
                    known_id = self._identities[matched_id]
                    return IdentityMatch(
                        identity_id=known_id.id,
                        identity_name=known_id.name,
                        matched_credential_type=cred_type,
                        credential_key=h_name,
                        credential_value_preview=self._mask_token(token_val),
                        is_anonymous=False,
                        tenant_ids=known_id.tenant_ids,
                    )

                # Inferred identity from unique token hash
                token_hash = hashlib.sha256(token_val.encode("utf-8")).hexdigest()[:8]
                return IdentityMatch(
                    identity_id=None,
                    identity_name=f"inferred-user-{token_hash}",
                    matched_credential_type=cred_type,
                    credential_key=h_name,
                    credential_value_preview=self._mask_token(token_val),
                    is_anonymous=False,
                )

        # 3. Check Auth Cookies
        for c_name in self._auth_cookies:
            if c_name in cookies_dict:
                c_val = cookies_dict[c_name]
                if not c_val or c_val.strip() == "":
                    continue

                matched_id = self._lookup_token(c_val)
                if matched_id and matched_id in self._identities:
                    known_id = self._identities[matched_id]
                    return IdentityMatch(
                        identity_id=known_id.id,
                        identity_name=known_id.name,
                        matched_credential_type="COOKIE",
                        credential_key=c_name,
                        credential_value_preview=self._mask_token(c_val),
                        is_anonymous=False,
                        tenant_ids=known_id.tenant_ids,
                    )

                token_hash = hashlib.sha256(c_val.encode("utf-8")).hexdigest()[:8]
                return IdentityMatch(
                    identity_id=None,
                    identity_name=f"inferred-session-{token_hash}",
                    matched_credential_type="COOKIE",
                    credential_key=c_name,
                    credential_value_preview=self._mask_token(c_val),
                    is_anonymous=False,
                )

        # 4. Anonymous / Unauthenticated
        return IdentityMatch(
            identity_id=None,
            identity_name="anonymous",
            matched_credential_type="ANONYMOUS",
            credential_key="none",
            credential_value_preview="none",
            is_anonymous=True,
        )

    # -------------------------------------------------------------------------
    # Resource Correlation
    # -------------------------------------------------------------------------

    def correlate_resources(
        self,
        template_result: TemplateMatchResult,
        query_params: dict[str, Any] | None = None,
        body: str | dict[str, Any] | None = None,
    ) -> list[ResourceMatch]:
        """Correlate path, query, and payload identifiers with target resource entities.

        Args:
            template_result: Extracted route template result.
            query_params: HTTP query parameters.
            body: HTTP request body payload.

        Returns:
            List of detected ResourceMatch entities.
        """
        matches: list[ResourceMatch] = []
        seen_ext_ids: set[str] = set()

        # 1. Match from path parameters
        for p in template_result.parameter_details:
            ext_id = p.value
            if ext_id in seen_ext_ids:
                continue
            seen_ext_ids.add(ext_id)

            known_res = self._resources_by_ext_id.get(ext_id)
            res_type = known_res.resource_type.value if known_res else self._infer_resource_type(p.name)

            matches.append(
                ResourceMatch(
                    resource_id=known_res.id if known_res else None,
                    external_id=ext_id,
                    resource_type=res_type,
                    source_location="PATH",
                    parameter_name=p.name,
                )
            )

        # 2. Match from query parameters
        if query_params:
            for q_key, q_val in query_params.items():
                if not q_val:
                    continue
                q_val_str = str(q_val)
                if self._is_potential_resource_id_key(q_key) and q_val_str not in seen_ext_ids:
                    seen_ext_ids.add(q_val_str)
                    known_res = self._resources_by_ext_id.get(q_val_str)
                    res_type = known_res.resource_type.value if known_res else self._infer_resource_type(q_key)

                    matches.append(
                        ResourceMatch(
                            resource_id=known_res.id if known_res else None,
                            external_id=q_val_str,
                            resource_type=res_type,
                            source_location="QUERY",
                            parameter_name=q_key,
                        )
                    )

        # 3. Match from JSON body if applicable
        if body:
            parsed_body = None
            if isinstance(body, dict):
                parsed_body = body
            elif isinstance(body, str) and body.strip().startswith("{"):
                with contextlib.suppress(Exception):
                    parsed_body = json.loads(body)

            if isinstance(parsed_body, dict):
                for b_key, b_val in parsed_body.items():
                    if not b_val or isinstance(b_val, (dict, list)):
                        continue
                    b_val_str = str(b_val)
                    if self._is_potential_resource_id_key(b_key) and b_val_str not in seen_ext_ids:
                        seen_ext_ids.add(b_val_str)
                        known_res = self._resources_by_ext_id.get(b_val_str)
                        res_type = known_res.resource_type.value if known_res else self._infer_resource_type(b_key)

                        matches.append(
                            ResourceMatch(
                                resource_id=known_res.id if known_res else None,
                                external_id=b_val_str,
                                resource_type=res_type,
                                source_location="BODY",
                                parameter_name=b_key,
                            )
                        )

        return matches

    # -------------------------------------------------------------------------
    # Single Record Correlation
    # -------------------------------------------------------------------------

    def correlate_record(self, record: Any) -> CorrelatedTrafficRecord:
        """Enrich a single HTTP traffic record with identity and resource links.

        Accepts either an ORM TrafficRecordModel, Pydantic model, or plain dictionary.

        Args:
            record: Input HTTP traffic data object.

        Returns:
            CorrelatedTrafficRecord.
        """
        rec_id = str(getattr(record, "id", None) or (record.get("id") if isinstance(record, dict) else uuid4()))
        method = getattr(record, "method", None) or (record.get("method") if isinstance(record, dict) else "GET")
        raw_url = getattr(record, "url", None) or (record.get("url") if isinstance(record, dict) else None)
        path = getattr(record, "path", None) or (record.get("path") if isinstance(record, dict) else "")
        if not path and raw_url:
            path = urllib.parse.urlparse(raw_url).path
        url = raw_url or path or ""

        headers = getattr(record, "request_headers", None) or (
            record.get("request_headers") if isinstance(record, dict) else {}
        )
        query = getattr(record, "query_params", None) or (
            record.get("query_params") if isinstance(record, dict) else {}
        )
        body = getattr(record, "request_body", None) or (
            record.get("request_body") if isinstance(record, dict) else None
        )
        resp_status = getattr(record, "response_status", None) or (
            record.get("response_status") if isinstance(record, dict) else None
        )
        explicit_id = getattr(record, "identity_id", None) or (
            record.get("identity_id") if isinstance(record, dict) else None
        )

        cookies = self._extract_cookies_from_headers(headers)
        template_res = self.extract_template(path, method=method)
        identity_match = self.correlate_identity(
            headers=headers,
            cookies=cookies,
            explicit_identity_id=explicit_id,
        )
        resource_matches = self.correlate_resources(
            template_result=template_res,
            query_params=query,
            body=body,
        )

        is_success = bool(resp_status and 200 <= resp_status < 300)

        return CorrelatedTrafficRecord(
            record_id=rec_id,
            method=method.upper(),
            url=url,
            raw_path=path,
            template=template_res.template,
            endpoint_identifier=template_res.endpoint_identifier,
            identity_match=identity_match,
            resource_matches=resource_matches,
            response_status=resp_status,
            is_success_status=is_success,
        )

    # -------------------------------------------------------------------------
    # Batch Analysis & IDOR Identification
    # -------------------------------------------------------------------------

    def analyze_traffic(
        self,
        records: list[Any],
        project_id: UUID | None = None,
    ) -> TrafficCorrelationReport:
        """Run full correlation analysis across a collection of imported HTTP traffic records.

        Args:
            records: Collection of traffic records (ORM, Pydantic, or dictionaries).
            project_id: Context project identifier.

        Returns:
            TrafficCorrelationReport with templates, identities, IDOR candidates, and test suggestions.
        """
        proj_id = project_id or uuid4()
        correlated_records: list[CorrelatedTrafficRecord] = [self.correlate_record(rec) for rec in records]

        # Gather summary stats
        templates_seen: set[str] = set()
        identities_count: dict[str, int] = {}
        resources_count: dict[str, int] = {}

        for cr in correlated_records:
            templates_seen.add(cr.template)
            id_name = cr.identity_match.identity_name
            identities_count[id_name] = identities_count.get(id_name, 0) + 1

            for rm in cr.resource_matches:
                ext_id = rm.external_id
                resources_count[ext_id] = resources_count.get(ext_id, 0) + 1

        # Identify IDOR and cross-user vulnerabilities
        idor_candidates = self.identify_idor_candidates(correlated_records)

        # Synthesize actionable test cases
        test_case_suggestions = self.suggest_test_cases(idor_candidates, project_id=proj_id)

        # Synthesize inferred graph relationships
        inferred_relationships = self.generate_inferred_relationships(
            correlated_records=correlated_records,
            idor_candidates=idor_candidates,
        )

        return TrafficCorrelationReport(
            total_records_analyzed=len(correlated_records),
            templates_discovered=sorted(list(templates_seen)),
            identities_correlated=identities_count,
            resources_correlated=resources_count,
            potential_idor_candidates=idor_candidates,
            inferred_relationships=inferred_relationships,
            test_case_suggestions=test_case_suggestions,
            correlated_records=correlated_records,
        )

    def identify_idor_candidates(
        self,
        correlated_records: list[CorrelatedTrafficRecord],
    ) -> list[PotentialIDORCandidate]:
        """Detect cross-user and cross-tenant access anomalies from correlated records.

        Compares requests targeting the same endpoint template and external resource ID
        with distinct identity credentials that both succeed.

        Args:
            correlated_records: List of normalized correlated traffic records.

        Returns:
            List of PotentialIDORCandidate detections.
        """
        candidates: list[PotentialIDORCandidate] = []

        # Group successful requests by (endpoint_identifier, external_resource_id)
        # Key: (endpoint_template, method, external_id) -> list of records
        resource_access_map: dict[tuple[str, str, str], list[CorrelatedTrafficRecord]] = {}

        for rec in correlated_records:
            if not rec.is_success_status:
                continue

            for rm in rec.resource_matches:
                key = (rec.template, rec.method, rm.external_id)
                if key not in resource_access_map:
                    resource_access_map[key] = []
                resource_access_map[key].append(rec)

        # Analyze groups accessed by distinct identities
        for (template, method, ext_id), recs in resource_access_map.items():
            unique_identities: dict[str, CorrelatedTrafficRecord] = {}
            for r in recs:
                id_name = r.identity_match.identity_name
                if id_name not in unique_identities:
                    unique_identities[id_name] = r

            if len(unique_identities) < 2:
                continue  # Single user accessing their own resource, normal behavior

            # Multiple distinct identities accessed the SAME resource ID successfully
            identity_names = list(unique_identities.keys())
            participating_rec_ids = [r.record_id for r in recs]
            participating_id_uuids = [
                str(r.identity_match.identity_id) for r in recs if r.identity_match.identity_id is not None
            ]

            # Look up known resource if exists
            known_resource = self._resources_by_ext_id.get(ext_id)
            res_id = known_resource.id if known_resource else None
            res_type = (
                known_resource.resource_type.value if known_resource else recs[0].resource_matches[0].resource_type
            )
            owner_id = (
                str(known_resource.owning_identity_id) if known_resource and known_resource.owning_identity_id else None
            )
            owner_tenant = (
                str(known_resource.owning_tenant_id) if known_resource and known_resource.owning_tenant_id else None
            )

            # Check for cross-tenant breach
            is_cross_tenant = False
            distinct_tenants: set[str] = set()
            for r in recs:
                for t in r.identity_match.tenant_ids:
                    distinct_tenants.add(str(t))

            if len(distinct_tenants) > 1 or (owner_tenant and any(t != owner_tenant for t in distinct_tenants)):
                is_cross_tenant = True

            # Classify category and severity
            has_anonymous = any(r.identity_match.is_anonymous for r in recs)
            if is_cross_tenant:
                category = FindingCategory.CROSS_TENANT_ACCESS
                severity = FindingSeverity.CRITICAL
                title = f"Cross-Tenant Access on {method} {template} ({res_type} #{ext_id})"
                desc = (
                    f"Identities from distinct organizational tenants {list(distinct_tenants)} "
                    f"both successfully accessed target resource '{ext_id}' on endpoint '{method} {template}' "
                    f"with HTTP 2xx response codes."
                )
            elif has_anonymous:
                category = FindingCategory.MISSING_AUTHORIZATION
                severity = FindingSeverity.HIGH
                title = f"Unauthenticated BOLA/IDOR on {method} {template} ({res_type} #{ext_id})"
                desc = (
                    f"An anonymous request successfully accessed resource '{ext_id}' which was also accessed "
                    f"by authenticated identities ({identity_names}), indicating missing authorization."
                )
            else:
                category = FindingCategory.IDOR
                severity = FindingSeverity.HIGH
                title = f"Horizontal IDOR Candidate on {method} {template} ({res_type} #{ext_id})"
                desc = (
                    f"Multiple distinct authenticated identities ({', '.join(identity_names)}) successfully accessed "
                    f"identical resource ID '{ext_id}' on '{method} {template}'. "
                    f"If this resource is scoped to an individual owner, this represents an IDOR vulnerability."
                )

            obs_snapshots = [
                {
                    "traffic_record_id": r.record_id,
                    "identity": r.identity_match.identity_name,
                    "method": r.method,
                    "status_code": r.response_status,
                    "url": r.url,
                }
                for r in recs[:5]
            ]

            candidates.append(
                PotentialIDORCandidate(
                    endpoint_template=template,
                    method=method,
                    resource_external_id=ext_id,
                    resource_id=res_id,
                    resource_type=res_type,
                    category=category,
                    severity=severity,
                    traffic_record_ids=participating_rec_ids,
                    participating_identity_ids=participating_id_uuids,
                    participating_identity_names=identity_names,
                    primary_owner_identity_id=owner_id,
                    primary_tenant_id=owner_tenant,
                    cross_tenant=is_cross_tenant,
                    title=title,
                    description=desc,
                    reproduction_observations=obs_snapshots,
                    suggested_action=(
                        f"Implement strict object-level authorization check verifying that requesting identity "
                        f"owns or is tenant-authorized for {res_type} #{ext_id} before returning data."
                    ),
                )
            )

        return candidates

    # -------------------------------------------------------------------------
    # Relationship & Test Case Generation
    # -------------------------------------------------------------------------

    def generate_inferred_relationships(
        self,
        correlated_records: list[CorrelatedTrafficRecord],
        idor_candidates: list[PotentialIDORCandidate],
    ) -> list[Relationship]:
        """Generate inferred graph edges linking identities to resources and endpoints.

        Args:
            correlated_records: List of correlated traffic records.
            idor_candidates: Detected IDOR candidates.

        Returns:
            List of inferred Relationship domain objects.
        """
        relationships: list[Relationship] = []
        seen_pairs: set[tuple[str, str, RelationshipType]] = set()

        for rec in correlated_records:
            if not rec.identity_match.identity_id:
                continue
            id_uuid = rec.identity_match.identity_id

            for rm in rec.resource_matches:
                if not rm.resource_id:
                    continue
                res_uuid = rm.resource_id

                # Observed successful access
                rel_type = RelationshipType.HAS_ACCESS if rec.is_success_status else RelationshipType.DENIED_ACCESS
                pair_key = (str(id_uuid), str(res_uuid), rel_type)
                if pair_key not in seen_pairs:
                    seen_pairs.add(pair_key)
                    relationships.append(
                        Relationship(
                            source_type="identity",
                            source_id=id_uuid,
                            target_type="resource",
                            target_id=res_uuid,
                            relationship_type=rel_type,
                            confidence=RelationshipConfidence.INFERRED,
                            description=(
                                f"Observed {rec.method} access to resource '{rm.external_id}' "
                                f"resulting in HTTP {rec.response_status}"
                            ),
                        )
                    )

        # Add violation relationships for IDOR candidates
        for cand in idor_candidates:
            if cand.resource_id and cand.participating_identity_ids:
                for id_str in cand.participating_identity_ids:
                    try:
                        u_id = UUID(id_str)
                    except ValueError:
                        continue

                    # If this identity is NOT the primary owner, flag suspected violation
                    if cand.primary_owner_identity_id and id_str == cand.primary_owner_identity_id:
                        continue

                    viol_key = (id_str, str(cand.resource_id), RelationshipType.VIOLATES)
                    if viol_key not in seen_pairs:
                        seen_pairs.add(viol_key)
                        relationships.append(
                            Relationship(
                                source_type="identity",
                                source_id=u_id,
                                target_type="resource",
                                target_id=cand.resource_id,
                                relationship_type=RelationshipType.VIOLATES,
                                confidence=RelationshipConfidence.SUSPECTED_VIOLATION,
                                description=(
                                    f"Suspected IDOR violation: Identity accessed {cand.resource_type} "
                                    f"#{cand.resource_external_id} without confirmed ownership."
                                ),
                            )
                        )

        return relationships

    def suggest_test_cases(
        self,
        candidates: list[PotentialIDORCandidate],
        project_id: UUID | None = None,
    ) -> list[TestCaseDefinition]:
        """Synthesize concrete executable TestCaseDefinition objects from detected IDOR candidates.

        Args:
            candidates: Detected potential IDOR candidates.
            project_id: Context project ID.

        Returns:
            List of TestCaseDefinition instances configured for boundary verification.
        """
        proj_id = project_id or uuid4()
        suggestions: list[TestCaseDefinition] = []

        for cand in candidates:
            # Map HTTP method to PolicyAction
            action_map = {
                "GET": "READ",
                "POST": "WRITE",
                "PUT": "WRITE",
                "PATCH": "WRITE",
                "DELETE": "DELETE",
            }
            action_str = action_map.get(cand.method, "READ")

            # Determine subject identity for negative verification
            subject_uuid = uuid4()
            if cand.participating_identity_ids:
                with contextlib.suppress(ValueError):
                    subject_uuid = UUID(cand.participating_identity_ids[-1])

            # Construct URL template
            url_template = cand.endpoint_template
            test_name = (
                f"Assert Authorization Denial: {cand.participating_identity_names[-1]} "
                f"accessing {cand.resource_type} #{cand.resource_external_id} ({cand.method})"
            )

            req_template = RequestTemplate(
                method=cand.method,
                url_template=url_template,
                headers={"Accept": "application/json"},
                body_template=None,
            )

            suggestions.append(
                TestCaseDefinition(
                    project_id=proj_id,
                    name=test_name,
                    subject_identity_id=subject_uuid,
                    target_resource_id=cand.resource_id,
                    action=action_str,
                    expected_decision="DENY",
                    request_template=req_template,
                    preconditions=[
                        f"Resource #{cand.resource_external_id} belongs to a distinct owner",
                        "Subject must NOT possess elevated ADMIN role",
                    ],
                    execution_mode=ExecutionMode.PREVIEW,
                )
            )

        return suggestions

    # -------------------------------------------------------------------------
    # Helper Utilities
    # -------------------------------------------------------------------------

    @staticmethod
    def _classify_token(segment: str) -> str | None:
        """Determine if a path segment is a dynamic identifier token."""
        seg = segment.strip()
        if _UUID_RE.match(seg):
            return "uuid"
        if _INT_RE.match(seg):
            return "integer"
        if _HEX_ID_RE.match(seg):
            return "hex"
        if _PREFIXED_ID_RE.match(seg):
            return "prefixed"
        if _BASE64_SLUG_RE.match(seg):
            return "slug"
        return None

    @staticmethod
    def _singularize(word: str) -> str:
        """Convert common English plural nouns to singular parameter names."""
        w = word.lower().strip()
        if w.endswith("ies") and len(w) > 3:
            return w[:-3] + "y"
        if w.endswith("es") and not w.endswith("sses") and len(w) > 3:
            return w[:-2]
        if w.endswith("s") and not w.endswith("ss") and len(w) > 2:
            return w[:-1]
        return w

    @staticmethod
    def _infer_resource_type(param_name: str) -> str:
        """Infer ResourceType enum string from parameter naming conventions."""
        p = param_name.lower()
        if "user" in p or "profile" in p or "account" in p:
            return ResourceType.USER_PROFILE.value
        if "project" in p or "workspace" in p:
            return ResourceType.PROJECT.value
        if "doc" in p or "file" in p or "report" in p:
            return ResourceType.DOCUMENT.value
        if "order" in p or "cart" in p:
            return ResourceType.ORDER.value
        if "inv" in p or "bill" in p:
            return ResourceType.INVOICE.value
        if "org" in p or "tenant" in p:
            return ResourceType.ORGANIZATION.value
        return ResourceType.API_RESOURCE.value

    @staticmethod
    def _is_potential_resource_id_key(key: str) -> bool:
        """Determine if a query parameter or body attribute represents a target resource ID."""
        k = key.lower()
        return k in {"id", "resource_id", "external_id"} or k.endswith("_id") or k.endswith("id") and len(k) <= 15

    @staticmethod
    def _extract_cookies_from_headers(headers: dict[str, Any]) -> dict[str, str]:
        """Parse Cookie header into a dictionary of key-value pairs."""
        cookies: dict[str, str] = {}
        cookie_header = None
        for k, v in headers.items():
            if k.lower() == "cookie":
                cookie_header = str(v)
                break

        if cookie_header:
            parts = cookie_header.split(";")
            for part in parts:
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip().lower()] = v.strip()

        return cookies

    def _lookup_token(self, token_value: str) -> str | None:
        """Search token map for known token strings or substrings."""
        clean_token = token_value.strip()
        if clean_token in self._token_map:
            return self._token_map[clean_token]
        # Partial match
        for mapped_token, id_val in self._token_map.items():
            if mapped_token in clean_token or clean_token in mapped_token:
                return id_val
        return None

    @staticmethod
    def _mask_token(token: str) -> str:
        """Mask sensitive credential tokens to preserve security in logs and UI."""
        if len(token) <= 8:
            return "***"
        return f"{token[:4]}...{token[-4:]}"
