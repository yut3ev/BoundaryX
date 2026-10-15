"""Core authorization test execution engine for BoundaryX.

Provides offline policy evaluation, preview rendering without traffic emission,
controlled active HTTP test execution with scope validation, and batch orchestrations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse
from uuid import UUID, uuid4

from boundaryx.application.testing.models import (
    ExecutionMode,
    TestCaseDefinition,
    TestExecutionResult,
    TestOutcome,
    TestResultStatus,
)
from boundaryx.domain.identities.models import Identity, RoleType
from boundaryx.domain.policies.engine import PolicyEngine
from boundaryx.domain.policies.models import ExpectedDecision, PolicyAction
from boundaryx.domain.resources.models import Resource, ResourceType
from boundaryx.infrastructure.http.client import (
    HttpClient,
    HttpResponse,
    RequestCancelledError,
    ScopeViolationError,
)
from boundaryx.security.audit import TEST_STARTED, TEST_STOPPED, AuditLogger
from boundaryx.security.redaction import RedactionEngine
from boundaryx.security.scope import ScopeManager

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(UTC)


class TestRunner:
    """Core authorization test runner and evaluation engine for BoundaryX.

    Guarantees:
    - Never emits active HTTP traffic in OFFLINE or PREVIEW modes.
    - Strictly re-validates scope before EVERY outgoing HTTP request.
    - Conservative analytical response classification (never blindly equates 200 to ALLOW).
    - Thread-safe cancellation and progress monitoring.
    """

    __test__ = False

    def __init__(
        self,
        http_client: HttpClient,
        scope_manager: ScopeManager,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger | None = None,
        redaction_engine: RedactionEngine | None = None,
    ) -> None:
        """Initialize the TestRunner engine.

        Args:
            http_client: Configured HttpClient for network interaction.
            scope_manager: ScopeManager enforcing authorized boundary rules.
            policy_engine: PolicyEngine for evaluating domain authorization rules.
            audit_logger: Optional security AuditLogger for recording test milestones.
            redaction_engine: Optional RedactionEngine for sanitizing sensitive evidence.
        """
        self._http_client = http_client
        self._scope_manager = scope_manager
        self._policy_engine = policy_engine
        self._audit = audit_logger
        self._redactor = redaction_engine or RedactionEngine()
        self._cancelled = False
        self._running_count = 0
        self._lock = threading.Lock()

    @property
    def is_cancelled(self) -> bool:
        """Return True if execution cancellation has been requested."""
        return self._cancelled

    def cancel(self) -> None:
        """Cancel all running and pending test executions."""
        with self._lock:
            self._cancelled = True
        self._http_client.cancel()
        logger.info("TestRunner cancellation signaled")

    def reset(self) -> None:
        """Reset the cancellation state to allow new test runs."""
        with self._lock:
            self._cancelled = False
        self._http_client.reset_cancel()
        logger.info("TestRunner cancellation state reset")

    def preview_test(
        self,
        test_case: TestCaseDefinition,
        identity: dict[str, Any] | Identity,
        resource: dict[str, Any] | Resource | None = None,
    ) -> dict[str, Any]:
        """Preview test execution without sending network traffic.

        Resolves URL placeholders, checks target scope compliance, redacts
        sensitive headers, and displays identity and resource details.

        Args:
            test_case: TestCaseDefinition describing the test configuration.
            identity: Subject identity dictionary or model.
            resource: Optional target resource dictionary or model.

        Returns:
            Dictionary containing preview details:
            url, method, headers (redacted), scope_ok, scope_reason,
            identity_name, resource_name, action, expected_decision.
        """
        resolved_url = self._resolve_url(test_case.request_template.url_template, resource)

        # Append query parameters to resolved URL if present
        if test_case.request_template.query_params:
            parsed = urlparse(resolved_url)
            existing_query = parsed.query
            new_params = urlencode(test_case.request_template.query_params)
            combined_query = f"{existing_query}&{new_params}" if existing_query else new_params
            resolved_url = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    combined_query,
                    parsed.fragment,
                )
            )

        scope_ok, scope_reason = self._scope_manager.is_in_scope(resolved_url)

        # Redact headers
        raw_headers = dict(test_case.request_template.headers)
        redacted_headers = self._redactor.redact_headers(raw_headers)

        # Resolve identity name and resource display name
        if isinstance(identity, dict):
            identity_name = identity.get("name", "Unknown Identity")
            identity_role = identity.get("role_type", "AUTHENTICATED")
        else:
            identity_name = identity.name
            identity_role = identity.role_type.value

        resource_name = "None"
        if resource is not None:
            if isinstance(resource, dict):
                resource_name = resource.get("display_name") or resource.get("name") or "Unnamed Resource"
            else:
                resource_name = resource.display_name

        return {
            "test_case_id": str(test_case.id),
            "test_case_name": test_case.name,
            "url": self._redactor.redact_url(resolved_url),
            "raw_url": resolved_url,
            "method": test_case.request_template.method.upper(),
            "headers": redacted_headers,
            "body_preview": (
                self._redactor.redact_body(test_case.request_template.body_template)
                if test_case.request_template.body_template
                else None
            ),
            "scope_ok": scope_ok,
            "scope_reason": scope_reason,
            "identity_name": identity_name,
            "identity_role": identity_role,
            "resource_name": resource_name,
            "action": test_case.action,
            "expected_decision": test_case.expected_decision.upper(),
            "execution_mode": test_case.execution_mode.value,
        }

    def execute_offline(
        self,
        test_case: TestCaseDefinition,
        policy_engine: PolicyEngine,
        identity: dict[str, Any] | Identity,
        resource: dict[str, Any] | Resource | None = None,
        existing_evidence: list[Any] | None = None,
    ) -> TestExecutionResult:
        """Perform offline authorization analysis without sending HTTP requests.

        Evaluates expected decisions using the PolicyEngine and compares
        them against previously collected evidence or imported traffic records.

        Args:
            test_case: TestCaseDefinition being evaluated.
            policy_engine: PolicyEngine instance to compute expected policy decision.
            identity: Subject identity executing the action.
            resource: Target resource being accessed.
            existing_evidence: List of historical evidence records or traffic entries.

        Returns:
            TestExecutionResult with analytical reasoning and classification.
        """
        start_time = _utc_now()
        reasoning: list[str] = [
            f"Initiating offline evaluation for test case '{test_case.name}' ({test_case.id}).",
        ]

        # Coerce identity to domain model
        identity_model = self._coerce_identity(identity)
        resource_model = self._coerce_resource(resource) if resource is not None else None

        # Parse policy action
        action_str = test_case.action.upper()
        try:
            policy_action = PolicyAction(action_str)
        except ValueError:
            policy_action = PolicyAction.CUSTOM

        # Evaluate expected access via PolicyEngine if resource available
        expected_pol_decision = test_case.expected_decision.upper()
        if resource_model is not None:
            evaluation = policy_engine.evaluate(
                identity=identity_model,
                resource=resource_model,
                action=policy_action,
                endpoint=test_case.request_template.url_template,
            )
            reasoning.append(f"Policy engine evaluation: {evaluation.reasoning}")
            if evaluation.expected_decision != ExpectedDecision.UNKNOWN:
                expected_pol_decision = evaluation.expected_decision.value

        # Search existing evidence / imported traffic for matching interactions
        resolved_url = self._resolve_url(test_case.request_template.url_template, resource)
        matching_evidence = self._find_matching_evidence(
            existing_evidence or [],
            method=test_case.request_template.method,
            url=resolved_url,
            identity_id=identity_model.id,
        )

        completed_time = _utc_now()

        if not matching_evidence:
            reasoning.append(
                f"No matching historical traffic or evidence found for URL '{resolved_url}' "
                f"and identity '{identity_model.name}'."
            )
            return TestExecutionResult(
                id=uuid4(),
                test_case_id=test_case.id,
                started_at=start_time,
                completed_at=completed_time,
                status=TestResultStatus.INCONCLUSIVE,
                outcome=TestOutcome.INSUFFICIENT_EVIDENCE,
                request_snapshot={"url": resolved_url, "method": test_case.request_template.method},
                response_snapshot=None,
                actual_status_code=None,
                actual_decision=None,
                error_message=None,
                scope_check_passed=True,
                reasoning=reasoning,
            )

        # Inspect the matched evidence
        ev_item = matching_evidence[0]
        status_code, body, resp_headers = self._extract_evidence_response(ev_item)
        reasoning.append(f"Found matching evidence record (status: {status_code}) for comparison.")

        dummy_resp = HttpResponse(
            status_code=status_code or 0,
            headers=resp_headers,
            body=body or "",
            content_type=resp_headers.get("content-type", ""),
            url=resolved_url,
        )

        outcome, actual_decision, class_reasoning = self._classify_response(
            response=dummy_resp,
            expected_decision=expected_pol_decision,
            resource=resource,
        )
        reasoning.extend(class_reasoning)

        # Determine overall test status
        if outcome in (TestOutcome.EXPECTED_ALLOW, TestOutcome.EXPECTED_DENIAL):
            status = TestResultStatus.PASSED
        elif outcome in (TestOutcome.UNEXPECTED_ALLOW, TestOutcome.UNEXPECTED_DENIAL):
            status = TestResultStatus.FAILED
        elif outcome == TestOutcome.INSUFFICIENT_EVIDENCE:
            status = TestResultStatus.INCONCLUSIVE
        else:
            status = TestResultStatus.ERROR

        ev_id = getattr(ev_item, "id", None)
        if isinstance(ev_id, str):
            try:
                ev_id = UUID(ev_id)
            except ValueError:
                ev_id = None

        return TestExecutionResult(
            id=uuid4(),
            test_case_id=test_case.id,
            started_at=start_time,
            completed_at=completed_time,
            status=status,
            outcome=outcome,
            request_snapshot={"url": resolved_url, "method": test_case.request_template.method},
            response_snapshot={"status_code": status_code, "body": body[:500] if body else None},
            actual_status_code=status_code,
            actual_decision=actual_decision,
            evidence_id=ev_id,
            scope_check_passed=True,
            reasoning=reasoning,
        )

    def execute_active(
        self,
        test_case: TestCaseDefinition,
        identity: dict[str, Any] | Identity,
        auth_headers: dict[str, str],
        resource: dict[str, Any] | Resource | None = None,
    ) -> TestExecutionResult:
        """Send controlled real HTTP requests to verify authorization boundaries.

        Enforces mandatory scope validation prior to execution, captures evidence,
        and conservative analytical classification of responses.

        Args:
            test_case: TestCaseDefinition to execute.
            identity: Subject identity performing request.
            auth_headers: Decrypted authentication headers (e.g. Bearer token, Cookie).
            resource: Target resource being accessed.

        Returns:
            TestExecutionResult containing detailed request/response snapshots and verdict.
        """
        start_time = _utc_now()
        reasoning: list[str] = [
            f"Starting active test execution for '{test_case.name}' ({test_case.id}).",
        ]

        if self._cancelled:
            reasoning.append("Execution aborted: cancellation requested prior to request dispatch.")
            return TestExecutionResult(
                id=uuid4(),
                test_case_id=test_case.id,
                started_at=start_time,
                completed_at=_utc_now(),
                status=TestResultStatus.CANCELLED,
                outcome=None,
                error_message="Test run was cancelled",
                scope_check_passed=True,
                reasoning=reasoning,
            )

        # 1. Resolve URL template
        resolved_url = self._resolve_url(test_case.request_template.url_template, resource)
        if test_case.request_template.query_params:
            parsed = urlparse(resolved_url)
            existing_query = parsed.query
            new_params = urlencode(test_case.request_template.query_params)
            combined_query = f"{existing_query}&{new_params}" if existing_query else new_params
            resolved_url = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    combined_query,
                    parsed.fragment,
                )
            )

        # 2. Strict Scope Re-check (MUST check before EVERY outgoing request)
        scope_ok, scope_reason = self._scope_manager.is_in_scope(resolved_url)
        if not scope_ok:
            reasoning.append(f"SCOPE VIOLATION BLOCKED: URL '{resolved_url}' is out of scope ({scope_reason}).")
            logger.warning("Active test blocked by scope check: %s (%s)", resolved_url, scope_reason)
            return TestExecutionResult(
                id=uuid4(),
                test_case_id=test_case.id,
                started_at=start_time,
                completed_at=_utc_now(),
                status=TestResultStatus.BLOCKED_BY_SCOPE,
                outcome=None,
                actual_status_code=None,
                actual_decision=None,
                error_message=f"Scope violation: {scope_reason}",
                scope_check_passed=False,
                reasoning=reasoning,
            )

        reasoning.append(f"Target URL passed scope boundary validation: {resolved_url}")

        # 3. Log test start via audit if configured
        if self._audit:
            try:
                self._audit.log(
                    event_type=TEST_STARTED,
                    description=f"Active authorization test started: {test_case.name}",
                    project_id=test_case.project_id,
                    details={
                        "test_case_id": str(test_case.id),
                        "url": self._redactor.redact_url(resolved_url),
                        "method": test_case.request_template.method,
                    },
                )
            except Exception as exc:
                logger.warning("Failed to record audit event for test start: %s", exc)

        # 4. Prepare request headers and body
        request_headers = dict(test_case.request_template.headers)
        request_body = test_case.request_template.body_template

        # 5. Send request via HttpClient
        response: HttpResponse | None = None
        error_msg: str | None = None
        try:
            with self._lock:
                self._running_count += 1

            response = self._http_client.send_request(
                method=test_case.request_template.method,
                url=resolved_url,
                headers=request_headers,
                body=request_body,
                auth_headers=auth_headers,
            )
        except ScopeViolationError as exc:
            reasoning.append(f"Execution terminated: Scope violation during redirect hop: {exc}")
            return TestExecutionResult(
                id=uuid4(),
                test_case_id=test_case.id,
                started_at=start_time,
                completed_at=_utc_now(),
                status=TestResultStatus.BLOCKED_BY_SCOPE,
                outcome=None,
                error_message=str(exc),
                scope_check_passed=False,
                reasoning=reasoning,
            )
        except RequestCancelledError:
            reasoning.append("Request cancelled during execution.")
            return TestExecutionResult(
                id=uuid4(),
                test_case_id=test_case.id,
                started_at=start_time,
                completed_at=_utc_now(),
                status=TestResultStatus.CANCELLED,
                outcome=None,
                error_message="Execution was cancelled",
                scope_check_passed=True,
                reasoning=reasoning,
            )
        except Exception as exc:
            error_msg = f"Unexpected execution error: {exc}"
            reasoning.append(error_msg)
            return TestExecutionResult(
                id=uuid4(),
                test_case_id=test_case.id,
                started_at=start_time,
                completed_at=_utc_now(),
                status=TestResultStatus.ERROR,
                outcome=TestOutcome.EXECUTION_ERROR,
                error_message=error_msg,
                scope_check_passed=True,
                reasoning=reasoning,
            )
        finally:
            with self._lock:
                if self._running_count > 0:
                    self._running_count -= 1

        completed_time = _utc_now()

        # Handle HTTP level network failures (status_code 0 or response.error)
        if response.status_code == 0 or response.error:
            error_msg = response.error or "HTTP connection failure (status 0)"
            reasoning.append(f"HTTP transport failed: {error_msg}")
            return TestExecutionResult(
                id=uuid4(),
                test_case_id=test_case.id,
                started_at=start_time,
                completed_at=completed_time,
                status=TestResultStatus.ERROR,
                outcome=TestOutcome.HTTP_ERROR,
                actual_status_code=0,
                error_message=error_msg,
                scope_check_passed=True,
                reasoning=reasoning,
            )

        # 6. Classify Response
        outcome, actual_decision, class_reasoning = self._classify_response(
            response=response,
            expected_decision=test_case.expected_decision,
            resource=resource,
        )
        reasoning.extend(class_reasoning)

        # Determine overall test status
        if outcome in (TestOutcome.EXPECTED_ALLOW, TestOutcome.EXPECTED_DENIAL):
            status = TestResultStatus.PASSED
        elif outcome in (TestOutcome.UNEXPECTED_ALLOW, TestOutcome.UNEXPECTED_DENIAL):
            status = TestResultStatus.FAILED
        elif outcome == TestOutcome.INSUFFICIENT_EVIDENCE:
            status = TestResultStatus.INCONCLUSIVE
        else:
            status = TestResultStatus.ERROR

        # 7. Create Evidence Snapshot
        request_data = {
            "method": test_case.request_template.method,
            "url": resolved_url,
            "headers": {**request_headers, **auth_headers},
            "body": request_body,
        }
        evidence_snapshot = self._create_evidence_snapshot(request_data, response)

        # Redact snapshots for result storage
        sanitized_req_snapshot = self._redactor.redact_evidence(request_data)
        sanitized_resp_snapshot = self._redactor.redact_evidence(
            {
                "status_code": response.status_code,
                "headers": response.headers,
                "body": response.body,
                "content_type": response.content_type,
                "elapsed_ms": response.elapsed_ms,
            }
        )
        sanitized_resp_snapshot["evidence_hash"] = evidence_snapshot["content_hash"]

        if self._audit:
            try:
                self._audit.log(
                    event_type=TEST_STOPPED,
                    description=f"Active authorization test finished: {test_case.name} ({status.value})",
                    project_id=test_case.project_id,
                    details={
                        "test_case_id": str(test_case.id),
                        "status": status.value,
                        "outcome": outcome.value if outcome else None,
                        "status_code": response.status_code,
                        "evidence_hash": evidence_snapshot["content_hash"],
                    },
                )
            except Exception as exc:
                logger.warning("Failed to record audit event for test stop: %s", exc)

        return TestExecutionResult(
            id=uuid4(),
            test_case_id=test_case.id,
            started_at=start_time,
            completed_at=completed_time,
            status=status,
            outcome=outcome,
            request_snapshot=sanitized_req_snapshot,
            response_snapshot=sanitized_resp_snapshot,
            actual_status_code=response.status_code,
            actual_decision=actual_decision,
            error_message=None,
            scope_check_passed=True,
            reasoning=reasoning,
        )

    def execute_batch(
        self,
        test_cases: list[TestCaseDefinition],
        identities: dict[UUID | str, Any],
        resources: dict[UUID | str, Any],
        auth_profiles: dict[UUID | str, Any],
        mode: ExecutionMode,
        progress_callback: Callable[[int, int, TestExecutionResult], None] | None = None,
    ) -> list[TestExecutionResult]:
        """Execute multiple authorization test cases with progress feedback.

        Respects cancellation requests between test case steps.

        Args:
            test_cases: List of TestCaseDefinition instances to evaluate.
            identities: Lookup mapping of identity ID to Identity entity or dictionary.
            resources: Lookup mapping of resource ID to Resource entity or dictionary.
            auth_profiles: Lookup mapping of auth profile ID to headers/profile info.
            mode: Designated ExecutionMode (OFFLINE, PREVIEW, or ACTIVE).
            progress_callback: Optional callable invoked after each test case completion:
                progress_callback(completed_count, total_count, latest_result).

        Returns:
            List of TestExecutionResult instances.
        """
        results: list[TestExecutionResult] = []
        total = len(test_cases)

        logger.info("Executing batch of %d test cases in %s mode", total, mode.value)

        for idx, tc in enumerate(test_cases):
            if self._cancelled:
                logger.info("Batch execution interrupted by cancellation at item %d/%d", idx, total)
                cancel_result = TestExecutionResult(
                    id=uuid4(),
                    test_case_id=tc.id,
                    started_at=_utc_now(),
                    completed_at=_utc_now(),
                    status=TestResultStatus.CANCELLED,
                    outcome=None,
                    error_message="Batch execution was cancelled",
                    scope_check_passed=True,
                    reasoning=["Test execution was cancelled by user."],
                )
                results.append(cancel_result)
                if progress_callback:
                    progress_callback(idx + 1, total, cancel_result)
                continue

            # Resolve subject identity
            identity_id_str = str(tc.subject_identity_id)
            identity = (
                identities.get(tc.subject_identity_id)
                or identities.get(identity_id_str)
                or {"name": "Default Identity", "role_type": "AUTHENTICATED", "id": tc.subject_identity_id}
            )

            # Resolve target resource
            resource = None
            if tc.target_resource_id:
                resource_id_str = str(tc.target_resource_id)
                resource = resources.get(tc.target_resource_id) or resources.get(resource_id_str)

            # Resolve auth profile / headers
            auth_headers: dict[str, str] = {}
            if tc.auth_profile_id:
                auth_id_str = str(tc.auth_profile_id)
                profile = auth_profiles.get(tc.auth_profile_id) or auth_profiles.get(auth_id_str)
                if isinstance(profile, dict):
                    auth_headers = profile.get("headers", {})
                elif hasattr(profile, "headers"):
                    auth_headers = getattr(profile, "headers", {})

            # Execute according to mode
            result: TestExecutionResult
            if mode == ExecutionMode.ACTIVE:
                result = self.execute_active(
                    test_case=tc,
                    identity=identity,
                    auth_headers=auth_headers,
                    resource=resource,
                )
            elif mode == ExecutionMode.OFFLINE:
                result = self.execute_offline(
                    test_case=tc,
                    policy_engine=self._policy_engine,
                    identity=identity,
                    resource=resource,
                )
            else:  # PREVIEW
                preview = self.preview_test(test_case=tc, identity=identity, resource=resource)
                result = TestExecutionResult(
                    id=uuid4(),
                    test_case_id=tc.id,
                    started_at=_utc_now(),
                    completed_at=_utc_now(),
                    status=TestResultStatus.PASSED if preview["scope_ok"] else TestResultStatus.BLOCKED_BY_SCOPE,
                    outcome=None,
                    request_snapshot=preview,
                    response_snapshot=None,
                    actual_status_code=None,
                    actual_decision=None,
                    error_message=None if preview["scope_ok"] else preview["scope_reason"],
                    scope_check_passed=preview["scope_ok"],
                    reasoning=[
                        f"Preview evaluated: Scope OK={preview['scope_ok']} ({preview['scope_reason']}).",
                        f"Expected decision: {preview['expected_decision']} on {preview['method']} {preview['url']}.",
                    ],
                )

            results.append(result)
            if progress_callback:
                try:
                    progress_callback(idx + 1, total, result)
                except Exception as exc:
                    logger.warning("Error in test progress callback: %s", exc)

        return results

    def _resolve_url(self, template: str, resource: dict[str, Any] | Resource | None = None) -> str:
        """Resolve URL template placeholders using resource attributes.

        Supported placeholders:
        {resource_id}, {id}, {external_id}, {name}, or any key in resource metadata.

        Args:
            template: URL pattern with placeholder braces.
            resource: Target Resource entity or dictionary.

        Returns:
            Resolved absolute or relative URL string.
        """
        if not template:
            return ""

        url = template.strip()
        if resource is None:
            return url

        # Build replacement mapping
        mapping: dict[str, str] = {}
        if isinstance(resource, dict):
            for k, v in resource.items():
                if v is not None and not isinstance(v, (dict, list)):
                    mapping[str(k).lower()] = str(v)
            if "metadata" in resource and isinstance(resource["metadata"], dict):
                for k, v in resource["metadata"].items():
                    mapping[str(k).lower()] = str(v)
            if "id" in resource:
                mapping["resource_id"] = str(resource["id"])
            if "external_id" in resource:
                mapping["resource_id"] = str(resource["external_id"])
        else:
            mapping["id"] = str(resource.id)
            mapping["resource_id"] = str(resource.external_id or resource.id)
            mapping["external_id"] = str(resource.external_id or resource.id)
            mapping["display_name"] = str(resource.display_name)
            if resource.metadata:
                for k, v in resource.metadata.items():
                    mapping[str(k).lower()] = str(v)

        def _sub_placeholder(match: re.Match) -> str:
            key = match.group(1).lower()
            if key in mapping:
                return mapping[key]
            # Try default keys if specific placeholder not found
            if key in ("resource_id", "id", "external_id") and "external_id" in mapping:
                return mapping["external_id"]
            if key in ("resource_id", "id", "external_id") and "id" in mapping:
                return mapping["id"]
            return match.group(0)

        resolved = re.sub(r"\{(\w+)\}", _sub_placeholder, url)
        return resolved

    def _classify_response(
        self,
        response: HttpResponse,
        expected_decision: str,
        resource: dict[str, Any] | Resource | None = None,
    ) -> tuple[TestOutcome, str | None, list[str]]:
        """Conservative analytical response classification.

        Never blindly equates 200 to ALLOW or 403 to DENY.
        Verifies presence of actual target resource payload data where possible.

        Args:
            response: Captured HttpResponse.
            expected_decision: Expected access decision ('ALLOW' or 'DENY').
            resource: Optional target resource for payload matching.

        Returns:
            Tuple of (TestOutcome, actual_decision, reasoning_list).
        """
        expected = str(expected_decision).strip().upper()
        code = response.status_code
        reasoning: list[str] = []

        # 1. Transport error or connection timeout
        if code == 0 or response.error:
            reasoning.append(f"HTTP transport error encountered: {response.error or 'Code 0'}")
            return TestOutcome.HTTP_ERROR, None, reasoning

        # 2. Server Errors (500+) -> Inconclusive execution error
        if code >= 500:
            reasoning.append(
                f"Server error HTTP {code}: application failure or crash; inconclusive for authorization boundary."
            )
            return TestOutcome.EXECUTION_ERROR, None, reasoning

        # 3. Explicit Denial: 401 Unauthorized or 403 Forbidden
        if code in (401, 403):
            actual_decision = "DENY"
            if expected == "DENY":
                reasoning.append(f"HTTP {code} received: access denied as expected. Boundary properly enforced.")
                return TestOutcome.EXPECTED_DENIAL, actual_decision, reasoning
            else:
                reasoning.append(
                    f"HTTP {code} received: access denied unexpectedly (expected ALLOW). Potential under-permission."
                )
                return TestOutcome.UNEXPECTED_DENIAL, actual_decision, reasoning

        # 4. Not Found: 404
        if code == 404:
            # 404 can represent defense-in-depth object masking for unauthorized users
            if expected == "DENY":
                actual_decision = "DENY"
                reasoning.append(
                    "HTTP 404 received for expected DENY: resource either masked or not accessible, "
                    "consistent with denial."
                )
                return TestOutcome.EXPECTED_DENIAL, actual_decision, reasoning
            else:
                reasoning.append("HTTP 404 received for expected ALLOW: resource was not located. Inconclusive.")
                return TestOutcome.INSUFFICIENT_EVIDENCE, None, reasoning

        # 5. Success Codes: 200 to 299
        if 200 <= code < 300:
            body = response.body or ""
            # Inspect body to determine if target resource content is actually revealed
            has_resource_data, match_detail = self._verify_resource_payload(body, resource)

            # Check if response body actually contains an embedded soft-error (e.g. {"error": "unauthorized"})
            soft_error_detected = self._detect_soft_denial(body)
            if soft_error_detected:
                actual_decision = "DENY"
                reasoning.append(
                    f"HTTP {code} returned soft-error payload in body ({soft_error_detected}): treated as DENIAL."
                )
                if expected == "DENY":
                    return TestOutcome.EXPECTED_DENIAL, actual_decision, reasoning
                else:
                    return TestOutcome.UNEXPECTED_DENIAL, actual_decision, reasoning

            if resource is not None:
                if has_resource_data:
                    actual_decision = "ALLOW"
                    if expected == "ALLOW":
                        reasoning.append(
                            f"HTTP {code} with validated resource payload data ({match_detail}): "
                            "access granted as expected."
                        )
                        return TestOutcome.EXPECTED_ALLOW, actual_decision, reasoning
                    else:
                        reasoning.append(
                            f"SECURITY DEFECT: HTTP {code} returned target resource data ({match_detail}) "
                            f"when expected decision was DENY. Unauthorized boundary breached!"
                        )
                        return TestOutcome.UNEXPECTED_ALLOW, actual_decision, reasoning
                else:
                    # 200 without confirmation of resource data is INCONCLUSIVE
                    reasoning.append(
                        f"HTTP {code} received, but response body lacked expected resource identifiers: "
                        f"cannot confirm data access; marked INCONCLUSIVE."
                    )
                    return TestOutcome.INSUFFICIENT_EVIDENCE, None, reasoning
            else:
                # No specific resource target defined (e.g. general list/read action)
                actual_decision = "ALLOW"
                if expected == "ALLOW":
                    reasoning.append(f"HTTP {code} received for general endpoint test: access allowed as expected.")
                    return TestOutcome.EXPECTED_ALLOW, actual_decision, reasoning
                else:
                    reasoning.append(
                        f"HTTP {code} received on general endpoint where expected was DENY: "
                        "access granted unexpectedly."
                    )
                    return TestOutcome.UNEXPECTED_ALLOW, actual_decision, reasoning

        # 6. Redirects (300 to 399)
        if 300 <= code < 400:
            location = response.headers.get("location", "")
            if any(term in location.lower() for term in ("login", "signin", "auth", "unauthorized")):
                actual_decision = "DENY"
                reasoning.append(
                    f"HTTP {code} redirected to authentication gateway ({location}): treated as access denied."
                )
                if expected == "DENY":
                    return TestOutcome.EXPECTED_DENIAL, actual_decision, reasoning
                else:
                    return TestOutcome.UNEXPECTED_DENIAL, actual_decision, reasoning
            reasoning.append(f"HTTP {code} redirect to '{location}' without auth gateway: inconclusive.")
            return TestOutcome.INSUFFICIENT_EVIDENCE, None, reasoning

        # 7. Other client errors (400, 405, 422, etc.)
        reasoning.append(f"Client error HTTP {code} received: execution inconclusive.")
        return TestOutcome.HTTP_ERROR, None, reasoning

    def _verify_resource_payload(self, body: str, resource: dict[str, Any] | Resource | None) -> tuple[bool, str]:
        """Check if the response body contains verified attributes of the target resource."""
        if not body or resource is None:
            return False, "Empty response body or no resource target"

        identifiers: list[str] = []
        if isinstance(resource, dict):
            if "external_id" in resource and resource["external_id"]:
                identifiers.append(str(resource["external_id"]))
            if "id" in resource and resource["id"]:
                identifiers.append(str(resource["id"]))
            if "display_name" in resource and resource["display_name"]:
                identifiers.append(str(resource["display_name"]))
        else:
            if resource.external_id:
                identifiers.append(str(resource.external_id))
            identifiers.append(str(resource.id))
            if resource.display_name:
                identifiers.append(str(resource.display_name))

        # Filter out trivial strings (e.g. single digits or very short values that easily collide)
        meaningful_ids = [ident for ident in identifiers if len(ident) >= 2]
        if not meaningful_ids:
            # If identifiers were trivial, look for structured JSON
            if body.strip().startswith("{") and body.strip().endswith("}"):
                return True, "Structured JSON payload returned"
            return False, "No non-trivial identifiers to match"

        for ident in meaningful_ids:
            if ident in body:
                return True, f"Matched identifier token '{ident}'"

        return False, "Identifiers not found in body content"

    def _detect_soft_denial(self, body: str) -> str | None:
        """Detect whether a 200 OK response contains an application-level denial message."""
        if not body:
            return None

        trimmed = body.strip().lower()
        # Look for explicit JSON error structures
        if trimmed.startswith("{") and trimmed.endswith("}"):
            try:
                data = json.loads(trimmed)
                if isinstance(data, dict):
                    msg = str(data.get("error") or data.get("message") or "").lower()
                    if any(kw in msg for kw in ("unauthorized", "forbidden", "access denied", "permission denied")):
                        return f"JSON body contains error message '{msg}'"
            except Exception:
                pass

        # Check raw text for unambiguous denial phrases
        for phrase in ("access denied", "permission denied", "unauthorized access"):
            if phrase in trimmed:
                return f"Body text contains '{phrase}'"

        return None

    def _create_evidence_snapshot(self, request_data: dict[str, Any], response: HttpResponse) -> dict[str, Any]:
        """Create a cryptographically verifiable evidence dictionary from request and response."""
        canonical_content = {
            "request": {
                "method": request_data.get("method"),
                "url": request_data.get("url"),
                "headers": sorted(dict(request_data.get("headers", {})).items()),
                "body": request_data.get("body"),
            },
            "response": {
                "status_code": response.status_code,
                "headers": sorted(dict(response.headers).items()),
                "body": response.body,
                "content_type": response.content_type,
                "elapsed_ms": response.elapsed_ms,
            },
            "timestamp": _utc_now().isoformat(),
        }

        serialized = json.dumps(canonical_content, sort_keys=True, default=str)
        content_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        return {
            "content_hash": content_hash,
            "raw": canonical_content,
        }

    def _coerce_identity(self, identity: dict[str, Any] | Identity) -> Identity:
        """Coerce a dictionary or Identity model to an Identity instance."""
        if isinstance(identity, Identity):
            return identity

        raw_id = identity.get("id") or uuid4()
        if isinstance(raw_id, str):
            try:
                raw_id = UUID(raw_id)
            except ValueError:
                raw_id = uuid4()

        raw_role = identity.get("role_type", "AUTHENTICATED")
        try:
            role_type = RoleType(raw_role)
        except ValueError:
            role_type = RoleType.AUTHENTICATED

        return Identity(
            id=raw_id,
            name=identity.get("name", "Unknown Identity"),
            role_type=role_type,
            tenant_ids=[UUID(t) if isinstance(t, str) else t for t in identity.get("tenant_ids", [])],
        )

    def _coerce_resource(self, resource: dict[str, Any] | Resource) -> Resource:
        """Coerce a dictionary or Resource model to a Resource instance."""
        if isinstance(resource, Resource):
            return resource

        raw_id = resource.get("id") or uuid4()
        if isinstance(raw_id, str):
            try:
                raw_id = UUID(raw_id)
            except ValueError:
                raw_id = uuid4()

        raw_type = resource.get("resource_type", "API_RESOURCE")
        try:
            res_type = ResourceType(raw_type)
        except ValueError:
            res_type = ResourceType.API_RESOURCE

        ext_id = str(resource.get("external_id") or resource.get("id") or raw_id)

        return Resource(
            id=raw_id,
            display_name=resource.get("display_name") or resource.get("name", "Unknown Resource"),
            resource_type=res_type,
            external_id=ext_id,
            associated_endpoints=list(resource.get("associated_endpoints", [])),
            owning_identity_id=(UUID(resource["owning_identity_id"]) if resource.get("owning_identity_id") else None),
            owning_tenant_id=(UUID(resource["owning_tenant_id"]) if resource.get("owning_tenant_id") else None),
        )

    def _find_matching_evidence(
        self,
        evidence_pool: list[Any],
        method: str,
        url: str,
        identity_id: UUID | None = None,
    ) -> list[Any]:
        """Search existing evidence pool for requests matching target method and URL."""
        matches = []
        norm_method = method.upper()
        norm_url = url.split("?")[0].rstrip("/")

        for item in evidence_pool:
            item_method = ""
            item_url = ""

            # Check TrafficRecordModel or dict or Evidence
            if hasattr(item, "method") and hasattr(item, "url"):
                item_method = str(item.method).upper()
                item_url = str(item.url).split("?")[0].rstrip("/")
            elif isinstance(item, dict):
                req = item.get("request_snapshot") or item
                item_method = str(req.get("method", "")).upper()
                item_url = str(req.get("url", "")).split("?")[0].rstrip("/")
            elif hasattr(item, "request_snapshot") and item.request_snapshot:
                item_method = str(getattr(item.request_snapshot, "method", "")).upper()
                item_url = str(getattr(item.request_snapshot, "url", "")).split("?")[0].rstrip("/")

            if item_method == norm_method and (norm_url == item_url or norm_url.endswith(item_url)):
                matches.append(item)

        return matches

    def _extract_evidence_response(self, item: Any) -> tuple[int | None, str, dict[str, str]]:
        """Extract status code, body, and headers from an evidence or traffic record item."""
        if hasattr(item, "response_status"):
            # TrafficRecordModel
            return (
                item.response_status,
                item.response_body or "",
                dict(item.response_headers or {}),
            )
        if isinstance(item, dict):
            resp = item.get("response_snapshot") or item.get("response") or item
            sc = resp.get("status_code") if resp.get("status_code") is not None else resp.get("response_status")
            body = resp.get("body") if resp.get("body") is not None else resp.get("response_body", "")
            hdrs = resp.get("headers") if resp.get("headers") is not None else resp.get("response_headers", {})
            return (
                sc,
                body or "",
                dict(hdrs or {}),
            )
        if hasattr(item, "response_snapshot") and item.response_snapshot:
            snap = item.response_snapshot
            return (
                getattr(snap, "status_code", None),
                getattr(snap, "body", "") or "",
                dict(getattr(snap, "headers", {}) or {}),
            )
        return None, "", {}
