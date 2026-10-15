"""Test case management and execution orchestration service for BoundaryX.

Provides CRUD for test cases, batch execution, historical tracking,
and automated test matrix generation from defined authorization policies.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from boundaryx.application.testing.models import (
    ExecutionMode,
    RequestTemplate,
    TestCaseDefinition,
    TestExecutionResult,
    TestOutcome,
    TestResultStatus,
)
from boundaryx.application.testing.runner import TestRunner
from boundaryx.domain.findings.models import (
    ConfidenceExplanation,
    ConfidenceLevel,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
)
from boundaryx.infrastructure.database.models import (
    AuthenticationProfileModel,
    FindingModel,
    IdentityModel,
    PolicyModel,
    ResourceModel,
    TestCaseModel,
    TestExecutionModel,
    TrafficRecordModel,
)
from boundaryx.security.audit import AuditLogger
from boundaryx.security.secrets import SecretManager

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class TestCaseService:
    """Application service coordinating test case lifecycle, execution, and policy matrix synthesis."""

    __test__ = False

    def __init__(
        self,
        db_manager: Any,
        test_runner: TestRunner,
        audit_logger: AuditLogger | None = None,
        secret_manager: SecretManager | None = None,
    ) -> None:
        """Initialize TestCaseService with database manager and execution runner.

        Args:
            db_manager: Database connection/session manager.
            test_runner: Core TestRunner execution engine.
            audit_logger: Optional security AuditLogger for milestone tracking.
            secret_manager: Optional SecretManager for resolving stored credentials.
        """
        self._db_manager = db_manager
        self._runner = test_runner
        self._audit = audit_logger
        self._secret_manager = secret_manager

    @property
    def runner(self) -> TestRunner:
        """Return the underlying TestRunner instance."""
        return self._runner

    def _to_uuid(self, val: UUID | str) -> UUID:
        """Coerce string or UUID representation to uuid.UUID."""
        if isinstance(val, UUID):
            return val
        return UUID(str(val))

    def _to_str(self, val: UUID | str | None) -> str | None:
        """Convert UUID or string to clean string or None."""
        if val is None:
            return None
        return str(val)

    def create_test_case(
        self,
        session: Session,
        project_id: UUID | str,
        definition: TestCaseDefinition,
    ) -> UUID:
        """Persist a new authorization test case definition to the database.

        Args:
            session: Active database session.
            project_id: ID of the parent project.
            definition: TestCaseDefinition specification.

        Returns:
            UUID of the created test case.
        """
        proj_str = str(project_id)
        tc_id = definition.id or uuid4()

        model = TestCaseModel(
            id=str(tc_id),
            project_id=proj_str,
            name=definition.name,
            subject_identity_id=str(definition.subject_identity_id),
            target_resource_id=self._to_str(definition.target_resource_id),
            action=definition.action.upper(),
            expected_decision=definition.expected_decision.upper(),
            request_template=definition.request_template.to_dict(),
            preconditions={"assertions": definition.preconditions},
            auth_profile_id=self._to_str(definition.auth_profile_id),
            execution_mode=definition.execution_mode.value,
            evidence_ids=[],
            result_status=TestResultStatus.NOT_RUN.value,
            created_at=_utc_now(),
            updated_at=_utc_now(),
        )

        session.add(model)
        session.commit()
        session.refresh(model)

        logger.info("Created test case '%s' (%s) for project %s", model.name, model.id, proj_str)
        return UUID(model.id)

    def get_test_case(self, session: Session, test_case_id: UUID | str) -> dict[str, Any] | None:
        """Retrieve a test case by ID as a dictionary.

        Args:
            session: Active database session.
            test_case_id: ID of the test case.

        Returns:
            Dictionary containing test case attributes, or None if not found.
        """
        tc_str = str(test_case_id)
        stmt = select(TestCaseModel).where(TestCaseModel.id == tc_str)
        model = session.scalars(stmt).first()
        if not model:
            return None

        return self._model_to_dict(model)

    def list_test_cases(
        self,
        session: Session,
        project_id: UUID | str,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """List all test cases for a project with optional filtering.

        Args:
            session: Active database session.
            project_id: Project identifier.
            filters: Optional dictionary of filter criteria:
                - result_status: str
                - action: str
                - subject_identity_id: UUID/str
                - target_resource_id: UUID/str

        Returns:
            List of test case dictionaries ordered by creation time descending.
        """
        proj_str = str(project_id)
        stmt = select(TestCaseModel).where(TestCaseModel.project_id == proj_str)

        if filters:
            if "result_status" in filters and filters["result_status"]:
                stmt = stmt.where(TestCaseModel.result_status == str(filters["result_status"]).lower())
            if "action" in filters and filters["action"]:
                stmt = stmt.where(TestCaseModel.action == str(filters["action"]).upper())
            if "subject_identity_id" in filters and filters["subject_identity_id"]:
                stmt = stmt.where(TestCaseModel.subject_identity_id == str(filters["subject_identity_id"]))
            if "target_resource_id" in filters and filters["target_resource_id"]:
                stmt = stmt.where(TestCaseModel.target_resource_id == str(filters["target_resource_id"]))

        stmt = stmt.order_by(TestCaseModel.created_at.desc())
        models = session.scalars(stmt).all()
        return [self._model_to_dict(m) for m in models]

    def update_test_case(
        self,
        session: Session,
        test_case_id: UUID | str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Update fields of an existing test case.

        Args:
            session: Active database session.
            test_case_id: Test case identifier.
            **kwargs: Attributes to update on the test case.

        Returns:
            Updated test case dictionary.

        Raises:
            KeyError: If test case is not found.
        """
        tc_str = str(test_case_id)
        stmt = select(TestCaseModel).where(TestCaseModel.id == tc_str)
        model = session.scalars(stmt).first()
        if not model:
            raise KeyError(f"TestCase with ID {test_case_id} not found")

        for key, value in kwargs.items():
            if key == "request_template" and isinstance(value, RequestTemplate):
                model.request_template = value.to_dict()
            elif key == "request_template" and isinstance(value, dict):
                model.request_template = value
            elif key == "execution_mode" and isinstance(value, ExecutionMode):
                model.execution_mode = value.value
            elif key == "preconditions" and isinstance(value, list):
                model.preconditions = {"assertions": value}
            elif key in ("subject_identity_id", "target_resource_id", "auth_profile_id"):
                setattr(model, key, self._to_str(value))
            elif hasattr(model, key):
                setattr(model, key, value)

        model.updated_at = _utc_now()
        session.commit()
        session.refresh(model)

        logger.info("Updated test case %s", tc_str)
        return self._model_to_dict(model)

    def delete_test_case(self, session: Session, test_case_id: UUID | str) -> bool:
        """Delete a test case from the database.

        Args:
            session: Active database session.
            test_case_id: ID of the test case to delete.

        Returns:
            True if deleted, False if not found.
        """
        tc_str = str(test_case_id)
        stmt = select(TestCaseModel).where(TestCaseModel.id == tc_str)
        model = session.scalars(stmt).first()
        if not model:
            return False

        session.delete(model)
        session.commit()
        logger.info("Deleted test case %s", tc_str)
        return True

    def execute_test(
        self,
        session: Session,
        test_case_id: UUID | str,
        mode: ExecutionMode | None = None,
    ) -> TestExecutionResult:
        """Execute a single test case according to designated mode, storing execution history.

        Args:
            session: Active database session.
            test_case_id: Test case ID to execute.
            mode: Optional ExecutionMode override; defaults to test case configuration.

        Returns:
            TestExecutionResult containing execution status, response, and reasoning.

        Raises:
            KeyError: If test case does not exist.
        """
        tc_str = str(test_case_id)
        stmt = select(TestCaseModel).where(TestCaseModel.id == tc_str)
        tc_model = session.scalars(stmt).first()
        if not tc_model:
            raise KeyError(f"TestCase with ID {test_case_id} not found")

        # Resolve mode
        eff_mode = mode or ExecutionMode.from_str(tc_model.execution_mode)

        # Load Subject Identity
        id_stmt = select(IdentityModel).where(IdentityModel.id == tc_model.subject_identity_id)
        id_model = session.scalars(id_stmt).first()
        identity_dict: dict[str, Any] = (
            {
                "id": UUID(id_model.id),
                "name": id_model.name,
                "role_type": id_model.role_type,
                "tenant_ids": [],
            }
            if id_model
            else {
                "id": UUID(tc_model.subject_identity_id),
                "name": "Unknown Identity",
                "role_type": "AUTHENTICATED",
                "tenant_ids": [],
            }
        )

        # Load Target Resource
        resource_dict: dict[str, Any] | None = None
        if tc_model.target_resource_id:
            res_stmt = select(ResourceModel).where(ResourceModel.id == tc_model.target_resource_id)
            res_model = session.scalars(res_stmt).first()
            if res_model:
                resource_dict = {
                    "id": UUID(res_model.id),
                    "display_name": res_model.display_name,
                    "resource_type": res_model.resource_type,
                    "external_id": res_model.external_id or res_model.id,
                    "associated_endpoints": list(res_model.associated_endpoints or []),
                    "owning_identity_id": res_model.owning_identity_id,
                    "owning_tenant_id": res_model.owning_tenant_id,
                    "metadata": res_model.metadata_json or {},
                }

        # Resolve Authentication Headers
        auth_headers: dict[str, str] = {}
        if tc_model.auth_profile_id:
            ap_stmt = select(AuthenticationProfileModel).where(
                AuthenticationProfileModel.id == tc_model.auth_profile_id
            )
            ap_model = session.scalars(ap_stmt).first()
            if ap_model:
                auth_headers = self._resolve_auth_headers(ap_model, identity_dict)

        # Build TestCaseDefinition
        preconds = tc_model.preconditions.get("assertions", []) if isinstance(tc_model.preconditions, dict) else []
        definition = TestCaseDefinition(
            id=UUID(tc_model.id),
            project_id=UUID(tc_model.project_id),
            name=tc_model.name,
            subject_identity_id=UUID(tc_model.subject_identity_id),
            target_resource_id=UUID(tc_model.target_resource_id) if tc_model.target_resource_id else None,
            action=tc_model.action,
            expected_decision=tc_model.expected_decision,
            request_template=RequestTemplate.model_validate(tc_model.request_template),
            preconditions=list(preconds),
            auth_profile_id=UUID(tc_model.auth_profile_id) if tc_model.auth_profile_id else None,
            execution_mode=eff_mode,
        )

        # Execute
        result: TestExecutionResult
        if eff_mode == ExecutionMode.ACTIVE:
            result = self._runner.execute_active(
                test_case=definition,
                identity=identity_dict,
                auth_headers=auth_headers,
                resource=resource_dict,
            )
        elif eff_mode == ExecutionMode.OFFLINE:
            # Query existing traffic for project
            tr_stmt = select(TrafficRecordModel).where(TrafficRecordModel.project_id == tc_model.project_id)
            traffic_records = list(session.scalars(tr_stmt).all())
            result = self._runner.execute_offline(
                test_case=definition,
                policy_engine=self._runner._policy_engine,
                identity=identity_dict,
                resource=resource_dict,
                existing_evidence=traffic_records,
            )
        else:  # PREVIEW
            preview = self._runner.preview_test(
                test_case=definition,
                identity=identity_dict,
                resource=resource_dict,
            )
            result = TestExecutionResult(
                id=uuid4(),
                test_case_id=definition.id,
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
                    f"Preview rendered: Scope={preview['scope_ok']} ({preview['scope_reason']}).",
                    f"Planned request: {preview['method']} {preview['url']}.",
                ],
            )

        # Persist Execution Record
        exec_model = TestExecutionModel(
            id=str(result.id),
            test_case_id=tc_model.id,
            project_id=tc_model.project_id,
            started_at=result.started_at,
            completed_at=result.completed_at,
            status=result.status.value.lower(),
            request_snapshot=result.request_snapshot or {},
            response_snapshot=result.response_snapshot or {},
            actual_status_code=result.actual_status_code,
            actual_decision=result.actual_decision,
            error_message=result.error_message,
        )
        session.add(exec_model)

        # Update test case status
        tc_model.result_status = result.status.value.lower()
        tc_model.updated_at = _utc_now()

        # Check for boundary violation finding
        if result.outcome == TestOutcome.UNEXPECTED_ALLOW:
            self._record_finding_from_violation(
                session=session,
                tc_model=tc_model,
                result=result,
                identity_dict=identity_dict,
                resource_dict=resource_dict,
            )

        session.commit()
        return result

    def execute_batch(
        self,
        session: Session,
        project_id: UUID | str,
        test_case_ids: list[UUID | str] | None = None,
        mode: ExecutionMode = ExecutionMode.PREVIEW,
        progress_callback: Callable[[int, int, TestExecutionResult], None] | None = None,
    ) -> list[TestExecutionResult]:
        """Execute a collection of test cases with step-by-step progress reporting.

        Args:
            session: Active database session.
            project_id: Project identifier.
            test_case_ids: Optional list of test case IDs to execute. If None or empty,
                all test cases in the project are executed.
            mode: Designated ExecutionMode (OFFLINE, PREVIEW, or ACTIVE).
            progress_callback: Optional progress reporter callback:
                progress_callback(completed_count, total_count, latest_result).

        Returns:
            List of TestExecutionResult instances.
        """
        proj_str = str(project_id)
        stmt = select(TestCaseModel).where(TestCaseModel.project_id == proj_str)
        if test_case_ids:
            target_ids = [str(t) for t in test_case_ids]
            stmt = stmt.where(TestCaseModel.id.in_(target_ids))

        stmt = stmt.order_by(TestCaseModel.created_at.asc())
        test_cases = list(session.scalars(stmt).all())
        total = len(test_cases)
        results: list[TestExecutionResult] = []

        logger.info("Starting batch execution of %d test cases for project %s in %s mode", total, proj_str, mode.value)

        for idx, tc in enumerate(test_cases):
            if self._runner.is_cancelled:
                logger.info("Batch execution halted by cancellation request at index %d", idx)
                break

            result = self.execute_test(session, tc.id, mode=mode)
            results.append(result)

            if progress_callback:
                try:
                    progress_callback(idx + 1, total, result)
                except Exception as exc:
                    logger.warning("Progress callback raised an exception: %s", exc)

        return results

    def get_execution_history(
        self,
        session: Session,
        test_case_id: UUID | str,
    ) -> list[dict[str, Any]]:
        """Retrieve execution history records for a specific test case.

        Args:
            session: Active database session.
            test_case_id: ID of the test case.

        Returns:
            List of execution dictionaries ordered by execution initiation descending.
        """
        tc_str = str(test_case_id)
        stmt = (
            select(TestExecutionModel)
            .where(TestExecutionModel.test_case_id == tc_str)
            .order_by(TestExecutionModel.started_at.desc())
        )
        executions = session.scalars(stmt).all()

        return [
            {
                "id": e.id,
                "test_case_id": e.test_case_id,
                "project_id": e.project_id,
                "started_at": e.started_at.isoformat() if e.started_at else None,
                "completed_at": e.completed_at.isoformat() if e.completed_at else None,
                "status": e.status,
                "actual_status_code": e.actual_status_code,
                "actual_decision": e.actual_decision,
                "error_message": e.error_message,
                "request_snapshot": e.request_snapshot,
                "response_snapshot": e.response_snapshot,
            }
            for e in executions
        ]

    def cancel_execution(self) -> None:
        """Signal cancellation to the underlying TestRunner."""
        self._runner.cancel()

    def generate_test_cases_from_policies(
        self,
        session: Session,
        project_id: UUID | str,
    ) -> list[UUID]:
        """Auto-generate comprehensive authorization test cases from defined policies.

        Iterates through enabled policies, subject identities, and target resources,
        synthesizing verified request templates for positive and negative test cases.

        Args:
            session: Active database session.
            project_id: Project identifier.

        Returns:
            List of UUIDs for newly created TestCase definitions.
        """
        proj_str = str(project_id)

        # Load policies, identities, resources
        pols = list(
            session.scalars(
                select(PolicyModel).where(
                    PolicyModel.project_id == proj_str,
                    PolicyModel.enabled.is_(True),
                )
            ).all()
        )
        identities = list(session.scalars(select(IdentityModel).where(IdentityModel.project_id == proj_str)).all())
        resources = list(session.scalars(select(ResourceModel).where(ResourceModel.project_id == proj_str)).all())

        generated_ids: list[UUID] = []

        # Standard action HTTP method mappings
        method_map = {
            "READ": "GET",
            "WRITE": "POST",
            "DELETE": "DELETE",
            "EXECUTE": "POST",
            "ADMIN": "POST",
            "CUSTOM": "GET",
        }

        for pol in pols:
            action = pol.action.upper()
            http_method = method_map.get(action, "GET")
            expected_dec = pol.expected_decision.upper()

            # Find matching or applicable resources
            matched_resources = []
            for res in resources:
                # Check policy resource selector
                res_sel = pol.resource_selector or {}
                res_id_sel = res_sel.get("resource_id")
                res_type_sel = res_sel.get("resource_type")
                endpoint_sel = res_sel.get("endpoint")

                if res_id_sel and res_id_sel != res.id:
                    continue
                if res_type_sel and res_type_sel.upper() != res.resource_type.upper():
                    continue
                if endpoint_sel and res.associated_endpoints and endpoint_sel not in res.associated_endpoints:
                    continue
                matched_resources.append(res)

            # If no specific resource matched, create general resource placeholder
            if not matched_resources and resources:
                matched_resources = resources[:2]

            for ident in identities:
                # Check policy subject selector
                subj_sel = pol.subject_selector or {}
                id_sel = subj_sel.get("identity_id")
                role_sel = subj_sel.get("role_type")

                if id_sel and id_sel != ident.id:
                    continue
                if role_sel and role_sel.upper() != ident.role_type.upper():
                    continue

                for res in matched_resources:
                    endpoint_pattern = (
                        res.associated_endpoints[0]
                        if res.associated_endpoints
                        else f"https://target.local/api/{res.resource_type.lower()}s/{{resource_id}}"
                    )

                    tc_name = f"Verify {action} on {res.display_name} as {ident.name} ({expected_dec})"
                    tc_id = uuid4()

                    req_template = RequestTemplate(
                        method=http_method,
                        url_template=endpoint_pattern,
                        headers={"Accept": "application/json"},
                        body_template='{"action": "test"}' if http_method in ("POST", "PUT", "PATCH") else None,
                        query_params={},
                    )

                    tc_model = TestCaseModel(
                        id=str(tc_id),
                        project_id=proj_str,
                        name=tc_name,
                        subject_identity_id=ident.id,
                        target_resource_id=res.id,
                        action=action,
                        expected_decision=expected_dec,
                        request_template=req_template.to_dict(),
                        preconditions={
                            "assertions": list(pol.preconditions.get("assertions", []))
                            if isinstance(pol.preconditions, dict)
                            else []
                        },
                        auth_profile_id=None,
                        execution_mode="preview",
                        evidence_ids=[],
                        result_status=TestResultStatus.NOT_RUN.value.lower(),
                        created_at=_utc_now(),
                        updated_at=_utc_now(),
                    )
                    session.add(tc_model)
                    generated_ids.append(tc_id)

        session.commit()
        logger.info(
            "Auto-generated %d test cases from %d policies for project %s",
            len(generated_ids),
            len(pols),
            proj_str,
        )
        return generated_ids

    def _resolve_auth_headers(
        self,
        ap_model: AuthenticationProfileModel,
        identity_dict: dict[str, Any],
    ) -> dict[str, str]:
        """Resolve decrypted or configured authentication headers."""
        headers: dict[str, str] = {}
        auth_method = ap_model.auth_method.upper()

        secret_val = ""
        if self._secret_manager:
            try:
                # Look up secret by auth profile ID or identity ID
                secret_val = (
                    self._secret_manager.get_secret(f"auth_{ap_model.id}")
                    or self._secret_manager.get_secret(f"id_{identity_dict.get('id')}")
                    or ""
                )
            except Exception as exc:
                logger.warning("Could not decrypt secret for profile %s: %s", ap_model.id, exc)

        token = secret_val or "sample-token"

        if auth_method == "BEARER_TOKEN":
            headers["Authorization"] = f"Bearer {token}"
        elif auth_method == "COOKIE":
            headers["Cookie"] = f"session={token}"
        elif auth_method == "CUSTOM_HEADER":
            header_name = ap_model.header_name or "X-API-Key"
            headers[header_name] = token
        elif auth_method == "BASIC_AUTH":
            headers["Authorization"] = f"Basic {token}"

        return headers

    def _record_finding_from_violation(
        self,
        session: Session,
        tc_model: TestCaseModel,
        result: TestExecutionResult,
        identity_dict: dict[str, Any],
        resource_dict: dict[str, Any] | None,
    ) -> None:
        """Record a vulnerability Finding entity when an unexpected allow outcome occurs."""
        endpoint = (
            result.request_snapshot.get("url")
            if result.request_snapshot
            else tc_model.request_template.get("url_template", "Unknown Endpoint")
        )
        res_name = resource_dict.get("display_name", "target resource") if resource_dict else "target resource"
        ident_name = identity_dict.get("name", "unauthorized identity")

        finding_title = f"Unauthorized Access Detected: {tc_model.name}"

        # Check if finding already logged for this test case
        existing = session.scalars(
            select(FindingModel).where(
                FindingModel.project_id == tc_model.project_id,
                FindingModel.title == finding_title,
            )
        ).first()

        if existing:
            existing.last_verified = _utc_now()
            existing.updated_at = _utc_now()
            return

        repro_steps = [
            f"1. Authenticate with identity credentials for '{ident_name}'.",
            f"2. Dispatch {tc_model.action} HTTP request to '{endpoint}'.",
            f"3. Observe response HTTP status {result.actual_status_code} granting unauthorized access to {res_name}.",
        ]

        confidence_explanation = ConfidenceExplanation(
            level=ConfidenceLevel.HIGH,
            factors=[
                f"HTTP status code {result.actual_status_code} received.",
                "Target resource data confirmed in response payload.",
                f"Policy mandated expected decision: {tc_model.expected_decision}.",
            ],
            missing_evidence=[],
            is_reproducible=True,
            has_explicit_policy=True,
            notes="Automated test verified unauthorized boundary crossing.",
        )

        finding = FindingModel(
            id=str(uuid4()),
            project_id=tc_model.project_id,
            title=finding_title,
            category=FindingCategory.IDOR.value,
            affected_endpoint=str(endpoint),
            affected_resource_id=tc_model.target_resource_id,
            subject_identity_id=tc_model.subject_identity_id,
            expected_decision=tc_model.expected_decision,
            observed_decision=f"HTTP {result.actual_status_code} ALLOW",
            severity=FindingSeverity.HIGH.value,
            confidence_data=confidence_explanation.model_dump(mode="json"),
            evidence_ids=[],
            reproduction_steps=repro_steps,
            status=FindingStatus.NEW.value,
            reviewer_notes="Automatically detected during active authorization test run.",
            first_seen=_utc_now(),
            last_verified=_utc_now(),
            related_test_case_ids=[tc_model.id],
            created_at=_utc_now(),
            updated_at=_utc_now(),
        )

        session.add(finding)
        logger.warning("Logged security finding: %s on %s", finding_title, endpoint)

    def _model_to_dict(self, model: TestCaseModel) -> dict[str, Any]:
        """Convert a TestCaseModel to a clean dictionary representation."""
        preconds = model.preconditions.get("assertions", []) if isinstance(model.preconditions, dict) else []
        return {
            "id": model.id,
            "project_id": model.project_id,
            "name": model.name,
            "subject_identity_id": model.subject_identity_id,
            "target_resource_id": model.target_resource_id,
            "action": model.action,
            "expected_decision": model.expected_decision,
            "request_template": dict(model.request_template or {}),
            "preconditions": list(preconds),
            "auth_profile_id": model.auth_profile_id,
            "execution_mode": model.execution_mode,
            "result_status": model.result_status,
            "created_at": model.created_at.isoformat() if model.created_at else None,
            "updated_at": model.updated_at.isoformat() if model.updated_at else None,
        }
