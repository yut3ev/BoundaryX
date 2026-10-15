"""Analysis service for traffic inspection, policy matching, and differential analysis.

Provides deep authorization analysis of imported HTTP traffic, bulk inspection,
response differential calculation, and project-wide security posture summaries.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from boundaryx.application.analysis.normalization import NormalizationConfig, NormalizationEngine
from boundaryx.domain.identities.models import Identity, RoleType
from boundaryx.domain.policies.engine import PolicyEngine
from boundaryx.domain.policies.models import ExpectedDecision, Policy, PolicyAction, ResourceSelector, SubjectSelector
from boundaryx.domain.resources.models import Resource, ResourceType
from boundaryx.infrastructure.database.models import (
    FindingModel,
    IdentityModel,
    PolicyModel,
    ResourceModel,
    TestCaseModel,
    TestExecutionModel,
    TrafficRecordModel,
)
from boundaryx.security.audit import AuditLogger

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class AnalysisService:
    """Application service for traffic record authorization analysis and response comparison."""

    def __init__(
        self,
        db_manager: Any,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger | None = None,
        normalization_engine: NormalizationEngine | None = None,
    ) -> None:
        """Initialize AnalysisService with dependencies.

        Args:
            db_manager: Database manager/session provider.
            policy_engine: PolicyEngine for domain authorization rule evaluation.
            audit_logger: Optional security audit logger.
            normalization_engine: Optional NormalizationEngine for response diffing.
        """
        self._db_manager = db_manager
        self._policy_engine = policy_engine
        self._audit = audit_logger
        self._normalization_engine = normalization_engine or NormalizationEngine()

    @property
    def normalization_engine(self) -> NormalizationEngine:
        """Return the underlying NormalizationEngine."""
        return self._normalization_engine

    def analyze_traffic_record(
        self,
        session: Session,
        record_id: UUID | str,
        policies: list[Policy | PolicyModel] | None = None,
        identities: list[Identity | IdentityModel] | None = None,
        resources: list[Resource | ResourceModel] | None = None,
    ) -> dict[str, Any]:
        """Match and analyze a captured HTTP traffic record against defined policies and identities.

        Args:
            session: Active database session.
            record_id: Identifier of the TrafficRecordModel to analyze.
            policies: Optional pre-loaded policy list to evaluate against.
            identities: Optional pre-loaded identities list.
            resources: Optional pre-loaded resources list.

        Returns:
            Dictionary containing evaluation results, matched policies, observed vs
            expected decisions, and boundary violation flags.

        Raises:
            KeyError: If the specified traffic record is not found.
        """
        rec_str = str(record_id)
        stmt = select(TrafficRecordModel).where(TrafficRecordModel.id == rec_str)
        record = session.scalars(stmt).first()
        if not record:
            raise KeyError(f"Traffic record with ID {record_id} not found")

        project_id = record.project_id

        # 1. Load domain entities if not provided
        domain_policies = self._resolve_policies(session, project_id, policies)
        domain_identities = self._resolve_identities(session, project_id, identities)
        domain_resources = self._resolve_resources(session, project_id, resources)

        # 2. Infer or match Identity
        matched_identity = self._infer_identity(record, domain_identities)

        # 3. Infer or match Resource
        matched_resource = self._infer_resource(record, domain_resources)

        # 4. Infer Policy Action from HTTP method
        method = record.method.upper()
        action_map = {
            "GET": PolicyAction.READ,
            "HEAD": PolicyAction.READ,
            "OPTIONS": PolicyAction.READ,
            "POST": PolicyAction.WRITE,
            "PUT": PolicyAction.WRITE,
            "PATCH": PolicyAction.WRITE,
            "DELETE": PolicyAction.DELETE,
        }
        action = action_map.get(method, PolicyAction.CUSTOM)

        # 5. Evaluate Expected Decision via PolicyEngine
        if matched_identity and matched_resource:
            evaluation = self._policy_engine.evaluate(
                identity=matched_identity,
                resource=matched_resource,
                action=action,
                endpoint=record.path,
                policies=domain_policies,
            )
            expected_decision = evaluation.expected_decision.value
            eval_reasoning = evaluation.reasoning
            matched_policy_id = str(evaluation.policy_id) if evaluation.policy_id else None
        else:
            expected_decision = "UNKNOWN"
            eval_reasoning = "Could not unambiguously associate traffic record with both an identity and a resource."
            matched_policy_id = None

        # 6. Infer Observed Decision from HTTP response status code
        status_code = record.response_status
        if status_code is None:
            observed_decision = "NO_RESPONSE"
        elif status_code in (401, 403):
            observed_decision = "DENY"
        elif 200 <= status_code < 300:
            observed_decision = "ALLOW"
        elif status_code == 404:
            observed_decision = "NOT_FOUND"
        elif status_code >= 500:
            observed_decision = "ERROR"
        else:
            observed_decision = f"HTTP_{status_code}"

        # 7. Discrepancy & Violation Classification
        is_violation = False
        violation_type = None
        severity = "INFORMATIONAL"

        if expected_decision == "DENY" and observed_decision == "ALLOW":
            is_violation = True
            violation_type = "UNEXPECTED_ALLOW"
            severity = "HIGH"
        elif expected_decision == "ALLOW" and observed_decision == "DENY":
            is_violation = True
            violation_type = "UNEXPECTED_DENIAL"
            severity = "LOW"

        return {
            "record_id": record.id,
            "project_id": project_id,
            "method": method,
            "url": record.url,
            "path": record.path,
            "status_code": status_code,
            "action": action.value,
            "matched_identity_id": str(matched_identity.id) if matched_identity else None,
            "matched_identity_name": matched_identity.name if matched_identity else "Unmatched/Anonymous",
            "matched_resource_id": str(matched_resource.id) if matched_resource else None,
            "matched_resource_name": matched_resource.display_name if matched_resource else "Unmatched Resource",
            "matched_policy_id": matched_policy_id,
            "expected_decision": expected_decision,
            "observed_decision": observed_decision,
            "is_violation": is_violation,
            "violation_type": violation_type,
            "severity": severity,
            "reasoning": eval_reasoning,
            "timestamp": record.created_at.isoformat() if record.created_at else None,
        }

    def bulk_analyze(
        self,
        session: Session,
        project_id: UUID | str,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> dict[str, Any]:
        """Execute authorization analysis across all traffic records for a project.

        Args:
            session: Active database session.
            project_id: Target project identifier.
            progress_callback: Optional progress callback: progress_callback(processed, total).

        Returns:
            Dictionary containing batch analysis metrics, violations detected, and breakdowns.
        """
        proj_str = str(project_id)
        records = list(
            session.scalars(
                select(TrafficRecordModel)
                .where(TrafficRecordModel.project_id == proj_str)
                .order_by(TrafficRecordModel.created_at.asc())
            ).all()
        )

        total = len(records)
        logger.info("Starting bulk traffic analysis of %d records for project %s", total, proj_str)

        # Preload domain models once for performance
        policies = self._resolve_policies(session, proj_str)
        identities = self._resolve_identities(session, proj_str)
        resources = self._resolve_resources(session, proj_str)

        violations: list[dict[str, Any]] = []
        action_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        matched_records = 0

        for idx, rec in enumerate(records):
            analysis = self.analyze_traffic_record(
                session=session,
                record_id=rec.id,
                policies=policies,
                identities=identities,
                resources=resources,
            )

            # Accumulate statistics
            act = analysis["action"]
            action_counts[act] = action_counts.get(act, 0) + 1

            sc_key = str(analysis["status_code"] or "unknown")
            status_counts[sc_key] = status_counts.get(sc_key, 0) + 1

            if analysis["matched_identity_id"] and analysis["matched_resource_id"]:
                matched_records += 1

            if analysis["is_violation"]:
                violations.append(analysis)

            if progress_callback:
                try:
                    progress_callback(idx + 1, total)
                except Exception as exc:
                    logger.warning("Progress callback raised: %s", exc)

        coverage_rate = round((matched_records / total * 100.0), 2) if total > 0 else 0.0

        return {
            "project_id": proj_str,
            "total_records": total,
            "matched_records": matched_records,
            "coverage_percentage": coverage_rate,
            "violations_count": len(violations),
            "violations": violations,
            "action_breakdown": action_counts,
            "status_code_breakdown": status_counts,
            "analyzed_at": _utc_now().isoformat(),
        }

    def compare_responses(
        self,
        response_a: dict[str, Any],
        response_b: dict[str, Any],
        normalization_config: NormalizationConfig | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compare two HTTP response snapshots with normalization and noise elimination.

        Calculates semantic differences and similarity score.

        Args:
            response_a: First response snapshot dictionary.
            response_b: Second response snapshot dictionary.
            normalization_config: Optional configuration override.

        Returns:
            Dictionary with comparison analysis:
            {"identical": bool, "differences_count": int, "differences": list, "similarity_score": float}.
        """
        cfg: NormalizationConfig | None = None
        if isinstance(normalization_config, dict):
            cfg = NormalizationConfig.model_validate(normalization_config)
        elif isinstance(normalization_config, NormalizationConfig):
            cfg = normalization_config

        diffs = self._normalization_engine.diff_responses(response_a, response_b, config=cfg)

        # Heuristic similarity scoring (1.0 = identical, decreasing with each significant diff)
        diff_count = len(diffs)
        similarity = max(0.0, round(1.0 - (diff_count * 0.1), 4)) if diff_count > 0 else 1.0

        return {
            "identical": diff_count == 0,
            "differences_count": diff_count,
            "differences": diffs,
            "similarity_score": similarity,
        }

    def get_analysis_summary(self, session: Session, project_id: UUID | str) -> dict[str, Any]:
        """Aggregate authorization test matrix status, finding severities, and project posture.

        Args:
            session: Active database session.
            project_id: Target project identifier.

        Returns:
            Comprehensive analytics summary dictionary.
        """
        proj_str = str(project_id)

        # Entity counts
        total_identities = (
            session.scalar(select(func.count(IdentityModel.id)).where(IdentityModel.project_id == proj_str)) or 0
        )
        total_resources = (
            session.scalar(select(func.count(ResourceModel.id)).where(ResourceModel.project_id == proj_str)) or 0
        )
        total_policies = (
            session.scalar(select(func.count(PolicyModel.id)).where(PolicyModel.project_id == proj_str)) or 0
        )
        total_test_cases = (
            session.scalar(select(func.count(TestCaseModel.id)).where(TestCaseModel.project_id == proj_str)) or 0
        )
        total_executions = (
            session.scalar(select(func.count(TestExecutionModel.id)).where(TestExecutionModel.project_id == proj_str))
            or 0
        )
        total_traffic = (
            session.scalar(select(func.count(TrafficRecordModel.id)).where(TrafficRecordModel.project_id == proj_str))
            or 0
        )

        # Findings breakdown by severity and status
        findings = list(session.scalars(select(FindingModel).where(FindingModel.project_id == proj_str)).all())
        total_findings = len(findings)

        severity_counts: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFORMATIONAL": 0,
        }
        status_counts: dict[str, int] = {}
        for f in findings:
            sev = (f.severity or "MEDIUM").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            st = (f.status or "open").lower()
            status_counts[st] = status_counts.get(st, 0) + 1

        # Test case status breakdown
        tc_stmt = (
            select(TestCaseModel.result_status, func.count(TestCaseModel.id))
            .where(TestCaseModel.project_id == proj_str)
            .group_by(TestCaseModel.result_status)
        )
        tc_status_counts = dict(session.execute(tc_stmt).all())

        # Security Posture Score calculation (0 - 100)
        # Deduct 30 per critical finding, 15 per high, 5 per medium
        deductions = (
            (severity_counts.get("CRITICAL", 0) * 30)
            + (severity_counts.get("HIGH", 0) * 15)
            + (severity_counts.get("MEDIUM", 0) * 5)
        )
        posture_score = max(0, min(100, 100 - deductions))

        return {
            "project_id": proj_str,
            "counts": {
                "identities": total_identities,
                "resources": total_resources,
                "policies": total_policies,
                "test_cases": total_test_cases,
                "test_executions": total_executions,
                "traffic_records": total_traffic,
                "findings": total_findings,
            },
            "findings_by_severity": severity_counts,
            "findings_by_status": status_counts,
            "test_cases_by_status": tc_status_counts,
            "security_posture_score": posture_score,
            "generated_at": _utc_now().isoformat(),
        }

    def _resolve_policies(
        self,
        session: Session,
        project_id: str,
        policies: list[Any] | None = None,
    ) -> list[Policy]:
        """Convert policy ORM models or list to domain Policy instances."""
        if policies is not None:
            return [p if isinstance(p, Policy) else self._orm_to_policy(p) for p in policies]

        stmt = select(PolicyModel).where(
            PolicyModel.project_id == project_id,
            PolicyModel.enabled.is_(True),
        )
        orm_policies = list(session.scalars(stmt).all())
        if orm_policies:
            return [self._orm_to_policy(p) for p in orm_policies]
        return self._policy_engine.policies

    def _resolve_identities(
        self,
        session: Session,
        project_id: str,
        identities: list[Any] | None = None,
    ) -> list[Identity]:
        """Convert identity ORM models or list to domain Identity instances."""
        if identities is not None:
            return [i if isinstance(i, Identity) else self._orm_to_identity(i) for i in identities]

        stmt = select(IdentityModel).where(IdentityModel.project_id == project_id)
        orm_identities = session.scalars(stmt).all()
        return [self._orm_to_identity(i) for i in orm_identities]

    def _resolve_resources(
        self,
        session: Session,
        project_id: str,
        resources: list[Any] | None = None,
    ) -> list[Resource]:
        """Convert resource ORM models or list to domain Resource instances."""
        if resources is not None:
            return [r if isinstance(r, Resource) else self._orm_to_resource(r) for r in resources]

        stmt = select(ResourceModel).where(ResourceModel.project_id == project_id)
        orm_resources = session.scalars(stmt).all()
        return [self._orm_to_resource(r) for r in orm_resources]

    def _infer_identity(self, record: TrafficRecordModel, identities: list[Identity]) -> Identity | None:
        """Infer which identity produced a given traffic record."""
        # 1. Direct record annotation
        if record.identity_id:
            for ident in identities:
                if str(ident.id) == str(record.identity_id):
                    return ident

        # 2. Header-based token inspection
        req_headers = {str(k).lower(): str(v) for k, v in (record.request_headers or {}).items()}
        auth_val = req_headers.get("authorization", "")
        cookie_val = req_headers.get("cookie", "")

        for ident in identities:
            # Check if identity name or ID appears in cookies or token
            if ident.name and (ident.name.lower() in auth_val.lower() or ident.name.lower() in cookie_val.lower()):
                return ident

        # Default to first non-admin identity or Anonymous
        if identities:
            return identities[0]
        return None

    def _infer_resource(self, record: TrafficRecordModel, resources: list[Resource]) -> Resource | None:
        """Infer which resource is targeted by a given traffic record."""
        # 1. Direct record annotation
        if record.resource_id:
            for res in resources:
                if str(res.id) == str(record.resource_id):
                    return res

        # 2. URL/Endpoint pattern matching
        rec_path = record.path or ""
        for res in resources:
            for ep in res.associated_endpoints:
                clean_ep = ep.split("?")[0].rstrip("/")
                clean_rec = rec_path.split("?")[0].rstrip("/")
                if clean_ep and clean_ep in clean_rec:
                    return res
            # Check external_id token in path
            if res.external_id and f"/{res.external_id}" in rec_path:
                return res

        if resources:
            return resources[0]
        return None

    def _orm_to_policy(self, p: PolicyModel) -> Policy:
        """Convert PolicyModel to domain Policy."""
        subj_sel = SubjectSelector.model_validate(p.subject_selector) if p.subject_selector else SubjectSelector()
        res_sel = ResourceSelector.model_validate(p.resource_selector) if p.resource_selector else ResourceSelector()
        return Policy(
            id=UUID(p.id),
            project_id=UUID(p.project_id),
            name=p.name,
            description=p.description or "",
            subject_selector=subj_sel,
            resource_selector=res_sel,
            action=PolicyAction(p.action.upper()),
            expected_decision=ExpectedDecision(p.expected_decision.upper()),
            preconditions=list(p.preconditions.get("assertions", [])) if isinstance(p.preconditions, dict) else [],
            enabled=p.enabled,
        )

    def _orm_to_identity(self, i: IdentityModel) -> Identity:
        """Convert IdentityModel to domain Identity."""
        try:
            role_type = RoleType(i.role_type.upper())
        except ValueError:
            role_type = RoleType.AUTHENTICATED
        return Identity(
            id=UUID(i.id),
            name=i.name,
            role_type=role_type,
            tenant_ids=[],
        )

    def _orm_to_resource(self, r: ResourceModel) -> Resource:
        """Convert ResourceModel to domain Resource."""
        try:
            res_type = ResourceType(r.resource_type.upper())
        except ValueError:
            res_type = ResourceType.API_RESOURCE
        return Resource(
            id=UUID(r.id),
            display_name=r.display_name,
            resource_type=res_type,
            external_id=r.external_id or r.id,
            associated_endpoints=list(r.associated_endpoints or []),
            owning_identity_id=UUID(r.owning_identity_id) if r.owning_identity_id else None,
            owning_tenant_id=UUID(r.owning_tenant_id) if r.owning_tenant_id else None,
            metadata=dict(r.metadata_json or {}),
        )
