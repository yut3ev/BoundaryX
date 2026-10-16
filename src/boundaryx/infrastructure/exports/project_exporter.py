"""Project export and import module for BoundaryX database state."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import select

from boundaryx.infrastructure.database.models import (
    AuditEventModel,
    AuthenticationProfileModel,
    EvidenceModel,
    FindingModel,
    IdentityModel,
    PolicyModel,
    ProjectModel,
    ResourceModel,
    ScopeRuleModel,
    TenantMembershipModel,
    TenantModel,
    TestCaseModel,
    TrafficRecordModel,
)
from boundaryx.infrastructure.exports.report_exporter import ReportExporter

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class ProjectExportError(Exception):
    """Raised when project export or import encounters a critical error."""


class ProjectExporter:
    """Exports and imports full project workspaces and databases."""

    @classmethod
    def export_project(
        cls,
        session: Session,
        project_id: UUID | str,
        output_path: Path | str,
        include_secrets: bool = False,
    ) -> Path:
        """Export all data associated with a project to a JSON file.

        Args:
            session: Active database session.
            project_id: Project UUID.
            output_path: Target JSON export path.
            include_secrets: If True, sensitive credentials will be included.

        Returns:
            Resolved output Path.

        Raises:
            ProjectExportError: If project is not found or writing fails.
        """
        proj_str = str(project_id)
        project = session.get(ProjectModel, proj_str)
        if project is None:
            raise ProjectExportError(f"Project with ID '{proj_str}' does not exist")

        if include_secrets:
            logger.warning(
                "SECURITY WARNING: export_project called with include_secrets=True. "
                "The exported JSON will contain sensitive credential materials!"
            )

        target = ReportExporter._sanitize_path(output_path)

        # Helper to convert model attributes to serializable dict
        def _model_to_dict(model_obj: Any) -> dict[str, Any]:
            res: dict[str, Any] = {}
            for col in model_obj.__table__.columns:
                val = getattr(model_obj, col.name)
                if isinstance(val, datetime):
                    res[col.name] = val.isoformat()
                elif isinstance(val, UUID):
                    res[col.name] = str(val)
                else:
                    res[col.name] = val
            return res

        # Query all related entities
        scope_rules = (
            session.execute(select(ScopeRuleModel).where(ScopeRuleModel.project_id == proj_str)).scalars().all()
        )

        identities = session.execute(select(IdentityModel).where(IdentityModel.project_id == proj_str)).scalars().all()

        auth_profiles = (
            session.execute(select(AuthenticationProfileModel).where(AuthenticationProfileModel.project_id == proj_str))
            .scalars()
            .all()
        )

        tenants = session.execute(select(TenantModel).where(TenantModel.project_id == proj_str)).scalars().all()

        tenant_ids = [t.id for t in tenants]
        tenant_memberships = []
        if tenant_ids:
            tenant_memberships = (
                session.execute(select(TenantMembershipModel).where(TenantMembershipModel.tenant_id.in_(tenant_ids)))
                .scalars()
                .all()
            )

        resources = session.execute(select(ResourceModel).where(ResourceModel.project_id == proj_str)).scalars().all()

        policies = session.execute(select(PolicyModel).where(PolicyModel.project_id == proj_str)).scalars().all()

        traffic_records = (
            session.execute(select(TrafficRecordModel).where(TrafficRecordModel.project_id == proj_str)).scalars().all()
        )

        test_cases = session.execute(select(TestCaseModel).where(TestCaseModel.project_id == proj_str)).scalars().all()

        findings = session.execute(select(FindingModel).where(FindingModel.project_id == proj_str)).scalars().all()

        evidence_records = (
            session.execute(select(EvidenceModel).where(EvidenceModel.project_id == proj_str)).scalars().all()
        )

        audit_events = (
            session.execute(select(AuditEventModel).where(AuditEventModel.project_id == proj_str)).scalars().all()
        )

        export_data = {
            "format": "boundaryx_project_export",
            "version": "1.0",
            "exported_at": datetime.now(UTC).isoformat(),
            "include_secrets": include_secrets,
            "project": _model_to_dict(project),
            "scope_rules": [_model_to_dict(r) for r in scope_rules],
            "identities": [_model_to_dict(i) for i in identities],
            "auth_profiles": [_model_to_dict(a) for a in auth_profiles],
            "tenants": [_model_to_dict(t) for t in tenants],
            "tenant_memberships": [_model_to_dict(m) for m in tenant_memberships],
            "resources": [_model_to_dict(r) for r in resources],
            "policies": [_model_to_dict(p) for p in policies],
            "traffic_records": [_model_to_dict(tr) for tr in traffic_records],
            "test_cases": [_model_to_dict(tc) for tc in test_cases],
            "findings": [_model_to_dict(f) for f in findings],
            "evidence_records": [_model_to_dict(e) for e in evidence_records],
            "audit_events": [_model_to_dict(ae) for ae in audit_events],
        }

        try:
            with target.open("w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=str)
            logger.info("Project '%s' successfully exported to %s", proj_str, target)
            return target
        except OSError as exc:
            raise ProjectExportError(f"Failed to write project export to {target}: {exc}") from exc

    @classmethod
    def import_project(cls, session: Session, file_path: Path | str) -> UUID:
        """Import a project from a JSON export file, assigning fresh IDs to prevent collisions.

        Args:
            session: Active database session.
            file_path: Path to the exported JSON project file.

        Returns:
            UUID of the newly created project.

        Raises:
            ProjectExportError: If file is missing, invalid, or import fails.
        """
        path = Path(file_path).resolve()
        if not path.is_file():
            raise ProjectExportError(f"Project export file not found: {path}")

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            raise ProjectExportError(f"Failed to read project export JSON: {exc}") from exc

        if not isinstance(data, dict) or "project" not in data:
            raise ProjectExportError("Invalid project export format: missing 'project' element")

        orig_proj = data["project"]
        new_project_id = uuid4()
        new_proj_str = str(new_project_id)

        # Mapping old IDs to new UUIDs
        id_map: dict[str, str] = {}

        def _map_id(old_id: str | None) -> str:
            if not old_id:
                return str(uuid4())
            if old_id not in id_map:
                id_map[old_id] = str(uuid4())
            return id_map[old_id]

        new_project = ProjectModel(
            id=new_proj_str,
            name=f"{orig_proj.get('name', 'Imported Project')} (Imported)",
            description=orig_proj.get("description"),
            settings=orig_proj.get("settings", {}),
            archived=bool(orig_proj.get("archived", False)),
        )
        session.add(new_project)

        # 1. Scope Rules
        for r in data.get("scope_rules", []):
            rule = ScopeRuleModel(
                id=str(uuid4()),
                project_id=new_proj_str,
                hostname=r["hostname"],
                port=r.get("port"),
                scheme=r.get("scheme"),
                path_prefix=r.get("path_prefix"),
                path_exclusions=r.get("path_exclusions", []),
                is_excluded=bool(r.get("is_excluded", False)),
                notes=r.get("notes"),
            )
            session.add(rule)

        # 2. Identities
        for ident in data.get("identities", []):
            new_id = _map_id(ident.get("id"))
            identity = IdentityModel(
                id=new_id,
                project_id=new_proj_str,
                name=ident.get("name", "Identity"),
                description=ident.get("description"),
                role_type=ident.get("role_type", "CUSTOM"),
                custom_role_name=ident.get("custom_role_name"),
                status=ident.get("status", "active"),
                tags=ident.get("tags", []),
                notes=ident.get("notes"),
            )
            session.add(identity)

        # 3. Auth Profiles
        for ap in data.get("auth_profiles", []):
            new_id = _map_id(ap.get("id"))
            auth_prof = AuthenticationProfileModel(
                id=new_id,
                project_id=new_proj_str,
                name=ap.get("name", "Profile"),
                auth_method=ap.get("auth_method", "COOKIE"),
                header_name=ap.get("header_name"),
                description=ap.get("description"),
            )
            session.add(auth_prof)

        # 4. Tenants
        for t in data.get("tenants", []):
            new_id = _map_id(t.get("id"))
            owner_id = id_map.get(t.get("owner_identity_id")) if t.get("owner_identity_id") else None
            tenant = TenantModel(
                id=new_id,
                project_id=new_proj_str,
                name=t.get("name", "Tenant"),
                description=t.get("description"),
                owner_identity_id=owner_id,
                metadata_json=t.get("metadata_json", {}),
            )
            session.add(tenant)

        # 5. Tenant Memberships
        for tm in data.get("tenant_memberships", []):
            mapped_tenant = id_map.get(tm.get("tenant_id"))
            mapped_ident = id_map.get(tm.get("identity_id"))
            if mapped_tenant and mapped_ident:
                membership = TenantMembershipModel(
                    id=str(uuid4()),
                    tenant_id=mapped_tenant,
                    identity_id=mapped_ident,
                    role_in_tenant=tm.get("role_in_tenant", "member"),
                )
                session.add(membership)

        # 6. Resources
        for res in data.get("resources", []):
            new_id = _map_id(res.get("id"))
            owner_id = id_map.get(res.get("owning_identity_id")) if res.get("owning_identity_id") else None
            tenant_id = id_map.get(res.get("owning_tenant_id")) if res.get("owning_tenant_id") else None
            endpoints = res.get("associated_endpoints", [])
            if not endpoints and res.get("endpoint_url_pattern"):
                endpoints = [res["endpoint_url_pattern"]]
            resource = ResourceModel(
                id=new_id,
                project_id=new_proj_str,
                display_name=res.get("display_name", "Resource"),
                resource_type=res.get("resource_type", "CUSTOM"),
                custom_type_name=res.get("custom_type_name"),
                owning_identity_id=owner_id,
                owning_tenant_id=tenant_id,
                sensitivity=res.get("sensitivity", res.get("sensitivity_level", "medium")),
                associated_endpoints=endpoints,
                metadata_json=res.get("metadata_json", {}),
                tags=res.get("tags", []),
                notes=res.get("notes", res.get("description")),
            )
            session.add(resource)

        # 7. Policies
        for pol in data.get("policies", []):
            new_id = _map_id(pol.get("id"))
            policy = PolicyModel(
                id=new_id,
                project_id=new_proj_str,
                name=pol.get("name", "Policy"),
                description=pol.get("description"),
                subject_selector=pol.get("subject_selector", {}),
                resource_selector=pol.get("resource_selector", {}),
                action=pol.get("action", "READ"),
                expected_decision=pol.get("expected_decision", "DENY"),
                preconditions=pol.get("preconditions", {}),
                confidence_source=pol.get("confidence_source"),
                evidence_notes=pol.get("evidence_notes"),
                enabled=bool(pol.get("enabled", True)),
            )
            session.add(policy)

        # 8. Traffic Records
        for tr in data.get("traffic_records", []):
            new_id = _map_id(tr.get("id"))
            url_str = tr.get("url", "")
            scheme = tr.get("scheme", "https")
            host = tr.get("host", "")
            path = tr.get("path", "")
            if url_str and (not host or not path):
                from urllib.parse import urlparse

                parsed = urlparse(url_str)
                scheme = parsed.scheme or scheme
                host = parsed.netloc or host
                path = parsed.path or "/"

            traffic = TrafficRecordModel(
                id=new_id,
                project_id=new_proj_str,
                method=tr.get("method", "GET"),
                url=url_str,
                scheme=scheme,
                host=host,
                path=path,
                query_params=tr.get("query_params", {}),
                request_headers=tr.get("request_headers", {}),
                request_content_type=tr.get("request_content_type", tr.get("content_type")),
                request_body=tr.get("request_body"),
                response_status=tr.get("response_status", tr.get("status_code")),
                response_headers=tr.get("response_headers", {}),
                response_body=tr.get("response_body"),
                timing_ms=tr.get("timing_ms", tr.get("elapsed_ms", 0.0)),
                source_file=tr.get("source_file", tr.get("source", "import")),
                annotations=tr.get("annotations", {}),
            )
            session.add(traffic)

        # 9. Test Cases
        for tc in data.get("test_cases", []):
            new_id = _map_id(tc.get("id"))
            sub_id = id_map.get(tc.get("subject_identity_id")) or tc.get("subject_identity_id") or ""
            target_res_id = id_map.get(tc.get("target_resource_id")) if tc.get("target_resource_id") else None
            auth_prof_id = id_map.get(tc.get("auth_profile_id")) if tc.get("auth_profile_id") else None
            test_case = TestCaseModel(
                id=new_id,
                project_id=new_proj_str,
                name=tc.get("name", "Test Case"),
                subject_identity_id=sub_id,
                target_resource_id=target_res_id,
                action=tc.get("action", "READ"),
                expected_decision=tc.get("expected_decision", tc.get("expected_outcome", "DENY")),
                request_template=tc.get("request_template", tc.get("parameters", {})),
                preconditions=tc.get("preconditions", {}),
                auth_profile_id=auth_prof_id,
                execution_mode=tc.get("execution_mode", "automated"),
                evidence_ids=tc.get("evidence_ids", []),
                result_status=tc.get("result_status", "pending"),
            )
            session.add(test_case)

        # 10. Findings
        for f in data.get("findings", []):
            new_id = _map_id(f.get("id"))
            aff_res = id_map.get(f.get("affected_resource_id")) if f.get("affected_resource_id") else None
            sub_id = id_map.get(f.get("subject_identity_id")) if f.get("subject_identity_id") else None
            finding = FindingModel(
                id=new_id,
                project_id=new_proj_str,
                title=str(f.get("title") or "Finding"),
                category=str(f.get("category") or "BOLA"),
                affected_endpoint=str(f.get("affected_endpoint") or "/"),
                affected_resource_id=aff_res,
                subject_identity_id=sub_id,
                expected_decision=str(f.get("expected_decision") or "DENY"),
                observed_decision=str(f.get("observed_decision") or "ALLOW"),
                severity=str(f.get("severity") or "medium"),
                status=str(f.get("status") or "open"),
                confidence_data=f.get("confidence_data") or {},
                evidence_ids=f.get("evidence_ids") or [],
                reproduction_steps=f.get("reproduction_steps") or [],
                reviewer_notes=f.get("reviewer_notes") or f.get("description") or f.get("remediation"),
            )
            session.add(finding)

        # 11. Evidence
        for ev in data.get("evidence_records", []):
            new_id = _map_id(ev.get("id"))
            req_snap = ev.get("request_snapshot") or (
                ev.get("data_json", {}).get("request") if isinstance(ev.get("data_json"), dict) else None
            )
            resp_snap = ev.get("response_snapshot") or (
                ev.get("data_json", {}).get("response") if isinstance(ev.get("data_json"), dict) else None
            )
            evidence = EvidenceModel(
                id=new_id,
                project_id=new_proj_str,
                evidence_type=ev.get("evidence_type", "REQUEST_RESPONSE"),
                title=ev.get("title", "Evidence"),
                description=ev.get("description", ev.get("notes")),
                request_snapshot=req_snap,
                response_snapshot=resp_snap,
                content_hash=ev.get("content_hash", ev.get("sha256_hash", "0" * 64)),
                metadata_json=ev.get("metadata_json", {}),
            )
            session.add(evidence)

        # 12. Audit Events
        for ae in data.get("audit_events", []):
            audit_ev = AuditEventModel(
                id=str(uuid4()),
                project_id=new_proj_str,
                event_type=ae.get("event_type", "AUDIT"),
                description=ae.get("description", ""),
                details=ae.get("details", {}),
            )
            session.add(audit_ev)

        session.flush()
        logger.info("Successfully imported project '%s' as new ID '%s'", orig_proj.get("name"), new_proj_str)
        return new_project_id
