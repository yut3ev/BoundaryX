#!/usr/bin/env python3
"""CLI utility to seed a BoundaryX database with rich demonstration and testing data.

Populates projects, scope boundaries, tenant partitions, user identities,
resources, authorization policies, test cases, findings, cryptographically-hashed
evidence, and audit logs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Ensure src is on sys.path if running directly from repository root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from boundaryx.domain.findings.models import FindingCategory, FindingSeverity, FindingStatus
from boundaryx.domain.identities.models import RoleType
from boundaryx.domain.policies.models import ExpectedDecision, PolicyAction
from boundaryx.domain.resources.models import ResourceType
from boundaryx.infrastructure.database.manager import DatabaseManager
from boundaryx.infrastructure.database.models import (
    AppSettingModel,
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
    TestExecutionModel,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_demo_data")


def seed_database(db_path: Path | str, clean: bool = False) -> None:
    """Populate database with demonstration data.

    Args:
        db_path: SQLite database file path.
        clean: If True, drop existing tables before seeding.
    """
    logger.info("Initializing DatabaseManager for target: %s", db_path)
    db_mgr = DatabaseManager(db_path=db_path)

    if clean:
        logger.warning("Cleaning existing database schema...")
        db_mgr.drop_tables()

    db_mgr.create_tables()

    now = datetime.now(UTC)

    with db_mgr.get_session() as session:
        # 1. Primary Project
        project_id = str(uuid.uuid4())
        project = ProjectModel(
            id=project_id,
            name="Apex SaaS Enterprise Platform Audit",
            description=(
                "Comprehensive authorization boundary analysis for Apex SaaS multi-tenant "
                "enterprise services. Evaluates BOLA/IDOR, tenant isolation boundaries, and privilege escalation."
            ),
            archived=False,
            settings={
                "default_execution_mode": "preview",
                "rate_limit_rps": 10.0,
                "max_concurrency": 4,
                "tls_verify": True,
                "evidence_retention_days": 90,
            },
            created_at=now - timedelta(days=2),
            updated_at=now,
        )
        session.add(project)

        # 2. Scope Rules
        scope_allow = ScopeRuleModel(
            id=str(uuid.uuid4()),
            project_id=project_id,
            rule_index=0,
            hostname="api.apex-saas.internal",
            port=443,
            scheme="https",
            path_prefix="/api/v2",
            path_exclusions=["/api/v2/admin/debug-console", "/api/v2/system/telemetry"],
            is_excluded=False,
            notes="Main customer API gateway endpoint",
            created_at=now - timedelta(days=2),
        )
        scope_excl = ScopeRuleModel(
            id=str(uuid.uuid4()),
            project_id=project_id,
            rule_index=1,
            hostname="kms.apex-saas.internal",
            port=443,
            scheme="https",
            path_prefix="/",
            path_exclusions=[],
            is_excluded=True,
            notes="Key management service - explicit out-of-scope restriction",
            created_at=now - timedelta(days=2),
        )
        session.add_all([scope_allow, scope_excl])

        # 3. Tenants
        tenant_alpha_id = str(uuid.uuid4())
        tenant_beta_id = str(uuid.uuid4())

        tenant_alpha = TenantModel(
            id=tenant_alpha_id,
            project_id=project_id,
            name="Alpha Corp (Enterprise)",
            description="Tier-1 Enterprise customer tenant partition",
            metadata_json={"tier": "enterprise", "seats": 500, "region": "us-east"},
            created_at=now - timedelta(days=2),
            updated_at=now - timedelta(days=2),
        )
        tenant_beta = TenantModel(
            id=tenant_beta_id,
            project_id=project_id,
            name="Beta Ltd (Commercial)",
            description="Tier-2 Commercial customer tenant partition",
            metadata_json={"tier": "commercial", "seats": 50, "region": "eu-central"},
            created_at=now - timedelta(days=2),
            updated_at=now - timedelta(days=2),
        )
        session.add_all([tenant_alpha, tenant_beta])

        # 4. Identities
        alice_id = str(uuid.uuid4())
        bob_id = str(uuid.uuid4())
        charlie_id = str(uuid.uuid4())
        mallory_id = str(uuid.uuid4())

        alice = IdentityModel(
            id=alice_id,
            project_id=project_id,
            name="Alice Vance (Alpha Admin)",
            description="Tenant administrator for Alpha Corp",
            role_type=RoleType.ADMIN.value,
            status="active",
            tags=["admin", "tenant-alpha"],
            notes="Full access to Alpha Corp organization settings and records",
            created_at=now - timedelta(days=2),
            updated_at=now - timedelta(days=2),
        )
        bob = IdentityModel(
            id=bob_id,
            project_id=project_id,
            name="Bob Miller (Alpha Member)",
            description="Standard business user in Alpha Corp",
            role_type=RoleType.EDITOR.value,
            status="active",
            tags=["member", "tenant-alpha"],
            notes="Regular team member managing customer orders",
            created_at=now - timedelta(days=2),
            updated_at=now - timedelta(days=2),
        )
        charlie = IdentityModel(
            id=charlie_id,
            project_id=project_id,
            name="Charlie King (Beta Member)",
            description="Standard business user in Beta Ltd",
            role_type=RoleType.TENANT_MEMBER.value,
            status="active",
            tags=["member", "tenant-beta"],
            notes="External tenant actor used to verify tenant boundary isolation",
            created_at=now - timedelta(days=2),
            updated_at=now - timedelta(days=2),
        )
        mallory = IdentityModel(
            id=mallory_id,
            project_id=project_id,
            name="Mallory (Unauthenticated Subject)",
            description="Anonymous external user with no session token",
            role_type=RoleType.ANONYMOUS.value,
            status="active",
            tags=["anonymous", "external"],
            notes="Used to verify public endpoint authorization boundaries",
            created_at=now - timedelta(days=2),
            updated_at=now - timedelta(days=2),
        )
        session.add_all([alice, bob, charlie, mallory])

        # 5. Tenant Memberships
        m_alice = TenantMembershipModel(
            id=str(uuid.uuid4()),
            tenant_id=tenant_alpha_id,
            identity_id=alice_id,
            role_in_tenant="admin",
            joined_at=now - timedelta(days=2),
        )
        m_bob = TenantMembershipModel(
            id=str(uuid.uuid4()),
            tenant_id=tenant_alpha_id,
            identity_id=bob_id,
            role_in_tenant="member",
            joined_at=now - timedelta(days=2),
        )
        m_charlie = TenantMembershipModel(
            id=str(uuid.uuid4()),
            tenant_id=tenant_beta_id,
            identity_id=charlie_id,
            role_in_tenant="member",
            joined_at=now - timedelta(days=2),
        )
        session.add_all([m_alice, m_bob, m_charlie])

        # 6. Authentication Profiles
        auth_alice = AuthenticationProfileModel(
            id=str(uuid.uuid4()),
            project_id=project_id,
            name="Alice Admin Token",
            auth_method="BEARER_TOKEN",
            header_name="Authorization",
            description="Valid JWT Bearer token representing Alice Vance (Alpha Admin)",
            created_at=now - timedelta(days=2),
            updated_at=now - timedelta(days=2),
        )
        auth_charlie = AuthenticationProfileModel(
            id=str(uuid.uuid4()),
            project_id=project_id,
            name="Charlie User Token",
            auth_method="BEARER_TOKEN",
            header_name="Authorization",
            description="Valid JWT Bearer token representing Charlie King (Beta Ltd)",
            created_at=now - timedelta(days=2),
            updated_at=now - timedelta(days=2),
        )
        session.add_all([auth_alice, auth_charlie])

        # 7. Resources
        res_order_alpha_id = str(uuid.uuid4())
        res_invoice_alpha_id = str(uuid.uuid4())
        res_settings_alpha_id = str(uuid.uuid4())

        res_order_alpha = ResourceModel(
            id=res_order_alpha_id,
            project_id=project_id,
            display_name="Alpha Corp Order #98210",
            resource_type=ResourceType.ORDER.value,
            owning_identity_id=bob_id,
            owning_tenant_id=tenant_alpha_id,
            sensitivity="high",
            associated_endpoints=[
                "/api/v2/orders/98210",
                "/api/v2/orders/98210/items",
            ],
            metadata_json={"order_total": 45200.0, "currency": "USD"},
            tags=["orders", "financial", "tenant-alpha"],
            notes="Confidential wholesale purchase order belonging to Alpha Corp",
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        res_invoice_alpha = ResourceModel(
            id=res_invoice_alpha_id,
            project_id=project_id,
            display_name="Alpha Corp Tax Invoice INV-2026-081",
            resource_type=ResourceType.INVOICE.value,
            owning_identity_id=alice_id,
            owning_tenant_id=tenant_alpha_id,
            sensitivity="critical",
            associated_endpoints=["/api/v2/invoices/inv-2026-081"],
            metadata_json={"invoice_status": "PAID", "tax_id": "US-99128471"},
            tags=["invoices", "tenant-alpha"],
            notes="Restricted financial accounting record",
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        res_settings_alpha = ResourceModel(
            id=res_settings_alpha_id,
            project_id=project_id,
            display_name="Alpha Corp Organization Configuration",
            resource_type=ResourceType.API_RESOURCE.value,
            owning_identity_id=alice_id,
            owning_tenant_id=tenant_alpha_id,
            sensitivity="critical",
            associated_endpoints=["/api/v2/admin/tenant/settings"],
            metadata_json={"sso_enabled": True, "mfa_required": True},
            tags=["settings", "admin-only"],
            notes="Organization-wide identity and security configuration",
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        session.add_all([res_order_alpha, res_invoice_alpha, res_settings_alpha])

        # 8. Policies
        pol_tenant_isolation = PolicyModel(
            id=str(uuid.uuid4()),
            project_id=project_id,
            name="Strict Tenant Isolation Invariant",
            description="Users belonging to Tenant X are strictly forbidden from reading or mutating resources owned by Tenant Y",
            subject_selector={"tenant_id": tenant_beta_id},
            resource_selector={"tenant_id": tenant_alpha_id},
            action=PolicyAction.READ.value,
            expected_decision=ExpectedDecision.DENY.value,
            preconditions={},
            confidence_source="DOCUMENTATION",
            evidence_notes="Architecture security specification section 4.1",
            enabled=True,
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        pol_admin_config = PolicyModel(
            id=str(uuid.uuid4()),
            project_id=project_id,
            name="Admin Configuration Protection",
            description="Only tenant administrators can read and update organization configuration",
            subject_selector={"role_type": RoleType.ADMIN.value},
            resource_selector={"resource_id": res_settings_alpha_id},
            action=PolicyAction.WRITE.value,
            expected_decision=ExpectedDecision.ALLOW.value,
            preconditions={},
            confidence_source="DOCUMENTATION",
            evidence_notes="Role-based access matrix",
            enabled=True,
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        session.add_all([pol_tenant_isolation, pol_admin_config])

        # 9. Test Cases
        tc_bola_id = str(uuid.uuid4())
        tc_bola = TestCaseModel(
            id=tc_bola_id,
            project_id=project_id,
            name="Cross-Tenant Order Retrieval (BOLA)",
            subject_identity_id=charlie_id,
            target_resource_id=res_order_alpha_id,
            action=PolicyAction.READ.value,
            expected_decision=ExpectedDecision.DENY.value,
            request_template={
                "method": "GET",
                "url_template": "https://api.apex-saas.internal/api/v2/orders/98210",
                "headers": {"Accept": "application/json"},
                "query_params": {},
            },
            preconditions={},
            auth_profile_id=auth_charlie.id,
            execution_mode="ACTIVE",
            evidence_ids=[],
            result_status="FAILED",
            created_at=now - timedelta(hours=6),
            updated_at=now - timedelta(hours=5),
        )
        session.add(tc_bola)

        # 10. Test Execution & Evidence
        exec_id = str(uuid.uuid4())
        ev_id = str(uuid.uuid4())

        req_payload = {
            "method": "GET",
            "url": "https://api.apex-saas.internal/api/v2/orders/98210",
            "headers": {
                "Host": "api.apex-saas.internal",
                "Authorization": "Bearer [REDACTED_CHARLIE_TOKEN]",
                "Accept": "application/json",
            },
            "body": None,
        }
        resp_payload = {
            "status_code": 200,
            "headers": {
                "Content-Type": "application/json",
                "X-Tenant": "Alpha Corp",
            },
            "body": '{"order_id": 98210, "tenant_id": "'
            + tenant_alpha_id
            + '", "total": 45200.0, "customer": "Global Distributors"}',
        }

        # Calculate cryptographic hash
        canonical_bytes = json.dumps({"req": req_payload, "resp": resp_payload}, sort_keys=True).encode("utf-8")
        evidence_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

        test_exec = TestExecutionModel(
            id=exec_id,
            test_case_id=tc_bola_id,
            project_id=project_id,
            started_at=now - timedelta(hours=5, minutes=1),
            completed_at=now - timedelta(hours=5),
            status="completed",
            request_snapshot=req_payload,
            response_snapshot=resp_payload,
            actual_status_code=200,
            actual_decision="ALLOW",
            error_message="Observed HTTP 200 ALLOW contrary to expected DENY policy.",
            evidence_id=None,
        )
        session.add(test_exec)
        session.flush()

        evidence = EvidenceModel(
            id=ev_id,
            project_id=project_id,
            evidence_type="REQUEST_RESPONSE",
            title="Evidence of Cross-Tenant Order 98210 Leakage",
            description="HTTP GET executed with Charlie King credentials against Alpha Corp order endpoint.",
            request_snapshot=req_payload,
            response_snapshot=resp_payload,
            test_execution_id=exec_id,
            timestamp=now - timedelta(hours=5),
            content_hash=evidence_sha256,
            sanitization_applied=["Authorization Bearer Token redacted"],
            metadata_json={"elapsed_ms": 34.5, "runner": "AsyncTestWorker-1"},
            created_at=now - timedelta(hours=5),
        )
        session.add(evidence)
        session.flush()

        test_exec.evidence_id = ev_id

        # 11. Finding
        finding_id = str(uuid.uuid4())
        finding = FindingModel(
            id=finding_id,
            project_id=project_id,
            title="BOLA: Unauthorized Cross-Tenant Order Data Access via /api/v2/orders/{id}",
            category=FindingCategory.CROSS_TENANT_ACCESS.value,
            affected_endpoint="/api/v2/orders/98210",
            affected_resource_id=res_order_alpha_id,
            subject_identity_id=charlie_id,
            expected_decision=ExpectedDecision.DENY.value,
            observed_decision=ExpectedDecision.ALLOW.value,
            severity=FindingSeverity.CRITICAL.value,
            confidence_data={
                "level": "HIGH",
                "factors": [
                    "HTTP 200 OK returned across tenant boundary",
                    "Response body contains Alpha Corp financial order record",
                    "Reproduced deterministically in active test mode",
                ],
                "is_reproducible": True,
                "has_explicit_policy": True,
            },
            evidence_ids=[ev_id],
            reproduction_steps=[
                "1. Acquire bearer token for Charlie King (Beta Ltd tenant).",
                "2. Issue HTTP GET to https://api.apex-saas.internal/api/v2/orders/98210.",
                "3. Observe HTTP 200 OK containing proprietary customer records belonging to Alpha Corp.",
            ],
            status=FindingStatus.CONFIRMED.value,
            reviewer_notes="Immediate patch: Enforce WHERE tenant_id = :current_tenant on Order queries.",
            first_seen=now - timedelta(hours=5),
            last_verified=now - timedelta(hours=5),
            related_test_case_ids=[tc_bola_id],
            created_at=now - timedelta(hours=5),
            updated_at=now - timedelta(hours=5),
        )
        session.add(finding)

        # 12. Audit Events
        audit_1 = AuditEventModel(
            id=str(uuid.uuid4()),
            project_id=project_id,
            event_type="PROJECT_CREATED",
            description="Initialized security assessment workspace: Apex SaaS Enterprise Platform Audit",
            details={"project_name": project.name},
            timestamp=now - timedelta(days=2),
        )
        audit_2 = AuditEventModel(
            id=str(uuid.uuid4()),
            project_id=project_id,
            event_type="SCOPE_CHANGED",
            description="Configured authorized testing boundary for api.apex-saas.internal",
            details={"hostname": "api.apex-saas.internal", "path_prefix": "/api/v2"},
            timestamp=now - timedelta(days=2),
        )
        audit_3 = AuditEventModel(
            id=str(uuid.uuid4()),
            project_id=project_id,
            event_type="TEST_STARTED",
            description="Started active execution run for test case 'Cross-Tenant Order Retrieval (BOLA)'",
            details={"test_case_id": tc_bola_id, "mode": "ACTIVE"},
            timestamp=now - timedelta(hours=5, minutes=1),
        )
        audit_4 = AuditEventModel(
            id=str(uuid.uuid4()),
            project_id=project_id,
            event_type="FINDING_STATUS_CHANGED",
            description="Marked finding as CONFIRMED: BOLA on /api/v2/orders/{id}",
            details={"finding_id": finding_id, "new_status": "CONFIRMED"},
            timestamp=now - timedelta(hours=4),
        )
        session.add_all([audit_1, audit_2, audit_3, audit_4])

        # 13. Application Settings
        setting = AppSettingModel(
            key="last_opened_project",
            value=project_id,
            updated_at=now,
        )
        session.add(setting)

    logger.info("Successfully seeded BoundaryX demonstration project '%s' into %s", project.name, db_path)
    logger.info("  - 1 Project")
    logger.info("  - 2 Scope Rules")
    logger.info("  - 2 Tenants (Alpha Corp, Beta Ltd)")
    logger.info("  - 4 Identities (Alice, Bob, Charlie, Mallory)")
    logger.info("  - 3 Tenant Memberships")
    logger.info("  - 2 Authentication Profiles")
    logger.info("  - 3 Resources (Orders, Invoices, Organization Config)")
    logger.info("  - 2 Authorization Policies")
    logger.info("  - 1 Test Case & 1 Test Execution")
    logger.info("  - 1 SHA-256 Verifiable Evidence Record")
    logger.info("  - 1 Confirmed CRITICAL Vulnerability Finding")
    logger.info("  - 4 Audit Log Records")


def main() -> None:
    """Parse arguments and execute seed operation."""
    parser = argparse.ArgumentParser(
        description="BoundaryX Demo Data Seeder - Populate SQLite database with multi-tenant test data",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("boundaryx_demo.db"),
        help="Target SQLite database file path (default: boundaryx_demo.db)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Drop and recreate existing tables before seeding",
    )
    args = parser.parse_args()

    seed_database(db_path=args.db, clean=args.clean)


if __name__ == "__main__":
    main()
