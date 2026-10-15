"""Deterministic confidence evaluation engine for BoundaryX security findings.

Evaluates evidence strength and assigns verifiable confidence tiers without
arbitrary percentages. Validates explicit policies, multi-trial reproducibility,
error baseline comparisons, response body semantic content, and cross-tenant
boundary isolation proofs.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from boundaryx.domain.evidence.models import Evidence, HttpSnapshot
from boundaryx.domain.findings.models import (
    ConfidenceExplanation,
    ConfidenceLevel,
    Finding,
    FindingCategory,
)
from boundaryx.domain.policies.models import ExpectedDecision, Policy
from boundaryx.domain.resources.models import Resource


class FindingEvaluationContext(BaseModel):
    """Structured context parameterizing confidence evaluation for a finding."""

    model_config = ConfigDict(from_attributes=True)

    explicit_policy_present: bool = Field(
        default=False,
        description="Whether an explicit authorization policy rule covers this operation",
    )
    policy_name: str | None = Field(
        default=None,
        description="Name of the matching authorization policy",
    )
    policy_expected_decision: ExpectedDecision | str | None = Field(
        default=None,
        description="Expected decision prescribed by policy (e.g. DENY)",
    )
    reproduction_trials: int = Field(
        default=0,
        description="Total number of independent reproduction attempts conducted",
    )
    successful_reproductions: int = Field(
        default=0,
        description="Number of attempts that identically reproduced the finding",
    )
    is_reproducible: bool | None = Field(
        default=None,
        description="Deterministic flag indicating confirmed multi-trial reproducibility",
    )
    error_baseline_compared: bool = Field(
        default=False,
        description="Whether response was compared against a negative/error baseline request",
    )
    differs_from_error_baseline: bool = Field(
        default=False,
        description="True if observed response is distinct from baseline error page/message",
    )
    baseline_similarity_ratio: float | None = Field(
        default=None,
        description="Text or structural similarity to negative baseline (0.0=distinct, 1.0=identical)",
    )
    target_resource_data_verified: bool = Field(
        default=False,
        description="Whether response payload was confirmed to contain target entity data",
    )
    matched_resource_identifiers: list[str] = Field(
        default_factory=list,
        description="Identified target resource IDs or attributes found in response body",
    )
    response_status_code: int | None = Field(
        default=None,
        description="Observed HTTP response status code",
    )
    response_body: str | None = Field(
        default=None,
        description="Raw or normalized response body string",
    )
    response_content_type: str | None = Field(
        default=None,
        description="Response MIME content type (e.g. 'application/json')",
    )
    cross_tenant_tested: bool = Field(
        default=False,
        description="Whether cross-tenant boundary isolation was explicitly evaluated",
    )
    cross_tenant_verified: bool = Field(
        default=False,
        description="Whether response payload proved unauthorized cross-tenant data leak",
    )
    source_tenant_id: str | None = Field(
        default=None,
        description="Tenant ID of requesting user",
    )
    target_tenant_id: str | None = Field(
        default=None,
        description="Tenant ID owning the target resource",
    )
    evidence_records: list[Evidence] = Field(
        default_factory=list,
        description="Linked supporting evidence objects",
    )


class ConfidenceEvaluator:
    """Deterministic confidence assessment engine for authorization boundary defects.

    Evaluates findings across five core security verification pillars:
    1. Explicit policy rule existence vs. heuristics
    2. Multi-trial test reproducibility
    3. Error baseline comparison (ruling out 200 OK errors and SPA login shells)
    4. Verified target resource attributes inside response body
    5. Structural cross-tenant boundary violation proof

    Produces a fully justified ConfidenceExplanation with factor breakdown,
    missing evidence warnings, and actionable recommendations.
    """

    def evaluate(
        self,
        context: FindingEvaluationContext | dict[str, Any],
    ) -> ConfidenceExplanation:
        """Evaluate finding evidence strength and return a structured ConfidenceExplanation.

        Args:
            context: FindingEvaluationContext model or equivalent dictionary.

        Returns:
            ConfidenceExplanation containing level, factors, missing_evidence, and notes.
        """
        ctx = context if isinstance(context, FindingEvaluationContext) else FindingEvaluationContext(**context)

        factors: list[str] = []
        missing_evidence: list[str] = []
        recommendations: list[str] = []

        # ---------------------------------------------------------------------
        # 1. Policy Pillar
        # ---------------------------------------------------------------------
        has_explicit = ctx.explicit_policy_present
        if has_explicit:
            pol_desc = f" '{ctx.policy_name}'" if ctx.policy_name else ""
            exp_dec = (
                ctx.policy_expected_decision.value
                if isinstance(ctx.policy_expected_decision, ExpectedDecision)
                else str(ctx.policy_expected_decision or "DENY")
            )
            factors.append(f"Explicit authorization policy rule{pol_desc} specifies expected decision '{exp_dec}'.")
        else:
            missing_evidence.append(
                "No explicit authorization policy defined; finding relies on heuristic role expectation."
            )
            recommendations.append(
                "Define an explicit authorization policy rule specifying expected permissions for this endpoint."
            )

        # ---------------------------------------------------------------------
        # 2. Reproducibility Pillar
        # ---------------------------------------------------------------------
        is_reproducible: bool | None = ctx.is_reproducible

        if ctx.reproduction_trials > 0:
            if ctx.successful_reproductions == ctx.reproduction_trials and ctx.reproduction_trials >= 2:
                is_reproducible = True
                factors.append(
                    f"Consistently reproduced across {ctx.reproduction_trials} consecutive independent requests."
                )
            elif ctx.successful_reproductions > 0 and ctx.successful_reproductions == ctx.reproduction_trials:
                is_reproducible = True
                factors.append(
                    f"Defect reproduced on independent re-test ({ctx.successful_reproductions}/{ctx.reproduction_trials} trials)."
                )
            elif ctx.successful_reproductions == 0:
                is_reproducible = False
                missing_evidence.append(
                    f"Failed to reproduce defect on repeated trial (0/{ctx.reproduction_trials} trials succeeded)."
                )
                recommendations.append(
                    "Re-run reproduction request to confirm if the initial finding was a transient state anomaly."
                )
            else:
                is_reproducible = False
                missing_evidence.append(
                    f"Intermittent reproducibility ({ctx.successful_reproductions}/{ctx.reproduction_trials} trials succeeded)."
                )
                recommendations.append(
                    "Investigate caching, rate-limiting, or session concurrency causing intermittent behavior."
                )
        elif is_reproducible is True:
            factors.append("Defect was verified as reproducible by analyst or runner.")
        elif is_reproducible is False:
            missing_evidence.append("Defect was marked non-reproducible.")
            recommendations.append("Re-test with fresh session credentials.")
        else:
            missing_evidence.append("Single observation only; multi-trial reproduction has not yet been executed.")
            recommendations.append(
                "Execute at least 2 independent reproduction trials with freshly issued credentials."
            )

        # ---------------------------------------------------------------------
        # 3. Error Baseline Comparison Pillar
        # ---------------------------------------------------------------------
        if ctx.error_baseline_compared:
            if ctx.differs_from_error_baseline:
                sim_note = (
                    f" (similarity ratio: {ctx.baseline_similarity_ratio:.2f})"
                    if ctx.baseline_similarity_ratio is not None
                    else ""
                )
                factors.append(
                    f"Response normalized and verified distinct from negative error baseline{sim_note} "
                    "(rules out false-positive 200 OK error pages, SPA shells, or login redirects)."
                )
            else:
                missing_evidence.append(
                    "Observed response matches negative error baseline; probable 200 OK generic error or login page."
                )
                recommendations.append(
                    "Verify whether the endpoint returns HTTP 200 with an embedded client-side error message."
                )
        else:
            missing_evidence.append(
                "Response was not compared against a negative error baseline (invalid ID or unauthenticated request)."
            )
            recommendations.append(
                "Perform negative baseline test (requesting invalid ID or anonymous) and verify structural divergence."
            )

        # ---------------------------------------------------------------------
        # 4. Target Resource Data Verification Pillar
        # ---------------------------------------------------------------------
        # Check for HTML login page or SPA shell if body available
        is_html_shell = False
        if ctx.response_body:
            body_strip = ctx.response_body.strip().lower()
            if body_strip.startswith("<!doctype html") or body_strip.startswith("<html"):
                is_html_shell = True

        if is_html_shell:
            missing_evidence.append(
                "Response body is an HTML document rather than API data (probable web login redirect or SPA shell)."
            )
            recommendations.append(
                "Verify API client headers (Accept: application/json) to prevent HTML error shell returns."
            )
        elif ctx.target_resource_data_verified:
            id_list = f" [{', '.join(ctx.matched_resource_identifiers)}]" if ctx.matched_resource_identifiers else ""
            factors.append(f"Response body contains confirmed target resource identifiers/attributes{id_list}.")
        else:
            missing_evidence.append(
                "Response payload was not verified to contain specific private target resource data."
            )
            recommendations.append(
                "Inspect response JSON fields to confirm target resource object schema and private data presence."
            )

        # ---------------------------------------------------------------------
        # 5. Cross-Tenant Boundary Pillar
        # ---------------------------------------------------------------------
        if ctx.cross_tenant_tested:
            if ctx.cross_tenant_verified:
                s_t = ctx.source_tenant_id or "Tenant A"
                t_t = ctx.target_tenant_id or "Tenant B"
                factors.append(
                    f"Cross-tenant isolation boundary violation proven: Request with {s_t} credentials "
                    f"retrieved data belonging to {t_t}."
                )
            else:
                missing_evidence.append(
                    "Cross-tenant boundary test inconclusive: target data could not be definitively attributed to distinct tenant."
                )
                recommendations.append(
                    "Provision two distinct tenant environments with distinct partition IDs to confirm tenant leak."
                )

        # ---------------------------------------------------------------------
        # 6. Status Code & Snapshot Completeness
        # ---------------------------------------------------------------------
        if ctx.response_status_code is not None:
            if 200 <= ctx.response_status_code < 300:
                factors.append(f"HTTP {ctx.response_status_code} Success status returned.")
            elif ctx.response_status_code in {401, 403}:
                factors.append(f"HTTP {ctx.response_status_code} Access Denied status observed.")
            elif ctx.response_status_code >= 500:
                missing_evidence.append(
                    f"Server returned HTTP {ctx.response_status_code} Internal Server Error instead of clean response."
                )
                recommendations.append(
                    "Check server logs to verify whether status 500 was an authorization crash or unrelated exception."
                )

        # ---------------------------------------------------------------------
        # Deterministic Confidence Level Tiering
        # ---------------------------------------------------------------------
        # Tier rules:
        # INSUFFICIENT_EVIDENCE:
        #   - Missing response status, or 500 error, or non-reproducible (is_reproducible=False),
        #     or body confirmed identical to error baseline, or HTML shell with no data.
        # HIGH:
        #   - target_resource_data_verified is True
        #   - is_reproducible is True
        #   - differs_from_error_baseline is True
        #   - NOT is_html_shell
        #   - AND (has_explicit OR cross_tenant_verified OR len(factors) >= 4)
        # MEDIUM:
        #   - HTTP 2xx observed + (has_explicit OR target_resource_data_verified OR is_reproducible is True)
        #   - NOT is_html_shell
        # LOW:
        #   - Any other observed deviation that doesn't meet Medium criteria.

        if (
            ctx.response_status_code is None
            or (ctx.response_status_code and ctx.response_status_code >= 500)
            or is_reproducible is False
            or is_html_shell
            or (ctx.error_baseline_compared and not ctx.differs_from_error_baseline)
        ):
            level = ConfidenceLevel.INSUFFICIENT_EVIDENCE
        elif (
            ctx.target_resource_data_verified
            and is_reproducible is True
            and ctx.differs_from_error_baseline
            and not is_html_shell
            and (has_explicit or ctx.cross_tenant_verified or len(factors) >= 4)
        ):
            level = ConfidenceLevel.HIGH
        elif (
            (ctx.response_status_code and 200 <= ctx.response_status_code < 300)
            and (has_explicit or ctx.target_resource_data_verified or is_reproducible is True)
            and not is_html_shell
        ):
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        # Format actionable notes summarizing factors and recommendations
        notes_lines: list[str] = [
            f"Confidence Tier: {level.value}",
            f"Factors Established: {len(factors)} verified indicator(s).",
        ]
        if missing_evidence:
            notes_lines.append(f"Evidence Gaps: {len(missing_evidence)} unverified factor(s).")
        if recommendations:
            notes_lines.append("Actionable Recommendations:")
            for rec in recommendations:
                notes_lines.append(f"  - {rec}")

        return ConfidenceExplanation(
            level=level,
            factors=factors,
            missing_evidence=missing_evidence,
            is_reproducible=is_reproducible,
            has_explicit_policy=has_explicit,
            notes="\n".join(notes_lines),
        )

    # -------------------------------------------------------------------------
    # Convenience Evaluation from Domain Entities
    # -------------------------------------------------------------------------

    def evaluate_finding(
        self,
        finding: Finding,
        evidence_records: list[Evidence] | None = None,
        policy: Policy | None = None,
        baseline_evidence: Evidence | None = None,
        target_resource: Resource | None = None,
    ) -> ConfidenceExplanation:
        """Evaluate a Finding domain entity using attached evidence and policy definitions.

        Args:
            finding: Target security finding to assess.
            evidence_records: List of supporting evidence objects.
            policy: Matched authorization policy rule (if available).
            baseline_evidence: Negative/error baseline evidence record for comparison.
            target_resource: Resource entity accessed in finding.

        Returns:
            Computed ConfidenceExplanation.
        """
        ev_list = evidence_records or []
        resp_snapshot: HttpSnapshot | None = None
        for ev in ev_list:
            if ev.response_snapshot:
                resp_snapshot = ev.response_snapshot
                break

        status_code = resp_snapshot.status_code if resp_snapshot else None
        body_text = resp_snapshot.body if resp_snapshot else None
        content_type = resp_snapshot.content_type if resp_snapshot else None

        # Policy checks
        has_policy = policy is not None
        pol_name = policy.name if policy else None
        exp_dec = policy.expected_decision if policy else finding.expected_decision

        # Baseline comparison
        baseline_compared = baseline_evidence is not None
        differs_from_baseline = False
        similarity: float | None = None

        if baseline_compared and baseline_evidence and baseline_evidence.response_snapshot and body_text:
            base_body = baseline_evidence.response_snapshot.body or ""
            differs_from_baseline, similarity = self._compare_bodies(body_text, base_body)

        # Target resource verification
        resource_data_verified = False
        matched_tokens: list[str] = []
        if target_resource and body_text:
            if target_resource.external_id and target_resource.external_id in body_text:
                resource_data_verified = True
                matched_tokens.append(f"id:{target_resource.external_id}")
            if (
                target_resource.display_name
                and len(target_resource.display_name) > 3
                and target_resource.display_name in body_text
            ):
                resource_data_verified = True
                matched_tokens.append(f"name:{target_resource.display_name}")

        # Check category for cross-tenant
        cross_tenant_tested = finding.category == FindingCategory.CROSS_TENANT_ACCESS
        cross_tenant_verified = cross_tenant_tested and resource_data_verified

        context = FindingEvaluationContext(
            explicit_policy_present=has_policy,
            policy_name=pol_name,
            policy_expected_decision=exp_dec,
            reproduction_trials=1 if finding.last_verified else 0,
            successful_reproductions=1 if finding.last_verified else 0,
            is_reproducible=True if finding.last_verified else None,
            error_baseline_compared=baseline_compared,
            differs_from_error_baseline=differs_from_baseline,
            baseline_similarity_ratio=similarity,
            target_resource_data_verified=resource_data_verified,
            matched_resource_identifiers=matched_tokens,
            response_status_code=status_code,
            response_body=body_text,
            response_content_type=content_type,
            cross_tenant_tested=cross_tenant_tested,
            cross_tenant_verified=cross_tenant_verified,
            evidence_records=ev_list,
        )

        return self.evaluate(context)

    # -------------------------------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _compare_bodies(observed: str, baseline: str) -> tuple[bool, float]:
        """Compare observed response body with baseline error response.

        Returns (differs_bool, similarity_ratio).
        """
        if not observed or not baseline:
            return True, 0.0

        obs_clean = re.sub(r"\s+", " ", observed).strip()
        base_clean = re.sub(r"\s+", " ", baseline).strip()

        if obs_clean == base_clean:
            return False, 1.0

        # Simple character 3-gram Jaccard similarity for deterministic metric
        def _ngrams(s: str, n: int = 3) -> set[str]:
            return {s[i : i + n] for i in range(len(s) - n + 1)} if len(s) >= n else {s}

        obs_ng = _ngrams(obs_clean[:1000])
        base_ng = _ngrams(base_clean[:1000])

        inter = len(obs_ng & base_ng)
        union = len(obs_ng | base_ng)
        sim = inter / union if union > 0 else 0.0

        # If similarity < 0.85, they are considered significantly distinct
        differs = sim < 0.85
        return differs, round(sim, 3)
