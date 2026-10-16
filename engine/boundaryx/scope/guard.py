from typing import List, Optional
from urllib.parse import urljoin

from pydantic import BaseModel

from boundaryx.domain.enums import ScopeRuleType, ScopeStatus
from boundaryx.domain.models import ScopeRule
from boundaryx.scope.canonicalizer import ScopeCanonicalizationError, parse_and_canonicalize_target
from boundaryx.scope.matcher import matches_scope_rule


class ScopeDecision(BaseModel):
    is_in_scope: bool
    status: ScopeStatus
    canonical_host: str
    canonical_path: str
    scheme: Optional[str] = None
    port: Optional[int] = None
    matched_rule_id: Optional[str] = None
    denial_reason: Optional[str] = None


class ScopeGuard:
    """
    Central Scope Guard engine for BoundaryX.
    Enforces authorization boundaries before any request is dispatched or target resolved.
    """

    def __init__(self, rules: List[ScopeRule]):
        self.rules = rules
        self.include_rules = [r for r in rules if r.rule_type == ScopeRuleType.INCLUDE]
        self.exclude_rules = [r for r in rules if r.rule_type == ScopeRuleType.EXCLUDE]

    def evaluate(self, target: str) -> ScopeDecision:
        """
        Evaluates a target string (URL or host) against scope rules.
        Exclusion rules take precedence over inclusion rules.
        """
        try:
            host, scheme, port, path = parse_and_canonicalize_target(target)
        except ScopeCanonicalizationError as err:
            return ScopeDecision(
                is_in_scope=False,
                status=ScopeStatus.OUT_OF_SCOPE,
                canonical_host="invalid",
                canonical_path="/",
                denial_reason=f"Canonicalization failure: {str(err)}",
            )

        # 1. Check exclusions first (Precedence)
        for ex_rule in self.exclude_rules:
            if matches_scope_rule(ex_rule, host, scheme, port, path):
                return ScopeDecision(
                    is_in_scope=False,
                    status=ScopeStatus.OUT_OF_SCOPE,
                    canonical_host=host,
                    canonical_path=path,
                    scheme=scheme,
                    port=port,
                    matched_rule_id=ex_rule.id,
                    denial_reason=f"Target matched explicit exclusion rule: {ex_rule.pattern}",
                )

        # 2. Check inclusions
        matched_include: Optional[ScopeRule] = None
        for inc_rule in self.include_rules:
            if matches_scope_rule(inc_rule, host, scheme, port, path):
                matched_include = inc_rule
                break

        if matched_include:
            return ScopeDecision(
                is_in_scope=True,
                status=ScopeStatus.IN_SCOPE,
                canonical_host=host,
                canonical_path=path,
                scheme=scheme,
                port=port,
                matched_rule_id=matched_include.id,
                denial_reason=None,
            )

        # If no inclusion matched, deny by default
        return ScopeDecision(
            is_in_scope=False,
            status=ScopeStatus.OUT_OF_SCOPE,
            canonical_host=host,
            canonical_path=path,
            scheme=scheme,
            port=port,
            denial_reason="Target did not match any active in-scope inclusion rules",
        )

    def validate_redirect(self, original_url: str, redirect_location: str) -> ScopeDecision:
        """
        Validates an HTTP redirect hop before following.
        Resolves relative redirect paths against the original URL and evaluates the target.
        """
        resolved_url = urljoin(original_url, redirect_location)
        decision = self.evaluate(resolved_url)
        if not decision.is_in_scope:
            decision.denial_reason = (
                f"Redirect to '{resolved_url}' blocked by scope guard: {decision.denial_reason}"
            )
        return decision

    # Convenience alias for target validation
    validate_target = evaluate
