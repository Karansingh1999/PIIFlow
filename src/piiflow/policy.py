from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from piiflow.fingerprints import stable_fingerprint
from piiflow.models import (
    Finding,
    PolicyConfig,
    PolicyDecision,
    PolicyRule,
    ScanResult,
    ScanSummary,
    Severity,
)


class PolicyError(ValueError):
    pass


def load_policy(path: Path) -> PolicyConfig:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"Could not read policy {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"Invalid YAML in policy {path}: {exc}") from exc
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise PolicyError(f"Policy {path} must be a mapping")
    try:
        policy = PolicyConfig.model_validate(loaded)
    except ValidationError as exc:
        raise PolicyError(f"Invalid policy {path}: {exc}") from exc
    _validate_policy(policy, path)
    return policy


def evaluate_policy(finding: Finding, policy: PolicyConfig) -> PolicyDecision:
    provider = finding.provider
    trust_zone = finding.trust_zone
    observed = sorted({item.name for item in finding.sanitizers} | set(finding.observed_sanitizers))
    for rule in policy.rules:
        if (
            _matches(rule.categories, finding.category)
            and _matches(rule.providers, provider)
            and _matches(rule.trust_zones, trust_zone)
        ):
            return _decision_for_rule(finding, rule, observed, provider, trust_zone)

    if policy.default_action == "allow":
        return PolicyDecision(
            status="compliant",
            action="allow",
            reason_code="DEFAULT_ALLOW",
            reason="No policy rule matched; default action allows the flow.",
            category=finding.category,
            provider=provider,
            trust_zone=trust_zone,
            observed_sanitizers=observed,
            fingerprint=_policy_fingerprint(finding, "DEFAULT_ALLOW", None),
        )
    return PolicyDecision(
        status="violation",
        action="deny",
        reason_code="DEFAULT_DENY",
        reason="No policy rule matched; default action denies the flow.",
        category=finding.category,
        provider=provider,
        trust_zone=trust_zone,
        observed_sanitizers=observed,
        fingerprint=_policy_fingerprint(finding, "DEFAULT_DENY", None),
    )


def apply_policy(findings: list[Finding], policy: PolicyConfig) -> list[Finding]:
    annotated: list[Finding] = []
    for finding in findings:
        decision = evaluate_policy(finding, policy)
        updated = finding.model_copy(
            update={
                "severity": Severity.INFO if decision.status == "compliant" else finding.severity,
                "policy_evaluated": True,
                "policy_status": decision.status,
                "policy_action": decision.action,
                "policy_rule_id": decision.matched_rule_id,
                "policy_reason_code": decision.reason_code,
                "policy_reason": decision.reason,
                "provider": decision.provider,
                "trust_zone": decision.trust_zone,
                "required_sanitizers": decision.required_sanitizers,
                "observed_sanitizers": decision.observed_sanitizers,
                "policy_fingerprint": decision.fingerprint,
            }
        )
        annotated.append(updated)
    return annotated


def apply_policy_to_result(result: ScanResult, policy: PolicyConfig) -> ScanResult:
    findings = apply_policy(result.findings, policy)
    counts = Counter(finding.severity.value for finding in findings)
    summary = ScanSummary(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
    )
    return result.model_copy(
        update={"findings": findings, "summary": summary, "policy_evaluated": True}
    )


def _validate_policy(policy: PolicyConfig, path: Path) -> None:
    if policy.version != 1:
        raise PolicyError(f"Policy {path} uses unsupported version {policy.version}; expected 1")
    seen: set[str] = set()
    for index, rule in enumerate(policy.rules, start=1):
        if not rule.id:
            raise PolicyError(f"Policy {path} rule #{index} is missing a rule id")
        if rule.id in seen:
            raise PolicyError(f"Policy {path} contains duplicate rule id {rule.id!r}")
        seen.add(rule.id)
        _require_nonempty(path, rule.id, "categories", rule.categories)
        _require_nonempty(path, rule.id, "providers", rule.providers)
        _require_nonempty(path, rule.id, "trust_zones", rule.trust_zones)
        if rule.action == "require_sanitizer":
            _require_nonempty(path, rule.id, "sanitizers", rule.sanitizers)


def _require_nonempty(path: Path, rule_id: str, field: str, values: list[str]) -> None:
    if not values or any(not isinstance(value, str) or not value for value in values):
        raise PolicyError(f"Policy {path} rule {rule_id!r} needs non-empty {field}")


def _decision_for_rule(
    finding: Finding,
    rule: PolicyRule,
    observed: list[str],
    provider: str,
    trust_zone: str,
) -> PolicyDecision:
    if rule.action == "allow":
        return PolicyDecision(
            status="compliant",
            action="allow",
            matched_rule_id=rule.id,
            reason_code="POLICY_ALLOW",
            reason=rule.description or "The matching policy rule allows this flow.",
            category=finding.category,
            provider=provider,
            trust_zone=trust_zone,
            observed_sanitizers=observed,
            fingerprint=_policy_fingerprint(finding, "POLICY_ALLOW", rule.id),
        )
    if rule.action == "deny":
        return PolicyDecision(
            status="violation",
            action="deny",
            matched_rule_id=rule.id,
            reason_code="POLICY_DENY",
            reason=rule.description or "The matching policy rule denies this flow.",
            category=finding.category,
            provider=provider,
            trust_zone=trust_zone,
            observed_sanitizers=observed,
            fingerprint=_policy_fingerprint(finding, "POLICY_DENY", rule.id),
        )
    required = sorted(rule.sanitizers)
    present = "*" in rule.sanitizers or bool(set(required) & set(observed))
    if present:
        return PolicyDecision(
            status="compliant",
            action="require_sanitizer",
            matched_rule_id=rule.id,
            reason_code="REQUIRED_SANITIZER_PRESENT",
            reason=rule.description or "An accepted sanitizer is present on the flow path.",
            category=finding.category,
            provider=provider,
            trust_zone=trust_zone,
            required_sanitizers=required,
            observed_sanitizers=observed,
            fingerprint=_policy_fingerprint(finding, "REQUIRED_SANITIZER_PRESENT", rule.id),
        )
    return PolicyDecision(
        status="violation",
        action="require_sanitizer",
        matched_rule_id=rule.id,
        reason_code="REQUIRED_SANITIZER_MISSING",
        reason=rule.description or "The flow is missing a sanitizer required by policy.",
        category=finding.category,
        provider=provider,
        trust_zone=trust_zone,
        required_sanitizers=required,
        observed_sanitizers=observed,
        fingerprint=_policy_fingerprint(finding, "REQUIRED_SANITIZER_MISSING", rule.id),
    )


def _matches(patterns: list[str], value: str) -> bool:
    return "*" in patterns or value in patterns


def _policy_fingerprint(finding: Finding, reason_code: str, rule_id: str | None) -> str:
    payload: dict[str, Any] = {
        "flow": finding.fingerprint,
        "reason_code": reason_code,
        "rule_id": rule_id,
    }
    source = finding.source
    sink = finding.sink
    return stable_fingerprint(
        rule_id=json.dumps(payload, sort_keys=True),
        category=finding.category,
        source=source,
        sink=sink,
        sanitized=finding.sanitized,
    )
