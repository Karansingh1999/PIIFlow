from __future__ import annotations

import json
from pathlib import Path

import pytest

from piiflow.models import Finding, Location, Severity, SinkRef, SourceRef
from piiflow.policy import PolicyError, apply_policy, evaluate_policy, load_policy


def write_policy(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "policy.yml"
    path.write_text(source, encoding="utf-8")
    return path


def finding(
    *,
    category: str = "EMAIL",
    provider: str = "openai",
    trust_zone: str = "external",
    observed_sanitizers: list[str] | None = None,
) -> Finding:
    sanitizers = [
        {"name": name, "location": Location(file="app.py", line=index + 1)}
        for index, name in enumerate(observed_sanitizers or [])
    ]
    return Finding(
        severity=Severity.HIGH,
        category=category,
        source=SourceRef(file="app.py", line=1, expression='request.json["email"]'),
        sink=SinkRef(file="app.py", line=2, call="client.responses.create", argument="input"),
        path=['request.json["email"]', "email"],
        sanitized=bool(observed_sanitizers),
        sanitizers=sanitizers,
        message="Email data may reach an external LLM.",
        remediation="redact",
        fingerprint="flow-fingerprint",
        provider=provider,
        trust_zone=trust_zone,
    )


def test_valid_policy_loading_and_allow_decision(tmp_path: Path) -> None:
    policy = load_policy(
        write_policy(
            tmp_path,
            """
version: 1
default_action: deny
rules:
  - id: allow-email-openai
    categories: [EMAIL]
    providers: [openai]
    trust_zones: [external]
    action: allow
""",
        )
    )

    decision = evaluate_policy(finding(), policy)

    assert decision.status == "compliant"
    assert decision.reason_code == "POLICY_ALLOW"
    assert decision.matched_rule_id == "allow-email-openai"


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("[", "Invalid YAML"),
        ("version: 2\ndefault_action: deny\nrules: []\n", "unsupported version"),
        (
            """
version: 1
default_action: deny
rules:
  - id: duplicate
    categories: [EMAIL]
    providers: [openai]
    trust_zones: [external]
    action: allow
  - id: duplicate
    categories: [PHONE]
    providers: [openai]
    trust_zones: [external]
    action: allow
""",
            "duplicate rule id",
        ),
        (
            """
version: 1
default_action: deny
rules:
  - id: bad-action
    categories: [EMAIL]
    providers: [openai]
    trust_zones: [external]
    action: maybe
""",
            "Invalid policy",
        ),
        (
            """
version: 1
default_action: maybe
rules: []
""",
            "Invalid policy",
        ),
        (
            """
version: 1
default_action: deny
rules:
  - id: missing-sanitizer
    categories: [EMAIL]
    providers: [openai]
    trust_zones: [external]
    action: require_sanitizer
""",
            "sanitizers",
        ),
        (
            """
version: 1
default_action: deny
rules:
  - id: empty-category
    categories: []
    providers: [openai]
    trust_zones: [external]
    action: deny
""",
            "categories",
        ),
    ],
)
def test_invalid_policies_raise_clean_errors(tmp_path: Path, source: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        load_policy(write_policy(tmp_path, source))


def test_first_match_wildcard_and_default_semantics(tmp_path: Path) -> None:
    policy = load_policy(
        write_policy(
            tmp_path,
            """
version: 1
default_action: allow
rules:
  - id: deny-all-external
    categories: ["*"]
    providers: ["*"]
    trust_zones: [external]
    action: deny
  - id: allow-email-openai
    categories: [EMAIL]
    providers: [openai]
    trust_zones: [external]
    action: allow
""",
        )
    )

    assert evaluate_policy(finding(), policy).reason_code == "POLICY_DENY"
    local = evaluate_policy(finding(provider="local", trust_zone="local"), policy)
    assert local.reason_code == "DEFAULT_ALLOW"


def test_default_deny_provider_trust_zone_and_category_matching(tmp_path: Path) -> None:
    policy = load_policy(write_policy(tmp_path, "version: 1\ndefault_action: deny\nrules: []\n"))

    decision = evaluate_policy(
        finding(category="MEDICAL", provider="anthropic", trust_zone="external"), policy
    )

    assert decision.status == "violation"
    assert decision.reason_code == "DEFAULT_DENY"
    assert decision.category == "MEDICAL"
    assert decision.provider == "anthropic"
    assert decision.trust_zone == "external"


def test_require_sanitizer_accepts_only_listed_evidence(tmp_path: Path) -> None:
    policy = load_policy(
        write_policy(
            tmp_path,
            """
version: 1
default_action: deny
rules:
  - id: require-email-redaction
    categories: [EMAIL]
    providers: [openai]
    trust_zones: [external]
    action: require_sanitizer
    sanitizers: [redact_email]
""",
        )
    )

    assert (
        evaluate_policy(finding(observed_sanitizers=["redact_email"]), policy).reason_code
        == "REQUIRED_SANITIZER_PRESENT"
    )
    assert (
        evaluate_policy(finding(observed_sanitizers=["hash_value"]), policy).reason_code
        == "REQUIRED_SANITIZER_MISSING"
    )
    assert evaluate_policy(finding(), policy).reason_code == "REQUIRED_SANITIZER_MISSING"


def test_multiple_observed_sanitizers_are_deterministic(tmp_path: Path) -> None:
    policy = load_policy(
        write_policy(
            tmp_path,
            """
version: 1
default_action: deny
rules:
  - id: require-any
    categories: [EMAIL]
    providers: [openai]
    trust_zones: [external]
    action: require_sanitizer
    sanitizers: ["*"]
""",
        )
    )

    decision = evaluate_policy(finding(observed_sanitizers=["mask_email", "redact_email"]), policy)

    assert decision.status == "compliant"
    assert decision.observed_sanitizers == ["mask_email", "redact_email"]


def test_apply_policy_keeps_flow_fingerprint_stable_across_policies(tmp_path: Path) -> None:
    allow = load_policy(
        write_policy(
            tmp_path,
            """
version: 1
default_action: allow
rules: []
""",
        )
    )
    deny = load_policy(
        write_policy(
            tmp_path,
            """
version: 1
default_action: deny
rules: []
""",
        )
    )
    flow = finding()

    allowed = apply_policy([flow], allow)[0]
    denied = apply_policy([flow], deny)[0]

    assert allowed.fingerprint == denied.fingerprint == "flow-fingerprint"
    assert allowed.policy_fingerprint != denied.policy_fingerprint
    assert json.dumps(allowed.model_dump(mode="json"), sort_keys=True)
