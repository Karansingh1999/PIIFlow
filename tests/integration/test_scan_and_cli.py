from pathlib import Path

from typer.testing import CliRunner

from piiflow.cli import app
from piiflow.config import ConfigError, load_config
from piiflow.policy import apply_policy_to_result, load_policy
from piiflow.reporting import finding_fails, render_text, result_to_json
from piiflow.scanner import scan_path

runner = CliRunner()


def test_vulnerable_example_produces_expected_findings() -> None:
    result = scan_path(Path("examples/vulnerable_app"))

    assert result.summary.critical == 2
    assert result.summary.high == 1
    assert {finding.category for finding in result.findings if not finding.sanitized} == {
        "EMAIL",
        "MEDICAL",
        "FINANCIAL",
    }


def test_safe_example_produces_no_failing_findings() -> None:
    result = scan_path(Path("examples/safe_app"))

    assert [finding for finding in result.findings if not finding.sanitized] == []
    assert result.summary.info == 1


def test_directory_scan_skips_excluded_paths(tmp_path: Path) -> None:
    included = tmp_path / "included.py"
    skipped_dir = tmp_path / "skip_me"
    skipped_dir.mkdir()
    skipped = skipped_dir / "leak.py"
    source = """
def handle(request, client):
    email = request.json["email"]
    client.responses.create(input=email)
"""
    included.write_text(source, encoding="utf-8")
    skipped.write_text(source, encoding="utf-8")

    result = scan_path(tmp_path, excludes=("skip_me/*",))

    assert result.scanned_files == 1
    assert result.summary.high == 1


def test_json_output_validates_expected_structure() -> None:
    result = scan_path(Path("examples/vulnerable_app"))
    payload = result_to_json(result)

    assert '"tool": "piiflow"' in payload
    assert '"findings": [' in payload
    assert '"fingerprint":' in payload


def test_exit_code_fail_on_behavior() -> None:
    failed = runner.invoke(app, ["scan", "examples/vulnerable_app", "--format", "json"])
    ignored = runner.invoke(
        app,
        ["scan", "examples/vulnerable_app", "--format", "json", "--fail-on", "none"],
    )

    assert failed.exit_code == 1
    assert ignored.exit_code == 0


def test_cli_output_file_and_version(tmp_path: Path) -> None:
    output = tmp_path / "result.json"

    completed = runner.invoke(
        app,
        [
            "scan",
            "examples/safe_app",
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )
    version_only = runner.invoke(app, ["scan", "--version"])

    assert completed.exit_code == 0
    assert output.exists()
    assert version_only.exit_code == 0
    assert "0.3.0" in version_only.stdout


def test_cli_invalid_format_and_config_errors(tmp_path: Path) -> None:
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text("[]", encoding="utf-8")

    invalid_format = runner.invoke(app, ["scan", "examples/safe_app", "--format", "xml"])

    with_config_error = runner.invoke(
        app,
        ["scan", "examples/safe_app", "--config", str(bad_config)],
    )

    assert invalid_format.exit_code == 2
    assert with_config_error.exit_code == 2
    try:
        load_config(bad_config)
    except ConfigError as exc:
        assert "must be a mapping" in str(exc)
    else:
        raise AssertionError("invalid config should raise")


def test_text_report_and_threshold_helpers() -> None:
    result = scan_path(Path("examples/vulnerable_app"))
    rendered = render_text(result)

    assert "PIIFlow 0.3.0" in rendered
    assert "Findings" in rendered
    assert finding_fails(result.findings[0], None) is False


def test_syntax_error_reported_while_other_files_analyzed(tmp_path: Path) -> None:
    good = tmp_path / "good.py"
    bad = tmp_path / "bad.py"
    good.write_text(
        """
def handle(request, client):
    email = request.json["email"]
    client.responses.create(input=email)
""",
        encoding="utf-8",
    )
    bad.write_text("def nope(:\n", encoding="utf-8")

    result = scan_path(tmp_path)

    assert result.summary.high == 1
    assert len(result.parse_errors) == 1


def test_cli_parse_error_takes_precedence_over_privacy_finding(tmp_path: Path) -> None:
    good = tmp_path / "good.py"
    bad = tmp_path / "bad.py"
    good.write_text(
        """
def handle(request, client):
    email = request.json["email"]
    client.responses.create(input=email)
""",
        encoding="utf-8",
    )
    bad.write_text("def nope(:\n", encoding="utf-8")

    completed = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])

    assert completed.exit_code == 3
    assert '"findings": [' in completed.stdout
    assert '"parse_errors": [' in completed.stdout


def test_cli_parse_error_exit_code_when_no_finding(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("def nope(:\n", encoding="utf-8")

    completed = runner.invoke(app, ["scan", str(tmp_path)])

    assert completed.exit_code == 3


def test_invalid_utf8_source_is_reported_as_parse_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_bytes(b"\xff\xfe\xfa")

    result = scan_path(tmp_path)

    assert result.parse_errors
    assert "could not decode as UTF-8" in result.parse_errors[0].message


def test_cli_output_write_failure_is_clean_exit_code(tmp_path: Path) -> None:
    destination = tmp_path / "missing" / "result.json"

    completed = runner.invoke(
        app,
        ["scan", "examples/safe_app", "--format", "json", "--output", str(destination)],
    )

    assert completed.exit_code == 2
    assert "Could not write output file" in completed.stderr
    assert not completed.exception or not isinstance(completed.exception, UnicodeDecodeError)


def test_packaged_default_rules_can_be_loaded() -> None:
    config = load_config()

    assert config.version == 1
    assert any(rule.id == "openai-responses" for rule in config.sink_patterns)


def test_cli_policy_violation_exits_one_and_reports_json(tmp_path: Path) -> None:
    app_path = tmp_path / "app.py"
    policy = tmp_path / "policy.yml"
    app_path.write_text(
        """
def handle(request, client):
    medical_history = request.json["medical_history"]
    client.responses.create(input=medical_history)
""",
        encoding="utf-8",
    )
    policy.write_text(
        """
version: 1
default_action: allow
rules:
  - id: deny-medical-external
    description: Medical data cannot leave the organization.
    categories: [MEDICAL]
    providers: ["*"]
    trust_zones: [external]
    action: deny
""",
        encoding="utf-8",
    )

    completed = runner.invoke(
        app,
        ["scan", str(app_path), "--policy", str(policy), "--format", "json"],
    )

    assert completed.exit_code == 1
    assert '"policy_evaluated": true' in completed.stdout
    assert '"policy_status": "violation"' in completed.stdout
    assert '"provider": "openai"' in completed.stdout


def test_cli_policy_compliant_only_scan_exits_zero_and_text_is_readable(tmp_path: Path) -> None:
    app_path = tmp_path / "app.py"
    policy = tmp_path / "policy.yml"
    app_path.write_text(
        """
def redact_email(value):
    return "[redacted]"

def handle(request, client):
    email = request.json["email"]
    client.responses.create(input=redact_email(email))
""",
        encoding="utf-8",
    )
    policy.write_text(
        """
version: 1
default_action: deny
rules:
  - id: require-email-redaction
    description: Email must be redacted before OpenAI.
    categories: [EMAIL]
    providers: [openai]
    trust_zones: [external]
    action: require_sanitizer
    sanitizers: [redact_email]
""",
        encoding="utf-8",
    )

    completed = runner.invoke(app, ["scan", str(app_path), "--policy", str(policy)])

    assert completed.exit_code == 0
    assert "Policy: compliant" in completed.stdout
    assert "Observed sanitizers: redact_email" in completed.stdout


def test_cli_malformed_policy_exits_two_without_traceback(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yml"
    policy.write_text("[", encoding="utf-8")

    completed = runner.invoke(app, ["scan", "examples/safe_app", "--policy", str(policy)])

    assert completed.exit_code == 2
    assert "Invalid YAML" in completed.stderr
    assert "Traceback" not in completed.stderr


def test_cli_policy_output_file_and_parse_error_precedence(tmp_path: Path) -> None:
    good = tmp_path / "good.py"
    bad = tmp_path / "bad.py"
    policy = tmp_path / "policy.yml"
    output = tmp_path / "result.json"
    good.write_text(
        """
def handle(request, client):
    email = request.json["email"]
    client.responses.create(input=email)
""",
        encoding="utf-8",
    )
    bad.write_text("def nope(:\n", encoding="utf-8")
    policy.write_text("version: 1\ndefault_action: deny\nrules: []\n", encoding="utf-8")

    completed = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--policy",
            str(policy),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert completed.exit_code == 3
    assert output.exists()
    payload = output.read_text(encoding="utf-8")
    assert '"policy_status": "violation"' in payload
    assert '"parse_errors": [' in payload


def test_policy_decision_preserves_sanitizer_evidence_through_branch_and_helper(
    tmp_path: Path,
) -> None:
    app_path = tmp_path / "app.py"
    policy_path = tmp_path / "policy.yml"
    app_path.write_text(
        """
def redact_email(value):
    return "[redacted]"

def helper(value):
    return redact_email(value)

def handle(request, client, flag):
    email = request.json["email"]
    if flag:
        prompt = helper(email)
    else:
        prompt = redact_email(email)
    client.responses.create(input=prompt)
""",
        encoding="utf-8",
    )
    policy_path.write_text(
        """
version: 1
default_action: deny
rules:
  - id: require-redact-email
    categories: [EMAIL]
    providers: [openai]
    trust_zones: [external]
    action: require_sanitizer
    sanitizers: [redact_email]
""",
        encoding="utf-8",
    )

    result = apply_policy_to_result(scan_path(app_path), load_policy(policy_path))

    assert result.findings[0].policy_status == "compliant"
    assert result.findings[0].observed_sanitizers == ["redact_email"]


def test_example_policies_cover_documented_cli_scenarios() -> None:
    scenarios = [
        (
            [
                "scan",
                "examples/policy_apps/medical_external.py",
                "--policy",
                "examples/policies/strict_external.yml",
            ],
            1,
            "Policy: violation",
        ),
        (
            [
                "scan",
                "examples/policy_apps/redacted_email.py",
                "--policy",
                "examples/policies/sanitized_email.yml",
            ],
            0,
            "Policy: compliant",
        ),
        (
            [
                "scan",
                "examples/policy_apps/local_financial.py",
                "--config",
                "examples/policy_apps/local_rules.yml",
                "--policy",
                "examples/policies/local_model.yml",
            ],
            0,
            "Provider: local; trust zone: local",
        ),
        (
            [
                "scan",
                "examples/policy_apps/redacted_medical_external.py",
                "--policy",
                "examples/policies/strict_external.yml",
            ],
            1,
            "Policy: violation",
        ),
        (
            [
                "scan",
                "examples/policy_apps/wrong_email_sanitizer.py",
                "--policy",
                "examples/policies/sanitized_email.yml",
            ],
            1,
            "REQUIRED_SANITIZER_MISSING",
        ),
    ]

    for args, exit_code, expected in scenarios:
        completed = runner.invoke(app, args)
        assert completed.exit_code == exit_code
        assert expected in completed.stdout
