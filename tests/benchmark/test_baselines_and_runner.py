from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import yaml

from benchmarks.baselines.direct_flow import DirectFlowBaseline
from benchmarks.baselines.lexical import LexicalBaseline
from benchmarks.evaluator.loader import load_manifest
from benchmarks.evaluator.reporting import render_markdown_report
from benchmarks.evaluator.runner import build_systems, evaluate, select_cases
from benchmarks.run import main
from benchmarks.run_policy import file_hash as policy_file_hash
from benchmarks.run_policy import load_manifest as load_policy_manifest
from benchmarks.run_policy import main as policy_main
from benchmarks.run_policy import policy_content_hash


def test_lexical_baseline_flags_cooccurrence(tmp_path: Path) -> None:
    case = tmp_path / "case.py"
    case.write_text(
        'def handle(request, client):\n    email = request.json["email"]\n'
        '    client.responses.create(input="public")\n',
        encoding="utf-8",
    )

    result = LexicalBaseline().analyze(case)

    assert result.predicted_vulnerable is True
    assert result.predicted_categories == ["EMAIL"]


def test_direct_flow_baseline_only_detects_direct_sources(tmp_path: Path) -> None:
    direct = tmp_path / "direct.py"
    indirect = tmp_path / "indirect.py"
    direct.write_text(
        'def handle(request, client):\n    client.responses.create(input=request.json["email"])\n',
        encoding="utf-8",
    )
    indirect.write_text(
        'def handle(request, client):\n    email = request.json["email"]\n'
        "    client.responses.create(input=email)\n",
        encoding="utf-8",
    )

    assert DirectFlowBaseline().analyze(direct).predicted_vulnerable is True
    assert DirectFlowBaseline().analyze(indirect).predicted_vulnerable is False


def test_runner_generates_json_jsonl_and_markdown(tmp_path: Path) -> None:
    output = tmp_path / "results"
    exit_code = main(
        [
            "--manifest",
            "benchmarks/manifest.yaml",
            "--partition",
            "in_scope",
            "--system",
            "all",
            "--output-directory",
            str(output),
            "--limit",
            "4",
        ]
    )

    metrics_path = output / "metrics.json"
    jsonl_path = output / "case_results.jsonl"
    report_path = output / "report.md"

    assert exit_code == 0
    assert metrics_path.exists()
    assert jsonl_path.exists()
    assert report_path.exists()

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    records = [
        json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines() if line
    ]
    assert metrics["case_counts"]["total"] == 4
    assert metrics["metadata"]["systems"] == ["lexical", "direct", "piiflow_legacy", "piiflow"]
    assert len(records) == 16
    assert "Overall Comparison" in report_path.read_text(encoding="utf-8")


def test_deterministic_case_ordering_and_metrics_payload(tmp_path: Path) -> None:
    manifest = load_manifest(Path("benchmarks/manifest.yaml"))
    output = tmp_path / "results"

    first = evaluate(
        manifest_path=Path("benchmarks/manifest.yaml"),
        manifest=manifest,
        partition="in_scope",
        system="piiflow",
        output_directory=output,
        limit=5,
    )
    second = evaluate(
        manifest_path=Path("benchmarks/manifest.yaml"),
        manifest=manifest,
        partition="in_scope",
        system="piiflow",
        output_directory=output,
        limit=5,
    )

    assert [case.id for case in select_cases(manifest, "in_scope", 5)] == sorted(
        case.id for case in select_cases(manifest, "in_scope", 5)
    )
    first_systems = cast(dict[str, Any], first["systems"])
    second_systems = cast(dict[str, Any], second["systems"])
    assert (
        first_systems["piiflow"]["overall"]["metrics"]
        == second_systems["piiflow"]["overall"]["metrics"]
    )


def test_system_all_includes_legacy_ablation() -> None:
    assert [system.name for system in build_systems("all")] == [
        "lexical",
        "direct",
        "piiflow_legacy",
        "piiflow",
    ]


def test_policy_benchmark_smoke(tmp_path: Path) -> None:
    output = tmp_path / "policy_results"

    exit_code = policy_main(
        [
            "--manifest",
            "benchmarks/policy_manifest.yml",
            "--system",
            "all",
            "--limit",
            "4",
            "--output-directory",
            str(output),
        ]
    )

    metrics = json.loads((output / "metrics.json").read_text(encoding="utf-8"))
    records = [
        json.loads(line)
        for line in (output / "case_results.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert exit_code == 0
    assert len(records) == 8
    assert metrics["metadata"]["systems"] == ["piiflow_policy", "policy_blind"]


def test_policy_benchmark_hashes_are_stable_across_lf_and_crlf(tmp_path: Path) -> None:
    manifest_text = """
version: 1
cases:
  - id: policy_case_001
    path: policy_cases/apps/app.py
    policy: policy_cases/policies/policy.yml
    partition: in_scope
    family: direct
    description: Email to OpenAI is denied.
    expected:
      status: violation
      categories: [EMAIL]
      action: deny
      provider: openai
      trust_zone: external
    tags: [email, openai]
""".lstrip()
    source_text = (
        "def handle(request, client):\n"
        '    email = request.json["email"]\n'
        "    client.responses.create(input=email)\n"
    )
    policy_text = """
version: 1
default_action: deny
rules: []
""".lstrip()

    roots = []
    for newline in ["lf", "crlf"]:
        root = tmp_path / newline
        app_dir = root / "policy_cases" / "apps"
        policy_dir = root / "policy_cases" / "policies"
        app_dir.mkdir(parents=True)
        policy_dir.mkdir(parents=True)
        line_ending = "\n" if newline == "lf" else "\r\n"
        (root / "policy_manifest.yml").write_bytes(
            manifest_text.replace("\n", line_ending).encode()
        )
        (app_dir / "app.py").write_bytes(source_text.replace("\n", line_ending).encode())
        (policy_dir / "policy.yml").write_bytes(policy_text.replace("\n", line_ending).encode())
        roots.append(root)

    lf_manifest = load_policy_manifest(roots[0] / "policy_manifest.yml")
    crlf_manifest = load_policy_manifest(roots[1] / "policy_manifest.yml")

    assert policy_file_hash(roots[0] / "policy_manifest.yml") == policy_file_hash(
        roots[1] / "policy_manifest.yml"
    )
    assert policy_content_hash(roots[0], lf_manifest) == policy_content_hash(
        roots[1],
        crlf_manifest,
    )


def test_production_code_has_no_benchmark_specific_references() -> None:
    production = "\n".join(
        path.read_text(encoding="utf-8") for path in Path("src/piiflow").glob("*.py")
    )

    assert "policy_in_scope_" not in production
    assert "policy_challenge_" not in production
    assert "challenge_" not in production


def test_markdown_report_generation() -> None:
    metrics = {
        "metadata": {"manifest_hash": "abc"},
        "case_counts": {"total": 0, "in_scope": 0, "challenge": 0},
        "label_distribution": {"positive": 0, "negative": 0},
        "systems": {
            "piiflow": {
                "overall": {
                    "case_count": 0,
                    "metrics": {
                        "precision": 0.0,
                        "recall": 0.0,
                        "f1": 0.0,
                        "accuracy": 0.0,
                    },
                    "runtime": {},
                },
                "by_partition": {},
                "by_family": {},
                "by_category": {},
                "by_sink": {},
                "false_positive_ids": [],
                "false_negative_ids": [],
                "runtime": {
                    "mean_seconds": 0.0,
                    "median_seconds": 0.0,
                    "p95_seconds": 0.0,
                    "total_seconds": 0.0,
                },
            }
        },
    }

    report = render_markdown_report(metrics)

    assert "PIIFlow-Bench Report" in report
    assert "Threats To Validity" in report


def test_invalid_manifest_runner_error(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(yaml.safe_dump({"version": 99, "cases": []}), encoding="utf-8")

    assert main(["--manifest", str(manifest), "--fail-on-invalid-manifest"]) == 2
    assert main(["--manifest", str(manifest)]) == 0
