from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

Status = Literal["violation", "compliant"]
Outcome = Literal["tp", "fp", "tn", "fn"]


class ExpectedPolicy(BaseModel):
    status: Status
    categories: list[str] = Field(default_factory=list)
    action: str
    provider: str
    trust_zone: str


class PolicyCase(BaseModel):
    id: str
    path: str
    policy: str
    config: str | None = None
    partition: str
    family: str
    description: str
    expected: ExpectedPolicy
    tags: list[str] = Field(default_factory=list)


class PolicyManifest(BaseModel):
    version: int
    cases: list[PolicyCase]


class PolicyCaseResult(BaseModel):
    case_id: str
    partition: str
    family: str
    system: str
    expected_status: Status
    predicted_status: Status
    expected_categories: list[str]
    predicted_categories: list[str]
    action: str
    provider: str
    trust_zone: str
    tags: list[str]
    outcome: Outcome
    finding_count: int
    runtime_seconds: float
    error: str | None = None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the PIIFlow policy benchmark.")
    parser.add_argument(
        "--manifest", type=Path, default=Path(__file__).with_name("policy_manifest.yml")
    )
    parser.add_argument(
        "--system", choices=["all", "policy_blind", "piiflow_policy"], default="all"
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path(__file__).with_name("results") / "phase2b2_policy",
    )
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)

    manifest = load_manifest(args.manifest)
    systems = ["policy_blind", "piiflow_policy"] if args.system == "all" else [args.system]
    cases = sorted(manifest.cases, key=lambda case: case.id)
    if args.limit is not None:
        cases = cases[: args.limit]
    root = args.manifest.parent.resolve()
    results: list[PolicyCaseResult] = []
    for system in systems:
        for case in cases:
            results.append(run_case(root, case, system))

    metrics = summarize(manifest_path=args.manifest, manifest=manifest, results=results)
    write_outputs(args.output_directory, metrics, results)
    return 0


def load_manifest(path: Path) -> PolicyManifest:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    manifest = PolicyManifest.model_validate(loaded)
    if manifest.version != 1:
        raise ValueError("Unsupported policy benchmark manifest version")
    ids = [case.id for case in manifest.cases]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate policy benchmark case IDs")
    return manifest


def run_case(root: Path, case: PolicyCase, system: str) -> PolicyCaseResult:
    from piiflow.policy import apply_policy_to_result, load_policy
    from piiflow.scanner import scan_path

    started = time.perf_counter()
    predicted_status: Status = "compliant"
    predicted_categories: list[str] = []
    finding_count = 0
    error: str | None = None
    try:
        path = (root / case.path).resolve()
        policy_path = (root / case.policy).resolve()
        config_path = (root / case.config).resolve() if case.config else None
        result = scan_path(path, config_path=config_path)
        if system == "policy_blind":
            finding_count = len(result.findings)
            predicted_status = "violation" if result.findings else "compliant"
            predicted_categories = sorted({finding.category for finding in result.findings})
        else:
            policy_result = apply_policy_to_result(result, load_policy(policy_path))
            violations = [
                finding
                for finding in policy_result.findings
                if finding.policy_status == "violation"
            ]
            finding_count = len(violations)
            predicted_status = "violation" if violations else "compliant"
            predicted_categories = sorted({finding.category for finding in violations})
    except Exception as exc:
        error = f"{exc.__class__.__name__}: {exc}"
        predicted_status = "violation"
    runtime = time.perf_counter() - started
    return PolicyCaseResult(
        case_id=case.id,
        partition=case.partition,
        family=case.family,
        system=system,
        expected_status=case.expected.status,
        predicted_status=predicted_status,
        expected_categories=sorted(case.expected.categories),
        predicted_categories=predicted_categories,
        action=case.expected.action,
        provider=case.expected.provider,
        trust_zone=case.expected.trust_zone,
        tags=sorted(case.tags),
        outcome=classify(case.expected.status, predicted_status),
        finding_count=finding_count,
        runtime_seconds=runtime,
        error=error,
    )


def summarize(
    *,
    manifest_path: Path,
    manifest: PolicyManifest,
    results: list[PolicyCaseResult],
) -> dict[str, Any]:
    from piiflow import __version__ as piiflow_version

    root = manifest_path.parent.resolve()
    return {
        "metadata": {
            "python_version": sys.version,
            "platform": platform.platform(),
            "piiflow_version": piiflow_version,
            "manifest_hash": file_hash(manifest_path),
            "policy_content_hash": policy_content_hash(root, manifest),
            "systems": sorted({result.system for result in results}),
            "case_count": len(manifest.cases),
        },
        "case_counts": {
            "total": len(manifest.cases),
            "in_scope": sum(1 for case in manifest.cases if case.partition == "in_scope"),
            "challenge": sum(1 for case in manifest.cases if case.partition == "challenge"),
        },
        "label_distribution": {
            "violation": sum(1 for case in manifest.cases if case.expected.status == "violation"),
            "compliant": sum(1 for case in manifest.cases if case.expected.status == "compliant"),
        },
        "systems": summarize_results(results),
    }


def summarize_results(results: list[PolicyCaseResult]) -> dict[str, Any]:
    grouped: dict[str, list[PolicyCaseResult]] = defaultdict(list)
    for result in results:
        grouped[result.system].append(result)
    return {system: summarize_group(values) for system, values in sorted(grouped.items())}


def summarize_group(results: list[PolicyCaseResult]) -> dict[str, Any]:
    return {
        "overall": group_payload(results),
        "by_partition": grouped_payload(results, "partition"),
        "by_action": grouped_payload(results, "action"),
        "by_provider": grouped_payload(results, "provider"),
        "by_trust_zone": grouped_payload(results, "trust_zone"),
        "by_category": category_payload(results),
        "false_positive_ids": sorted(row.case_id for row in results if row.outcome == "fp"),
        "false_negative_ids": sorted(row.case_id for row in results if row.outcome == "fn"),
        "runtime": runtime_stats(results),
        "error_count": sum(1 for row in results if row.error),
    }


def grouped_payload(results: list[PolicyCaseResult], field: str) -> dict[str, Any]:
    values = sorted({str(getattr(result, field)) for result in results})
    return {
        value: group_payload([result for result in results if str(getattr(result, field)) == value])
        for value in values
    }


def category_payload(results: list[PolicyCaseResult]) -> dict[str, Any]:
    categories = sorted({category for result in results for category in result.expected_categories})
    return {
        category: group_payload(
            [result for result in results if category in result.expected_categories]
        )
        for category in categories
    }


def group_payload(results: list[PolicyCaseResult]) -> dict[str, Any]:
    return {
        "case_count": len(results),
        "metrics": binary_metrics(results),
        "runtime": runtime_stats(results),
    }


def binary_metrics(results: list[PolicyCaseResult]) -> dict[str, float | int]:
    counts = Counter(result.outcome for result in results)
    tp = counts["tp"]
    fp = counts["fp"]
    tn = counts["tn"]
    fn = counts["fn"]
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    return {
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": safe_div(2 * precision * recall, precision + recall),
        "accuracy": safe_div(tp + tn, tp + fp + tn + fn),
    }


def runtime_stats(results: list[PolicyCaseResult]) -> dict[str, float]:
    values = sorted(result.runtime_seconds for result in results)
    if not values:
        return {"median_seconds": 0.0, "total_seconds": 0.0}
    return {"median_seconds": statistics.median(values), "total_seconds": sum(values)}


def classify(expected: Status, predicted: Status) -> Outcome:
    expected_vulnerable = expected == "violation"
    predicted_vulnerable = predicted == "violation"
    if expected_vulnerable and predicted_vulnerable:
        return "tp"
    if not expected_vulnerable and predicted_vulnerable:
        return "fp"
    if not expected_vulnerable and not predicted_vulnerable:
        return "tn"
    return "fn"


def write_outputs(
    output_directory: Path,
    metrics: dict[str, Any],
    results: list[PolicyCaseResult],
) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / "metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    with (output_directory / "case_results.jsonl").open("w", encoding="utf-8") as handle:
        for result in sorted(results, key=lambda row: (row.system, row.case_id)):
            handle.write(result.model_dump_json() + "\n")
    (output_directory / "report.md").write_text(render_report(metrics), encoding="utf-8")


def render_report(metrics: dict[str, Any]) -> str:
    lines = [
        "# PIIFlow Policy Benchmark Report",
        "",
        f"- Cases: {metrics['case_counts']['total']}",
        f"- In-scope: {metrics['case_counts']['in_scope']}",
        f"- Challenge: {metrics['case_counts']['challenge']}",
        f"- Violations: {metrics['label_distribution']['violation']}",
        f"- Compliant: {metrics['label_distribution']['compliant']}",
        "",
        "## Overall",
        "",
        table(metrics["systems"], "overall"),
        "",
        "## By Partition",
        "",
        nested_tables(metrics["systems"], "by_partition"),
        "",
        "## By Policy Action",
        "",
        nested_tables(metrics["systems"], "by_action"),
        "",
        "## By Provider",
        "",
        nested_tables(metrics["systems"], "by_provider"),
        "",
        "## By Trust Zone",
        "",
        nested_tables(metrics["systems"], "by_trust_zone"),
        "",
        "## By Category",
        "",
        nested_tables(metrics["systems"], "by_category"),
        "",
        "## False Positives",
        "",
        failures(metrics["systems"], "false_positive_ids"),
        "",
        "## False Negatives",
        "",
        failures(metrics["systems"], "false_negative_ids"),
        "",
        "## Metadata",
        "",
        "```json",
        json.dumps(metrics["metadata"], indent=2, sort_keys=True),
        "```",
    ]
    return "\n".join(lines)


def table(systems: dict[str, Any], key: str) -> str:
    rows = [
        "| System | Cases | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for system, payload in sorted(systems.items()):
        group = payload[key]
        metrics = group["metrics"]
        rows.append(
            f"| {system} | {group['case_count']} | {fmt(metrics['precision'])} | "
            f"{fmt(metrics['recall'])} | {fmt(metrics['f1'])} | "
            f"{fmt(metrics['accuracy'])} | {metrics['true_positives']} | "
            f"{metrics['false_positives']} | {metrics['true_negatives']} | "
            f"{metrics['false_negatives']} |"
        )
    return "\n".join(rows)


def nested_tables(systems: dict[str, Any], key: str) -> str:
    lines: list[str] = []
    for system, payload in sorted(systems.items()):
        lines.append(f"### {system}")
        lines.append("")
        rows = [
            "| Group | Cases | Precision | Recall | F1 | Accuracy |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        for group, group_payload in sorted(payload[key].items()):
            metrics = group_payload["metrics"]
            rows.append(
                f"| {group} | {group_payload['case_count']} | "
                f"{fmt(metrics['precision'])} | {fmt(metrics['recall'])} | "
                f"{fmt(metrics['f1'])} | {fmt(metrics['accuracy'])} |"
            )
        lines.append("\n".join(rows))
        lines.append("")
    return "\n".join(lines)


def failures(systems: dict[str, Any], key: str) -> str:
    return "\n".join(
        f"- {system}: {', '.join(payload[key]) if payload[key] else 'none'}"
        for system, payload in sorted(systems.items())
    )


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def policy_content_hash(root: Path, manifest: PolicyManifest) -> str:
    digest = hashlib.sha256()
    for case in sorted(manifest.cases, key=lambda item: item.id):
        for relative in [case.path, case.policy, case.config]:
            if relative is None:
                continue
            path = root / relative
            digest.update(relative.encode("utf-8"))
            digest.update(path.read_bytes())
    return digest.hexdigest()


def safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def fmt(value: float) -> str:
    return f"{value:.3f}"


if __name__ == "__main__":
    raise SystemExit(main())
