from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_markdown_report(metrics: dict[str, Any], output_directory: Path) -> None:
    report = render_markdown_report(metrics)
    (output_directory / "report.md").write_text(report, encoding="utf-8")


def render_markdown_report(metrics: dict[str, Any]) -> str:
    systems = metrics["systems"]
    lines = [
        "# PIIFlow-Bench Report",
        "",
        "## Purpose",
        "",
        (
            "PIIFlow-Bench measures case-level privacy-flow detection on synthetic "
            "Python LLM application examples."
        ),
        "",
        "## Benchmark Composition",
        "",
        f"- Total cases: {metrics['case_counts']['total']}",
        f"- In-scope cases: {metrics['case_counts']['in_scope']}",
        f"- Challenge cases: {metrics['case_counts']['challenge']}",
        f"- Positive labels: {metrics['label_distribution']['positive']}",
        f"- Negative labels: {metrics['label_distribution']['negative']}",
        "",
        "## Systems Compared",
        "",
        "- Lexical co-occurrence baseline",
        "- Direct-flow AST baseline",
        "- PIIFlow legacy mode with structured state disabled",
        "- Full PIIFlow",
        "",
        "## Overall Comparison",
        "",
        _comparison_table(systems, "overall"),
        "",
        "## In-Scope Comparison",
        "",
        _partition_table(systems, "in_scope"),
        "",
        "## Challenge Comparison",
        "",
        _partition_table(systems, "challenge"),
        "",
        "## Family-Level Results",
        "",
        _family_sections(systems),
        "",
        "## Category-Level Results",
        "",
        _category_sections(systems),
        "",
        "## Sink-Level Results",
        "",
        _sink_sections(systems),
        "",
        "## False Positives",
        "",
        _failure_list(systems, "false_positive_ids"),
        "",
        "## False Negatives",
        "",
        _failure_list(systems, "false_negative_ids"),
        "",
        "## Runtime Statistics",
        "",
        _runtime_table(systems),
        "",
        "## Interpretation",
        "",
        (
            "These numbers compare PIIFlow with two intentionally weak transparent "
            "baselines. They do not establish superiority over state-of-the-art "
            "static-analysis systems."
        ),
        "",
        "## Threats To Validity",
        "",
        "- Benchmark cases are synthetic and smaller than production repositories.",
        "- The analyzer authors also constructed the benchmark.",
        "- Baselines are intentionally simple and are not state-of-the-art analyzers.",
        "- Python dynamic behavior is only partially represented.",
        "- Case-level binary metrics do not fully measure source-to-sink path quality.",
        "- Similarity between development tests and benchmark cases may inflate performance.",
        "- The challenge set is not exhaustive.",
        "- Category labels may not capture every privacy-policy nuance.",
        "- High performance does not imply legal or regulatory compliance.",
        "- Results must not be generalized to other programming languages.",
        (
            "- Benchmark performance does not prove superiority over CodeQL, Pysa, "
            "or commercial systems."
        ),
        "",
        "## Known Limitations",
        "",
        (
            "Challenge cases intentionally include documented unsupported or "
            "partially supported behavior. Failures are retained rather than "
            "relabeled."
        ),
        "",
        "## Reproduction Commands",
        "",
        "```bash",
        "uv run python benchmarks/run.py --partition all --system all",
        "```",
        "",
        "## Metadata",
        "",
        "```json",
        json.dumps(metrics["metadata"], indent=2, sort_keys=True),
        "```",
    ]
    return "\n".join(lines)


def _comparison_table(systems: dict[str, Any], group: str) -> str:
    rows = [
        "| System | Cases | Precision | Recall | F1 | Accuracy |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for system, payload in sorted(systems.items()):
        group_payload = payload[group]
        metrics = group_payload["metrics"]
        rows.append(
            f"| {system} | {group_payload['case_count']} | {_fmt(metrics['precision'])} | "
            f"{_fmt(metrics['recall'])} | {_fmt(metrics['f1'])} | {_fmt(metrics['accuracy'])} |"
        )
    return "\n".join(rows)


def _partition_table(systems: dict[str, Any], partition: str) -> str:
    rows = [
        "| System | Cases | Precision | Recall | F1 | Accuracy |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for system, payload in sorted(systems.items()):
        group_payload = payload["by_partition"].get(partition)
        if group_payload is None:
            rows.append(f"| {system} | 0 | 0.000 | 0.000 | 0.000 | 0.000 |")
            continue
        metrics = group_payload["metrics"]
        rows.append(
            f"| {system} | {group_payload['case_count']} | {_fmt(metrics['precision'])} | "
            f"{_fmt(metrics['recall'])} | {_fmt(metrics['f1'])} | {_fmt(metrics['accuracy'])} |"
        )
    return "\n".join(rows)


def _family_sections(systems: dict[str, Any]) -> str:
    lines: list[str] = []
    for system, payload in sorted(systems.items()):
        lines.append(f"### {system}")
        lines.append("")
        lines.append("| Family | Cases | Precision | Recall | F1 |")
        lines.append("|---|---:|---:|---:|---:|")
        for family, group in sorted(payload["by_family"].items()):
            metrics = group["metrics"]
            lines.append(
                f"| {family} | {group['case_count']} | {_fmt(metrics['precision'])} | "
                f"{_fmt(metrics['recall'])} | {_fmt(metrics['f1'])} |"
            )
        lines.append("")
    return "\n".join(lines)


def _category_sections(systems: dict[str, Any]) -> str:
    lines: list[str] = []
    for system, payload in sorted(systems.items()):
        lines.append(f"### {system}")
        lines.append("")
        lines.append("| Category | Precision | Recall | F1 |")
        lines.append("|---|---:|---:|---:|")
        for category, metrics in sorted(payload["by_category"].items()):
            lines.append(
                f"| {category} | {_fmt(metrics['precision'])} | "
                f"{_fmt(metrics['recall'])} | {_fmt(metrics['f1'])} |"
            )
        lines.append("")
    return "\n".join(lines)


def _sink_sections(systems: dict[str, Any]) -> str:
    lines: list[str] = []
    for system, payload in sorted(systems.items()):
        lines.append(f"### {system}")
        lines.append("")
        lines.append("| Sink tag | Cases | Precision | Recall | F1 |")
        lines.append("|---|---:|---:|---:|---:|")
        for sink, group in sorted(payload["by_sink"].items()):
            metrics = group["metrics"]
            lines.append(
                f"| {sink} | {group['case_count']} | {_fmt(metrics['precision'])} | "
                f"{_fmt(metrics['recall'])} | {_fmt(metrics['f1'])} |"
            )
        lines.append("")
    return "\n".join(lines)


def _failure_list(systems: dict[str, Any], key: str) -> str:
    lines: list[str] = []
    for system, payload in sorted(systems.items()):
        values = payload[key]
        joined = ", ".join(values) if values else "none"
        lines.append(f"- {system}: {joined}")
    return "\n".join(lines)


def _runtime_table(systems: dict[str, Any]) -> str:
    rows = [
        "| System | Mean seconds | Median seconds | P95 seconds | Total seconds |",
        "|---|---:|---:|---:|---:|",
    ]
    for system, payload in sorted(systems.items()):
        runtime = payload["runtime"]
        rows.append(
            f"| {system} | {_fmt(runtime['mean_seconds'])} | "
            f"{_fmt(runtime['median_seconds'])} | {_fmt(runtime['p95_seconds'])} | "
            f"{_fmt(runtime['total_seconds'])} |"
        )
    return "\n".join(rows)


def _fmt(value: float) -> str:
    return f"{value:.3f}"


def write_phase2b1_comparison_report(
    *,
    baseline_metrics_path: Path,
    baseline_case_results_path: Path,
    phase_metrics_path: Path,
    phase_case_results_path: Path,
    output_path: Path,
) -> None:
    baseline_metrics = json.loads(baseline_metrics_path.read_text(encoding="utf-8"))
    phase_metrics = json.loads(phase_metrics_path.read_text(encoding="utf-8"))
    baseline_cases = _load_case_results(baseline_case_results_path)
    phase_cases = _load_case_results(phase_case_results_path)

    lines = [
        "# Phase 2B1 Structured State Comparison",
        "",
        "## Frozen Benchmark Integrity",
        "",
        f"- Manifest hash: `{phase_metrics['metadata']['manifest_hash']}`",
        f"- Benchmark content hash: `{phase_metrics['metadata']['benchmark_content_hash']}`",
        (
            "- Benchmark content changed during run: "
            f"{phase_metrics['metadata']['benchmark_content_changed_during_run']}"
        ),
        "",
        "## Overall Metrics",
        "",
        "| System | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    rows = [
        ("baseline_piiflow_v0.1.0", baseline_metrics["systems"]["piiflow"]["overall"]),
        ("piiflow_legacy", phase_metrics["systems"]["piiflow_legacy"]["overall"]),
        ("piiflow", phase_metrics["systems"]["piiflow"]["overall"]),
    ]
    for name, payload in rows:
        metrics = payload["metrics"]
        lines.append(
            f"| {name} | {_fmt(metrics['precision'])} | {_fmt(metrics['recall'])} | "
            f"{_fmt(metrics['f1'])} | {_fmt(metrics['accuracy'])} | "
            f"{metrics['true_positives']} | {metrics['false_positives']} | "
            f"{metrics['true_negatives']} | {metrics['false_negatives']} |"
        )

    lines.extend(
        [
            "",
            "## Overall Metric Changes",
            "",
            "| Comparison | Precision | Recall | F1 | Accuracy | Runtime |",
            "|---|---:|---:|---:|---:|---:|",
            _delta_row(
                "structured minus v0.1.0",
                baseline_metrics["systems"]["piiflow"]["overall"],
                phase_metrics["systems"]["piiflow"]["overall"],
            ),
            _delta_row(
                "structured minus legacy",
                phase_metrics["systems"]["piiflow_legacy"]["overall"],
                phase_metrics["systems"]["piiflow"]["overall"],
            ),
            "",
            "## Relative Metric Changes",
            "",
            "| Comparison | Precision | Recall | F1 | Accuracy | Runtime |",
            "|---|---:|---:|---:|---:|---:|",
            _relative_delta_row(
                "structured vs v0.1.0",
                baseline_metrics["systems"]["piiflow"]["overall"],
                phase_metrics["systems"]["piiflow"]["overall"],
            ),
            _relative_delta_row(
                "structured vs legacy",
                phase_metrics["systems"]["piiflow_legacy"]["overall"],
                phase_metrics["systems"]["piiflow"]["overall"],
            ),
            "",
            "## Challenge Metrics",
            "",
            "| System | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    challenge_rows = [
        (
            "baseline_piiflow_v0.1.0",
            baseline_metrics["systems"]["piiflow"]["by_partition"]["challenge"],
        ),
        ("piiflow_legacy", phase_metrics["systems"]["piiflow_legacy"]["by_partition"]["challenge"]),
        ("piiflow", phase_metrics["systems"]["piiflow"]["by_partition"]["challenge"]),
    ]
    for name, payload in challenge_rows:
        metrics = payload["metrics"]
        lines.append(
            f"| {name} | {_fmt(metrics['precision'])} | {_fmt(metrics['recall'])} | "
            f"{_fmt(metrics['f1'])} | {_fmt(metrics['accuracy'])} | "
            f"{metrics['true_positives']} | {metrics['false_positives']} | "
            f"{metrics['true_negatives']} | {metrics['false_negatives']} |"
        )

    baseline_piiflow = _system_cases(baseline_cases, "piiflow")
    phase_piiflow = _system_cases(phase_cases, "piiflow")
    fixed = [
        case_id
        for case_id, baseline in sorted(baseline_piiflow.items())
        if baseline["outcome"] in {"fp", "fn"} and phase_piiflow[case_id]["outcome"] in {"tp", "tn"}
    ]
    regressions = [
        case_id
        for case_id, baseline in sorted(baseline_piiflow.items())
        if baseline["outcome"] in {"tp", "tn"} and phase_piiflow[case_id]["outcome"] in {"fp", "fn"}
    ]
    changed = [
        case_id
        for case_id, baseline in sorted(baseline_piiflow.items())
        if baseline["predicted_vulnerable"] != phase_piiflow[case_id]["predicted_vulnerable"]
    ]
    baseline_fp = set(baseline_metrics["systems"]["piiflow"]["false_positive_ids"])
    baseline_fn = set(baseline_metrics["systems"]["piiflow"]["false_negative_ids"])
    structured_fp = set(phase_metrics["systems"]["piiflow"]["false_positive_ids"])
    structured_fn = set(phase_metrics["systems"]["piiflow"]["false_negative_ids"])
    false_positives_removed = sorted(baseline_fp - structured_fp)
    false_negatives_removed = sorted(baseline_fn - structured_fn)
    false_positives_introduced = sorted(structured_fp - baseline_fp)
    false_negatives_introduced = sorted(structured_fn - baseline_fn)

    lines.extend(
        [
            "",
            "## Case-Level Changes",
            "",
            f"- Fixed baseline failures: {_joined(fixed)}",
            f"- New regressions: {_joined(regressions)}",
            f"- Changed PIIFlow predictions: {_joined(changed)}",
            f"- False positives removed: {_joined(false_positives_removed)}",
            f"- False negatives removed: {_joined(false_negatives_removed)}",
            f"- False positives introduced: {_joined(false_positives_introduced)}",
            f"- False negatives introduced: {_joined(false_negatives_introduced)}",
            "",
            "## Runtime Overhead",
            "",
            _runtime_comparison(
                baseline_metrics["systems"]["piiflow"]["overall"],
                phase_metrics["systems"]["piiflow_legacy"]["overall"],
                phase_metrics["systems"]["piiflow"]["overall"],
            ),
            "",
            "## Memory And State Growth",
            "",
            (
                "Peak memory is not separately instrumented in this benchmark runner. "
                "Structured state growth is bounded by max access-path depth, max known fields "
                "per object, and wildcard collapse when known-field limits are exceeded."
            ),
            "",
            "## Interpretation",
            "",
            (
                "Structured field and alias modeling improves challenge performance by fixing "
                "general dictionary-field, request-alias, attribute-storage, and collection-alias "
                "behaviors while preserving in-scope performance."
            ),
            "",
            "## Threats To Validity",
            "",
            "- Benchmark cases are synthetic and smaller than production repositories.",
            (
                "- The same project owns the analyzer and benchmark, so confirmation bias "
                "remains possible."
            ),
            "- Runtime measurements are single-process wall-clock timings on this machine.",
            "- Memory growth is controlled by bounds but not independently profiled here.",
            "- The analysis remains intentionally incomplete for later challenge families.",
            "",
            "## Notes",
            "",
            (
                "The comparison uses the saved v0.1.0 baseline outputs and the current "
                "Phase 2B1 run. Benchmark labels and case files are not rewritten by this report."
            ),
            "",
        ]
    )
    output_path.write_text("\n".join(lines), encoding="utf-8")


def _delta_row(label: str, before: dict[str, Any], after: dict[str, Any]) -> str:
    before_metrics = before["metrics"]
    after_metrics = after["metrics"]
    before_runtime = before["runtime"]["total_seconds"]
    after_runtime = after["runtime"]["total_seconds"]
    return (
        f"| {label} | {_signed(after_metrics['precision'] - before_metrics['precision'])} | "
        f"{_signed(after_metrics['recall'] - before_metrics['recall'])} | "
        f"{_signed(after_metrics['f1'] - before_metrics['f1'])} | "
        f"{_signed(after_metrics['accuracy'] - before_metrics['accuracy'])} | "
        f"{_signed(after_runtime - before_runtime)}s |"
    )


def _relative_delta_row(label: str, before: dict[str, Any], after: dict[str, Any]) -> str:
    before_metrics = before["metrics"]
    after_metrics = after["metrics"]
    before_runtime = before["runtime"]["total_seconds"]
    after_runtime = after["runtime"]["total_seconds"]
    return (
        f"| {label} | {_relative(before_metrics['precision'], after_metrics['precision'])} | "
        f"{_relative(before_metrics['recall'], after_metrics['recall'])} | "
        f"{_relative(before_metrics['f1'], after_metrics['f1'])} | "
        f"{_relative(before_metrics['accuracy'], after_metrics['accuracy'])} | "
        f"{_relative(before_runtime, after_runtime)} |"
    )


def _runtime_comparison(
    baseline: dict[str, Any],
    legacy: dict[str, Any],
    structured: dict[str, Any],
) -> str:
    baseline_total = baseline["runtime"]["total_seconds"]
    legacy_total = legacy["runtime"]["total_seconds"]
    structured_total = structured["runtime"]["total_seconds"]
    return "\n".join(
        [
            f"- Structured total runtime: {_fmt(structured_total)} seconds",
            f"- v0.1.0 baseline total runtime: {_fmt(baseline_total)} seconds",
            f"- Legacy-mode total runtime: {_fmt(legacy_total)} seconds",
            (
                f"- Structured vs v0.1.0 overhead: "
                f"{_signed(structured_total - baseline_total)} seconds"
            ),
            f"- Structured vs legacy overhead: {_signed(structured_total - legacy_total)} seconds",
        ]
    )


def _signed(value: float) -> str:
    return f"{value:+.3f}"


def _relative(before: float, after: float) -> str:
    if before == 0:
        return "n/a"
    return f"{((after - before) / before) * 100:+.1f}%"


def _load_case_results(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _system_cases(rows: list[dict[str, Any]], system: str) -> dict[str, dict[str, Any]]:
    return {row["case_id"]: row for row in rows if row["system"] == system}


def _joined(values: list[str]) -> str:
    return ", ".join(values) if values else "none"
