from __future__ import annotations

import json
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Literal

from benchmarks.baselines.base import BaselineResult, BaselineSystem
from benchmarks.baselines.direct_flow import DirectFlowBaseline
from benchmarks.baselines.lexical import LexicalBaseline
from benchmarks.evaluator.loader import (
    BenchmarkCase,
    Manifest,
    benchmark_content_hash,
    case_file_path,
    manifest_hash,
)
from benchmarks.evaluator.metrics import CaseResult, classify, summarize_results
from piiflow import __version__ as piiflow_version
from piiflow.models import AnalysisOptions
from piiflow.scanner import scan_path

SystemName = Literal["lexical", "direct", "piiflow_legacy", "piiflow"]

SYSTEM_ORDER: tuple[SystemName, ...] = ("lexical", "direct", "piiflow_legacy", "piiflow")


class PIIFlowSystem(BaselineSystem):
    def __init__(self, *, name: str = "piiflow", structured_state: bool = True) -> None:
        self.name = name
        self.structured_state = structured_state

    def analyze(self, path: Path) -> BaselineResult:
        result = scan_path(path, options=AnalysisOptions(structured_state=self.structured_state))
        unsanitized = [finding for finding in result.findings if not finding.sanitized]
        categories = sorted({finding.category for finding in unsanitized})
        error = "; ".join(error.message for error in result.parse_errors) or None
        return BaselineResult(
            predicted_vulnerable=bool(unsanitized),
            predicted_categories=categories,
            finding_count=len(unsanitized),
            error=error,
        )


def build_systems(system: str) -> list[BaselineSystem]:
    systems: dict[str, BaselineSystem] = {
        "lexical": LexicalBaseline(),
        "direct": DirectFlowBaseline(),
        "piiflow_legacy": PIIFlowSystem(name="piiflow_legacy", structured_state=False),
        "piiflow": PIIFlowSystem(),
    }
    if system == "all":
        return [systems[name] for name in SYSTEM_ORDER]
    if system not in systems:
        raise ValueError(f"Unknown system: {system}")
    return [systems[system]]


def select_cases(
    manifest: Manifest,
    partition: str,
    limit: int | None = None,
) -> list[BenchmarkCase]:
    if partition not in {"all", "in_scope", "challenge"}:
        raise ValueError(f"Unknown partition: {partition}")
    cases = [case for case in manifest.cases if partition == "all" or case.partition == partition]
    cases = sorted(cases, key=lambda case: case.id)
    if limit is not None:
        return cases[:limit]
    return cases


def evaluate(
    *,
    manifest_path: Path,
    manifest: Manifest,
    partition: str,
    system: str,
    output_directory: Path,
    limit: int | None = None,
) -> dict[str, object]:
    root = manifest_path.parent.resolve()
    _ensure_safe_output_directory(root, output_directory)
    cases = select_cases(manifest, partition, limit)
    systems = build_systems(system)
    before_hash = benchmark_content_hash(manifest, root)

    results: list[CaseResult] = []
    for selected_system in systems:
        for case in cases:
            results.append(_run_case(root, case, selected_system))

    after_hash = benchmark_content_hash(manifest, root)
    metadata = {
        "python_version": sys.version,
        "platform": platform.platform(),
        "piiflow_version": piiflow_version,
        "git_commit": _git_commit(root),
        "manifest_version": manifest.version,
        "manifest_hash": manifest_hash(manifest_path),
        "benchmark_content_hash": before_hash,
        "benchmark_content_changed_during_run": before_hash != after_hash,
        "systems": [system.name for system in systems],
        "partition": partition,
    }
    metrics = {
        "metadata": metadata,
        "case_counts": _case_counts(cases),
        "label_distribution": _label_distribution(cases),
        "systems": summarize_results(results),
    }
    write_results(output_directory, metrics, results)
    return metrics


def write_results(
    output_directory: Path,
    metrics: dict[str, object],
    results: list[CaseResult],
) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / "metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    with (output_directory / "case_results.jsonl").open("w", encoding="utf-8") as handle:
        for result in sorted(results, key=lambda item: (item.system, item.case_id)):
            handle.write(result.model_dump_json() + "\n")


def _run_case(root: Path, case: BenchmarkCase, system: BaselineSystem) -> CaseResult:
    started = time.perf_counter()
    predicted = BaselineResult(predicted_vulnerable=False)
    error: str | None = None
    try:
        predicted = system.analyze(case_file_path(root, case))
        error = predicted.error
    except Exception as exc:
        error = f"{exc.__class__.__name__}: {exc}"
    runtime = time.perf_counter() - started
    outcome = classify(case.expected.vulnerable, predicted.predicted_vulnerable)
    return CaseResult(
        case_id=case.id,
        partition=case.partition,
        family=case.family,
        system=system.name,
        expected_vulnerable=case.expected.vulnerable,
        predicted_vulnerable=predicted.predicted_vulnerable,
        expected_categories=sorted(case.expected.categories),
        predicted_categories=sorted(predicted.predicted_categories),
        tags=sorted(case.tags),
        minimum_unsanitized_findings=case.expected.minimum_unsanitized_findings,
        maximum_unsanitized_findings=case.expected.maximum_unsanitized_findings,
        outcome=outcome,
        finding_count=predicted.finding_count,
        runtime_seconds=runtime,
        error=error,
    )


def _ensure_safe_output_directory(root: Path, output_directory: Path) -> None:
    destination = output_directory.resolve()
    cases_root = (root / "cases").resolve()
    if destination == root.resolve() or destination == cases_root:
        raise ValueError("Output directory cannot overwrite benchmark source files")
    if destination == (root / "manifest.yaml").resolve():
        raise ValueError("Output directory cannot overwrite manifest.yaml")
    try:
        destination.relative_to(cases_root)
    except ValueError:
        return
    raise ValueError("Output directory cannot be inside benchmark case files")


def _case_counts(cases: list[BenchmarkCase]) -> dict[str, int]:
    return {
        "total": len(cases),
        "in_scope": sum(1 for case in cases if case.partition == "in_scope"),
        "challenge": sum(1 for case in cases if case.partition == "challenge"),
    }


def _label_distribution(cases: list[BenchmarkCase]) -> dict[str, int]:
    return {
        "positive": sum(1 for case in cases if case.expected.vulnerable),
        "negative": sum(1 for case in cases if not case.expected.vulnerable),
    }


def _git_commit(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root.parent,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    if completed.returncode != 0:
        return "unavailable"
    return completed.stdout.strip() or "unavailable"
