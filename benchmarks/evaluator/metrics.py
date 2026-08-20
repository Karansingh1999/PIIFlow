from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from statistics import mean, median
from typing import Any, Literal

from pydantic import BaseModel, Field

Outcome = Literal["tp", "fp", "tn", "fn"]


class CaseResult(BaseModel):
    case_id: str
    partition: str
    family: str
    system: str
    expected_vulnerable: bool
    predicted_vulnerable: bool
    expected_categories: list[str]
    predicted_categories: list[str]
    tags: list[str] = Field(default_factory=list)
    minimum_unsanitized_findings: int | None = None
    maximum_unsanitized_findings: int | None = None
    outcome: Outcome
    finding_count: int
    runtime_seconds: float
    error: str | None = None


class BinaryMetrics(BaseModel):
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    accuracy: float = 0.0
    specificity: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0


class RuntimeStats(BaseModel):
    mean_seconds: float = 0.0
    median_seconds: float = 0.0
    p95_seconds: float = 0.0
    total_seconds: float = 0.0


class CategoryMetrics(BaseModel):
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


def classify(expected: bool, predicted: bool) -> Outcome:
    if expected and predicted:
        return "tp"
    if not expected and predicted:
        return "fp"
    if not expected and not predicted:
        return "tn"
    return "fn"


def calculate_binary(results: Iterable[CaseResult]) -> BinaryMetrics:
    counts = Counter(result.outcome for result in results)
    tp = counts["tp"]
    fp = counts["fp"]
    tn = counts["tn"]
    fn = counts["fn"]
    total = tp + fp + tn + fn
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    return BinaryMetrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=_safe_div(2 * precision * recall, precision + recall),
        accuracy=_safe_div(tp + tn, total),
        specificity=specificity,
        false_positive_rate=_safe_div(fp, fp + tn),
        false_negative_rate=_safe_div(fn, fn + tp),
    )


def calculate_category_metrics(results: Iterable[CaseResult]) -> dict[str, CategoryMetrics]:
    expected_by_category: Counter[str] = Counter()
    predicted_by_category: Counter[str] = Counter()
    matched_by_category: Counter[str] = Counter()
    for result in results:
        expected = set(result.expected_categories)
        predicted = set(result.predicted_categories)
        for category in expected:
            expected_by_category[category] += 1
        for category in predicted:
            predicted_by_category[category] += 1
        for category in expected & predicted:
            matched_by_category[category] += 1

    categories = sorted(set(expected_by_category) | set(predicted_by_category))
    metrics: dict[str, CategoryMetrics] = {}
    for category in categories:
        precision = _safe_div(matched_by_category[category], predicted_by_category[category])
        recall = _safe_div(matched_by_category[category], expected_by_category[category])
        metrics[category] = CategoryMetrics(
            precision=precision,
            recall=recall,
            f1=_safe_div(2 * precision * recall, precision + recall),
        )
    return metrics


def runtime_stats(results: Iterable[CaseResult]) -> RuntimeStats:
    values = sorted(result.runtime_seconds for result in results)
    if not values:
        return RuntimeStats()
    p95_index = min(len(values) - 1, int(0.95 * (len(values) - 1)))
    return RuntimeStats(
        mean_seconds=mean(values),
        median_seconds=median(values),
        p95_seconds=values[p95_index],
        total_seconds=sum(values),
    )


def summarize_results(results: list[CaseResult]) -> dict[str, Any]:
    by_system: dict[str, list[CaseResult]] = defaultdict(list)
    for result in results:
        by_system[result.system].append(result)

    return {
        system: _summarize_group(system_results)
        for system, system_results in sorted(by_system.items())
    }


def _summarize_group(results: list[CaseResult]) -> dict[str, Any]:
    partitions = sorted({result.partition for result in results})
    families = sorted({result.family for result in results})
    return {
        "overall": _group_payload(results),
        "by_partition": {
            partition: _group_payload(
                [result for result in results if result.partition == partition]
            )
            for partition in partitions
        },
        "by_family": {
            family: _group_payload([result for result in results if result.family == family])
            for family in families
        },
        "by_sink": {
            sink: _group_payload([result for result in results if sink in result.tags])
            for sink in _sink_tags(results)
        },
        "by_category": {
            category: metrics.model_dump()
            for category, metrics in calculate_category_metrics(results).items()
        },
        "false_positive_ids": sorted(
            result.case_id for result in results if result.outcome == "fp"
        ),
        "false_negative_ids": sorted(
            result.case_id for result in results if result.outcome == "fn"
        ),
        "category_mismatches": category_mismatches(results),
        "unexpected_additional_findings": unexpected_additional_findings(results),
        "expected_finding_bound_violations": expected_finding_bound_violations(results),
        "runtime": runtime_stats(results).model_dump(),
        "error_count": sum(1 for result in results if result.error),
    }


def category_mismatches(results: list[CaseResult]) -> list[dict[str, Any]]:
    mismatches = []
    for result in results:
        expected = set(result.expected_categories)
        predicted = set(result.predicted_categories)
        if result.expected_vulnerable and expected != predicted:
            mismatches.append(
                {
                    "case_id": result.case_id,
                    "system": result.system,
                    "expected": sorted(expected),
                    "predicted": sorted(predicted),
                }
            )
    return mismatches


def unexpected_additional_findings(results: list[CaseResult]) -> list[str]:
    return sorted(
        result.case_id
        for result in results
        if not result.expected_vulnerable and result.finding_count > 0
    )


def expected_finding_bound_violations(results: list[CaseResult]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for result in results:
        if (
            result.minimum_unsanitized_findings is not None
            and result.finding_count < result.minimum_unsanitized_findings
        ):
            violations.append(
                {
                    "case_id": result.case_id,
                    "system": result.system,
                    "expected_minimum": result.minimum_unsanitized_findings,
                    "actual": result.finding_count,
                }
            )
        if (
            result.maximum_unsanitized_findings is not None
            and result.finding_count > result.maximum_unsanitized_findings
        ):
            violations.append(
                {
                    "case_id": result.case_id,
                    "system": result.system,
                    "expected_maximum": result.maximum_unsanitized_findings,
                    "actual": result.finding_count,
                }
            )
    return violations


def _sink_tags(results: list[CaseResult]) -> list[str]:
    known = {"openai", "anthropic", "generic", "no_sink"}
    return sorted({tag for result in results for tag in result.tags if tag in known})


def _group_payload(results: list[CaseResult]) -> dict[str, Any]:
    return {
        "case_count": len(results),
        "metrics": calculate_binary(results).model_dump(),
        "runtime": runtime_stats(results).model_dump(),
        "parse_error_count": sum(1 for result in results if result.error),
    }


def _safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator
