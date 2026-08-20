from __future__ import annotations

from benchmarks.evaluator.metrics import (
    CaseResult,
    calculate_binary,
    calculate_category_metrics,
    classify,
    expected_finding_bound_violations,
    runtime_stats,
    summarize_results,
)


def result(case_id: str, expected: bool, predicted: bool, runtime: float = 0.01) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        partition="in_scope",
        family="direct",
        system="piiflow",
        expected_vulnerable=expected,
        predicted_vulnerable=predicted,
        expected_categories=["EMAIL"] if expected else [],
        predicted_categories=["EMAIL"] if predicted else [],
        tags=["openai"],
        minimum_unsanitized_findings=1 if expected else None,
        maximum_unsanitized_findings=None if expected else 0,
        outcome=classify(expected, predicted),
        finding_count=1 if predicted else 0,
        runtime_seconds=runtime,
    )


def test_confusion_matrix_and_binary_metrics() -> None:
    results = [
        result("tp", True, True),
        result("fp", False, True),
        result("tn", False, False),
        result("fn", True, False),
    ]

    metrics = calculate_binary(results)

    assert classify(True, True) == "tp"
    assert classify(False, True) == "fp"
    assert classify(False, False) == "tn"
    assert classify(True, False) == "fn"
    assert metrics.true_positives == 1
    assert metrics.false_positives == 1
    assert metrics.true_negatives == 1
    assert metrics.false_negatives == 1
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1 == 0.5


def test_zero_division_handling() -> None:
    metrics = calculate_binary([])

    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.specificity == 0.0


def test_category_scoring_runtime_and_summary() -> None:
    results = [result("a", True, True, 0.01), result("b", True, False, 0.03)]

    category = calculate_category_metrics(results)["EMAIL"]
    runtime = runtime_stats(results)
    summary = summarize_results(results)["piiflow"]

    assert category.precision == 1.0
    assert category.recall == 0.5
    assert runtime.mean_seconds == 0.02
    assert summary["by_sink"]["openai"]["case_count"] == 2
    assert summary["false_negative_ids"] == ["b"]


def test_expected_bound_violations() -> None:
    violations = expected_finding_bound_violations([result("missed", True, False)])

    assert violations[0]["case_id"] == "missed"
