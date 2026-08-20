from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FLOAT_TOLERANCE = 1e-12

ORIGINAL_EXPECTED = {
    "metadata.manifest_hash": "2335f30a119652db32aca3163e4b1a4d91a1e2bb8331cec51d247cd444ee51c7",
    "metadata.benchmark_content_hash": (
        "a34c9817f0da31aaf4bd8a9590796614c62cbf33137b6486c3192d794f361f94"
    ),
    "systems.piiflow.overall.metrics.precision": 0.9545454545454546,
    "systems.piiflow.overall.metrics.recall": 0.84,
    "systems.piiflow.overall.metrics.f1": 0.8936170212765958,
    "systems.piiflow.overall.metrics.accuracy": 0.8888888888888888,
    "systems.piiflow.overall.metrics.true_positives": 42,
    "systems.piiflow.overall.metrics.false_positives": 2,
    "systems.piiflow.overall.metrics.true_negatives": 38,
    "systems.piiflow.overall.metrics.false_negatives": 8,
}

POLICY_EXPECTED = {
    "metadata.manifest_hash": "694cf6af4faa5cf7e002a57d650ee3e6ad7aa1204b9d0db0f2c96edcc20a3511",
    "metadata.policy_content_hash": (
        "be63a102eff6f4c89100221f153f713dda74475662c5783c257d46efd2eddc66"
    ),
    "systems.piiflow_policy.overall.metrics.precision": 1.0,
    "systems.piiflow_policy.overall.metrics.recall": 1.0,
    "systems.piiflow_policy.overall.metrics.f1": 1.0,
    "systems.piiflow_policy.overall.metrics.accuracy": 1.0,
    "systems.piiflow_policy.overall.metrics.true_positives": 20,
    "systems.piiflow_policy.overall.metrics.false_positives": 0,
    "systems.piiflow_policy.overall.metrics.true_negatives": 16,
    "systems.piiflow_policy.overall.metrics.false_negatives": 0,
}


@dataclass(frozen=True)
class CheckResult:
    name: str
    expected: object
    actual: object
    passed: bool


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify PIIFlow v0.3.0 release benchmark hashes and metrics."
    )
    parser.add_argument(
        "--original-metrics",
        type=Path,
        default=Path("benchmarks/results/metrics.json"),
    )
    parser.add_argument(
        "--policy-metrics",
        type=Path,
        default=Path("benchmarks/results/phase2b2_policy/metrics.json"),
    )
    args = parser.parse_args(argv)

    original = _load_json(args.original_metrics)
    policy = _load_json(args.policy_metrics)
    results = verify_release(original, policy)
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"{status} {result.name}")
        if not result.passed:
            print(f"  expected: {result.expected!r}")
            print(f"  actual:   {result.actual!r}")
    if all(result.passed for result in results):
        return 0
    print(f"Float tolerance: abs_tol={FLOAT_TOLERANCE}, rel_tol=0.0")
    return 1


def verify_release(
    original_metrics: dict[str, Any],
    policy_metrics: dict[str, Any],
) -> list[CheckResult]:
    results: list[CheckResult] = []
    results.extend(_verify_payload("original", original_metrics, ORIGINAL_EXPECTED))
    results.extend(_verify_payload("policy", policy_metrics, POLICY_EXPECTED))
    return results


def _verify_payload(
    prefix: str,
    payload: dict[str, Any],
    expected: dict[str, object],
) -> list[CheckResult]:
    return [
        _check(f"{prefix}.{path}", expected_value, _lookup(payload, path))
        for path, expected_value in expected.items()
    ]


def _check(name: str, expected: object, actual: object) -> CheckResult:
    if isinstance(expected, float):
        passed = isinstance(actual, int | float) and math.isclose(
            float(actual),
            expected,
            rel_tol=0.0,
            abs_tol=FLOAT_TOLERANCE,
        )
    else:
        passed = actual == expected
    return CheckResult(name=name, expected=expected, actual=actual, passed=passed)


def _lookup(payload: dict[str, Any], dotted_path: str) -> object:
    current: object = payload
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return "<missing>"
        current = current[part]
    return current


def _load_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return loaded


if __name__ == "__main__":
    raise SystemExit(main())
