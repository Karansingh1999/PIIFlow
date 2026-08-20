from __future__ import annotations

import json
from pathlib import Path

from benchmarks.verify_release import (
    ORIGINAL_EXPECTED,
    POLICY_EXPECTED,
    main,
    verify_release,
)


def payload_from_expected(expected: dict[str, object]) -> dict[str, object]:
    root: dict[str, object] = {}
    for path, value in expected.items():
        current = root
        parts = path.split(".")
        for part in parts[:-1]:
            child = current.setdefault(part, {})
            assert isinstance(child, dict)
            current = child
        current[parts[-1]] = value
    return root


def test_release_verifier_accepts_expected_payloads() -> None:
    results = verify_release(
        payload_from_expected(ORIGINAL_EXPECTED),
        payload_from_expected(POLICY_EXPECTED),
    )

    assert all(result.passed for result in results)


def test_release_verifier_reports_expected_and_actual_on_failure(tmp_path: Path, capsys) -> None:
    original = payload_from_expected(ORIGINAL_EXPECTED)
    policy = payload_from_expected(POLICY_EXPECTED)
    metadata = original["metadata"]
    assert isinstance(metadata, dict)
    metadata["manifest_hash"] = "unexpected"

    original_path = tmp_path / "original-metrics.json"
    policy_path = tmp_path / "policy-metrics.json"
    original_path.write_text(json.dumps(original), encoding="utf-8")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    exit_code = main(
        [
            "--original-metrics",
            str(original_path),
            "--policy-metrics",
            str(policy_path),
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "FAIL original.metadata.manifest_hash" in output
    assert "expected:" in output
    assert "actual:" in output
    assert "unexpected" in output
