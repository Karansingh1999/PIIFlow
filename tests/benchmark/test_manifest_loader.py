from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from benchmarks.evaluator.loader import (
    ManifestError,
    benchmark_content_hash,
    load_manifest,
    manifest_hash,
)


def write_manifest(tmp_path: Path, cases: list[dict[str, object]], version: int = 1) -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump({"version": version, "cases": cases}), encoding="utf-8")
    return path


def valid_case(case_id: str = "case_001", path: str = "cases/app.py") -> dict[str, object]:
    return {
        "id": case_id,
        "path": path,
        "partition": "in_scope",
        "family": "direct",
        "description": "A direct email leak.",
        "expected": {
            "vulnerable": True,
            "categories": ["EMAIL"],
            "minimum_unsanitized_findings": 1,
        },
        "tags": ["openai", "email"],
    }


def test_valid_manifest_loading_and_hashes(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    (cases_dir / "app.py").write_text(
        'def handle(request, client):\n    client.responses.create(input=request.json["email"])\n',
        encoding="utf-8",
    )
    manifest_path = write_manifest(tmp_path, [valid_case()])

    manifest = load_manifest(manifest_path)

    assert [case.id for case in manifest.cases] == ["case_001"]
    assert manifest_hash(manifest_path) == manifest_hash(manifest_path)
    assert benchmark_content_hash(manifest, tmp_path) == benchmark_content_hash(manifest, tmp_path)


def test_original_benchmark_hashes_are_stable_across_lf_and_crlf(tmp_path: Path) -> None:
    case = valid_case()
    manifest_text = yaml.safe_dump({"version": 1, "cases": [case]}, sort_keys=False)
    source_text = (
        "def handle(request, client):\n"
        '    email = request.json["email"]\n'
        "    client.responses.create(input=email)\n"
    )

    roots = []
    for newline in ["lf", "crlf"]:
        root = tmp_path / newline
        cases_dir = root / "cases"
        cases_dir.mkdir(parents=True)
        line_ending = "\n" if newline == "lf" else "\r\n"
        (root / "manifest.yaml").write_bytes(manifest_text.replace("\n", line_ending).encode())
        (cases_dir / "app.py").write_bytes(source_text.replace("\n", line_ending).encode())
        roots.append(root)

    lf_manifest = load_manifest(roots[0] / "manifest.yaml")
    crlf_manifest = load_manifest(roots[1] / "manifest.yaml")

    assert manifest_hash(roots[0] / "manifest.yaml") == manifest_hash(roots[1] / "manifest.yaml")
    assert benchmark_content_hash(lf_manifest, roots[0]) == benchmark_content_hash(
        crlf_manifest, roots[1]
    )


def test_duplicate_case_ids_rejected(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    (cases_dir / "app.py").write_text("x = 1\n", encoding="utf-8")
    manifest_path = write_manifest(tmp_path, [valid_case(), valid_case()])

    with pytest.raises(ManifestError, match="Duplicate case id"):
        load_manifest(manifest_path)


def test_missing_case_path_rejected(tmp_path: Path) -> None:
    manifest_path = write_manifest(tmp_path, [valid_case()])

    with pytest.raises(ManifestError, match="Missing case file"):
        load_manifest(manifest_path)


def test_path_traversal_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside_case.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    manifest_path = write_manifest(tmp_path, [valid_case(path="../outside_case.py")])

    with pytest.raises(ManifestError, match="escapes"):
        load_manifest(manifest_path)


def test_invalid_partition_rejected(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    (cases_dir / "app.py").write_text("x = 1\n", encoding="utf-8")
    case = valid_case()
    case["partition"] = "future"
    manifest_path = write_manifest(tmp_path, [case])

    with pytest.raises(ManifestError):
        load_manifest(manifest_path)


def test_invalid_expected_bounds_rejected(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    (cases_dir / "app.py").write_text("x = 1\n", encoding="utf-8")
    case = valid_case()
    case["expected"] = {
        "vulnerable": False,
        "categories": ["EMAIL"],
        "maximum_unsanitized_findings": 1,
    }
    manifest_path = write_manifest(tmp_path, [case])

    with pytest.raises(ManifestError):
        load_manifest(manifest_path)


def test_unknown_manifest_version_rejected(tmp_path: Path) -> None:
    manifest_path = write_manifest(tmp_path, [], version=99)

    with pytest.raises(ManifestError, match="Unsupported manifest version"):
        load_manifest(manifest_path)
