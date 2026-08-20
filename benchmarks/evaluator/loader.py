from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

Partition = Literal["in_scope", "challenge"]


class ManifestError(ValueError):
    pass


class ExpectedLabel(BaseModel):
    vulnerable: bool
    categories: list[str] = Field(default_factory=list)
    minimum_unsanitized_findings: int | None = None
    maximum_unsanitized_findings: int | None = None

    @model_validator(mode="after")
    def validate_bounds(self) -> ExpectedLabel:
        if self.vulnerable:
            if not self.categories:
                raise ValueError("vulnerable cases must list expected categories")
            if self.minimum_unsanitized_findings is None:
                raise ValueError("vulnerable cases require minimum_unsanitized_findings")
            if self.minimum_unsanitized_findings < 1:
                raise ValueError("vulnerable minimum must be at least 1")
        else:
            if self.categories:
                raise ValueError("safe cases must not list expected categories")
            if self.maximum_unsanitized_findings != 0:
                raise ValueError("safe cases require maximum_unsanitized_findings: 0")
        return self


class BenchmarkCase(BaseModel):
    id: str
    path: str
    partition: Partition
    family: str
    description: str
    expected: ExpectedLabel
    tags: list[str] = Field(default_factory=list)


class Manifest(BaseModel):
    version: int
    cases: list[BenchmarkCase]


def load_manifest(path: Path) -> Manifest:
    root = path.parent.resolve()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ManifestError(f"Could not load manifest {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError("Manifest must be a mapping")
    if raw.get("version") != 1:
        raise ManifestError("Unsupported manifest version")
    try:
        manifest = Manifest.model_validate(raw)
    except ValidationError as exc:
        raise ManifestError(str(exc)) from exc
    _validate_manifest(manifest, root)
    return Manifest(
        version=manifest.version,
        cases=sorted(manifest.cases, key=lambda case: case.id),
    )


def manifest_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def benchmark_content_hash(manifest: Manifest, root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(str(manifest.version).encode("utf-8"))
    for case in sorted(manifest.cases, key=lambda item: item.id):
        digest.update(case.model_dump_json().encode("utf-8"))
        for file in _case_source_files(case_file_path(root, case)):
            digest.update(file.relative_to(root).as_posix().encode("utf-8"))
            digest.update(file.read_bytes())
    return digest.hexdigest()


def case_file_path(root: Path, case: BenchmarkCase) -> Path:
    return (root / case.path).resolve()


def _validate_manifest(manifest: Manifest, root: Path) -> None:
    seen: set[str] = set()
    for case in manifest.cases:
        if case.id in seen:
            raise ManifestError(f"Duplicate case id: {case.id}")
        seen.add(case.id)
        candidate = case_file_path(root, case)
        if not _is_relative_to(candidate, root):
            raise ManifestError(f"Case path escapes benchmark directory: {case.path}")
        if not candidate.exists():
            raise ManifestError(f"Missing case file for {case.id}: {case.path}")


def _case_source_files(path: Path) -> list[Path]:
    if path.is_dir():
        return sorted(path.rglob("*.py"))
    return [path]


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
