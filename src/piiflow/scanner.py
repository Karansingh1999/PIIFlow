from __future__ import annotations

import ast
import fnmatch
from collections import Counter
from pathlib import Path

from piiflow import __version__
from piiflow.config import load_config
from piiflow.indexing import collect_functions, collect_import_aliases
from piiflow.models import AnalysisOptions, FunctionInfo, ParseError, ScanResult, ScanSummary
from piiflow.propagation import PropagationAnalyzer

DEFAULT_EXCLUDES = (".git", ".venv", "venv", "node_modules", "dist", "build")


def discover_python_files(path: Path, excludes: tuple[str, ...] = ()) -> tuple[Path, list[Path]]:
    root = path if path.is_dir() else path.parent
    if path.is_file():
        if path.suffix != ".py":
            return root, []
        return root, [path]
    files: list[Path] = []
    for candidate in sorted(path.rglob("*.py")):
        relative = candidate.relative_to(path).as_posix()
        parts = set(candidate.relative_to(path).parts)
        if parts.intersection(DEFAULT_EXCLUDES):
            continue
        if any(fnmatch.fnmatch(relative, pattern) for pattern in excludes):
            continue
        files.append(candidate)
    return root, files


def scan_path(
    path: Path,
    *,
    config_path: Path | None = None,
    excludes: tuple[str, ...] = (),
    options: AnalysisOptions | None = None,
) -> ScanResult:
    config = load_config(config_path)
    root, files = discover_python_files(path, excludes)
    trees: dict[Path, ast.AST] = {}
    parse_errors: list[ParseError] = []
    functions: list[FunctionInfo] = []
    imports_by_file: dict[Path, dict[str, str]] = {}

    for file in files:
        try:
            source = file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file))
        except SyntaxError as exc:
            parse_errors.append(
                ParseError(
                    file=_relative(root, file),
                    line=exc.lineno or 1,
                    message=exc.msg,
                )
            )
            continue
        except UnicodeDecodeError as exc:
            parse_errors.append(
                ParseError(
                    file=_relative(root, file),
                    line=1,
                    message=f"could not decode as UTF-8: {exc.reason}",
                )
            )
            continue
        except OSError as exc:
            parse_errors.append(ParseError(file=_relative(root, file), line=1, message=str(exc)))
            continue
        trees[file] = tree
        module = _module_name(root, file)
        imports_by_file[file] = collect_import_aliases(tree)
        functions.extend(collect_functions(file, module, tree))

    analyzer = PropagationAnalyzer(
        config=config,
        root=root,
        functions=functions,
        imports_by_file=imports_by_file,
        options=options,
    )
    for file in sorted(trees):
        analyzer.analyze_module(file, trees[file])

    findings_by_fingerprint = {finding.fingerprint: finding for finding in analyzer.findings}
    findings = sorted(
        findings_by_fingerprint.values(),
        key=lambda item: (
            item.source.file,
            item.source.line,
            item.sink.file,
            item.sink.line,
            item.category,
            item.fingerprint,
        ),
    )
    counts = Counter(finding.severity.value for finding in findings)
    summary = ScanSummary(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
    )
    return ScanResult(
        version=__version__,
        scanned_files=len(files),
        parse_errors=sorted(parse_errors, key=lambda item: (item.file, item.line, item.message)),
        findings=findings,
        summary=summary,
    )


def _relative(root: Path, file: Path) -> str:
    try:
        return file.relative_to(root).as_posix()
    except ValueError:
        return file.name


def _module_name(root: Path, file: Path) -> str:
    try:
        relative = file.relative_to(root).with_suffix("")
    except ValueError:
        relative = file.with_suffix("")
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or file.stem
