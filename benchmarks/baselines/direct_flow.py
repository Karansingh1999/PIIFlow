from __future__ import annotations

import ast
from pathlib import Path

from benchmarks.baselines.base import BaselineFinding, BaselineResult, BaselineSystem
from piiflow.ast_utils import constant_str, qualified_name, source_expr_base
from piiflow.config import load_config
from piiflow.models import SinkRule
from piiflow.sinks import matching_sink
from piiflow.sources import is_request_collection, sensitive_category


class DirectFlowBaseline(BaselineSystem):
    name = "direct"

    def analyze(self, path: Path) -> BaselineResult:
        files = sorted(path.rglob("*.py")) if path.is_dir() else [path]
        all_findings: list[BaselineFinding] = []
        errors: list[str] = []
        for file in files:
            result = self._analyze_file(file)
            all_findings.extend(result.findings)
            if result.error:
                errors.append(result.error)
        categories = sorted({finding.category for finding in all_findings})
        return BaselineResult(
            predicted_vulnerable=bool(all_findings),
            predicted_categories=categories,
            finding_count=len(all_findings),
            findings=all_findings,
            error="; ".join(errors) or None,
        )

    def _analyze_file(self, path: Path) -> BaselineResult:
        config = load_config()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            return BaselineResult(predicted_vulnerable=False, error=str(exc))

        findings: list[BaselineFinding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = qualified_name(node.func)
            if call_name is None:
                continue
            rule = matching_sink(call_name, config.sink_patterns)
            if rule is None:
                continue
            findings.extend(self._sink_argument_findings(node, rule))

        return BaselineResult(
            predicted_vulnerable=bool(findings),
            predicted_categories=sorted({finding.category for finding in findings}),
            finding_count=len(findings),
            findings=findings,
        )

    def _sink_argument_findings(self, node: ast.Call, rule: SinkRule) -> list[BaselineFinding]:
        findings: list[BaselineFinding] = []
        for argument in rule.arguments:
            expressions: list[ast.AST] = []
            if isinstance(argument, int) and argument < len(node.args):
                expressions.append(node.args[argument])
            elif isinstance(argument, str):
                expressions.extend(
                    keyword.value for keyword in node.keywords if keyword.arg == argument
                )
            for expression in expressions:
                category = self._direct_source_category(expression)
                if category is not None:
                    findings.append(
                        BaselineFinding(
                            category=category,
                            detail=f"direct source in {rule.id}",
                        )
                    )
        return findings

    def _direct_source_category(self, node: ast.AST) -> str | None:
        config = load_config()
        if isinstance(node, ast.Subscript):
            base = source_expr_base(node.value)
            key = constant_str(node.slice)
            if base and key and is_request_collection(base, config):
                return sensitive_category(key, config)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr != "get" or not node.args:
                return None
            base = source_expr_base(node.func.value)
            key = constant_str(node.args[0])
            if base and key and is_request_collection(base, config):
                return sensitive_category(key, config)
        return None
