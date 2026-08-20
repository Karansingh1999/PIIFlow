from __future__ import annotations

import re
from pathlib import Path

from benchmarks.baselines.base import BaselineFinding, BaselineResult, BaselineSystem
from piiflow.config import load_config
from piiflow.sources import normalize_name

SINK_TOKENS = (
    "responses.create",
    "chat.completions.create",
    "messages.create",
    ".invoke",
)


class LexicalBaseline(BaselineSystem):
    name = "lexical"

    def analyze(self, path: Path) -> BaselineResult:
        config = load_config()
        try:
            source = _read_case_source(path)
        except (OSError, UnicodeDecodeError) as exc:
            return BaselineResult(predicted_vulnerable=False, error=str(exc))

        tokens = {normalize_name(token) for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", source)}
        categories = sorted(
            category
            for category, names in config.sensitive_names.items()
            if any(normalize_name(name) in tokens for name in names)
        )
        has_sink = any(token in source for token in SINK_TOKENS)
        predicted = bool(categories and has_sink)
        findings = [
            BaselineFinding(category=category, detail="sensitive token co-occurs with sink token")
            for category in categories
        ]
        return BaselineResult(
            predicted_vulnerable=predicted,
            predicted_categories=categories if predicted else [],
            finding_count=len(findings) if predicted else 0,
            findings=findings if predicted else [],
        )


def _read_case_source(path: Path) -> str:
    if path.is_dir():
        return "\n".join(
            candidate.read_text(encoding="utf-8") for candidate in sorted(path.rglob("*.py"))
        )
    return path.read_text(encoding="utf-8")
