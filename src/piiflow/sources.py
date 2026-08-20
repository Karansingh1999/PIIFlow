from __future__ import annotations

import re

from piiflow.models import RuleConfig

_CAMEL_RE = re.compile(r"(?<!^)(?=[A-Z])")
_SEP_RE = re.compile(r"[^a-z0-9]+")


def normalize_name(value: str) -> str:
    value = _CAMEL_RE.sub("_", value).lower()
    value = _SEP_RE.sub("_", value).strip("_")
    return "_".join(part for part in value.split("_") if part)


def sensitive_category(candidate: str, config: RuleConfig) -> str | None:
    normalized = normalize_name(candidate)
    for category, names in sorted(config.sensitive_names.items()):
        if normalized in {normalize_name(name) for name in names}:
            return category
    return None


def is_request_collection(base: str, config: RuleConfig) -> bool:
    configured = {pattern.removesuffix("[*]") for pattern in config.source_patterns}
    return base in configured
