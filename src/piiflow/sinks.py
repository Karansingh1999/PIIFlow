from __future__ import annotations

from piiflow.ast_utils import call_matches
from piiflow.models import SinkRule


def matching_sink(call_name: str, rules: list[SinkRule]) -> SinkRule | None:
    for rule in rules:
        if call_matches(rule.call, call_name):
            return rule
    return None
