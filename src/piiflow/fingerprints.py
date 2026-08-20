from __future__ import annotations

import hashlib

from piiflow.models import SinkRef, SourceRef


def stable_fingerprint(
    *,
    rule_id: str,
    category: str,
    source: SourceRef,
    sink: SinkRef,
    sanitized: bool,
) -> str:
    raw = "|".join(
        [
            rule_id,
            category,
            source.file,
            str(source.line),
            source.expression,
            sink.file,
            str(sink.line),
            sink.call,
            sink.argument,
            str(sanitized),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
