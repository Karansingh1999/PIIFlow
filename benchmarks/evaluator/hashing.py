from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Literal

CanonicalNewline = Literal["lf", "crlf"]


def canonical_text_bytes(data: bytes, newline: CanonicalNewline) -> bytes:
    normalized = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if newline == "lf":
        return normalized
    return normalized.replace(b"\n", b"\r\n")


def canonical_file_bytes(path: Path, newline: CanonicalNewline) -> bytes:
    return canonical_text_bytes(path.read_bytes(), newline)


def canonical_file_hash(path: Path, newline: CanonicalNewline) -> str:
    return hashlib.sha256(canonical_file_bytes(path, newline)).hexdigest()


def update_with_canonical_file(
    digest: Any,
    path: Path,
    newline: CanonicalNewline,
) -> None:
    digest.update(canonical_file_bytes(path, newline))
