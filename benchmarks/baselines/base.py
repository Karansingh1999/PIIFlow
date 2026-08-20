from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class BaselineFinding(BaseModel):
    category: str
    detail: str


class BaselineResult(BaseModel):
    predicted_vulnerable: bool
    predicted_categories: list[str] = Field(default_factory=list)
    finding_count: int = 0
    findings: list[BaselineFinding] = Field(default_factory=list)
    error: str | None = None


class BaselineSystem:
    name: str

    def analyze(self, path: Path) -> BaselineResult:
        raise NotImplementedError
