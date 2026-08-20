from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Location(BaseModel):
    file: str
    line: int
    column: int = 0


class SourceRef(BaseModel):
    file: str
    line: int
    expression: str


class SinkRef(BaseModel):
    file: str
    line: int
    call: str
    argument: str


class ParseError(BaseModel):
    file: str
    line: int
    message: str


class SanitizerEvidence(BaseModel):
    name: str
    location: Location


PolicyAction = Literal["allow", "deny", "require_sanitizer"]
PolicyStatus = Literal["compliant", "violation"]
PolicyReasonCode = Literal[
    "POLICY_ALLOW",
    "POLICY_DENY",
    "REQUIRED_SANITIZER_PRESENT",
    "REQUIRED_SANITIZER_MISSING",
    "DEFAULT_ALLOW",
    "DEFAULT_DENY",
]


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    description: str = ""
    categories: list[str]
    providers: list[str]
    trust_zones: list[str]
    action: PolicyAction
    sanitizers: list[str] = Field(default_factory=list)


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    default_action: Literal["allow", "deny"] = "deny"
    rules: list[PolicyRule] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    status: PolicyStatus
    action: PolicyAction
    matched_rule_id: str | None = None
    reason_code: PolicyReasonCode
    reason: str
    category: str
    provider: str
    trust_zone: str
    required_sanitizers: list[str] = Field(default_factory=list)
    observed_sanitizers: list[str] = Field(default_factory=list)
    fingerprint: str | None = None


class Finding(BaseModel):
    rule_id: str = "PIIFLOW001"
    severity: Severity
    category: str
    source: SourceRef
    sink: SinkRef
    path: list[str]
    sanitized: bool
    sanitizers: list[SanitizerEvidence] = Field(default_factory=list)
    message: str
    remediation: str
    fingerprint: str
    policy_evaluated: bool = False
    policy_status: PolicyStatus | None = None
    policy_action: PolicyAction | None = None
    policy_rule_id: str | None = None
    policy_reason_code: PolicyReasonCode | None = None
    policy_reason: str | None = None
    provider: str = "generic"
    trust_zone: str = "external"
    required_sanitizers: list[str] = Field(default_factory=list)
    observed_sanitizers: list[str] = Field(default_factory=list)
    policy_fingerprint: str | None = None


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResult(BaseModel):
    tool: str = "piiflow"
    version: str
    scanned_files: int
    parse_errors: list[ParseError]
    findings: list[Finding]
    summary: ScanSummary
    policy_evaluated: bool = False


class SinkRule(BaseModel):
    id: str
    call: str
    arguments: list[str | int]
    destination: str
    provider: str = "generic"
    trust_zone: str = "external"


class RuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    sensitive_names: dict[str, list[str]] = Field(default_factory=dict)
    source_patterns: list[str] = Field(default_factory=list)
    sink_patterns: list[SinkRule] = Field(default_factory=list)
    sanitizer_patterns: list[str] = Field(default_factory=list)


class AnalysisOptions(BaseModel):
    structured_state: bool = True
    max_access_path_depth: int = 4
    max_known_fields_per_object: int = 64
    max_aliases_per_object: int = 32


class FunctionInfo(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    module: str
    identity: str
    qualified_name: str
    class_name: str | None = None
    method_kind: Literal["function", "instance", "staticmethod", "classmethod"] = "function"
    file: Path
    node: Any
    params: list[str]
