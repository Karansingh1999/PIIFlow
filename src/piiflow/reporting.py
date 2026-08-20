from __future__ import annotations

import io
import json

from rich import box
from rich.console import Console
from rich.table import Table

from piiflow.models import Finding, ScanResult, Severity

SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def result_to_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)


def render_text(result: ScanResult) -> str:
    console = Console(file=io.StringIO(), record=True, width=120)
    console.print(f"PIIFlow {result.version}: scanned {result.scanned_files} file(s)")
    if result.parse_errors:
        console.print("[yellow]Parse errors[/yellow]")
        for error in result.parse_errors:
            console.print(f"  {error.file}:{error.line} {error.message}")
    if not result.findings:
        console.print("[green]No sensitive-data flows detected.[/green]")
        return console.export_text(styles=False)

    table = Table(title="Findings", box=box.ASCII)
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Source")
    table.add_column("Sink")
    table.add_column("Path")
    for finding in result.findings:
        table.add_row(
            finding.severity.value.upper(),
            finding.category,
            f"{finding.source.file}:{finding.source.line} {finding.source.expression}",
            (
                f"{finding.sink.file}:{finding.sink.line} "
                f"{finding.sink.call}({finding.sink.argument}=)"
            ),
            " -> ".join(finding.path),
        )
    console.print(table)
    for finding in result.findings:
        console.print(f"{finding.rule_id} {finding.severity.value.upper()} {finding.message}")
        if finding.policy_evaluated:
            console.print(
                "Policy: "
                f"{finding.policy_status} action={finding.policy_action} "
                f"rule={finding.policy_rule_id or '<default>'} "
                f"reason={finding.policy_reason_code}"
            )
            console.print(f"Provider: {finding.provider}; trust zone: {finding.trust_zone}")
            if finding.required_sanitizers:
                console.print(f"Required sanitizers: {', '.join(finding.required_sanitizers)}")
            console.print(f"Observed sanitizers: {_joined(finding.observed_sanitizers)}")
            if finding.policy_reason:
                console.print(f"Policy reason: {finding.policy_reason}")
        console.print(f"Remediation: {finding.remediation}")
        console.print(f"Fingerprint: {finding.fingerprint}")
    return console.export_text(styles=False)


def finding_fails(finding: Finding, threshold: Severity | None) -> bool:
    if threshold is None:
        return False
    if finding.policy_evaluated:
        return finding.policy_status == "violation"
    if finding.sanitized:
        return False
    return SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[threshold]


def _joined(values: list[str]) -> str:
    return ", ".join(values) if values else "none"
