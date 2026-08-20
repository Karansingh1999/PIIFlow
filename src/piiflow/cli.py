from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from piiflow import __version__
from piiflow.config import ConfigError
from piiflow.models import Severity
from piiflow.policy import PolicyError, apply_policy_to_result, load_policy
from piiflow.reporting import finding_fails, render_text, result_to_json
from piiflow.scanner import scan_path

app = typer.Typer(help="Detect sensitive-data flows from Python sources to AI sinks.")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit(0)


def _threshold(value: str) -> Severity | None:
    normalized = value.lower()
    if normalized == "none":
        return None
    try:
        return Severity(normalized)
    except ValueError as exc:
        raise typer.BadParameter("Use one of: none, low, medium, high, critical") from exc


@app.callback()
def main() -> None:
    """PIIFlow command group."""


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Custom YAML rule configuration."),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
    output: Annotated[Path | None, typer.Option("--output", help="Optional output file.")] = None,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="YAML privacy policy for allowed/denied LLM flows."),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", help="Failure threshold: none, low, medium, high, critical."),
    ] = "high",
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Path exclusion glob. Can be repeated."),
    ] = None,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Print version."),
    ] = False,
) -> None:
    del version
    if output_format not in {"text", "json"}:
        typer.echo("Invalid --format. Use text or json.", err=True)
        raise typer.Exit(2)
    try:
        threshold = _threshold(fail_on)
        policy_config = load_policy(policy) if policy is not None else None
        result = scan_path(path, config_path=config, excludes=tuple(exclude or ()))
        if policy_config is not None:
            result = apply_policy_to_result(result, policy_config)
    except (ConfigError, PolicyError, typer.BadParameter) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc

    rendered = result_to_json(result) if output_format == "json" else render_text(result)
    if output is not None:
        try:
            output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            typer.echo(f"Could not write output file {output}: {exc}", err=True)
            raise typer.Exit(2) from exc
    else:
        typer.echo(rendered)

    if result.parse_errors:
        raise typer.Exit(3)
    if any(finding_fails(finding, threshold) for finding in result.findings):
        raise typer.Exit(1)
    raise typer.Exit(0)


if __name__ == "__main__":
    app()
