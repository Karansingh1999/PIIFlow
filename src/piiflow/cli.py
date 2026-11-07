from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from piiflow import __version__
from piiflow.config import ConfigError
from piiflow.models import Severity
from piiflow.policy import PolicyError, apply_policy_to_result, load_policy
from piiflow.reporting import finding_fails, render_text, result_to_json
from piiflow.scanner import scan_path

app = typer.Typer(help="Detect sensitive-data flows from Python sources to AI sinks.")
orcarouter_app = typer.Typer(help="OrcaRouter Cyber Inference provider: credentials and models.")
app.add_typer(orcarouter_app, name="orcarouter")


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
    rule_provider: Annotated[
        str | None,
        typer.Option(
            "--rule-provider",
            help=(
                "Named LLM provider rule set, e.g. orcarouter "
                "(OrcaRouter Cyber Inference sink identities)."
            ),
        ),
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
        result = scan_path(
            path,
            config_path=config,
            excludes=tuple(exclude or ()),
            rule_provider=rule_provider,
        )
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


@orcarouter_app.command("login")
def orcarouter_login(
    key_stdin: Annotated[
        bool,
        typer.Option("--key-stdin", help="Read an existing sk-orca- key from standard input."),
    ] = False,
    print_url: Annotated[
        bool,
        typer.Option("--print-url", help="Print the authorization URL only; no exchange."),
    ] = False,
) -> None:
    """Authorize PIIFlow with an OrcaRouter account and obtain a key."""
    from piiflow.integrations.orcarouter import (
        OrcaRouterAuthRejected,
        OrcaRouterCredentialError,
        OrcaRouterExchangeError,
        OrcaRouterKeyAdapter,
        OrcaRouterPkceAdapter,
        UrlLibTransport,
    )

    if key_stdin:
        try:
            credential = OrcaRouterKeyAdapter().credential_from_input(sys.stdin.read())
        except OrcaRouterCredentialError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(2) from exc
        typer.echo(f"PIIFlow authorized with API key {credential.masked} (source=api_key)")
        return
    adapter = OrcaRouterPkceAdapter(UrlLibTransport())
    url, attempt = adapter.begin()
    if print_url:
        typer.echo(url)
        return
    typer.echo("Authorize PIIFlow in your browser, then paste the code shown:")
    typer.echo(url)
    if not sys.stdin.isatty():
        typer.echo("No interactive terminal; re-run inside a terminal.", err=True)
        raise typer.Exit(2)
    code = typer.prompt("Code", hide_input=True)
    try:
        credential = adapter.exchange(attempt, code)
    except (OrcaRouterExchangeError, OrcaRouterAuthRejected) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"PIIFlow authorized with API key {credential.masked} (source=pkce)")


@orcarouter_app.command("models")
def orcarouter_models(
    modality: Annotated[
        str | None,
        typer.Option("--modality", help="Require an input modality, e.g. image or audio."),
    ] = None,
) -> None:
    """List chat-capable models from the live OrcaRouter catalog."""
    from piiflow.integrations import orcarouter

    credential = _orcarouter_credential()
    transport = orcarouter.UrlLibTransport()
    try:
        catalog = orcarouter.fetch_catalog(transport, credential)
    except (orcarouter.OrcaRouterCatalogError, orcarouter.OrcaRouterAuthRejected) as exc:
        catalog = orcarouter.fallback_catalog()
        typer.echo(f"Live catalog unavailable ({exc}); showing {catalog.source} models.", err=True)
    options = catalog.multimodal_chat_models(modality) if modality else catalog.chat_models()
    typer.echo("Model\tContext\tModalities")
    for model in options:
        context = str(model.context_length) if model.context_length else "unknown"
        typer.echo(f"{model.id}\t{context}\t{','.join(model.input_modalities) or 'text'}")


def _orcarouter_credential() -> Any:
    from piiflow.integrations.orcarouter import OrcaRouterCredentialError, OrcaRouterKeyAdapter

    raw = os.environ.get("ORCA_KEY", "")
    if not raw:
        typer.echo("Set ORCA_KEY or run `piiflow orcarouter login`.", err=True)
        raise typer.Exit(2)
    try:
        return OrcaRouterKeyAdapter().credential_from_input(raw)
    except OrcaRouterCredentialError:
        typer.echo("ORCA_KEY is set but is not an sk-orca-… key.", err=True)
        raise typer.Exit(2) from None


if __name__ == "__main__":
    app()
