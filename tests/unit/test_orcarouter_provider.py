"""OrcaRouter rule provider: named sink identities, provider rules, CLI, and catalog filters."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from piiflow.cli import app
from piiflow.config import ConfigError, load_config, load_provider_config
from piiflow.integrations import orcarouter
from piiflow.integrations.orcarouter import (
    OrcaRouterCatalog,
    OrcaRouterModel,
    parse_catalog,
    resolve_model_selection,
)
from piiflow.scanner import scan_path

REPO_ROOT = Path(__file__).resolve().parents[2]
FAKE_KEY = "sk-orca-TESTONLY0000000000000000abcd"


def test_orcarouter_provider_rule_set_is_packaged_and_named() -> None:
    config = load_provider_config("orcarouter")
    rules = {rule.id: rule for rule in config.sink_patterns}
    assert rules["openai-chat"].provider == "orcarouter"
    assert rules["openai-responses"].provider == "orcarouter"
    assert rules["anthropic-messages"].provider == "orcarouter"
    assert rules["openai-chat"].trust_zone == "external"
    assert rules["generic-invoke"].provider == "generic"
    assert "sensitive_names" in config.model_dump()


def test_default_rule_set_is_unchanged() -> None:
    config = load_config()
    assert {rule.provider for rule in config.sink_patterns} == {"openai", "anthropic", "generic"}


def test_unknown_provider_rule_set_errors() -> None:
    with pytest.raises(ConfigError, match="orcarouter"):
        load_provider_config("not-a-provider")


def test_overlay_still_extends_provider_rules(tmp_path: Path) -> None:
    overlay = tmp_path / "rules.yml"
    overlay.write_text(
        "sink_patterns:\n  - id: internal-agent\n    call: '*.run_agent'\n"
        "    arguments: ['prompt']\n    destination: configurable_llm\n"
        "    provider: orcarouter\n    trust_zone: internal\n",
        encoding="utf-8",
    )
    config = load_provider_config("orcarouter", overlay)
    ids = [rule.id for rule in config.sink_patterns]
    assert ids[0] == "openai-responses"
    assert "internal-agent" in ids


def test_scan_attributes_openai_helper_calls_to_orcarouter(tmp_path: Path) -> None:
    app_file = tmp_path / "agent.py"
    app_file.write_text(
        "def run(request, client):\n"
        '    email = request.json["email"]\n'
        "    client.chat.completions.create(\n"
        '        model="orcarouter/auto", messages=[{"content": email}]\n'
        "    )\n",
        encoding="utf-8",
    )
    default = scan_path(app_file)
    provider = scan_path(app_file, rule_provider="orcarouter")
    assert [finding.provider for finding in default.findings] == ["openai"]
    assert [finding.provider for finding in provider.findings] == ["orcarouter"]


def test_cli_rule_provider_flag_routes_policy_identities(tmp_path: Path) -> None:
    app_file = tmp_path / "agent.py"
    app_file.write_text(
        "def run(request, client):\n"
        '    email = request.json["email"]\n'
        "    client.responses.create(input=email)\n",
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yml"
    policy.write_text(
        "version: 1\ndefault_action: deny\nrules:\n  - id: allow-orcarouter\n"
        "    categories: [EMAIL]\n    providers: [orcarouter]\n"
        "    trust_zones: [external]\n    action: allow\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    legacy = runner.invoke(app, ["scan", str(app_file), "--policy", str(policy)])
    named = runner.invoke(
        app,
        ["scan", str(app_file), "--policy", str(policy), "--rule-provider", "orcarouter"],
    )
    assert legacy.exit_code == 1
    assert named.exit_code == 0
    assert "rule=allow-orcarouter" in named.stdout


def test_cli_models_prints_live_catalog(monkeypatch) -> None:
    payload = {
        "data": [
            {"id": "orcarouter/auto", "supported_endpoint_types": ["openai"]},
            {
                "id": "openai/gpt-5.5",
                "context_length": 400000,
                "supported_endpoint_types": ["openai-response"],
                "architecture": {"input_modalities": ["text", "image"]},
            },
        ]
    }
    monkeypatch.setenv("ORCA_KEY", FAKE_KEY)
    monkeypatch.setattr(orcarouter, "fetch_catalog", lambda transport, credential: _live(payload))
    result = CliRunner().invoke(app, ["orcarouter", "models"])
    assert result.exit_code == 0
    assert "orcarouter/auto" in result.stdout


def test_cli_models_falls_back_to_seed(monkeypatch) -> None:
    monkeypatch.setenv("ORCA_KEY", FAKE_KEY)

    def broken(transport, credential):  # type: ignore[no-untyped-def]
        raise orcarouter.OrcaRouterCatalogError("offline")

    monkeypatch.setattr(orcarouter, "fetch_catalog", broken)
    result = CliRunner().invoke(app, ["orcarouter", "models", "--modality", "image"])
    assert result.exit_code == 0
    assert "verified_seed" in result.stderr
    assert "openai/gpt-5.5" in result.stdout
    assert "deepseek/deepseek-v4-pro" not in result.stdout


def test_cli_models_requires_key(monkeypatch) -> None:
    monkeypatch.delenv("ORCA_KEY", raising=False)
    result = CliRunner().invoke(app, ["orcarouter", "models"])
    assert result.exit_code == 2
    assert "ORCA_KEY" in result.stderr


def test_cli_login_print_url_never_contains_verifier(monkeypatch) -> None:
    result = CliRunner().invoke(app, ["orcarouter", "login", "--print-url"])
    assert result.exit_code == 0
    url = result.stdout.strip()
    assert url.startswith("https://www.orcarouter.ai/auth?")
    assert "callback_url=oob" in url
    assert "code_challenge_method=S256" in url
    assert "code_verifier" not in url


def test_cli_login_key_stdin(monkeypatch) -> None:
    result = CliRunner().invoke(app, ["orcarouter", "login", "--key-stdin"], input=f"{FAKE_KEY}\n")
    assert result.exit_code == 0
    assert FAKE_KEY not in result.stdout
    assert "source=api_key" in result.stdout


def _live(payload: dict[str, object]) -> OrcaRouterCatalog:
    return OrcaRouterCatalog(models=parse_catalog(payload), source="live", fetched_at=0.0)


def test_catalog_filters_chat_models_and_excludes_non_text_routes() -> None:
    payload = {
        "data": [
            {"id": "orcarouter/auto", "supported_endpoint_types": ["openai"]},
            {"id": "openai/gpt-5.5", "supported_endpoint_types": ["openai-response"]},
            {"id": "google/imagen", "supported_endpoint_types": ["image-generation"]},
            {"id": "openai/sora", "supported_endpoint_types": ["openai-video"]},
            {"id": "jina/rerank", "supported_endpoint_types": ["jina-rerank"]},
            {"id": "vendor/embed", "supported_endpoint_types": ["embeddings"]},
            {"id": "vendor/unknown"},
            {"not-a-model": True},
        ]
    }
    catalog = _live(payload)
    assert [model.id for model in catalog.chat_models()] == ["orcarouter/auto", "openai/gpt-5.5"]


def test_multimodal_filter_is_fail_closed() -> None:
    payload = {
        "data": [
            {"id": "text/only", "supported_endpoint_types": ["openai"]},
            {
                "id": "vision/model",
                "supported_endpoint_types": ["openai"],
                "architecture": {"input_modalities": ["text", "image"]},
            },
            {
                "id": "audio/model",
                "supported_endpoint_types": ["gemini"],
                "architecture": {"input_modalities": ["text", "audio"]},
            },
            {"id": "image/gen", "supported_endpoint_types": ["openai", "image-generation"]},
        ]
    }
    catalog = _live(payload)
    assert [model.id for model in catalog.multimodal_chat_models("image")] == ["vision/model"]
    assert [model.id for model in catalog.multimodal_chat_models("audio")] == ["audio/model"]


def test_stale_selection_is_cleared_when_incompatible() -> None:
    catalog = _live(
        {
            "data": [
                {"id": "text/only", "supported_endpoint_types": ["openai"]},
                {
                    "id": "vision/model",
                    "supported_endpoint_types": ["openai"],
                    "architecture": {"input_modalities": ["text", "image"]},
                },
            ]
        }
    )
    assert resolve_model_selection(catalog, "vision/model", modality="image") == "vision/model"
    assert resolve_model_selection(catalog, "vision/model") == "vision/model"
    assert resolve_model_selection(catalog, "text/only", modality="image") is None
    assert resolve_model_selection(catalog, "gone/model") is None


def test_catalog_parse_bounds_item_count() -> None:
    payload = {"data": [{"id": f"m/{index}"} for index in range(orcarouter.MAX_CATALOG_ITEMS + 5)]}
    assert len(parse_catalog(payload)) == orcarouter.MAX_CATALOG_ITEMS
    with pytest.raises(orcarouter.OrcaRouterCatalogError):
        parse_catalog({"data": []})


def test_seed_models_keep_verified_metadata() -> None:
    seed = orcarouter.fallback_catalog()
    assert seed.find("orcarouter/auto") is not None
    assert seed.find("openai/gpt-5.5") == OrcaRouterModel(
        id="openai/gpt-5.5",
        name="GPT-5.5",
        context_length=400000,
        input_modalities=("text", "image"),
        endpoint_types=("openai-response", "openai", "anthropic"),
        reasoning_effort=("low", "medium", "high", "xhigh"),
    )
    assert load_provider_config("orcarouter").sink_patterns
