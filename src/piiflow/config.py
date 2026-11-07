from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from piiflow.models import RuleConfig

EXTENDABLE_LIST_KEYS = {"source_patterns", "sink_patterns", "sanitizer_patterns"}


class ConfigError(ValueError):
    pass


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        msg = f"Could not read configuration {path}: {exc}"
        raise ConfigError(msg) from exc
    except yaml.YAMLError as exc:
        msg = f"Invalid YAML in {path}: {exc}"
        raise ConfigError(msg) from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigError(f"Configuration {path} must be a mapping")
    return loaded


# OrcaRouter Cyber Inference provider: Open- and Anthropic-wire sink identities are
# attributed to the named provider so policies can target `providers: [orcarouter]`.
ORCAROUTER_PROVIDER = "orcarouter"
PROVIDER_RULE_SETS: dict[str, tuple[str, ...]] = {
    ORCAROUTER_PROVIDER: ("rules/default.yaml",),
}


def _resource_yaml(relative: str) -> dict[str, Any]:
    resource = resources.files("piiflow").joinpath(relative)
    loaded = yaml.safe_load(resource.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        msg = f"Packaged rule configuration {relative} is invalid"
        raise ConfigError(msg)
    return loaded


def _default_data() -> dict[str, Any]:
    return _resource_yaml("rules/default.yaml")


def _provider_data(provider: str) -> dict[str, Any]:
    data = _default_data()
    if provider == ORCAROUTER_PROVIDER:
        data["sink_patterns"] = [
            {**rule, "provider": ORCAROUTER_PROVIDER}
            if rule.get("provider") in {"openai", "anthropic"}
            else rule
            for rule in data["sink_patterns"]
        ]
    return data


def _merge_config(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if key == "sensitive_names" and isinstance(value, dict):
            names = {category: list(values) for category, values in merged.get(key, {}).items()}
            for category, values in value.items():
                names.setdefault(category, [])
                names[category].extend(values or [])
            merged[key] = names
        elif key in EXTENDABLE_LIST_KEYS and isinstance(value, list):
            merged[key] = [*merged.get(key, []), *value]
        else:
            merged[key] = value
    return merged


def load_config(path: Path | None = None) -> RuleConfig:
    return _load_data(path)


def load_provider_config(provider: str, path: Path | None = None) -> RuleConfig:
    """Load the packaged rule set of a named provider instead of the built-in defaults.

    User overlays merge exactly as with :func:`load_config`, so custom rules keep
    extending the provider rules and policy identities stay plain provider strings.
    """
    if provider not in PROVIDER_RULE_SETS:
        known = ", ".join(sorted(PROVIDER_RULE_SETS))
        msg = f"Unknown rule provider {provider!r}. Available providers: {known}"
        raise ConfigError(msg)
    return _load_data(path, base=_provider_data(provider))


def _load_data(path: Path | None, base: dict[str, Any] | None = None) -> RuleConfig:
    data = _default_data() if base is None else dict(base)
    if path is not None:
        data = _merge_config(data, _load_yaml(path))
    try:
        return RuleConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
