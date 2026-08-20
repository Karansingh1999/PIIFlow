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


def _default_data() -> dict[str, Any]:
    default = resources.files("piiflow").joinpath("rules/default.yaml")
    with default.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if not isinstance(loaded, dict):
        raise ConfigError("Packaged default configuration is invalid")
    return loaded


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
    data = _default_data()
    if path is not None:
        data = _merge_config(data, _load_yaml(path))
    try:
        return RuleConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
