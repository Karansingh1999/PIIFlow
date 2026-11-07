"""OrcaRouter Cyber Inference provider: credential seam, PKCE login, catalog, and inference.

PIIFlow itself never calls a model while scanning. This module is the provider
definition users select (``--rule-provider orcarouter``), the credential seam used
to obtain an OrcaRouter API key (a pasted key or an OAuth 2.0 + PKCE login), the
model catalog used for model selection, and the authenticated request helper.

Orchestration (consent URLs, exchange, key storage) is kept separate from the
transport (:class:`OrcaRouterTransport`) so every network call goes through the
explicit auth/inference origin policy below.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

ORCAROUTER_PROVIDER_ID = "orcarouter"
ORCAROUTER_DISPLAY_NAME = "OrcaRouter Cyber Inference"
DEFAULT_AUTH_BASE_URL = "https://www.orcarouter.ai"
DEFAULT_API_BASE_URL = "https://api.orcarouter.ai/v1"
AUTHORIZE_PATH = "/auth"
EXCHANGE_PATH = "/api/v1/auth/keys"
CHAT_CAPABILITY = "chat"
DEFAULT_MODEL = "orcarouter/auto"
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_CATALOG_ITEMS = 2000
MAX_FALLBACK_CATALOG_DAYS = 7
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
KEY_PREFIX = "sk-orca-"
_KEY_PREFIX = KEY_PREFIX


class OrcaRouterError(Exception):
    """Base class for provider errors whose messages never contain secrets."""


class OrcaRouterCredentialError(OrcaRouterError):
    """Credential acquisition or validation failed."""


class OrcaRouterAuthRejected(OrcaRouterCredentialError):
    """The user denied authorization or an exchange failed terminally."""


class OrcaRouterExchangeError(OrcaRouterCredentialError):
    """The token exchange returned an error status."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"OrcaRouter key exchange failed (HTTP {status}): {message}")
        self.status = status


class OrcaRouterMissingCredential(OrcaRouterCredentialError):
    """No OrcaRouter credential is configured."""


class OrcaRouterCatalogError(OrcaRouterError):
    """The live model catalog could not be fetched or parsed."""


def resolve_auth_base_url(environ: Mapping[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    return _validated_origin(
        env.get("ORCA_AUTH_BASE_URL") or env.get("ORCA_BASE_URL") or DEFAULT_AUTH_BASE_URL,
        "auth",
    )


def resolve_api_base_url(environ: Mapping[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    base = env.get("ORCA_API_BASE_URL") or env.get("ORCA_BASE_URL")
    if not base:
        return DEFAULT_API_BASE_URL
    return _validated_origin(base, "api")


def _validated_origin(value: str, purpose: str) -> str:
    base = value.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.query:
        msg = f"OrcaRouter {purpose} base URL must be an absolute http(s) origin"
        raise OrcaRouterError(msg)
    if parsed.scheme == "http" and parsed.hostname not in _LOOPBACK_HOSTS:
        msg = f"OrcaRouter {purpose} base URL must use HTTPS unless it is loopback"
        raise OrcaRouterError(msg)
    return base


@dataclass(frozen=True)
class OrcaRouterCredential:
    """The single credential shape both authentication adapters produce."""

    key: str
    scope: str
    source: str
    account_id: str | None = None
    generation: int = 0

    def __repr__(self) -> str:
        return (
            f"OrcaRouterCredential(key='<redacted>', scope={self.scope!r}, "
            f"source={self.source!r}, account_id={self.account_id!r}, "
            f"generation={self.generation})"
        )

    @property
    def masked(self) -> str:
        return f"{_KEY_PREFIX}…{self.key[-4:]}" if len(self.key) > len(_KEY_PREFIX) + 4 else "***"


def make_credential(
    key: str,
    scope: str,
    source: str,
    *,
    account_id: str | None = None,
    generation: int = 0,
) -> OrcaRouterCredential:
    cleaned = key.strip()
    if not cleaned.startswith(_KEY_PREFIX) or len(cleaned) <= len(_KEY_PREFIX):
        msg = f"An OrcaRouter API key must start with {_KEY_PREFIX!r}"
        raise OrcaRouterCredentialError(msg)
    return OrcaRouterCredential(
        key=cleaned,
        scope=scope,
        source=source,
        account_id=account_id,
        generation=generation,
    )


class OrcaRouterTransport(Protocol):
    """Minimal HTTP seam so tests use a fake auth server instead of the network."""

    def get_json(self, url: str, headers: Mapping[str, str]) -> tuple[int, Any]: ...

    def post_json(
        self, url: str, body: Mapping[str, Any], headers: Mapping[str, str]
    ) -> tuple[int, Any]: ...


class UrlLibTransport:
    """urllib transport with bounded read size, timeouts, and no automatic retries."""

    def __init__(self, *, timeout: float = 20.0) -> None:
        self.timeout = timeout

    def get_json(self, url: str, headers: Mapping[str, str]) -> tuple[int, Any]:
        request = urllib.request.Request(url, headers=dict(headers), method="GET")  # noqa: S310
        return self._send(request)

    def post_json(
        self, url: str, body: Mapping[str, Any], headers: Mapping[str, str]
    ) -> tuple[int, Any]:
        payload = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", **headers},
            method="POST",
        )
        return self._send(request)

    def _send(self, request: urllib.request.Request) -> tuple[int, Any]:
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                raw = response.read(MAX_CATALOG_BYTES)
                status = response.status
        except urllib.error.HTTPError as exc:
            raw = exc.read(MAX_CATALOG_BYTES)
            status = exc.code
        except OSError as exc:
            raise OrcaRouterCatalogError(f"Network error talking to OrcaRouter: {exc}") from exc
        try:
            return status, json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise OrcaRouterCatalogError("OrcaRouter returned a non-JSON response") from exc


@dataclass(frozen=True)
class PkceAttempt:
    verifier: str
    challenge: str
    state: str


def new_pkce_attempt(rng: Callable[[int], bytes] = secrets.token_bytes) -> PkceAttempt:
    verifier = _b64url(rng(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    state = _b64url(rng(16))
    return PkceAttempt(verifier=verifier, challenge=challenge, state=state)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class OrcaRouterKeyAdapter:
    """Credentials supplied by the user as an existing ``sk-orca-…`` key."""

    source = "api_key"

    def credential_from_input(self, raw_key: str, scope: str = "api") -> OrcaRouterCredential:
        return make_credential(raw_key, scope, source=self.source)


class OrcaRouterPkceAdapter:
    """OAuth 2.0 + PKCE (S256) login that exchanges an auth code for an API key.

    Flow B (out-of-band code) is implemented: PIIFlow runs in terminals, CI boxes,
    containers and SSH sessions, where a loopback listener is often unreachable and
    the install address is not predictable.
    """

    source = "pkce"
    scopes: frozenset[str] = frozenset({"api"})
    redirect_uri = "oob"
    app_name = "PIIFlow"

    def __init__(
        self,
        transport: OrcaRouterTransport,
        *,
        auth_base_url: str | None = None,
        rng: Callable[[int], bytes] = secrets.token_bytes,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.transport = transport
        self.auth_base_url = auth_base_url or resolve_auth_base_url()
        self.rng = rng
        self.clock = clock

    def begin(self, scope: str = "api") -> tuple[str, PkceAttempt]:
        attempt = new_pkce_attempt(self.rng)
        params = {
            "callback_url": self.redirect_uri,
            "code_challenge": attempt.challenge,
            "code_challenge_method": "S256",
            "state": attempt.state,
            "app_name": self.app_name,
            "scope": scope,
        }
        url = f"{self.auth_base_url}{AUTHORIZE_PATH}?{urllib.parse.urlencode(params)}"
        return url, attempt

    def exchange(
        self,
        attempt: PkceAttempt,
        code: str,
        *,
        expected_scope: str = "api",
        generation: int = 0,
    ) -> OrcaRouterCredential:
        cleaned = code.strip()
        if not cleaned:
            raise OrcaRouterAuthRejected("No authorization code was provided")
        status, payload = self.transport.post_json(
            f"{self.auth_base_url}{EXCHANGE_PATH}",
            {
                "code": cleaned,
                "code_verifier": attempt.verifier,
                "code_challenge_method": "S256",
            },
            {},
        )
        if status != 200:
            description = payload.get("error_description") or payload.get("error") or "rejected"
            raise OrcaRouterExchangeError(status, str(description))
        if not isinstance(payload, dict) or not isinstance(payload.get("key"), str):
            raise OrcaRouterExchangeError(status, "response did not contain a key")
        granted = payload.get("scope")
        if not isinstance(granted, str) or not _scope_allows(granted, expected_scope):
            raise OrcaRouterAuthRejected(
                f"Granted scope {granted!r} does not allow {expected_scope!r} requests"
            )
        account = payload.get("user_id")
        return make_credential(
            payload["key"],
            granted,
            source=self.source,
            account_id=str(account) if account is not None else None,
            generation=generation,
        )


def _scope_allows(granted: str, expected: str) -> bool:
    granted_scopes = {item.strip() for item in granted.replace(",", " ").split()}
    return expected in granted_scopes


@dataclass(frozen=True)
class OrcaRouterModel:
    id: str
    name: str
    context_length: int | None
    input_modalities: tuple[str, ...]
    endpoint_types: tuple[str, ...]
    reasoning_effort: tuple[str, ...] = ()

    def supports_chat(self) -> bool:
        if not self.endpoint_types:
            return False
        supported = {
            "openai",
            "openai-response",
            "anthropic",
            "gemini",
        }
        return bool(supported.intersection(self.endpoint_types)) and not {
            "image-generation",
            "openai-video",
            "jina-rerank",
        } & set(self.endpoint_types)


# Verified cold-start seed, used only when live discovery is unavailable. Metadata is
# intentionally limited to what was verified for each id.
VERIFIED_SEED: tuple[OrcaRouterModel, ...] = (
    OrcaRouterModel(
        id="orcarouter/auto",
        name="OrcaRouter Auto",
        context_length=200000,
        input_modalities=("text",),
        endpoint_types=("openai",),
    ),
    OrcaRouterModel(
        id="openai/gpt-5.5",
        name="GPT-5.5",
        context_length=400000,
        input_modalities=("text", "image"),
        endpoint_types=("openai-response", "openai", "anthropic"),
        reasoning_effort=("low", "medium", "high", "xhigh"),
    ),
    OrcaRouterModel(
        id="anthropic/claude-opus-4.8",
        name="Claude Opus 4.8",
        context_length=200000,
        input_modalities=("text", "image"),
        endpoint_types=("anthropic",),
    ),
    OrcaRouterModel(
        id="google/gemini-3.5-flash",
        name="Gemini 3.5 Flash",
        context_length=1048576,
        input_modalities=("text", "image", "audio", "video"),
        endpoint_types=("gemini",),
    ),
    OrcaRouterModel(
        id="deepseek/deepseek-v4-pro",
        name="DeepSeek V4 Pro",
        context_length=128000,
        input_modalities=("text",),
        endpoint_types=("openai",),
    ),
)


@dataclass(frozen=True)
class OrcaRouterCatalog:
    models: tuple[OrcaRouterModel, ...]
    source: str
    fetched_at: float | None = None

    @property
    def degraded(self) -> bool:
        return self.source != "live"

    def chat_models(self) -> tuple[OrcaRouterModel, ...]:
        return tuple(model for model in self.models if model.supports_chat())

    def multimodal_chat_models(self, modality: str) -> tuple[OrcaRouterModel, ...]:
        return tuple(
            model
            for model in self.chat_models()
            if modality.lower() in {item.lower() for item in model.input_modalities}
        )

    def find(self, model_id: str) -> OrcaRouterModel | None:
        return next((model for model in self.models if model.id == model_id), None)


def resolve_model_selection(
    catalog: OrcaRouterCatalog, previous: str | None, *, modality: str | None = None
) -> str | None:
    """Keep a stored model id only while it is still in the compatible option list."""
    options = catalog.multimodal_chat_models(modality) if modality else catalog.chat_models()
    if previous and any(model.id == previous for model in options):
        return previous
    return None


def parse_catalog(payload: Any) -> tuple[OrcaRouterModel, ...]:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        raise OrcaRouterCatalogError("OrcaRouter /models response has no data list")
    models: list[OrcaRouterModel] = []
    for item in data[:MAX_CATALOG_ITEMS]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            continue
        raw_architecture = item.get("architecture")
        architecture: dict[str, Any] = (
            raw_architecture if isinstance(raw_architecture, dict) else {}
        )
        modalities = architecture.get("input_modalities")
        effort = item.get("reasoning_effort")
        models.append(
            OrcaRouterModel(
                id=item["id"],
                name=str(item.get("name") or item["id"]),
                context_length=_int_or_none(item.get("context_length")),
                input_modalities=_str_tuple(modalities),
                endpoint_types=_str_tuple(item.get("supported_endpoint_types")),
                reasoning_effort=_str_tuple(effort),
            )
        )
    if not models:
        raise OrcaRouterCatalogError("OrcaRouter /models response contained no usable models")
    return tuple(models)


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def fetch_catalog(
    transport: OrcaRouterTransport,
    credential: OrcaRouterCredential,
    *,
    api_base_url: str | None = None,
    capability: str = CHAT_CAPABILITY,
) -> OrcaRouterCatalog:
    base = api_base_url or resolve_api_base_url()
    query = urllib.parse.urlencode({"capability": capability})
    status, payload = transport.get_json(
        f"{base}/models?{query}", {"Authorization": f"Bearer {credential.key}"}
    )
    if status != 200:
        raise OrcaRouterCatalogError(f"OrcaRouter /models returned HTTP {status}")
    return OrcaRouterCatalog(models=parse_catalog(payload), source="live", fetched_at=time.time())


def fallback_catalog(*, now: float | None = None) -> OrcaRouterCatalog:
    return OrcaRouterCatalog(models=VERIFIED_SEED, source="verified_seed", fetched_at=now)


def last_known_good(
    cached: OrcaRouterCatalog | None, *, now: float | None = None
) -> OrcaRouterCatalog | None:
    current = time.time() if now is None else now
    if cached is None or cached.fetched_at is None:
        return None
    if current - cached.fetched_at > MAX_FALLBACK_CATALOG_DAYS * 86400:
        return None
    return OrcaRouterCatalog(
        models=cached.models, source="last_known_good", fetched_at=cached.fetched_at
    )


def request_chat_completion(
    transport: OrcaRouterTransport,
    credential: OrcaRouterCredential,
    *,
    model: str,
    messages: list[dict[str, str]],
    api_base_url: str | None = None,
) -> dict[str, Any]:
    """Send one OpenAI-compatible chat request to the inference origin."""
    base = api_base_url or resolve_api_base_url()
    status, payload = transport.post_json(
        f"{base}/chat/completions",
        {"model": model, "messages": messages},
        {"Authorization": f"Bearer {credential.key}"},
    )
    if status == 401:
        raise OrcaRouterAuthRejected("OrcaRouter rejected the API key; sign in again")
    if status != 200 or not isinstance(payload, dict):
        raise OrcaRouterError(f"OrcaRouter chat request failed with HTTP {status}")
    return payload
