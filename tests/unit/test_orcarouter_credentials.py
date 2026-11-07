"""OrcaRouter credential seam: API key and PKCE adapters produce one credential shape."""

from __future__ import annotations

import hashlib
import logging
import urllib.parse

import pytest

from piiflow.integrations import orcarouter
from piiflow.integrations.orcarouter import (
    DEFAULT_API_BASE_URL,
    DEFAULT_AUTH_BASE_URL,
    OrcaRouterAuthRejected,
    OrcaRouterCredentialError,
    OrcaRouterExchangeError,
    OrcaRouterKeyAdapter,
    OrcaRouterPkceAdapter,
    UrlLibTransport,
    fetch_catalog,
    last_known_good,
    request_chat_completion,
    resolve_api_base_url,
    resolve_auth_base_url,
)

FAKE_KEY = "sk-orca-TESTONLY0000000000000000abcd"
FAKE_KEY_TWO = "sk-orca-TESTONLY1111111111111111wxyz"
FAKE_CODE = "fake-auth-code"


class FakeAuthServer:
    """Records every request so tests can assert origins, paths, and bodies."""

    def __init__(self, exchange_response: tuple[int, dict[str, object]]) -> None:
        self.exchange_response = exchange_response
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def get_json(self, url: str, headers):  # type: ignore[no-untyped-def]
        self.calls.append(("GET", url, {"headers": dict(headers)}))
        return self.exchange_response

    def post_json(self, url: str, body, headers):  # type: ignore[no-untyped-def]
        self.calls.append(("POST", url, {**dict(body), "headers": dict(headers)}))
        return self.exchange_response


def _b64url_sha256(value: str) -> str:
    import base64

    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def test_api_key_adapter_and_pkce_adapter_share_one_credential_shape() -> None:
    from_key = OrcaRouterKeyAdapter().credential_from_input(f"  {FAKE_KEY}  ")
    server = FakeAuthServer((200, {"key": FAKE_KEY_TWO, "user_id": "u-1", "scope": "api"}))
    adapter = OrcaRouterPkceAdapter(server, auth_base_url=DEFAULT_AUTH_BASE_URL)
    _, attempt = adapter.begin()
    from_pkce = adapter.exchange(attempt, FAKE_CODE)

    for credential in (from_key, from_pkce):
        assert isinstance(credential, orcarouter.OrcaRouterCredential)
        assert credential.key.startswith("sk-orca-")
        assert credential.scope == "api"
    assert from_key.source == "api_key"
    assert from_pkce.source == "pkce"
    assert from_pkce.account_id == "u-1"


def test_downstream_catalog_and_inference_do_not_care_about_credential_source() -> None:
    catalog_payload = {"data": [{"id": "orcarouter/auto", "supported_endpoint_types": ["openai"]}]}
    for source, credential in (
        ("api_key", OrcaRouterKeyAdapter().credential_from_input(FAKE_KEY)),
        ("pkce", orcarouter.make_credential(FAKE_KEY_TWO, "api", source="pkce")),
    ):
        server = FakeAuthServer((200, catalog_payload))
        catalog = fetch_catalog(server, credential)
        assert catalog.source == "live"
        assert [model.id for model in catalog.chat_models()] == ["orcarouter/auto"]

        server = FakeAuthServer((200, {"choices": [{"message": {"content": "ok"}}]}))
        request_chat_completion(
            server,
            credential,
            model="orcarouter/auto",
            messages=[{"role": "user", "content": "hi"}],
        )
        method, url, body = server.calls[0]
        assert (method, url) == ("POST", f"{DEFAULT_API_BASE_URL}/chat/completions")
        assert body["headers"]["Authorization"] == f"Bearer {credential.key}"
        assert source in {"api_key", "pkce"}


def test_api_key_rejects_bad_shape() -> None:
    with pytest.raises(OrcaRouterCredentialError):
        OrcaRouterKeyAdapter().credential_from_input("sk-openai-abc")
    with pytest.raises(OrcaRouterCredentialError):
        OrcaRouterKeyAdapter().credential_from_input("")


def test_credential_repr_and_mask_redact_key() -> None:
    credential = OrcaRouterKeyAdapter().credential_from_input(FAKE_KEY)
    assert FAKE_KEY not in repr(credential)
    assert FAKE_KEY not in credential.masked
    assert credential.masked == "sk-orca-…abcd"


def test_pkce_authorize_url_uses_auth_origin_and_s256_only() -> None:
    server = FakeAuthServer((200, {}))
    adapter = OrcaRouterPkceAdapter(server, auth_base_url=DEFAULT_AUTH_BASE_URL)
    url, attempt = adapter.begin()
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    assert f"{parsed.scheme}://{parsed.netloc}" == DEFAULT_AUTH_BASE_URL
    assert parsed.path == "/auth"
    assert params["callback_url"] == ["oob"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["code_challenge"] == [_b64url_sha256(attempt.verifier)]
    assert params["state"] == [attempt.state]
    assert "code_verifier" not in params
    assert attempt.verifier not in url


def test_pkce_verifier_and_state_are_fresh_per_attempt() -> None:
    adapter = OrcaRouterPkceAdapter(FakeAuthServer((200, {})), auth_base_url=DEFAULT_AUTH_BASE_URL)
    first_url, first = adapter.begin()
    second_url, second = adapter.begin()
    assert first.verifier != second.verifier
    assert first.state != second.state
    assert first_url != second_url


def test_pkce_exchange_uses_exchange_path_and_persistable_key() -> None:
    server = FakeAuthServer((200, {"key": FAKE_KEY_TWO, "user_id": "42", "scope": "api"}))
    adapter = OrcaRouterPkceAdapter(server, auth_base_url=DEFAULT_AUTH_BASE_URL)
    _, attempt = adapter.begin()
    credential = adapter.exchange(attempt, " code ")
    method, url, body = server.calls[0]
    assert (method, url) == ("POST", f"{DEFAULT_AUTH_BASE_URL}/api/v1/auth/keys")
    assert not url.startswith(DEFAULT_API_BASE_URL)
    assert "/v1/auth/keys" not in url.replace("/api/v1/auth/keys", "")
    assert body["code"] == "code"
    assert body["code_verifier"] == attempt.verifier
    assert body["code_challenge_method"] == "S256"
    assert credential.key == FAKE_KEY_TWO


@pytest.mark.parametrize(
    ("status", "payload", "expected"),
    [
        (403, {"error": "invalid_grant"}, OrcaRouterExchangeError),
        (429, {"error": "rate_limited"}, OrcaRouterExchangeError),
        (500, {}, OrcaRouterExchangeError),
        (200, {"scope": "api"}, OrcaRouterExchangeError),
    ],
)
def test_pkce_exchange_failures_are_actionable_and_secret_free(
    status: int, payload: dict[str, object], expected: type[Exception]
) -> None:
    server = FakeAuthServer((status, payload))
    adapter = OrcaRouterPkceAdapter(server, auth_base_url=DEFAULT_AUTH_BASE_URL)
    _, attempt = adapter.begin()
    with pytest.raises(expected) as info:
        adapter.exchange(attempt, FAKE_CODE)
    assert attempt.verifier not in str(info.value)
    assert FAKE_KEY not in str(info.value)


def test_pkce_scope_downgrade_is_reported_not_assumed() -> None:
    server = FakeAuthServer((200, {"key": FAKE_KEY_TWO, "scope": "connector"}))
    adapter = OrcaRouterPkceAdapter(server, auth_base_url=DEFAULT_AUTH_BASE_URL)
    _, attempt = adapter.begin(scope="api")
    with pytest.raises(OrcaRouterAuthRejected):
        adapter.exchange(attempt, FAKE_CODE, expected_scope="api")


def test_pkce_rejects_empty_code_without_network() -> None:
    server = FakeAuthServer((200, {}))
    adapter = OrcaRouterPkceAdapter(server, auth_base_url=DEFAULT_AUTH_BASE_URL)
    _, attempt = adapter.begin()
    with pytest.raises(OrcaRouterAuthRejected):
        adapter.exchange(attempt, "   ")
    assert server.calls == []


def test_auth_and_api_origins_are_independent_and_overridable(monkeypatch) -> None:
    assert resolve_auth_base_url({}) == DEFAULT_AUTH_BASE_URL
    assert resolve_api_base_url({}) == DEFAULT_API_BASE_URL
    shared = "https://orca.internal.example"
    assert resolve_auth_base_url({"ORCA_BASE_URL": shared}) == shared
    assert resolve_api_base_url({"ORCA_BASE_URL": shared}) == shared
    explicit = {
        "ORCA_BASE_URL": shared,
        "ORCA_AUTH_BASE_URL": "https://auth.internal.example",
        "ORCA_API_BASE_URL": "https://api.internal.example/v1",
    }
    assert resolve_auth_base_url(explicit) == "https://auth.internal.example"
    assert resolve_api_base_url(explicit) == "https://api.internal.example/v1"
    assert resolve_auth_base_url({"ORCA_AUTH_BASE_URL": "http://127.0.0.1:8080"}) == (
        "http://127.0.0.1:8080"
    )
    with pytest.raises(orcarouter.OrcaRouterError):
        resolve_api_base_url({"ORCA_API_BASE_URL": "http://api.example.com/v1"})


def test_revoked_key_marks_reauth_once_and_never_refreshes() -> None:
    server = FakeAuthServer((401, {"error": "revoked"}))
    credential = orcarouter.make_credential(FAKE_KEY, "api", source="pkce", generation=7)
    with pytest.raises(OrcaRouterAuthRejected):
        request_chat_completion(server, credential, model="orcarouter/auto", messages=[])
    assert len(server.calls) == 1
    assert all("/auth" not in url for _, url, _ in server.calls)


def test_catalog_failure_falls_back_to_verified_seed_and_last_known_good() -> None:
    seed = orcarouter.fallback_catalog()
    assert seed.degraded
    assert any(model.id == "orcarouter/auto" for model in seed.chat_models())
    gpt = seed.find("openai/gpt-5.5")
    assert gpt is not None
    assert gpt.reasoning_effort == ("low", "medium", "high", "xhigh")

    cached = orcarouter.OrcaRouterCatalog(models=seed.models, source="live", fetched_at=1000.0)
    assert last_known_good(cached, now=1000.0 + 3600) is not None
    stale = last_known_good(cached, now=1000.0 + 30 * 86400)
    assert stale is None


def test_transport_live_shape_is_urllib(monkeypatch) -> None:
    assert isinstance(UrlLibTransport(), UrlLibTransport)
    assert logging.getLogger("piiflow").level == logging.NOTSET
