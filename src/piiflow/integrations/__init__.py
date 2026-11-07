"""Named LLM-provider integrations for PIIFlow."""

from piiflow.integrations.orcarouter import (
    DEFAULT_API_BASE_URL,
    DEFAULT_AUTH_BASE_URL,
    ORCAROUTER_PROVIDER_ID,
    OrcaRouterCatalog,
    OrcaRouterCatalogError,
    OrcaRouterCredential,
    OrcaRouterCredentialError,
    OrcaRouterKeyAdapter,
    OrcaRouterModel,
    OrcaRouterPkceAdapter,
    request_chat_completion,
)

__all__ = [
    "DEFAULT_API_BASE_URL",
    "DEFAULT_AUTH_BASE_URL",
    "ORCAROUTER_PROVIDER_ID",
    "OrcaRouterCatalog",
    "OrcaRouterCatalogError",
    "OrcaRouterCredential",
    "OrcaRouterCredentialError",
    "OrcaRouterKeyAdapter",
    "OrcaRouterModel",
    "OrcaRouterPkceAdapter",
    "request_chat_completion",
]
