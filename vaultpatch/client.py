"""Vault HTTP client wrapper for reading and writing secrets."""

from __future__ import annotations

from typing import Any

import hvac

from vaultpatch.config import VaultConfig


class VaultClientError(Exception):
    """Raised when a Vault operation fails."""


class VaultClient:
    """Thin wrapper around hvac.Client scoped to a single namespace."""

    def __init__(self, config: VaultConfig) -> None:
        self._config = config
        self._client = hvac.Client(
            url=config.address,
            token=config.token,
            namespace=config.namespace,
            verify=config.tls_verify,
        )

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    def is_authenticated(self) -> bool:
        """Return True when the current token is valid."""
        try:
            return self._client.is_authenticated()
        except Exception as exc:  # pragma: no cover
            raise VaultClientError(f"Auth check failed: {exc}") from exc

    # ------------------------------------------------------------------
    # KV v2 operations
    # ------------------------------------------------------------------

    def read_secret(self, path: str, mount: str = "secret") -> dict[str, Any]:
        """Read the latest version of a KV v2 secret.

        Returns the *data* dict or raises VaultClientError.
        """
        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount,
            )
            return response["data"]["data"]
        except hvac.exceptions.InvalidPath as exc:
            raise VaultClientError(f"Secret not found: {path!r}") from exc
        except Exception as exc:
            raise VaultClientError(f"Failed to read secret {path!r}: {exc}") from exc

    def write_secret(
        self, path: str, data: dict[str, Any], mount: str = "secret"
    ) -> None:
        """Write *data* to a KV v2 secret path."""
        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                mount_point=mount,
            )
        except Exception as exc:
            raise VaultClientError(f"Failed to write secret {path!r}: {exc}") from exc
