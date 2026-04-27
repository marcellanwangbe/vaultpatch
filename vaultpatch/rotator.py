"""High-level secret rotation logic with dry-run / audit support."""

from __future__ import annotations

from typing import Any

from vaultpatch.client import VaultClient
from vaultpatch.diff import SecretDiff, compute_diff


class RotationResult:
    """Outcome of a single secret rotation attempt."""

    def __init__(self, path: str, diff: SecretDiff, applied: bool) -> None:
        self.path = path
        self.diff = diff
        self.applied = applied

    def __repr__(self) -> str:  # pragma: no cover
        status = "applied" if self.applied else "dry-run"
        return f"<RotationResult path={self.path!r} status={status}>"


class SecretRotator:
    """Rotates secrets in Vault with optional dry-run previews."""

    def __init__(self, client: VaultClient, dry_run: bool = False) -> None:
        self._client = client
        self.dry_run = dry_run

    def rotate(
        self,
        path: str,
        updates: dict[str, Any],
        mount: str = "secret",
    ) -> RotationResult:
        """Merge *updates* into the existing secret at *path*.

        When *dry_run* is True the write is skipped and only the diff
        is returned.
        """
        current = self._client.read_secret(path, mount=mount)
        merged = {**current, **updates}
        diff = compute_diff(path, current, merged)

        applied = False
        if diff.has_changes and not self.dry_run:
            self._client.write_secret(path, merged, mount=mount)
            applied = True

        return RotationResult(path=path, diff=diff, applied=applied)

    def rotate_many(
        self,
        patches: list[dict],
        mount: str = "secret",
    ) -> list[RotationResult]:
        """Rotate multiple secrets from a list of patch dicts.

        Each entry must have ``path`` and ``data`` keys.
        """
        results = []
        for patch in patches:
            path = patch["path"]
            data = patch["data"]
            results.append(self.rotate(path, data, mount=mount))
        return results
