"""Prune stale or empty secrets from Vault paths."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from vaultpatch.client import VaultClient


@dataclass
class PruneResult:
    path: str
    pruned_keys: List[str]
    dry_run: bool
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def __repr__(self) -> str:
        status = "DRY-RUN" if self.dry_run else ("OK" if self.ok else "ERROR")
        return f"<PruneResult path={self.path!r} pruned={self.pruned_keys} status={status}>"


@dataclass
class PruneReport:
    results: List[PruneResult] = field(default_factory=list)

    @property
    def pruned_count(self) -> int:
        return sum(len(r.pruned_keys) for r in self.results if r.ok)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if not r.ok)

    def summary(self) -> str:
        return (
            f"Pruned {self.pruned_count} key(s) across {len(self.results)} path(s); "
            f"{self.error_count} error(s)."
        )


def _is_stale(value: str, empty_only: bool) -> bool:
    """Return True if the value should be pruned."""
    if value == "":
        return True
    if not empty_only and value.strip() in ("", "null", "none", "undefined"):
        return True
    return False


def prune_path(
    client: VaultClient,
    path: str,
    *,
    empty_only: bool = False,
    dry_run: bool = False,
) -> PruneResult:
    """Remove stale keys from a single Vault path."""
    try:
        secret = client.read_secret(path)
    except Exception as exc:  # noqa: BLE001
        return PruneResult(path=path, pruned_keys=[], dry_run=dry_run, error=str(exc))

    if secret is None:
        return PruneResult(path=path, pruned_keys=[], dry_run=dry_run, error="path not found")

    stale_keys = [k for k, v in secret.items() if _is_stale(str(v), empty_only)]

    if stale_keys and not dry_run:
        updated = {k: v for k, v in secret.items() if k not in stale_keys}
        client.write_secret(path, updated)

    return PruneResult(path=path, pruned_keys=stale_keys, dry_run=dry_run)


def prune_paths(
    client: VaultClient,
    paths: List[str],
    *,
    empty_only: bool = False,
    dry_run: bool = False,
) -> PruneReport:
    """Prune stale keys from multiple Vault paths."""
    report = PruneReport()
    for path in paths:
        result = prune_path(client, path, empty_only=empty_only, dry_run=dry_run)
        report.results.append(result)
    return report
