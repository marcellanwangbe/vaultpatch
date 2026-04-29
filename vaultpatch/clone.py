"""Clone secrets from one Vault path to another, with optional key filtering."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient


@dataclass
class CloneResult:
    source_path: str
    dest_path: str
    keys_copied: List[str] = field(default_factory=list)
    keys_skipped: List[str] = field(default_factory=list)
    dry_run: bool = False
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def __repr__(self) -> str:  # pragma: no cover
        status = "DRY-RUN" if self.dry_run else ("OK" if self.ok else "ERROR")
        return (
            f"CloneResult({status} {self.source_path!r} -> {self.dest_path!r}, "
            f"copied={len(self.keys_copied)}, skipped={len(self.keys_skipped)})"
        )


@dataclass
class CloneReport:
    results: List[CloneResult] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if not r.ok)

    def summary(self) -> str:
        return (
            f"Cloned {self.success_count} path(s), "
            f"{self.error_count} error(s)."
        )


def clone_secret(
    client: VaultClient,
    source_path: str,
    dest_path: str,
    *,
    include_keys: Optional[List[str]] = None,
    exclude_keys: Optional[List[str]] = None,
    dry_run: bool = False,
) -> CloneResult:
    """Copy secrets from *source_path* to *dest_path* with optional key filtering."""
    try:
        data: Dict[str, str] = client.read_secret(source_path)
    except Exception as exc:  # noqa: BLE001
        return CloneResult(
            source_path=source_path,
            dest_path=dest_path,
            dry_run=dry_run,
            error=str(exc),
        )

    copied: Dict[str, str] = {}
    keys_copied: List[str] = []
    keys_skipped: List[str] = []

    for key, value in data.items():
        if include_keys is not None and key not in include_keys:
            keys_skipped.append(key)
            continue
        if exclude_keys is not None and key in exclude_keys:
            keys_skipped.append(key)
            continue
        copied[key] = value
        keys_copied.append(key)

    if not dry_run and copied:
        try:
            client.write_secret(dest_path, copied)
        except Exception as exc:  # noqa: BLE001
            return CloneResult(
                source_path=source_path,
                dest_path=dest_path,
                keys_copied=keys_copied,
                keys_skipped=keys_skipped,
                dry_run=dry_run,
                error=str(exc),
            )

    return CloneResult(
        source_path=source_path,
        dest_path=dest_path,
        keys_copied=keys_copied,
        keys_skipped=keys_skipped,
        dry_run=dry_run,
    )
