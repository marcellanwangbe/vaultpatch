"""Merge secrets from one Vault path into another with conflict detection."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient


@dataclass
class MergeResult:
    path: str
    merged_keys: List[str] = field(default_factory=list)
    skipped_keys: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"MergeResult(path={self.path!r}, merged={len(self.merged_keys)}, "
            f"skipped={len(self.skipped_keys)}, ok={self.ok})"
        )


@dataclass
class MergeReport:
    results: List[MergeResult] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if not r.ok)

    @property
    def total_merged_keys(self) -> int:
        return sum(len(r.merged_keys) for r in self.results)

    def summary(self) -> str:
        return (
            f"{self.success_count} path(s) merged, "
            f"{self.error_count} error(s), "
            f"{self.total_merged_keys} key(s) written"
        )


def merge_secrets(
    client: VaultClient,
    src_path: str,
    dst_path: str,
    overwrite: bool = False,
    dry_run: bool = False,
) -> MergeResult:
    """Merge secrets from *src_path* into *dst_path*.

    Keys that already exist in the destination are skipped unless
    *overwrite* is True.  When *dry_run* is True no writes are performed.
    """
    try:
        src_data = client.read_secret(src_path)
    except Exception as exc:
        return MergeResult(path=dst_path, error=f"read src failed: {exc}")

    try:
        dst_data = client.read_secret(dst_path)
    except Exception:
        dst_data = {}

    merged: Dict[str, str] = dict(dst_data)
    merged_keys: List[str] = []
    skipped_keys: List[str] = []

    for key, value in src_data.items():
        if key in dst_data and not overwrite:
            skipped_keys.append(key)
        else:
            merged[key] = value
            merged_keys.append(key)

    if merged_keys and not dry_run:
        try:
            client.write_secret(dst_path, merged)
        except Exception as exc:
            return MergeResult(path=dst_path, error=f"write failed: {exc}")

    return MergeResult(path=dst_path, merged_keys=merged_keys, skipped_keys=skipped_keys)
