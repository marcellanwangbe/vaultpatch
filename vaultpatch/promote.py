"""Promote secrets from one Vault path to another (e.g. staging -> production)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient


@dataclass
class PromoteResult:
    src_path: str
    dst_path: str
    keys_promoted: List[str] = field(default_factory=list)
    skipped_keys: List[str] = field(default_factory=list)
    error: Optional[str] = None
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None

    def __repr__(self) -> str:
        status = "DRY-RUN" if self.dry_run else ("OK" if self.ok else "ERROR")
        return (
            f"PromoteResult({self.src_path!r} -> {self.dst_path!r}, "
            f"promoted={len(self.keys_promoted)}, skipped={len(self.skipped_keys)}, "
            f"status={status})"
        )


@dataclass
class PromoteReport:
    results: List[PromoteResult] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if not r.ok)

    def summary(self) -> str:
        return (
            f"Promoted {self.success_count} path(s), "
            f"{self.error_count} error(s) across {len(self.results)} operation(s)."
        )


def promote_secret(
    client: VaultClient,
    src_path: str,
    dst_path: str,
    include_keys: Optional[List[str]] = None,
    exclude_keys: Optional[List[str]] = None,
    dry_run: bool = False,
) -> PromoteResult:
    """Copy secrets from src_path to dst_path, with optional key filtering."""
    try:
        src_data: Dict[str, str] = client.read_secret(src_path) or {}
    except Exception as exc:
        return PromoteResult(src_path=src_path, dst_path=dst_path, error=str(exc), dry_run=dry_run)

    promoted: List[str] = []
    skipped: List[str] = []
    payload: Dict[str, str] = {}

    for key, value in src_data.items():
        if include_keys is not None and key not in include_keys:
            skipped.append(key)
            continue
        if exclude_keys is not None and key in exclude_keys:
            skipped.append(key)
            continue
        payload[key] = value
        promoted.append(key)

    if not dry_run and payload:
        try:
            client.write_secret(dst_path, payload)
        except Exception as exc:
            return PromoteResult(
                src_path=src_path, dst_path=dst_path,
                keys_promoted=promoted, skipped_keys=skipped,
                error=str(exc), dry_run=dry_run,
            )

    return PromoteResult(
        src_path=src_path, dst_path=dst_path,
        keys_promoted=promoted, skipped_keys=skipped,
        dry_run=dry_run,
    )
