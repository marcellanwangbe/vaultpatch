"""Rename (move) a secret path within or across Vault namespaces."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from vaultpatch.client import VaultClient, VaultClientError


@dataclass
class RenameResult:
    src_path: str
    dst_path: str
    dry_run: bool
    ok: bool
    error: Optional[str] = None
    keys_moved: int = 0

    def __repr__(self) -> str:  # pragma: no cover
        status = "DRY-RUN" if self.dry_run else ("OK" if self.ok else "ERROR")
        return f"<RenameResult {self.src_path!r} -> {self.dst_path!r} [{status}]>"


@dataclass
class RenameReport:
    results: list[RenameResult] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if not r.ok)

    def summary(self) -> str:
        return (
            f"Rename: {self.success_count} succeeded, "
            f"{self.error_count} failed "
            f"(total {len(self.results)})"
        )


def rename_secret(
    client: VaultClient,
    src_path: str,
    dst_path: str,
    *,
    dry_run: bool = False,
    delete_src: bool = True,
) -> RenameResult:
    """Copy src_path to dst_path and optionally delete the source."""
    try:
        data = client.read_secret(src_path)
    except VaultClientError as exc:
        return RenameResult(src_path=src_path, dst_path=dst_path, dry_run=dry_run, ok=False, error=str(exc))

    if data is None:
        return RenameResult(
            src_path=src_path, dst_path=dst_path, dry_run=dry_run,
            ok=False, error=f"Source path not found: {src_path}",
        )

    if dry_run:
        return RenameResult(
            src_path=src_path, dst_path=dst_path, dry_run=True,
            ok=True, keys_moved=len(data),
        )

    try:
        client.write_secret(dst_path, data)
        if delete_src:
            client.delete_secret(src_path)
    except VaultClientError as exc:
        return RenameResult(src_path=src_path, dst_path=dst_path, dry_run=False, ok=False, error=str(exc))

    return RenameResult(
        src_path=src_path, dst_path=dst_path, dry_run=False,
        ok=True, keys_moved=len(data),
    )


def rename_many(
    client: VaultClient,
    pairs: list[tuple[str, str]],
    *,
    dry_run: bool = False,
    delete_src: bool = True,
) -> RenameReport:
    report = RenameReport()
    for src, dst in pairs:
        result = rename_secret(client, src, dst, dry_run=dry_run, delete_src=delete_src)
        report.results.append(result)
    return report
