"""Rollback support: restore secrets from a previously captured snapshot."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient
from vaultpatch.snapshot import Snapshot, load_snapshot
from vaultpatch.diff import compute_diff, SecretDiff


@dataclass
class RollbackResult:
    path: str
    diff: SecretDiff
    applied: bool
    dry_run: bool
    error: Optional[str] = None

    def __repr__(self) -> str:  # pragma: no cover
        status = "dry-run" if self.dry_run else ("ok" if self.applied else "skipped")
        return f"<RollbackResult path={self.path!r} status={status}>"


@dataclass
class RollbackReport:
    snapshot_path: str
    results: List[RollbackResult] = field(default_factory=list)

    @property
    def applied_count(self) -> int:
        return sum(1 for r in self.results if r.applied)

    @property
    def skipped_count(self) -> int:
        return sum(1 for r in self.results if not r.applied and r.error is None)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.error is not None)

    def summary(self) -> str:
        return (
            f"Rollback from '{self.snapshot_path}': "
            f"{self.applied_count} applied, "
            f"{self.skipped_count} skipped, "
            f"{self.error_count} errors"
        )


class SecretRollback:
    def __init__(self, client: VaultClient, dry_run: bool = False) -> None:
        self.client = client
        self.dry_run = dry_run

    def rollback_from_snapshot(
        self, snapshot_path: str, paths: Optional[List[str]] = None
    ) -> RollbackReport:
        snapshot: Snapshot = load_snapshot(snapshot_path)
        report = RollbackReport(snapshot_path=snapshot_path)

        targets: Dict[str, Dict[str, str]] = snapshot.secrets
        if paths is not None:
            targets = {p: v for p, v in targets.items() if p in paths}

        for secret_path, desired in targets.items():
            try:
                current = self.client.read_secret(secret_path) or {}
                diff = compute_diff(current, desired)

                if not diff.has_changes:
                    report.results.append(
                        RollbackResult(
                            path=secret_path, diff=diff,
                            applied=False, dry_run=self.dry_run
                        )
                    )
                    continue

                if not self.dry_run:
                    self.client.write_secret(secret_path, desired)

                report.results.append(
                    RollbackResult(
                        path=secret_path, diff=diff,
                        applied=True, dry_run=self.dry_run
                    )
                )
            except Exception as exc:  # noqa: BLE001
                report.results.append(
                    RollbackResult(
                        path=secret_path,
                        diff=compute_diff({}, desired),
                        applied=False,
                        dry_run=self.dry_run,
                        error=str(exc),
                    )
                )

        return report
