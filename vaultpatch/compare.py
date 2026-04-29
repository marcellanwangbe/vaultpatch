"""Compare secrets across two Vault paths or namespaces."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient
from vaultpatch.diff import compute_diff, SecretDiff


@dataclass
class CompareResult:
    left_path: str
    right_path: str
    diff: SecretDiff
    left_error: Optional[str] = None
    right_error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.left_error is None and self.right_error is None

    def summary(self) -> str:
        if not self.ok:
            errors = ", ".join(filter(None, [self.left_error, self.right_error]))
            return f"[ERROR] {self.left_path} <-> {self.right_path}: {errors}"
        if not self.diff.has_changes:
            return f"[IDENTICAL] {self.left_path} <-> {self.right_path}"
        return (
            f"[DIFFERS] {self.left_path} <-> {self.right_path}: "
            f"{self.diff.summary()}"
        )


@dataclass
class CompareReport:
    results: List[CompareResult] = field(default_factory=list)

    @property
    def differs_count(self) -> int:
        return sum(1 for r in self.results if r.ok and r.diff.has_changes)

    @property
    def identical_count(self) -> int:
        return sum(1 for r in self.results if r.ok and not r.diff.has_changes)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if not r.ok)

    def summary(self) -> str:
        return (
            f"{len(self.results)} compared: "
            f"{self.identical_count} identical, "
            f"{self.differs_count} differ, "
            f"{self.error_count} errors"
        )


def compare_paths(
    client: VaultClient,
    path_pairs: List[tuple[str, str]],
    mask: bool = True,
) -> CompareReport:
    """Compare secret values at pairs of Vault paths."""
    report = CompareReport()
    for left_path, right_path in path_pairs:
        left_data: Dict[str, str] = {}
        right_data: Dict[str, str] = {}
        left_error: Optional[str] = None
        right_error: Optional[str] = None

        try:
            left_data = client.read_secret(left_path) or {}
        except Exception as exc:  # noqa: BLE001
            left_error = str(exc)

        try:
            right_data = client.read_secret(right_path) or {}
        except Exception as exc:  # noqa: BLE001
            right_error = str(exc)

        diff = compute_diff(left_data, right_data, mask=mask)
        report.results.append(
            CompareResult(
                left_path=left_path,
                right_path=right_path,
                diff=diff,
                left_error=left_error,
                right_error=right_error,
            )
        )
    return report
