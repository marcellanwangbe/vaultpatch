"""Quota enforcement: flag secrets paths exceeding key/value count thresholds."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from vaultpatch.client import VaultClient


@dataclass
class QuotaViolation:
    path: str
    key_count: int
    max_keys: int
    value_bytes: int
    max_bytes: int

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"QuotaViolation(path={self.path!r}, keys={self.key_count}/{self.max_keys}, "
            f"bytes={self.value_bytes}/{self.max_bytes})"
        )

    @property
    def exceeds_keys(self) -> bool:
        return self.key_count > self.max_keys

    @property
    def exceeds_bytes(self) -> bool:
        return self.value_bytes > self.max_bytes


@dataclass
class QuotaReport:
    violations: List[QuotaViolation] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def ok(self) -> bool:
        return not self.violations

    def summary(self) -> str:
        parts = [f"{self.violation_count} violation(s)"]
        if self.errors:
            parts.append(f"{self.error_count} error(s)")
        return ", ".join(parts)


def check_quota(
    client: VaultClient,
    paths: List[str],
    max_keys: int = 20,
    max_bytes: int = 4096,
) -> QuotaReport:
    """Check each path against key-count and total-value-size quotas."""
    report = QuotaReport()
    for path in paths:
        try:
            data = client.read_secret(path)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"{path}: {exc}")
            continue

        key_count = len(data)
        value_bytes = sum(
            len(str(v).encode()) for v in data.values()
        )
        if key_count > max_keys or value_bytes > max_bytes:
            report.violations.append(
                QuotaViolation(
                    path=path,
                    key_count=key_count,
                    max_keys=max_keys,
                    value_bytes=value_bytes,
                    max_bytes=max_bytes,
                )
            )
    return report
