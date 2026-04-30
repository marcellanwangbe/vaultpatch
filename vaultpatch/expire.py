"""Secret expiration tracking — flag paths whose secrets are older than a TTL."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from vaultpatch.client import VaultClient


@dataclass
class ExpireResult:
    path: str
    age_days: Optional[float]  # None if metadata unavailable
    ttl_days: float
    expired: bool
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def __repr__(self) -> str:  # pragma: no cover
        status = "EXPIRED" if self.expired else "ok"
        return f"<ExpireResult path={self.path!r} age={self.age_days} ttl={self.ttl_days} {status}>"


@dataclass
class ExpireReport:
    results: List[ExpireResult] = field(default_factory=list)

    @property
    def expired_count(self) -> int:
        return sum(1 for r in self.results if r.expired)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if not r.ok)

    def summary(self) -> str:
        total = len(self.results)
        return (
            f"{self.expired_count}/{total} paths expired, "
            f"{self.error_count} error(s)"
        )


def _age_days_from_metadata(metadata: dict) -> Optional[float]:
    """Extract age in days from a Vault KV-v2 metadata dict."""
    created_raw = metadata.get("created_time") or metadata.get("custom_metadata", {}).get("rotated_at")
    if not created_raw:
        return None
    # Strip sub-second precision and timezone suffix for fromisoformat compat
    created_raw = re.sub(r"\.\d+", "", str(created_raw)).replace("Z", "+00:00")
    try:
        created_at = datetime.fromisoformat(created_raw)
    except ValueError:
        return None
    now = datetime.now(tz=timezone.utc)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return (now - created_at).total_seconds() / 86400.0


def check_expiry(
    client: VaultClient,
    paths: List[str],
    ttl_days: float = 90.0,
) -> ExpireReport:
    """Check each path and flag those whose metadata age exceeds *ttl_days*."""
    report = ExpireReport()
    for path in paths:
        try:
            data = client.read_secret(path)
            metadata = data.get("metadata", {}) if isinstance(data, dict) else {}
            age = _age_days_from_metadata(metadata)
            expired = age is not None and age > ttl_days
            report.results.append(ExpireResult(path=path, age_days=age, ttl_days=ttl_days, expired=expired))
        except Exception as exc:  # noqa: BLE001
            report.results.append(ExpireResult(path=path, age_days=None, ttl_days=ttl_days, expired=False, error=str(exc)))
    return report
