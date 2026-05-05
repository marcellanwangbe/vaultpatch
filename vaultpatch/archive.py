"""Archive secrets from Vault paths to a compressed local backup."""
from __future__ import annotations

import gzip
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient


@dataclass
class ArchiveResult:
    path: str
    ok: bool
    data: Optional[Dict[str, str]] = None
    error: Optional[str] = None

    def __repr__(self) -> str:  # pragma: no cover
        status = "ok" if self.ok else f"error={self.error}"
        return f"ArchiveResult(path={self.path!r}, {status})"


@dataclass
class ArchiveReport:
    results: List[ArchiveResult] = field(default_factory=list)
    archive_path: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if not r.ok)

    def summary(self) -> str:
        return (
            f"archived {self.success_count} path(s), "
            f"{self.error_count} error(s) "
            f"-> {self.archive_path}"
        )


def archive_secrets(
    client: VaultClient,
    paths: List[str],
    dest: Path,
    mask: bool = True,
) -> ArchiveReport:
    """Read *paths* from Vault and write a gzip-compressed JSON archive to *dest*."""
    results: List[ArchiveResult] = []

    for path in paths:
        try:
            data = client.read_secret(path)
            if mask:
                data = {k: "***" for k in data}
            results.append(ArchiveResult(path=path, ok=True, data=data))
        except Exception as exc:  # noqa: BLE001
            results.append(ArchiveResult(path=path, ok=False, error=str(exc)))

    dest.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "created_at": time.time(),
        "paths": [
            {"path": r.path, "ok": r.ok, "data": r.data, "error": r.error}
            for r in results
        ],
    }

    with gzip.open(dest, "wt", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    return ArchiveReport(results=results, archive_path=str(dest))


def load_archive(src: Path) -> dict:
    """Load and return the raw archive payload from a gzip JSON file."""
    with gzip.open(src, "rt", encoding="utf-8") as fh:
        return json.load(fh)
