"""Baseline management: capture and compare a reference state for secret paths."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient
from vaultpatch.diff import compute_diff, SecretDiff


@dataclass
class BaselineEntry:
    path: str
    keys: List[str]
    captured_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"path": self.path, "keys": self.keys, "captured_at": self.captured_at}

    @classmethod
    def from_dict(cls, data: dict) -> "BaselineEntry":
        return cls(
            path=data["path"],
            keys=data["keys"],
            captured_at=data.get("captured_at", 0.0),
        )


@dataclass
class BaselineDrift:
    path: str
    added_keys: List[str]
    removed_keys: List[str]

    @property
    def has_drift(self) -> bool:
        return bool(self.added_keys or self.removed_keys)

    def summary(self) -> str:
        parts = []
        if self.added_keys:
            parts.append(f"+{len(self.added_keys)} added")
        if self.removed_keys:
            parts.append(f"-{len(self.removed_keys)} removed")
        return f"{self.path}: {', '.join(parts)}" if parts else f"{self.path}: no drift"


def capture_baseline(client: VaultClient, paths: List[str]) -> List[BaselineEntry]:
    """Read each path and record only the key names (not values)."""
    entries: List[BaselineEntry] = []
    for path in paths:
        data = client.read_secret(path) or {}
        entries.append(BaselineEntry(path=path, keys=sorted(data.keys())))
    return entries


def save_baseline(entries: List[BaselineEntry], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps([e.to_dict() for e in entries], indent=2))


def load_baseline(src: Path) -> List[BaselineEntry]:
    return [BaselineEntry.from_dict(d) for d in json.loads(src.read_text())]


def compare_baseline(
    client: VaultClient, entries: List[BaselineEntry]
) -> List[BaselineDrift]:
    """Compare live key names against the stored baseline."""
    results: List[BaselineDrift] = []
    for entry in entries:
        live = set((client.read_secret(entry.path) or {}).keys())
        base = set(entry.keys)
        results.append(
            BaselineDrift(
                path=entry.path,
                added_keys=sorted(live - base),
                removed_keys=sorted(base - live),
            )
        )
    return results
