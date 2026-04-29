"""Snapshot module for capturing and comparing Vault secret states."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient
from vaultpatch.diff import compute_diff, SecretDiff


@dataclass
class Snapshot:
    """Point-in-time capture of secrets at a given path."""

    path: str
    namespace: Optional[str]
    data: Dict[str, str]
    captured_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "namespace": self.namespace,
            "data": self.data,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "Snapshot":
        return cls(
            path=raw["path"],
            namespace=raw.get("namespace"),
            data=raw["data"],
            captured_at=raw["captured_at"],
        )


def capture_snapshot(client: VaultClient, path: str) -> Snapshot:
    """Read secrets from Vault and return a Snapshot."""
    data = client.read_secret(path) or {}
    return Snapshot(path=path, namespace=client.config.namespace, data=data)


def save_snapshot(snapshot: Snapshot, file: Path) -> None:
    """Persist a snapshot to a JSON file."""
    file.parent.mkdir(parents=True, exist_ok=True)
    with file.open("w") as fh:
        json.dump(snapshot.to_dict(), fh, indent=2)


def load_snapshot(file: Path) -> Snapshot:
    """Load a snapshot from a JSON file."""
    with file.open("r") as fh:
        return Snapshot.from_dict(json.load(fh))


def diff_snapshots(before: Snapshot, after: Snapshot) -> SecretDiff:
    """Compute a diff between two snapshots."""
    return compute_diff(path=after.path, old=before.data, new=after.data)
